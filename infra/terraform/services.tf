# =============================================================================
# Cloud Run services for the 7-service COMPASS pipeline.
#
# Image strategy: when var.image_tag = "bootstrap" (default) every service
# runs Google's `cloudrun/hello` placeholder. This lets `terraform apply`
# succeed before any real images are pushed, so PR 3 can be validated in
# isolation. Once PR 4's deploy workflow pushes real images and re-applies
# with `-var image_tag=<sha>`, services swap to the COMPASS images.
# =============================================================================

locals {
  # Per-service image refs, computed from the Artifact Registry URLs created
  # in PR 2. The "bootstrap" sentinel keeps the placeholder so PR 3 can
  # apply cleanly before any real images are pushed.
  is_bootstrap    = var.image_tag == "bootstrap"
  bootstrap_image = "us-docker.pkg.dev/cloudrun/container/hello"
  # The hello image only listens on $PORT (defaults to 8080). When bootstrap
  # is in play we have to override every service's container_port too,
  # otherwise Cloud Run's health probe goes to the service's real port and
  # times out. PR 4's first real-image apply restores per-service ports.
  bootstrap_port = 8080

  service_images = {
    for s in local.services :
    s => local.is_bootstrap ? local.bootstrap_image : "${module.artifact_registry.repo_urls[s]}/${s}:${var.image_tag}"
  }

  # Production container ports per service (matches each agent's hardcoded
  # listen port — see docker-compose.yml).
  prod_ports = {
    "api-gateway"        = 8094
    "orchestrator"       = 8093
    "scanner-agent"      = 8090
    "inventory-agent"    = 8091
    "threat-model-agent" = 8092
    "mitre-mcp"          = 8000
    "syft-mcp"           = 8080
  }

  service_ports = {
    for s in local.services :
    s => local.is_bootstrap ? local.bootstrap_port : local.prod_ports[s]
  }
}

# -----------------------------------------------------------------------------
# api-gateway — the public surface. Bundles the React SPA (served at /) plus
# the FastAPI backend (/api/*). Sits behind Cloud IAP via google_iap_brand
# below.
# -----------------------------------------------------------------------------
module "cloud_run_api_gateway" {
  source = "./modules/cloud_run"

  name                  = "${var.name_prefix}-api-gateway"
  project_id            = var.project_id
  region                = var.region
  image                 = local.service_images["api-gateway"]
  service_account_email = module.iam.runtime_service_accounts["api-gateway"]

  cpu                   = "1"
  memory                = "512Mi"
  concurrency           = 10
  max_instance_count    = 10
  timeout_seconds       = 3600
  cpu_boost             = true
  execution_environment = "EXECUTION_ENVIRONMENT_GEN2" # FUSE workspace mount needs Gen2
  ingress               = "INGRESS_TRAFFIC_ALL"        # public — IAP gates it (enabled out-of-band via `gcloud run services update --iap`)
  container_port        = local.service_ports["api-gateway"]
  session_affinity      = true # SSE stream must land on the instance that owns the JobRegistry entry
  workspace_bucket      = local.is_bootstrap ? "" : module.storage.workspace_bucket
  workspace_read_only   = false

  env_vars = {
    ORCHESTRATOR_URL       = module.cloud_run_orchestrator.uri
    COMPASS_WORKSPACE_ROOT = "/workspace"
    COMPASS_STATIC_DIR     = "/app/static" # also baked into Dockerfile.cloud, but explicit for clarity
  }
}

# -----------------------------------------------------------------------------
# orchestrator — fan-outs to scanner / inventory / threat-model. Concurrency
# 1 because each scan owns the worker thread (see orchestrator_agent.py:354).
# -----------------------------------------------------------------------------
module "cloud_run_orchestrator" {
  source = "./modules/cloud_run"

  name                  = "${var.name_prefix}-orchestrator"
  project_id            = var.project_id
  region                = var.region
  image                 = local.service_images["orchestrator"]
  service_account_email = module.iam.runtime_service_accounts["orchestrator"]

  cpu                = "1"
  memory             = "512Mi"
  concurrency        = 1
  max_instance_count = 10
  timeout_seconds    = 3600
  cpu_boost          = true
  ingress            = "INGRESS_TRAFFIC_INTERNAL_ONLY"
  container_port     = local.service_ports["orchestrator"]

  env_vars = {
    COMPASS_MODE     = "server"
    SCANNER_URL      = module.cloud_run_scanner.uri
    INVENTORY_URL    = module.cloud_run_inventory.uri
    THREAT_MODEL_URL = module.cloud_run_threat_model.uri
  }
}

# -----------------------------------------------------------------------------
# scanner-agent — heaviest service: Trivy + Semgrep + Bandit + sentence-
# transformers. Gen2 because scan tools shell out to native binaries that
# need full Linux syscalls.
# -----------------------------------------------------------------------------
module "cloud_run_scanner" {
  source = "./modules/cloud_run"

  name                  = "${var.name_prefix}-scanner-agent"
  project_id            = var.project_id
  region                = var.region
  image                 = local.service_images["scanner-agent"]
  service_account_email = module.iam.runtime_service_accounts["scanner-agent"]

  cpu                   = "2"
  memory                = "4Gi"
  concurrency           = 1
  max_instance_count    = 10
  timeout_seconds       = 3600
  cpu_boost             = true
  execution_environment = "EXECUTION_ENVIRONMENT_GEN2"
  ingress               = "INGRESS_TRAFFIC_INTERNAL_ONLY"
  container_port        = local.service_ports["scanner-agent"]
  workspace_bucket      = local.is_bootstrap ? "" : module.storage.workspace_bucket
  workspace_read_only   = true

  env_vars = {
    COMPASS_MODE     = "server"
    SCANNER_PORT     = "8090"
    SCAN_FOLDER_PATH = "/workspace"
    MITRE_MCP_URL    = "${module.cloud_run_mitre_mcp.uri}/mcp"
  }
}

# -----------------------------------------------------------------------------
# inventory-agent — Syft + architecture/dataflow analyzers. Also Gen2 for
# Syft's native binary dependencies.
# -----------------------------------------------------------------------------
module "cloud_run_inventory" {
  source = "./modules/cloud_run"

  name                  = "${var.name_prefix}-inventory-agent"
  project_id            = var.project_id
  region                = var.region
  image                 = local.service_images["inventory-agent"]
  service_account_email = module.iam.runtime_service_accounts["inventory-agent"]

  cpu                   = "1"
  memory                = "2Gi"
  concurrency           = 1
  max_instance_count    = 10
  timeout_seconds       = 3600
  cpu_boost             = true
  execution_environment = "EXECUTION_ENVIRONMENT_GEN2"
  ingress               = "INGRESS_TRAFFIC_INTERNAL_ONLY"
  container_port        = local.service_ports["inventory-agent"]
  workspace_bucket      = local.is_bootstrap ? "" : module.storage.workspace_bucket
  workspace_read_only   = true

  env_vars = {
    COMPASS_MODE     = "server"
    INVENTORY_PORT   = "8091"
    SCAN_FOLDER_PATH = "/workspace"
    SYFT_MCP_URL     = module.cloud_run_syft_mcp.uri
  }
}

# -----------------------------------------------------------------------------
# threat-model-agent — pure Python, no scanner shellouts, no FUSE. Fits Gen1.
# -----------------------------------------------------------------------------
module "cloud_run_threat_model" {
  source = "./modules/cloud_run"

  name                  = "${var.name_prefix}-threat-model-agent"
  project_id            = var.project_id
  region                = var.region
  image                 = local.service_images["threat-model-agent"]
  service_account_email = module.iam.runtime_service_accounts["threat-model-agent"]

  cpu                = "1"
  memory             = "1Gi"
  concurrency        = 1
  max_instance_count = 10
  timeout_seconds    = 3600
  cpu_boost          = true
  ingress            = "INGRESS_TRAFFIC_INTERNAL_ONLY"
  container_port     = local.service_ports["threat-model-agent"]

  env_vars = {
    COMPASS_MODE      = "server"
    THREAT_MODEL_PORT = "8092"
  }
}

# -----------------------------------------------------------------------------
# mitre-mcp — MCP server wrapping Montimage's MITRE ATT&CK data set.
# -----------------------------------------------------------------------------
module "cloud_run_mitre_mcp" {
  source = "./modules/cloud_run"

  name                  = "${var.name_prefix}-mitre-mcp"
  project_id            = var.project_id
  region                = var.region
  image                 = local.service_images["mitre-mcp"]
  service_account_email = module.iam.runtime_service_accounts["mitre-mcp"]

  cpu                = "1"
  memory             = "512Mi"
  concurrency        = 10
  max_instance_count = 5
  timeout_seconds    = 300
  ingress            = "INGRESS_TRAFFIC_INTERNAL_ONLY"
  container_port     = local.service_ports["mitre-mcp"]

  env_vars = {
    FASTMCP_HOST = "0.0.0.0"
    FASTMCP_PORT = "8000"
  }
}

# -----------------------------------------------------------------------------
# syft-mcp — MCP wrapper around the `syft` SBOM binary. Reads the workspace
# read-only.
# -----------------------------------------------------------------------------
module "cloud_run_syft_mcp" {
  source = "./modules/cloud_run"

  name                  = "${var.name_prefix}-syft-mcp"
  project_id            = var.project_id
  region                = var.region
  image                 = local.service_images["syft-mcp"]
  service_account_email = module.iam.runtime_service_accounts["syft-mcp"]

  cpu                   = "1"
  memory                = "512Mi"
  concurrency           = 10
  max_instance_count    = 5
  timeout_seconds       = 300
  ingress               = "INGRESS_TRAFFIC_INTERNAL_ONLY"
  container_port        = local.service_ports["syft-mcp"]
  execution_environment = "EXECUTION_ENVIRONMENT_GEN2" # FUSE workspace mount needs Gen2
  workspace_bucket      = local.is_bootstrap ? "" : module.storage.workspace_bucket
  workspace_read_only   = true
}
