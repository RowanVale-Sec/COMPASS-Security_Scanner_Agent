# =============================================================================
# Service-to-service authorization for COMPASS on Cloud Run.
#
# Every internal service is created with --no-allow-unauthenticated (i.e. no
# `allUsers` invoker binding). Each caller must hold roles/run.invoker on its
# specific callee — that's what these resources do.
#
# The auth header itself is minted at request time by shared/cloud_auth.py
# (added in PR 1) using the caller's runtime SA via the metadata server.
# =============================================================================

# api-gateway -> orchestrator
resource "google_cloud_run_v2_service_iam_member" "gateway_invokes_orchestrator" {
  project  = var.project_id
  location = var.region
  name     = module.cloud_run_orchestrator.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${module.iam.runtime_service_accounts["api-gateway"]}"
}

# orchestrator -> scanner / inventory / threat-model
resource "google_cloud_run_v2_service_iam_member" "orchestrator_invokes_scanner" {
  project  = var.project_id
  location = var.region
  name     = module.cloud_run_scanner.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${module.iam.runtime_service_accounts["orchestrator"]}"
}

resource "google_cloud_run_v2_service_iam_member" "orchestrator_invokes_inventory" {
  project  = var.project_id
  location = var.region
  name     = module.cloud_run_inventory.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${module.iam.runtime_service_accounts["orchestrator"]}"
}

resource "google_cloud_run_v2_service_iam_member" "orchestrator_invokes_threat_model" {
  project  = var.project_id
  location = var.region
  name     = module.cloud_run_threat_model.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${module.iam.runtime_service_accounts["orchestrator"]}"
}

# scanner -> mitre-mcp
resource "google_cloud_run_v2_service_iam_member" "scanner_invokes_mitre" {
  project  = var.project_id
  location = var.region
  name     = module.cloud_run_mitre_mcp.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${module.iam.runtime_service_accounts["scanner-agent"]}"
}

# inventory -> syft-mcp
resource "google_cloud_run_v2_service_iam_member" "inventory_invokes_syft" {
  project  = var.project_id
  location = var.region
  name     = module.cloud_run_syft_mcp.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${module.iam.runtime_service_accounts["inventory-agent"]}"
}

# =============================================================================
# Workspace bucket access for the 4 services that touch the FUSE mount.
# api-gateway writes (clones the repo); the other three only read.
# =============================================================================

resource "google_storage_bucket_iam_member" "gateway_workspace_admin" {
  bucket = module.storage.workspace_bucket
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${module.iam.runtime_service_accounts["api-gateway"]}"
}

resource "google_storage_bucket_iam_member" "scanner_workspace_reader" {
  bucket = module.storage.workspace_bucket
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${module.iam.runtime_service_accounts["scanner-agent"]}"
}

resource "google_storage_bucket_iam_member" "inventory_workspace_reader" {
  bucket = module.storage.workspace_bucket
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${module.iam.runtime_service_accounts["inventory-agent"]}"
}

resource "google_storage_bucket_iam_member" "syft_workspace_reader" {
  bucket = module.storage.workspace_bucket
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${module.iam.runtime_service_accounts["syft-mcp"]}"
}
