output "artifact_registry_repos" {
  description = "Service name -> Docker push URL (use as image base in builds)."
  value       = module.artifact_registry.repo_urls
}

output "workspace_bucket" {
  description = "GCS bucket name for per-scan workspaces."
  value       = module.storage.workspace_bucket
}

output "runtime_service_accounts" {
  description = "Service name -> runtime SA email. PR 3 attaches these to Cloud Run services."
  value       = module.iam.runtime_service_accounts
}

output "deployer_service_account" {
  description = "Email of the SA that GitHub Actions impersonates via WIF."
  value       = module.iam.deployer_service_account_email
}

output "workload_identity_provider" {
  description = "Resource name of the WIF provider — set as GCP_WORKLOAD_IDENTITY_PROVIDER in GitHub Secrets."
  value       = module.iam.workload_identity_provider
}

output "github_secrets_to_set" {
  description = "GitHub repo secrets the deploy workflow expects, in one map. Copy each into Settings -> Secrets and variables -> Actions."
  value = {
    GCP_PROJECT_ID                 = var.project_id
    GCP_REGION                     = var.region
    GCP_WORKLOAD_IDENTITY_PROVIDER = module.iam.workload_identity_provider
    GCP_DEPLOY_SERVICE_ACCOUNT     = module.iam.deployer_service_account_email
    COMPASS_OWNER_EMAIL            = var.owner_email
  }
}

# -----------------------------------------------------------------------------
# PR 3 outputs — Cloud Run service URLs.
# The api-gateway URL is the only one a human needs to visit; all others are
# internal-ingress and unreachable from a browser.
# -----------------------------------------------------------------------------

output "app_url" {
  description = "Public URL of COMPASS (gated by Cloud IAP — sign in with owner_email's Google account)."
  value       = module.cloud_run_api_gateway.uri
}

output "service_urls" {
  description = "All 7 service URLs. Internal services return 403 to anyone but their authorized callers."
  value = {
    api-gateway        = module.cloud_run_api_gateway.uri
    orchestrator       = module.cloud_run_orchestrator.uri
    scanner-agent      = module.cloud_run_scanner.uri
    inventory-agent    = module.cloud_run_inventory.uri
    threat-model-agent = module.cloud_run_threat_model.uri
    mitre-mcp          = module.cloud_run_mitre_mcp.uri
    syft-mcp           = module.cloud_run_syft_mcp.uri
  }
}

output "custom_domain_dns_records" {
  description = <<-EOT
    DNS records to add at your registrar after `terraform apply` so the
    custom domain mapping starts serving. Empty when var.custom_domain is
    unset. For each record, create that name/type/value at your DNS host.
    Once propagation completes, Google provisions a managed TLS cert (~15–60
    min) and the custom URL becomes reachable through IAP.
  EOT
  value = var.custom_domain != "" ? try(
    google_cloud_run_domain_mapping.api_gateway[0].status[0].resource_records,
    []
  ) : []
}
