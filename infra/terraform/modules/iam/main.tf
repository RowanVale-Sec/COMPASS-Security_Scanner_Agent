# =============================================================================
# Runtime service accounts — one per Cloud Run service that PR 3 will deploy.
# Each service runs as its own SA so we can scope `roles/run.invoker`
# tightly (api-gateway -> orchestrator only, orchestrator -> agents only,
# agents -> their MCPs only) instead of granting one mega-SA cross-service
# access.
# =============================================================================
resource "google_service_account" "runtime" {
  for_each = toset(var.services)

  project      = var.project_id
  account_id   = "${var.name_prefix}-${each.value}"
  display_name = "COMPASS runtime SA: ${each.value}"
}

# =============================================================================
# Deployer SA — impersonated by GitHub Actions via WIF to push images and
# update Cloud Run services. Project-level roles are coarse but adequate for
# a single-tenant deployment; tighten later if other workloads land here.
# =============================================================================
resource "google_service_account" "deployer" {
  project      = var.project_id
  account_id   = "${var.name_prefix}-deployer"
  display_name = "COMPASS GitHub Actions deployer"
}

resource "google_project_iam_member" "deployer_roles" {
  for_each = toset([
    "roles/run.admin",               # create / update Cloud Run services
    "roles/artifactregistry.writer", # push images
    "roles/iam.serviceAccountUser",  # act-as the runtime SAs at deploy time
    "roles/iap.admin",               # manage IAP gating in PR 3
    "roles/storage.admin",           # read/write Terraform state + workspace bucket
    "roles/serviceusage.serviceUsageConsumer",
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.deployer.email}"
}

# =============================================================================
# Workload Identity Federation — pool + GitHub OIDC provider, locked to a
# single repo and ref so a leaked workflow on a fork can't impersonate the
# deployer. The attribute_condition is the load-bearing piece here.
# =============================================================================
resource "google_iam_workload_identity_pool" "github" {
  project                   = var.project_id
  workload_identity_pool_id = "${var.name_prefix}-github"
  display_name              = "COMPASS GitHub OIDC"
  description               = "Pool for GitHub Actions OIDC federation"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github"
  display_name                       = "GitHub Actions OIDC"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
    "attribute.ref"        = "assertion.ref"
  }

  # Only this exact repo + ref can mint tokens. Anything else gets "no
  # matching credential" before any role binding is consulted.
  attribute_condition = "assertion.repository == \"${var.github_repo}\" && assertion.ref == \"${var.github_ref}\""

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

# Allow principals matching the WIF attribute condition above to impersonate
# the deployer SA. Combined with the attribute_condition, only workflows on
# the configured repo + ref can succeed.
resource "google_service_account_iam_member" "deployer_wif_binding" {
  service_account_id = google_service_account.deployer.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository/${var.github_repo}"
}
