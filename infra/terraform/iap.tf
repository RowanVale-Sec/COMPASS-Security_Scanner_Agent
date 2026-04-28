# Cloud IAP gating for the api-gateway service.
#
# Two IAM layers are required for IAP-on-Cloud-Run:
#   1. roles/iap.httpsResourceAccessor — granted to the human user(s) so they
#      can pass IAP's auth gate. Lives in modules/iap.
#   2. roles/run.invoker — granted to the IAP service agent so IAP can actually
#      forward authenticated requests to the Cloud Run service. Without this,
#      IAP authenticates the user but the service returns 403 ("Your client
#      does not have permission to get URL"). Lives below.

data "google_project" "current" {
  project_id = var.project_id
}

module "iap_api_gateway" {
  source = "./modules/iap"

  project_id       = var.project_id
  service_location = var.region
  service_name     = module.cloud_run_api_gateway.name

  # owner_email is always allowed. additional_iap_users is the list of other
  # Google accounts that may sign in. distinct() de-dupes if owner_email
  # accidentally appears in both.
  allowed_user_emails = distinct(concat([var.owner_email], var.additional_iap_users))
}

resource "google_cloud_run_v2_service_iam_member" "iap_invokes_api_gateway" {
  project  = var.project_id
  location = var.region
  name     = module.cloud_run_api_gateway.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-iap.iam.gserviceaccount.com"
}
