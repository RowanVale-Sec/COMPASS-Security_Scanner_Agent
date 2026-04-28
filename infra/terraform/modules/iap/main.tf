# Cloud IAP IAM binding for the api-gateway service.
#
# IMPORTANT: this module no longer creates the OAuth brand. As of mid-2025
# Google deprecated the IAP OAuth Admin API, and `google_iap_brand` is on
# borrowed time. The current pattern (Google-managed OAuth) auto-creates the
# brand the first time IAP is enabled on a service via gcloud. Run this once
# after `terraform apply`:
#
#   gcloud run services update compass-api-gateway \
#     --region=us-central1 --iap --project=<PROJECT_ID>
#
# That command provisions the OAuth bits with no human input. Then this
# resource grants the listed Google accounts access through IAP.

resource "google_iap_web_cloud_run_service_iam_member" "accessors" {
  for_each = toset(var.allowed_user_emails)

  project                = var.project_id
  location               = var.service_location
  cloud_run_service_name = var.service_name
  role                   = "roles/iap.httpsResourceAccessor"
  member                 = "user:${each.value}"
}
