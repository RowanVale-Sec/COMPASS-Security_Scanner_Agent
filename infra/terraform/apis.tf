# Required GCP APIs. `disable_on_destroy = false` so a teardown of COMPASS
# doesn't disable APIs that other things in the project might use.
locals {
  required_apis = toset([
    "artifactregistry.googleapis.com",
    "run.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "storage.googleapis.com",
    "iap.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "sts.googleapis.com",
    "serviceusage.googleapis.com",
  ])
}

resource "google_project_service" "enabled" {
  for_each = local.required_apis

  project = var.project_id
  service = each.value

  disable_on_destroy = false
}
