resource "google_storage_bucket" "workspace" {
  project  = var.project_id
  name     = "${var.name_prefix}-workspaces-${var.project_id}"
  location = var.region

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  # Workspaces are throwaway per-job clones; if the user tears down the stack
  # we don't want to fight Terraform over leftover prefixes.
  force_destroy = true

  # Belt-and-braces on top of api-gateway's own cleanup. If a clone leaks
  # because a job crashed mid-flight, GCS purges it within 24 hours so we
  # never accumulate orphan source code.
  lifecycle_rule {
    condition {
      age = 1
    }
    action {
      type = "Delete"
    }
  }

  versioning {
    enabled = false
  }
}
