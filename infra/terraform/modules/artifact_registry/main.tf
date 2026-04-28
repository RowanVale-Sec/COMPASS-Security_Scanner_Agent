resource "google_artifact_registry_repository" "service" {
  for_each = toset(var.services)

  project       = var.project_id
  location      = var.region
  repository_id = "${var.name_prefix}-${each.value}"
  format        = "DOCKER"
  description   = "COMPASS ${each.value} container images."

  # Keep the most recent 10 tagged revisions so rollbacks are possible without
  # cluttering the registry indefinitely.
  cleanup_policies {
    id     = "keep-last-10-tagged"
    action = "KEEP"
    most_recent_versions {
      keep_count = 10
    }
  }

  # Untagged layers from prior failed pushes / rebuilds get garbage-collected
  # after a week so AR storage cost stays in single-digit dollars.
  cleanup_policies {
    id     = "delete-untagged-after-7d"
    action = "DELETE"
    condition {
      tag_state  = "UNTAGGED"
      older_than = "604800s" # 7 days
    }
  }
}
