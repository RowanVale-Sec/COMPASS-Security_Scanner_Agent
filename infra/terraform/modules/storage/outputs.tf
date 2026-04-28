output "workspace_bucket" {
  description = "Name of the workspaces GCS bucket (used as the FUSE mount source in PR 3)."
  value       = google_storage_bucket.workspace.name
}
