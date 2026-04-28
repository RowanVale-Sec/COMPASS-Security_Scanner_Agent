output "uri" {
  description = "Public HTTPS URL of the service (https://service-hash-region.a.run.app)."
  value       = google_cloud_run_v2_service.this.uri
}

output "name" {
  description = "Service name (matches var.name)."
  value       = google_cloud_run_v2_service.this.name
}

output "id" {
  description = "Full resource ID, suitable for IAM bindings."
  value       = google_cloud_run_v2_service.this.id
}
