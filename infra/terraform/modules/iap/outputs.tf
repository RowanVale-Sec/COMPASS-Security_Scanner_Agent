output "accessor_count" {
  description = "Number of Google accounts granted IAP access to the protected service."
  value       = length(google_iap_web_cloud_run_service_iam_member.accessors)
}
