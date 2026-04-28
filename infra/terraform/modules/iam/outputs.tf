output "runtime_service_accounts" {
  description = "Service name -> runtime SA email."
  value       = { for s, sa in google_service_account.runtime : s => sa.email }
}

output "deployer_service_account_email" {
  description = "Email of the SA that GitHub Actions impersonates."
  value       = google_service_account.deployer.email
}

output "workload_identity_provider" {
  description = "Resource name of the WIF provider — what GitHub Actions passes to google-github-actions/auth."
  value       = google_iam_workload_identity_pool_provider.github.name
}
