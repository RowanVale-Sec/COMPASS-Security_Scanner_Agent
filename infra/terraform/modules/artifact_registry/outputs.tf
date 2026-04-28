output "repo_urls" {
  description = "Service name -> Docker push URL (without tag)."
  value = {
    for s, repo in google_artifact_registry_repository.service :
    s => "${var.region}-docker.pkg.dev/${var.project_id}/${repo.repository_id}"
  }
}
