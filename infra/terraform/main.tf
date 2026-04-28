module "artifact_registry" {
  source = "./modules/artifact_registry"

  project_id  = var.project_id
  region      = var.region
  name_prefix = var.name_prefix
  services    = local.services

  depends_on = [google_project_service.enabled]
}

module "storage" {
  source = "./modules/storage"

  project_id  = var.project_id
  region      = var.region
  name_prefix = var.name_prefix

  depends_on = [google_project_service.enabled]
}

module "iam" {
  source = "./modules/iam"

  project_id  = var.project_id
  name_prefix = var.name_prefix
  services    = local.services
  github_repo = var.github_repo
  github_ref  = var.github_ref

  depends_on = [google_project_service.enabled]
}
