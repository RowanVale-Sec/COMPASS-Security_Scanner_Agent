variable "project_id" {
  description = "GCP project ID where all COMPASS resources live."
  type        = string
}

variable "region" {
  description = "Primary GCP region for Cloud Run, Artifact Registry, GCS."
  type        = string
  default     = "us-central1"
}

variable "github_repo" {
  description = "GitHub repo allowed to assume the deployer SA via WIF, in 'owner/name' form."
  type        = string
}

variable "github_ref" {
  description = "Git ref the WIF provider trusts. Default pins to master so feature branches can't deploy."
  type        = string
  default     = "refs/heads/master"
}

variable "owner_email" {
  description = "Primary Google account email allowed through IAP. Always granted access. Used in docs and as the canonical operator identity."
  type        = string
}

variable "additional_iap_users" {
  description = <<-EOT
    Extra Google accounts (beyond owner_email) granted IAP access to the
    api-gateway. Each entry is a Google account email — gmail.com, Workspace
    accounts, or Cloud Identity all work. Don't include the owner_email here;
    it's added automatically.

    Example:
      additional_iap_users = ["alice@gmail.com", "bob@example.com"]

    To use a Google Group or entire domain, see the iap.tf root file —
    the underlying binding accepts group:..., domain:..., etc.
  EOT
  type        = list(string)
  default     = []
}

variable "name_prefix" {
  description = "Prefix for resource names. Keep short (<= 12 chars) — service-account IDs cap at 30."
  type        = string
  default     = "compass"
}

variable "image_tag" {
  description = <<-EOT
    Tag of the COMPASS images deployed to every Cloud Run service.

    Default ("bootstrap") makes every service run Google's cloudrun/hello
    placeholder image — useful for validating infra in isolation before any
    images are pushed. Set to a real git SHA / version once images live in
    Artifact Registry (PR 4's deploy.yml does this automatically).
  EOT
  type        = string
  default     = "bootstrap"
}
