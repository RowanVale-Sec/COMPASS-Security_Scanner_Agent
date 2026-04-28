variable "project_id" {
  type = string
}

variable "name_prefix" {
  type = string
}

variable "services" {
  description = "List of service short-names. One runtime SA is created per entry."
  type        = list(string)
}

variable "github_repo" {
  description = "GitHub repo allowed to assume the deployer SA, in 'owner/name' form."
  type        = string
}

variable "github_ref" {
  description = "Git ref the WIF provider trusts (e.g. 'refs/heads/master')."
  type        = string
}
