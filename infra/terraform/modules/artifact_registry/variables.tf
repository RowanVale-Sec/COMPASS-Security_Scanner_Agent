variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "name_prefix" {
  type = string
}

variable "services" {
  description = "List of service short-names. One Docker repo is created per entry."
  type        = list(string)
}
