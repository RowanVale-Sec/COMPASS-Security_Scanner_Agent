variable "project_id" {
  type = string
}

variable "service_location" {
  description = "Region the protected Cloud Run service lives in (e.g. us-central1)."
  type        = string
}

variable "service_name" {
  description = "Cloud Run service name to protect with IAP."
  type        = string
}

variable "allowed_user_emails" {
  description = "Google account emails granted access through IAP."
  type        = list(string)
}
