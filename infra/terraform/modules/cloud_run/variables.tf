variable "name" {
  description = "Cloud Run service name."
  type        = string
}

variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "image" {
  description = "Full container image reference including tag."
  type        = string
}

variable "container_port" {
  description = "Port the container listens on (each COMPASS service hardcodes its own — see docker-compose.yml)."
  type        = number
  default     = 8080
}

variable "service_account_email" {
  description = "Runtime SA the container runs as."
  type        = string
}

variable "cpu" {
  description = "vCPU for each instance, e.g. \"1\" or \"2\"."
  type        = string
  default     = "1"
}

variable "memory" {
  description = "Memory limit for each instance, e.g. \"512Mi\" or \"4Gi\"."
  type        = string
  default     = "512Mi"
}

variable "concurrency" {
  description = "Max concurrent requests per instance."
  type        = number
  default     = 80
}

variable "min_instance_count" {
  description = "Minimum instances. 0 = scale to zero (pay nothing while idle)."
  type        = number
  default     = 0
}

variable "max_instance_count" {
  description = "Maximum instances under load."
  type        = number
  default     = 10
}

variable "timeout_seconds" {
  description = "Request timeout (max 3600). Long-running scan agents need this near the cap."
  type        = number
  default     = 300
}

variable "cpu_boost" {
  description = "Allocate extra CPU during instance startup to cut cold-start latency."
  type        = bool
  default     = false
}

variable "execution_environment" {
  description = "EXECUTION_ENVIRONMENT_GEN1 (smaller, faster cold start) or EXECUTION_ENVIRONMENT_GEN2 (full Linux compat, needed for FUSE / heavy syscalls)."
  type        = string
  default     = "EXECUTION_ENVIRONMENT_GEN1"
}

variable "ingress" {
  description = "INGRESS_TRAFFIC_ALL (public — gate behind IAP) or INGRESS_TRAFFIC_INTERNAL_ONLY (only callable from inside the project)."
  type        = string
  default     = "INGRESS_TRAFFIC_INTERNAL_ONLY"
}

variable "env_vars" {
  description = "Plain (non-secret) environment variables passed to the container."
  type        = map(string)
  default     = {}
}

variable "workspace_bucket" {
  description = "If non-empty, mount this GCS bucket via Cloud Storage FUSE at /workspace. Requires execution_environment = GEN2."
  type        = string
  default     = ""
}

variable "workspace_read_only" {
  description = "If true, mount the workspace bucket read-only. Used by services that only consume the cloned repo."
  type        = bool
  default     = false
}

variable "session_affinity" {
  description = "Enable cookie-based session affinity. The api-gateway needs this so the SSE stream lands on the same instance that holds the in-memory JobRegistry."
  type        = bool
  default     = false
}
