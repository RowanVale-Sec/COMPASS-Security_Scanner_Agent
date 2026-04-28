resource "google_cloud_run_v2_service" "this" {
  project  = var.project_id
  location = var.region
  name     = var.name

  # v1 — we recreate services freely during iteration. Re-enable when the
  # service has data only Cloud Run holds (not the case here; state is in
  # GCS workspace + per-job in-memory only).
  deletion_protection = false

  ingress = var.ingress

  # IAP is NOT enabled here. The google provider v6.x schema doesn't expose
  # iap_enabled on cloud_run_v2_service, and google_iap_brand is deprecated
  # as of mid-2025. Instead, IAP gets enabled per-service via:
  #   gcloud run services update <name> --region=<region> --iap
  # which uses Google's auto-managed OAuth brand. Terraform then manages the
  # IAM binding via the iap module. See the iap.tf root file + README.

  template {
    service_account                  = var.service_account_email
    timeout                          = "${var.timeout_seconds}s"
    max_instance_request_concurrency = var.concurrency
    execution_environment            = var.execution_environment
    session_affinity                 = var.session_affinity

    scaling {
      min_instance_count = var.min_instance_count
      max_instance_count = var.max_instance_count
    }

    # Optional GCS FUSE workspace mount. Only services that read/write the
    # per-job clone need this (api-gateway writes; scanner/inventory/syft-mcp
    # read). Cloud Storage FUSE on Cloud Run requires Gen2 execution env.
    dynamic "volumes" {
      for_each = var.workspace_bucket != "" ? [1] : []
      content {
        name = "workspace"
        gcs {
          bucket    = var.workspace_bucket
          read_only = var.workspace_read_only
        }
      }
    }

    containers {
      image = var.image

      resources {
        limits = {
          cpu    = var.cpu
          memory = var.memory
        }
        # cpu_idle defaults to true — request-based billing, CPU throttled
        # between requests. This is what makes min_instance_count=0 actually
        # cost $0 when idle. Don't set it false unless you want instance-
        # based billing.
        startup_cpu_boost = var.cpu_boost
      }

      ports {
        container_port = var.container_port
      }

      dynamic "env" {
        for_each = var.env_vars
        content {
          name  = env.key
          value = env.value
        }
      }

      dynamic "volume_mounts" {
        for_each = var.workspace_bucket != "" ? [1] : []
        content {
          name       = "workspace"
          mount_path = "/workspace"
        }
      }
    }
  }

  # The deploy workflow (PR 4) updates only the image tag; everything else is
  # owned by Terraform. Without ignore_changes the next `terraform apply` after
  # a deploy would revert the image back to whatever's pinned in tfvars.
  lifecycle {
    ignore_changes = [
      client,
      client_version,
    ]
  }
}
