# Optional custom-domain mapping for the api-gateway.
#
# Controlled by var.custom_domain — when empty (default), nothing is created
# and only the *.run.app URL is reachable. When set (e.g.
# "app.compass-sec.app"), Cloud Run provisions a managed TLS cert for the
# domain and routes incoming HTTPS to the api-gateway service. IAP gating
# applies to the custom domain identically to the *.run.app URL.
#
# After apply, `terraform output custom_domain_dns_records` prints the DNS
# records you must add at your registrar. Cert provisioning starts only
# once DNS resolves.

resource "google_cloud_run_domain_mapping" "api_gateway" {
  count = var.custom_domain != "" ? 1 : 0

  name     = var.custom_domain
  location = var.region

  metadata {
    namespace = var.project_id
  }

  spec {
    route_name = module.cloud_run_api_gateway.name
  }
}
