locals {
  # The 7 services deployed to Cloud Run.
  #
  # NOTE: the original Linear issue listed 8 services with `frontend` separate.
  # During PR 3 design we decided to merge frontend + api-gateway into a single
  # `api-gateway` service so FastAPI serves the React build at /. This avoids a
  # broken IAP UX (cross-origin fetches don't survive IAP auth redirects) and
  # the cost of an HTTPS Load Balancer to host them under one domain.
  services = [
    "api-gateway",
    "orchestrator",
    "scanner-agent",
    "inventory-agent",
    "threat-model-agent",
    "mitre-mcp",
    "syft-mcp",
  ]
}
