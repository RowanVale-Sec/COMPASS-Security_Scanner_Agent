#!/usr/bin/env bash
# Re-asserts iapEnabled=true on compass-api-gateway.
#
# Required because the google Terraform provider's cloud_run_v2_service
# schema doesn't manage iap_enabled, so every `terraform apply` silently
# strips it back to false. Run this after every local apply. CI does the
# equivalent in .github/workflows/deploy.yml; this script is for dev use.
#
# Usage:
#   ./infra/scripts/enable-iap.sh
#   ./infra/scripts/enable-iap.sh other-project us-east1

set -euo pipefail

PROJECT_ID="${1:-${GCP_PROJECT_ID:-}}"
REGION="${2:-${GCP_REGION:-us-central1}}"
SERVICE="${3:-compass-api-gateway}"

if [[ -z "$PROJECT_ID" ]]; then
  echo "PROJECT_ID not set. Pass as first arg or export GCP_PROJECT_ID." >&2
  exit 1
fi

TOKEN=$(gcloud auth print-access-token)
if [[ -z "$TOKEN" ]]; then
  echo "Failed to get gcloud access token. Run 'gcloud auth login' first." >&2
  exit 1
fi

URL="https://run.googleapis.com/v2/projects/${PROJECT_ID}/locations/${REGION}/services/${SERVICE}?updateMask=iapEnabled"

echo "Asserting iapEnabled=true on ${SERVICE} in ${REGION}/${PROJECT_ID}..."
curl -fsS -X PATCH \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"iapEnabled": true}' \
  "${URL}" > /dev/null

sleep 3

ENABLED=$(curl -fsS \
  -H "Authorization: Bearer ${TOKEN}" \
  "https://run.googleapis.com/v2/projects/${PROJECT_ID}/locations/${REGION}/services/${SERVICE}" \
  | grep -o '"iapEnabled":\s*true' || true)

if [[ -n "$ENABLED" ]]; then
  echo "[OK] IAP is enabled on ${SERVICE}."
else
  echo "IAP enable PATCH succeeded but iapEnabled is still false. Check Cloud Console." >&2
  exit 1
fi
