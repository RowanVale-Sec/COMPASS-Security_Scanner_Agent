#!/usr/bin/env bash
# One-time bootstrap for COMPASS infrastructure.
#
# Creates the GCS bucket that holds Terraform state. Re-running is safe —
# the script skips bucket creation if it already exists.
#
# Usage:  ./infra/bootstrap.sh PROJECT_ID [REGION]

set -euo pipefail

PROJECT_ID="${1:?Usage: $0 PROJECT_ID [REGION]}"
REGION="${2:-us-central1}"
BUCKET="${PROJECT_ID}-tfstate"

echo "==> Enabling foundation APIs in ${PROJECT_ID}…"
gcloud services enable \
  storage.googleapis.com \
  cloudresourcemanager.googleapis.com \
  --project "${PROJECT_ID}"

if gcloud storage buckets describe "gs://${BUCKET}" --project "${PROJECT_ID}" >/dev/null 2>&1; then
  echo "==> State bucket gs://${BUCKET} already exists. Skipping create."
else
  echo "==> Creating Terraform state bucket gs://${BUCKET}…"
  gcloud storage buckets create "gs://${BUCKET}" \
    --project "${PROJECT_ID}" \
    --location "${REGION}" \
    --uniform-bucket-level-access \
    --public-access-prevention

  gcloud storage buckets update "gs://${BUCKET}" --versioning
fi

cat <<EOF

[OK] Bootstrap complete.

Next steps:
  1. cp infra/terraform/environments/prod/terraform.tfvars.example \\
        infra/terraform/environments/prod/terraform.tfvars
     (then set project_id="${PROJECT_ID}" and owner_email)

  2. cp infra/terraform/environments/prod/backend.tfvars.example \\
        infra/terraform/environments/prod/backend.tfvars
     (then set bucket="${BUCKET}")

  3. cd infra/terraform
     terraform init -backend-config=environments/prod/backend.tfvars
     terraform apply -var-file=environments/prod/terraform.tfvars
EOF
