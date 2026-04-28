# One-time bootstrap for COMPASS infrastructure.
#
# Creates the GCS bucket that holds Terraform state. Re-running is safe —
# the script skips bucket creation if it already exists.
#
# Usage:  .\infra\bootstrap.ps1 -ProjectId compass-prod-12345 [-Region us-central1]

param(
  [Parameter(Mandatory = $true)][string]$ProjectId,
  [string]$Region = "us-central1"
)

$ErrorActionPreference = "Stop"
$Bucket = "$ProjectId-tfstate"

Write-Host "==> Enabling foundation APIs in $ProjectId..."
gcloud services enable `
  storage.googleapis.com `
  cloudresourcemanager.googleapis.com `
  --project $ProjectId

# `gcloud storage buckets describe` exits non-zero if the bucket doesn't exist.
gcloud storage buckets describe "gs://$Bucket" --project $ProjectId 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) {
  Write-Host "==> State bucket gs://$Bucket already exists. Skipping create."
}
else {
  Write-Host "==> Creating Terraform state bucket gs://$Bucket..."
  gcloud storage buckets create "gs://$Bucket" `
    --project $ProjectId `
    --location $Region `
    --uniform-bucket-level-access `
    --public-access-prevention

  gcloud storage buckets update "gs://$Bucket" --versioning
}

Write-Host @"

[OK] Bootstrap complete.

Next steps:
  1. Copy-Item infra\terraform\environments\prod\terraform.tfvars.example ``
                 infra\terraform\environments\prod\terraform.tfvars
     (then set project_id="$ProjectId" and owner_email)

  2. Copy-Item infra\terraform\environments\prod\backend.tfvars.example ``
                 infra\terraform\environments\prod\backend.tfvars
     (then set bucket="$Bucket")

  3. cd infra\terraform
     terraform init -backend-config=environments/prod/backend.tfvars
     terraform apply -var-file=environments/prod/terraform.tfvars
"@
