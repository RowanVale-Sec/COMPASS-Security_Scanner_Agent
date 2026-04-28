# Re-asserts iapEnabled=true on compass-api-gateway.
#
# Required because the google Terraform provider's cloud_run_v2_service
# schema doesn't manage iap_enabled, so every `terraform apply` silently
# strips it back to false. Run this after every local apply. CI does the
# equivalent in .github/workflows/deploy.yml; this script is for dev use.
#
# Usage:
#   .\infra\scripts\enable-iap.ps1
#   .\infra\scripts\enable-iap.ps1 -ProjectId other-project -Region us-east1

param(
  [string]$ProjectId = $env:GCP_PROJECT_ID,
  [string]$Region = $(if ($env:GCP_REGION) { $env:GCP_REGION } else { "us-central1" }),
  [string]$Service = "compass-api-gateway"
)

$ErrorActionPreference = "Stop"

if (-not $ProjectId) {
  Write-Error "ProjectId not set. Pass -ProjectId <id> or set `$env:GCP_PROJECT_ID."
  exit 1
}

$token = gcloud auth print-access-token
if (-not $token) {
  Write-Error "Failed to get gcloud access token. Run 'gcloud auth login' first."
  exit 1
}

# Backtick-escape the ? so PowerShell doesn't treat it as a wildcard
$url = "https://run.googleapis.com/v2/projects/$ProjectId/locations/$Region/services/$Service" + "?updateMask=iapEnabled"

Write-Host "Asserting iapEnabled=true on $Service in $Region/$ProjectId..."
$null = Invoke-RestMethod -Method Patch -Uri $url `
  -Headers @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" } `
  -Body '{"iapEnabled": true}'

# Verify
Start-Sleep 3
$svc = Invoke-RestMethod -Uri "https://run.googleapis.com/v2/projects/$ProjectId/locations/$Region/services/$Service" `
  -Headers @{ Authorization = "Bearer $token" }
if ($svc.iapEnabled) {
  Write-Host "[OK] IAP is enabled on $Service."
} else {
  Write-Error "IAP enable PATCH succeeded but iapEnabled is still false. Check Cloud Console."
  exit 1
}
