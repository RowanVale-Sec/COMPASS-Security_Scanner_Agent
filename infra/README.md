# COMPASS Infrastructure (GCP, Terraform)

The cloud deployment is built in three Terraform layers, one per PR:

| PR | Scope |
|---|---|
| PR 2 | Foundation: Artifact Registry (7 repos), GCS workspace bucket, runtime + deployer SAs, GitHub WIF pool. |
| PR 3 | All 7 Cloud Run services + Cloud IAP gating on the api-gateway. |
| **PR 4 (current)** | `.github/workflows/{deploy,pr-check}.yml` — builds, pushes images, rolls revisions on every push to master. |

A note on the service count: the original Linear issue listed 8 services with `frontend` separate. During PR 3 design we merged frontend + api-gateway into one Cloud Run service (FastAPI serves the React build at `/`). This avoids a broken IAP UX (cross-origin fetches don't survive IAP redirects) and the cost of an HTTPS Load Balancer to host them under one domain. Local `docker compose up` still uses the original 8-container layout — only the cloud build path bundles them.

After PR 3 applies cleanly with placeholder images you can move on to PR 4. While idle the stack costs ~$1–3/mo (Artifact Registry storage, dominant component).

---

## Prerequisites

- A GCP project with a billing account attached.
- `gcloud` installed and authenticated as a user with `Owner` (or at minimum `Project IAM Admin`, `Storage Admin`, `Service Account Admin`, `Workload Identity Pool Admin`, `Service Usage Admin`).
- `terraform` >= 1.7 installed locally (only needed if you're applying from your laptop; PR 4 will run it from GitHub Actions).

---

## One-time bootstrap

Terraform state lives in a GCS bucket. The bucket can't be Terraform-managed before Terraform can run, so create it once with the bootstrap script:

**Windows (PowerShell):**
```powershell
.\infra\bootstrap.ps1 -ProjectId compass-prod-XXXXX
```

**macOS / Linux:**
```bash
./infra/bootstrap.sh compass-prod-XXXXX
```

Both scripts:
1. Enable `storage.googleapis.com` and `cloudresourcemanager.googleapis.com` in your project.
2. Create `gs://<PROJECT>-tfstate` (uniform-bucket-level-access, public-access-prevention, versioning on).

Re-running is safe — the script skips bucket creation if the bucket already exists.

---

## Apply

```bash
# 1. Copy the example tfvars and fill in your values.
cp infra/terraform/environments/prod/terraform.tfvars.example \
   infra/terraform/environments/prod/terraform.tfvars
cp infra/terraform/environments/prod/backend.tfvars.example \
   infra/terraform/environments/prod/backend.tfvars

# 2. Edit each file — the placeholders are clearly marked REPLACE_ME.

# 3. Init the GCS backend, then apply.
cd infra/terraform
terraform init -backend-config=environments/prod/backend.tfvars
terraform apply -var-file=environments/prod/terraform.tfvars
```

The two `*.tfvars` files are gitignored — only the `*.example` versions are committed.

---

## GitHub Secrets

After the foundation applies, capture the values that the deploy workflow needs:

```bash
cd infra/terraform
terraform output -json github_secrets_to_set
```

Set each key as a GitHub repo secret under **Settings → Secrets and variables → Actions**:

| GitHub Secret | Required? | What it is |
|---|---|---|
| `GCP_PROJECT_ID` | yes | Your GCP project. |
| `GCP_REGION` | yes | Region (e.g. `us-central1`). |
| `GCP_WORKLOAD_IDENTITY_PROVIDER` | yes | Full WIF provider resource name. |
| `GCP_DEPLOY_SERVICE_ACCOUNT` | yes | Email of the deployer SA the WIF impersonates. |
| `COMPASS_OWNER_EMAIL` | yes | Your Google account email. The deploy workflow passes this to `terraform apply` so the IAP allowlist re-applies on every deploy. |
| `COMPASS_ADDITIONAL_IAP_USERS` | optional | JSON array of extra Google accounts allowed through IAP. Empty/unset = only the owner. Format: `["alice@gmail.com","bob@example.com"]`. To add/remove a user, edit this secret and trigger a deploy — CI re-applies the allowlist on every push to master. |
| `COMPASS_CUSTOM_DOMAIN` | optional | Custom domain mapped to api-gateway, e.g. `app.compass-sec.app`. Empty/unset = default `*.run.app` URL only. Cloud Run provisions a managed TLS cert automatically. After first apply with this set, run `terraform output custom_domain_dns_records` and add the printed records at your DNS registrar — cert provisioning starts once DNS resolves (~15–60 min). |

No long-lived service-account JSON is needed anywhere — GitHub Actions mints a fresh OIDC token per run and exchanges it for a 1-hour GCP credential via Workload Identity Federation. The WIF provider's `attribute_condition` is locked to `RowanVale-Sec/COMPASS` on `refs/heads/master`, so even a leaked workflow on a fork can't impersonate the deployer.

---

## What this stack creates

**Foundation (PR 2):**
| Resource | Count | Purpose |
|---|---|---|
| Artifact Registry repos (Docker) | 7 | One per service. Cleanup policies keep last 10 tagged + delete untagged after 7 days. |
| GCS bucket | 1 | Per-scan workspaces. 1-day lifecycle rule purges any leaked clones. |
| Runtime service accounts | 7 | One per Cloud Run service. |
| Deployer service account | 1 | Impersonated by GitHub Actions via WIF. Has `run.admin`, `artifactregistry.writer`, `iam.serviceAccountUser`, `iap.admin`, `storage.admin`. |
| Workload Identity pool + provider | 1 + 1 | GitHub OIDC, locked to the configured repo + ref. |
| Project APIs enabled | 9 | AR, Cloud Run, IAM, IAM Credentials, Storage, IAP, Resource Manager, STS, Service Usage. |

**Services (PR 3):**
| Resource | Count | Purpose |
|---|---|---|
| Cloud Run services | 7 | api-gateway (public via IAP, Gen2, FUSE rw), orchestrator (internal, Gen1), scanner (internal, Gen2, FUSE ro), inventory (internal, Gen2, FUSE ro), threat-model (internal, Gen1), mitre-mcp (internal, Gen1), syft-mcp (internal, Gen1, FUSE ro). All `min_instance_count=0` — billed only while a scan runs. |
| IAP brand + IAM binding | 1 + 1 | OAuth consent screen + grants `owner_email` access through IAP. |
| Cloud Run invoker bindings | 6 | api-gateway → orchestrator, orchestrator → 3 agents, scanner → mitre-mcp, inventory → syft-mcp. |
| GCS bucket bindings | 4 | api-gateway (objectAdmin), scanner/inventory/syft-mcp (objectViewer). |

---

## CI/CD workflows

Two workflows in `.github/workflows/`:

### `pr-check.yml`
Runs on every PR to `master`. No GCP auth — purely local checks:
- `terraform fmt -check -recursive -diff`
- `terraform validate` (offline, no backend init)
- `hadolint` against all 9 Dockerfiles, failing only on real `error`-level issues

### `deploy.yml`
Runs on every push to `master` (and on `workflow_dispatch`). Two jobs:

1. **`build`** — 7-way matrix. Builds each service in parallel, pushes to its Artifact Registry repo tagged with `${{ github.sha }}`. Uses `gha` build cache so warm rebuilds take ~1–2 min instead of 10+.

2. **`terraform-apply`** (depends on `build`) — `terraform init` against the GCS state bucket, then `terraform apply -var image_tag=${{ github.sha }}`. The image tag flip is the only thing that changes — Cloud Run rolls a new revision per service. After apply, the smoke step asks Cloud Run for each service's deployed image and fails if any service is still on a different SHA.

The smoke test deliberately doesn't bypass IAP. Verifying the public URL works end-to-end requires being signed in as `owner_email`, which is a manual browser step. The deployer SA is **not** in the IAP allowlist by design — so a compromised workflow can't curl the live app.

### Triggering a deploy by hand

```bash
gh workflow run deploy.yml --ref master
gh run watch
```

## Required step after every local `terraform apply`: re-assert IAP

The google Terraform provider's `cloud_run_v2_service` resource doesn't expose `iap_enabled` — and worse, every `terraform apply` that touches the api-gateway service silently strips it back to false. Without re-asserting, the URL becomes a public Cloud Run service rejecting unauthenticated requests with HTTP 403 (no IAP gate, no Google sign-in flow).

After every `terraform apply`, run:

**Windows (PowerShell):**
```powershell
.\infra\scripts\enable-iap.ps1
```

**macOS / Linux:**
```bash
./infra/scripts/enable-iap.sh
```

Both scripts read `GCP_PROJECT_ID` from your environment (or accept it as the first arg / `-ProjectId` param), default `GCP_REGION` to `us-central1`, and default the service name to `compass-api-gateway`. Set `GCP_PROJECT_ID` in your shell once and you don't have to pass it each time:

```powershell
# Windows: add to your $PROFILE
$env:GCP_PROJECT_ID = "your-project-id"
```

```bash
# Linux/macOS: add to ~/.bashrc or ~/.zshrc
export GCP_PROJECT_ID=your-project-id
```

CI (`.github/workflows/deploy.yml`) does the equivalent inline — every push to `master` triggers a fresh terraform apply *and* re-asserts IAP, so production stays gated automatically. The scripts above are only for local applies (e.g., bootstrap, hotfixes).

Two IAM bindings make this work — both managed by Terraform in [iap.tf](terraform/iap.tf):
- `roles/iap.httpsResourceAccessor` granted to the human user (lets them past IAP's auth gate)
- `roles/run.invoker` granted to the IAP service agent (`service-${PROJECT_NUMBER}@gcp-sa-iap.iam.gserviceaccount.com`) on api-gateway (lets IAP forward authenticated requests to the service)

If you forget the second binding you get the misleading "Your client does not have permission to get URL /" error from Cloud Run *after* IAP has already authenticated you.

## End-to-end smoke test (after PR 3 applies)

The default `image_tag = "bootstrap"` deploys Google's `cloudrun/hello` placeholder image to every service so you can validate infra before any COMPASS images are built. To test:

1. Sign in to the api-gateway URL with your `owner_email` Google account:
   ```bash
   open "$(terraform output -raw app_url)"
   ```
   You should see Google sign-in → then the placeholder hello-world page.

2. Open the same URL in an Incognito window (no Google session) — IAP must return a 403 sign-in prompt **before** any container instance starts. Confirms the IAP gate works.

3. Wait 20 minutes idle, then check the Cloud Run console — every service shows 0 active instances. Confirms scale-to-zero.

Once PR 4 lands and pushes real COMPASS images, re-run with the new tag:
```bash
terraform apply -var-file=environments/prod/terraform.tfvars -var image_tag=<sha>
```

## IAP brand caveat

`google_iap_brand` only supports the create operation — re-applying when a brand already exists in the project will error. If you've previously enabled IAP in this project:

```bash
# Find the existing brand id
gcloud iap oauth-brands list --project="$GCP_PROJECT_ID"

# Import it before the first apply
terraform import \
  -var-file=environments/prod/terraform.tfvars \
  module.iap_api_gateway.google_iap_brand.default \
  projects/<PROJECT_NUMBER>/brands/<BRAND_ID>
```

For brand-new projects this is a no-op — terraform creates the brand cleanly.

## Tear-down

```bash
cd infra/terraform
terraform destroy -var-file=environments/prod/terraform.tfvars
```

For true `$0`, also delete the state bucket manually:
```bash
gcloud storage rm -r gs://<PROJECT>-tfstate
```
