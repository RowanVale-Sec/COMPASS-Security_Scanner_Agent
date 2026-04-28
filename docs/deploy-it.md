# Deploy COMPASS

You have two paths. Pick based on who's going to use it:

| Audience | Path | Setup time | Cost |
|---|---|---|---|
| Just you | **Local Docker** | 5 minutes | $0 |
| Your team | **GCP Cloud Run** | ~30 minutes (one-time) | ~$1–3/mo idle, free tier covers most scan volume |

This doc is the operator's perspective: how to deploy, how to operate, how to roll back, what to monitor. For end-user / scanner instructions see [use-it.md](use-it.md).

---

## Path 1: Local Docker (single user)

If you're the only person who will run scans, this is fine. Everything stays on your laptop, no cloud accounts, no DNS, no auth setup.

```bash
git clone https://github.com/RowanVale-Sec/COMPASS.git
cd COMPASS
docker compose up --build -d
```

Open `http://localhost:3000` in your browser. Done.

**You should know:**
- The 8 services run continuously while `docker compose` is up. Resource usage at idle: ~500 MB RAM, near-zero CPU.
- The `compass-workspace` Docker volume holds per-scan clones. The api-gateway cleans up after each job, so it shouldn't grow.
- LLM credentials are entered per-scan in the browser. You don't need a `.env` file; it's only for [optional knobs](reference/env-vars.md).
- Stop everything: `docker compose down -v` (the `-v` also drops the workspace volume — safe when idle).

For development on the code itself, see [contribute.md](contribute.md).

---

## Path 2: GCP Cloud Run (team / production)

This is the design that motivated the cloud migration. Properties you get:

- **Scale to zero.** Idle stack costs ~$1–3/mo (Artifact Registry image storage, dominant component). Pay-per-scan compute, fits in the GCP free tier at typical 50–70 scans/day.
- **Cloud IAP gating.** Only Google accounts on your IAP allowlist can reach the URL. A leaked URL costs nothing — IAP returns 403 before any container instance starts.
- **Workload Identity Federation.** GitHub Actions deploys via short-lived OIDC tokens scoped to your repo + branch. No service-account JSON anywhere.
- **One-domain deployment.** The frontend is bundled into the api-gateway service so the whole app sits behind a single IAP gate.

The full deploy walkthrough lives in **[infra/README.md](../infra/README.md)** — it covers bootstrap, the Terraform modules, the GitHub Secrets, the smoke-test, the rollback flow, and the IAP-brand caveat.

What follows here is the operator's overview.

### Three layers, three PRs (one-time setup)

| Layer | Files | What it creates |
|---|---|---|
| **Foundation** (PR 2 in the migration) | `infra/terraform/{apis,iap,runtime_iam,services,...}.tf` minus services + iap | 7 Artifact Registry repos, GCS workspace bucket, 7 runtime SAs, deployer SA, WIF pool. ~$0.10/mo at rest. |
| **Cloud Run services + IAP** (PR 3) | `infra/terraform/{services,iap,runtime_iam}.tf` | The 7 Cloud Run services, IAP brand + accessor binding, S2S invoker bindings, GCS bucket bindings. |
| **CI/CD** (PR 4) | `.github/workflows/{deploy,pr-check}.yml` | On push to master: builds 7 images in parallel, pushes to AR, runs `terraform apply -var image_tag=<sha>`, verifies all 7 services rolled. |

Apply once with `terraform apply` to bring up the foundation + services with placeholder images, then push to master and the deploy workflow handles the rest.

### Costs

| Resource | Idle | Per-scan |
|---|---|---|
| Cloud Run vCPU + memory | $0 (scales to zero) | ~$0.07 / 10-min scan, free tier covers 60–70 scans/month |
| Artifact Registry storage | ~$1.20/mo (7 images × ~1.5 GB) | $0 |
| GCS workspace bucket | ~$0.10/mo | ~$0 (24h lifecycle purge) |
| Cloud Run requests | $0 (under 2M/mo free tier) | $0 |
| IAP / WIF / IAM bindings | $0 | $0 |
| **Total** | **~$1.30/mo** | **~$5/mo at 70 scans/day, mostly free tier** |

Real-world: a project that runs 5–10 scans/week stays inside the free tier indefinitely.

### Rollback

Every deploy creates a new Cloud Run revision per service. Rolling back is moving traffic to a previous revision — no rebuild needed.

```bash
# List recent revisions for a service
gcloud run revisions list --service=compass-api-gateway \
  --region=us-central1 --project=$GCP_PROJECT_ID

# Send all traffic to a previous revision
gcloud run services update-traffic compass-api-gateway \
  --region=us-central1 --project=$GCP_PROJECT_ID \
  --to-revisions=compass-api-gateway-00012-abc=100
```

If the bad revision shipped to multiple services in one deploy, repeat for each. The deploy workflow's smoke-step will fail-fast on the broken service so you usually only need to roll back one or two.

For a clean redeploy of the prior known-good SHA:

```bash
gh workflow run deploy.yml --ref master \
  -f image_tag=<known-good-sha>
```

(That assumes you've added `workflow_dispatch` inputs — current `deploy.yml` derives the tag from `github.sha`. Easy follow-up if you want it.)

### Monitoring

Out of the box, Cloud Run logs everything to Cloud Logging. The most useful queries:

| Question | Cloud Logging query |
|---|---|
| Recent scan errors | `resource.type="cloud_run_revision" AND resource.labels.service_name="compass-api-gateway" AND severity>=ERROR` |
| Scanner agent failures specifically | `resource.labels.service_name="compass-scanner-agent" AND textPayload=~"failed"` |
| What ran in the last hour | `resource.type="cloud_run_revision" AND timestamp>"2026-04-26T00:00:00Z" AND httpRequest.requestMethod="POST"` |

Beyond that, an uptime check + alert policy on the api-gateway URL is a 2-minute setup in the GCP console — recommended for production.

### Custom domain

Out of scope for v1 (you chose default `*.run.app` URLs). When you want one:

```hcl
resource "google_cloud_run_domain_mapping" "app" {
  name     = "compass.example.com"
  location = var.region
  metadata { namespace = var.project_id }
  spec    { route_name = module.cloud_run_api_gateway.name }
}
```

Add a CNAME at your DNS registrar pointing at the value from `terraform output`. Managed TLS comes free.

### Pausing the stack

If you want to put the deployment "on ice" (zero attack surface, near-zero cost):

```bash
# Make the api-gateway internal-ingress only — IAP becomes irrelevant since
# nothing reaches it from the internet anyway.
gcloud run services update compass-api-gateway \
  --region=us-central1 --project=$GCP_PROJECT_ID \
  --ingress=internal
```

Reverse with `--ingress=all`. The other 6 services are already internal — nothing else to pause.

True $0 (delete everything): `terraform destroy -var-file=environments/prod/terraform.tfvars`. Brings the stack back up in ~5 min with `terraform apply` + the deploy workflow.

---

## Operating both side-by-side

You can run local Docker for development and GCP for production from the same checkout. The split:

| Concern | Local | Cloud |
|---|---|---|
| Frontend build | `frontend/Dockerfile` (separate nginx container) | `api_gateway/Dockerfile.cloud` (bundled into FastAPI) |
| Workspace handoff | `compass-workspace` Docker named volume | GCS bucket, Cloud Storage FUSE mount |
| Service-to-service auth | None (Docker network is trusted) | Google ID tokens via metadata server, scoped to runtime SAs |
| Public access control | Bound to `localhost:3000` | Cloud IAP, Google account allowlist |
| Credentials | Per-request via browser form | Same — no environment differences |

Both code paths run from the same source tree. The differences are entirely in Dockerfiles, env vars, and Terraform — no application code branches on "am I in cloud?".

---

## Where to go next

- **Full GCP deploy walkthrough** — [infra/README.md](../infra/README.md)
- **Per-service Cloud Run config** — [infra/terraform/services.tf](../infra/terraform/services.tf)
- **Architecture deep dive** — [understand-it.md](understand-it.md)
- **Security model** — [security.md](security.md)
- **All env vars** — [reference/env-vars.md](reference/env-vars.md)
