# Contributing to COMPASS

Thanks for taking a look. This file is the entry point GitHub auto-detects; the full contributor guide is at **[docs/contribute.md](docs/contribute.md)**.

In short:

1. Read [docs/understand-it.md](docs/understand-it.md) to understand the architecture.
2. Run the stack: `docker compose up --build -d`, then visit `http://localhost:3000`.
3. Make your change. Local testing is `docker compose up -d --build <service>`; there's no automated test suite yet (writing one would be a high-value contribution).
4. If you touched Terraform, run `terraform fmt -recursive` from `infra/terraform/`.
5. Open a PR against `master`. The PR-check workflow validates Terraform formatting and Dockerfiles.

For adding a scan tool, an agent, or a Cloud Run service end-to-end, see [docs/contribute.md](docs/contribute.md). For the security-related conventions (credential handling, log scrubbing, S2S auth), see [docs/security.md](docs/security.md).
