# Contributing to COMPASS

Thanks for taking a look. This file is the entry point GitHub auto-detects; the full contributor guide is at **[docs/contribute.md](docs/contribute.md)**.

In short:

1. Read [docs/understand-it.md](docs/understand-it.md) to understand the architecture.
2. **Set up pre-commit hooks** (one-time, per checkout):
   ```bash
   pip install pre-commit
   pre-commit install
   ```
   This wires `git commit` to auto-run `terraform fmt`, trailing-whitespace fixes, and a few light hygiene checks. Saves a CI round-trip when fmt drifts.
3. Run the stack: `docker compose up --build -d`, then visit `http://localhost:3000`.
4. Make your change. Local testing is `docker compose up -d --build <service>`; there's no automated test suite yet (writing one would be a high-value contribution).
5. If you touched Terraform and didn't install the hooks, run `terraform fmt -recursive` from `infra/terraform/` before pushing.
6. Open a PR against `master`. The PR-check workflow validates Terraform formatting and Dockerfiles.

For adding a scan tool, an agent, or a Cloud Run service end-to-end, see [docs/contribute.md](docs/contribute.md). For the security-related conventions (credential handling, log scrubbing, S2S auth), see [docs/security.md](docs/security.md).
