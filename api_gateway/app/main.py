"""
COMPASS API Gateway (BFF).

Routes:
  POST /api/scan              -> validates inputs, clones the repo, kicks off
                                 the pipeline, returns { job_id, events_url,
                                 download_url }
  GET  /api/scan/{id}/events  -> SSE stream of pipeline stage events
  GET  /api/download/{id}     -> downloads the final bundle as a JSON file
  GET  /health                -> liveness probe

Design guarantees:
  * Credentials (LLM tokens, GitHub PAT) never touch disk and are never
    logged. They flow: HTTP body -> ScanRequest (SecretStr) -> orchestrator
    HTTP body -> agents -> dropped.
  * Repo clones happen inside a per-job directory under WORKSPACE_ROOT. The
    directory is removed once the pipeline finishes (success or failure).
  * Rate limited per-IP on /api/scan (clone + full pipeline is expensive).
  * Pydantic models reject unknown fields so clients can't sneak extras
    through to internal agents.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, StreamingResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from .jobs import registry, Job
from .github import clone_github_repo, CloneError
from .models import ScanCreateResponse, ScanRequest
from .orchestrator_client import stream_pipeline
from .security import configure_scrubbed_logging, scrub
from .validators import (
    ValidationError,
    validate_azure_credentials,
    validate_claude_credentials,
    validate_github_pat,
    validate_github_url,
)


configure_scrubbed_logging()
logger = logging.getLogger("compass.api")
logger.setLevel(logging.INFO)


WORKSPACE_ROOT = Path(os.environ.get("COMPASS_WORKSPACE_ROOT", "/workspace"))
# Comma-separated allowlist so the cloud frontend URL can be added alongside
# the local dev origin without forcing a redeploy of the local config.
ALLOWED_ORIGINS = [
    o.strip()
    for o in os.environ.get("COMPASS_ALLOWED_ORIGIN", "http://localhost:3000").split(",")
    if o.strip()
]


limiter = Limiter(key_func=get_remote_address, default_limits=[])


app = FastAPI(title="COMPASS API Gateway", version="1.0.0")
app.state.limiter = limiter

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,  # we don't use cookies; tokens travel in body
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
    max_age=600,
)


@app.exception_handler(RateLimitExceeded)
async def _rate_limit_handler(_request: Request, exc: RateLimitExceeded) -> JSONResponse:
    return JSONResponse(status_code=429, content={"error": f"rate limit exceeded: {exc.detail}"})


@app.exception_handler(ValidationError)
async def _validation_handler(_request: Request, exc: ValidationError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"error": str(exc)})


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "healthy", "service": "api_gateway"}


def _build_credentials(provider: str, raw: Dict[str, Any]) -> Dict[str, Any]:
    """Validate provider credentials and return a clean dict for the orchestrator."""
    raw = dict(raw)
    raw["provider"] = provider
    if "api_key" not in raw:
        raise ValidationError("credentials.api_key is required")
    if provider == "azure":
        return validate_azure_credentials(raw)
    return validate_claude_credentials(raw)


@app.post("/api/scan", response_model=ScanCreateResponse)
@limiter.limit("3/minute")
async def create_scan(request: Request, body: ScanRequest) -> ScanCreateResponse:
    """Validate inputs, clone the repo, and start the pipeline in the background."""
    github_url = validate_github_url(body.github_url)
    pat = validate_github_pat(body.github_pat.get_secret_value() if body.github_pat else None)
    credentials = _build_credentials(body.provider, body.credentials)

    job = await registry.create()
    # Audit: non-sensitive fields only. Deployment / model names are not secrets
    # but they're enormously useful for diagnosing "wrong provider"-shaped bugs.
    audit = {
        "job_id": job.id,
        "url": github_url,
        "provider": credentials["provider"],
        "deployment": credentials.get("deployment"),
        "model": credentials.get("model"),
        "pat_present": pat is not None,
    }
    logger.info("scan accepted: %s", audit)

    # Launch the background worker. It owns cleanup of the cloned workspace.
    asyncio.create_task(_run_job(job, github_url, pat, credentials))

    return ScanCreateResponse(
        job_id=job.id,
        events_url=f"/api/scan/{job.id}/events",
        download_url=f"/api/download/{job.id}",
    )


async def _run_job(
    job: Job,
    github_url: str,
    pat: Optional[str],
    credentials: Dict[str, Any],
) -> None:
    """Clone the repo, stream the orchestrator's events into the job queue,
    and ensure the workspace is cleaned up regardless of outcome.

    `credentials` is never stored on the Job; once this coroutine returns,
    the only remaining reference is garbage-collected.
    """
    job.status = "running"
    workspace = WORKSPACE_ROOT / job.id
    clone_path = workspace / "repo"

    try:
        await job.queue.put({"event": "stage", "data": {"stage": "clone", "status": "started"}})

        try:
            await asyncio.to_thread(clone_github_repo, github_url, clone_path, pat)
        except CloneError as exc:
            await job.queue.put({"event": "error", "data": {"message": str(exc)}})
            job.status = "failed"
            job.error = str(exc)
            return
        except Exception as exc:  # noqa: BLE001 — any unexpected failure still needs to surface
            logger.exception("clone stage failed unexpectedly", extra={"job_id": job.id})
            msg = f"clone failed: {type(exc).__name__}: {exc}"
            await job.queue.put({"event": "error", "data": {"message": msg}})
            job.status = "failed"
            job.error = msg
            return

        await job.queue.put({"event": "stage", "data": {"stage": "clone", "status": "completed"}})

        try:
            async for event in stream_pipeline(str(clone_path), credentials):
                name = event.get("event")
                data = event.get("data") or {}
                if name == "complete":
                    bundle = data.get("bundle")
                    if isinstance(bundle, dict):
                        job.bundle = bundle
                        job.status = "succeeded"
                        await job.queue.put({
                            "event": "complete",
                            "data": {"download_url": f"/api/download/{job.id}"},
                        })
                    else:
                        job.status = "failed"
                        job.error = "orchestrator completed without a bundle"
                        await job.queue.put({"event": "error", "data": {"message": job.error}})
                    return
                if name == "error":
                    job.status = "failed"
                    job.error = data.get("message", "pipeline error")
                    await job.queue.put({"event": "error", "data": {"message": job.error}})
                    return
                # Forward any intermediate stage events verbatim.
                await job.queue.put(event)
        except Exception as exc:  # noqa: BLE001 — surface to client, don't crash
            job.status = "failed"
            job.error = f"gateway error: {exc}"
            await job.queue.put({"event": "error", "data": {"message": job.error}})
            logger.exception("pipeline streaming failed", extra={"job_id": job.id})

    finally:
        job.finished = True
        await job.queue.put(None)  # sentinel for event stream
        # Always clean up the clone, even on success. The user gets the bundle
        # via /api/download, not the filesystem.
        if workspace.exists():
            shutil.rmtree(workspace, ignore_errors=True)


@app.get("/api/scan/{job_id}/events")
async def scan_events(job_id: str) -> StreamingResponse:
    job = await registry.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="unknown job_id")

    async def sse() -> Any:
        while True:
            try:
                item = await asyncio.wait_for(job.queue.get(), timeout=30.0)
            except asyncio.TimeoutError:
                # keep-alive comment so proxies don't time out
                yield ": keep-alive\n\n"
                if job.finished and job.queue.empty():
                    return
                continue
            if item is None:
                return
            payload = json.dumps(item["data"])
            yield f"event: {item['event']}\ndata: {payload}\n\n"

    return StreamingResponse(
        sse(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/download/{job_id}")
async def download_bundle(job_id: str) -> Response:
    job = await registry.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="unknown job_id")
    if job.status != "succeeded" or not job.bundle:
        raise HTTPException(status_code=409, detail=f"bundle not ready (status={job.status})")

    content = json.dumps(job.bundle, indent=2).encode("utf-8")
    filename = f"compass-threat-model-{job_id}.json"
    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(content)),
            "Cache-Control": "no-store",
        },
    )


# When deployed via api_gateway/Dockerfile.cloud, the React SPA is bundled
# into /app/static and served from this same FastAPI process so a single
# Cloud Run service can sit behind one Cloud IAP gate. Local docker-compose
# runs the SPA from a separate nginx container, so this mount stays inert
# unless COMPASS_STATIC_DIR points at an existing directory.
#
# Mounted at the end of the file so that explicit @app routes above
# (/health, /api/*) win the route-match race before StaticFiles claims "/".
_static_dir_env = os.environ.get("COMPASS_STATIC_DIR")
if _static_dir_env:
    _static_path = Path(_static_dir_env)
    if _static_path.is_dir():
        from fastapi.staticfiles import StaticFiles
        app.mount("/", StaticFiles(directory=str(_static_path), html=True), name="spa")
        logger.info("Serving SPA from %s at /", _static_path)
    else:
        logger.warning("COMPASS_STATIC_DIR=%s is set but the directory does not exist", _static_dir_env)
