"""
COMPASS Local Intermediate Store.

Replaces the former AWS S3 intermediate store. Pipeline stages (aggregator ->
deduplicator -> mitre_mapper, sbom -> architecture -> dfd -> assets, etc.)
pass *local file paths* between each other as opaque string references, the
same way they used to pass s3:// URIs — but everything stays on the local
filesystem, scoped to a per-run directory.

Design:
  - `save_json(data, prefix, filename_suffix=...)` writes a JSON file under
    `<run_root>/<prefix>/<prefix>-<ts>{suffix}.json` and returns its absolute
    path.
  - `load_json(ref)` reads any absolute path previously returned by save_json.
  - `run_scope(...)` is a context manager that creates a dedicated temp
    directory for one agent run and cleans it up afterwards. Each agent wraps
    its /run handler in `run_scope(...)`.

The module never touches S3, never writes outside the current run root, and
always refuses inputs that look like s3:// URIs (those would indicate stale
callers). All file paths are validated to live under the active run root so
a compromised LLM tool cannot coax the loader into reading `/etc/passwd`.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime
from typing import Any, Dict, Iterator, Optional


# ContextVar so that nested tool calls pick up the current run root without
# having to thread it through every function signature.
_current_run_root: ContextVar[Optional[str]] = ContextVar(
    "compass_run_root", default=None
)


def _resolve_run_root() -> str:
    """Return the active run root. Raises if no run_scope is active."""
    root = _current_run_root.get()
    if not root:
        raise RuntimeError(
            "No active run scope. Wrap agent work in `with run_scope(...):`."
        )
    return root


def _validate_ref(ref: str, run_root: str) -> str:
    """Reject s3:// URIs, traversal, and paths outside the run root.

    Returns the resolved absolute path, guaranteed to live under `run_root`.
    """
    if not isinstance(ref, str) or not ref:
        raise ValueError("intermediate reference must be a non-empty string")
    if ref.startswith("s3://"):
        raise ValueError(
            "S3 URIs are no longer supported; the intermediate store is local"
        )
    # Resolve and confirm containment. commonpath raises on mixed drives on
    # Windows, so guard with a direct startswith fallback too.
    abs_ref = os.path.abspath(ref)
    abs_root = os.path.abspath(run_root)
    try:
        if os.path.commonpath([abs_ref, abs_root]) != abs_root:
            raise ValueError("reference escapes the active run scope")
    except ValueError:
        # Different drives on Windows, or unrelated roots.
        raise ValueError("reference escapes the active run scope")
    return abs_ref


def save_json(
    data: Dict[str, Any],
    prefix: str,
    filename_suffix: str = "",
) -> str:
    """Write `data` as JSON under the active run root and return its absolute path.

    Signature mirrors the old `upload_json_to_s3` so pipeline modules only need
    to change the import and the return semantics (local path vs s3:// URI).
    """
    if not prefix or "/" in prefix or ".." in prefix:
        raise ValueError("prefix must be a simple directory name")
    if filename_suffix and ("/" in filename_suffix or ".." in filename_suffix):
        raise ValueError("filename_suffix must not contain path separators")

    run_root = _resolve_run_root()
    subdir = os.path.join(run_root, prefix)
    os.makedirs(subdir, exist_ok=True)

    # Timestamp + short uuid so concurrent saves inside the same second don't
    # collide (the old S3 helper had the same risk but network latency masked it).
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    unique = uuid.uuid4().hex[:6]
    filename = f"{prefix}-{ts}-{unique}{filename_suffix}.json"
    path = os.path.join(subdir, filename)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    return path


def load_json(ref: str) -> Dict[str, Any]:
    """Load JSON previously written via `save_json`."""
    path = _validate_ref(ref, _resolve_run_root())
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_input_payload(name: str, data: Dict[str, Any]) -> str:
    """Materialize an incoming HTTP-body JSON payload as a file in the run root.

    Used by agents that receive scanner/inventory JSON in the request body and
    need to hand a *path* to an LLM tool (so the LLM sees "load_inventory(path)"
    instead of a multi-megabyte dict).
    """
    if not name or "/" in name or ".." in name:
        raise ValueError("payload name must be a simple filename")
    run_root = _resolve_run_root()
    path = os.path.join(run_root, f"{name}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return path


@contextmanager
def run_scope(base_dir: Optional[str] = None, job_id: Optional[str] = None) -> Iterator[str]:
    """Create an isolated per-run directory, set it as the active run root,
    and clean it up on exit.

    Args:
        base_dir: optional parent directory. Defaults to the system temp dir.
        job_id:   optional stable id so callers can find the directory while
                  the run is active (purely for debugging; external callers
                  should not rely on this layout).

    Yields:
        The absolute path of the run root.
    """
    parent = base_dir or os.environ.get("COMPASS_STORE_ROOT") or tempfile.gettempdir()
    os.makedirs(parent, exist_ok=True)

    suffix = f"-{job_id}" if job_id else ""
    run_root = tempfile.mkdtemp(prefix="compass-run-", suffix=suffix, dir=parent)

    token = _current_run_root.set(run_root)
    try:
        yield run_root
    finally:
        _current_run_root.reset(token)
        # Best-effort cleanup; never let cleanup errors mask the agent's result.
        shutil.rmtree(run_root, ignore_errors=True)
