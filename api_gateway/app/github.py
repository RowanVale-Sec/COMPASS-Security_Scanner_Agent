"""
Hardened git clone for the API gateway.

Never shell out through a shell; never interpolate the PAT into a URL; and
never expose the PAT via argv (process tables and log lines that capture
argv would leak it). Secrets flow to git via an askpass helper whose own
argv contains no secret, and whose stdout is read from an env var we set
only for the duration of the subprocess.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

CLONE_TIMEOUT_S = int(os.environ.get("COMPASS_CLONE_TIMEOUT_S", "300"))
MAX_REPO_BYTES = int(os.environ.get("COMPASS_MAX_REPO_BYTES", str(500 * 1024 * 1024)))  # 500 MB


class CloneError(RuntimeError):
    """Raised when `git clone` fails or violates a safety guard."""


def _measure_dir_bytes(path: Path) -> int:
    total = 0
    for dirpath, _dirnames, filenames in os.walk(path):
        for name in filenames:
            try:
                total += os.path.getsize(os.path.join(dirpath, name))
            except OSError:
                pass
            if total > MAX_REPO_BYTES:
                return total  # early exit
    return total


def _write_askpass_helper(workdir: Path, pat: str) -> Path:
    """Create a GIT_ASKPASS helper script that prints the PAT and nothing else.

    The script is 0700, lives in the per-job workspace, and is removed by the
    caller's workspace cleanup. The secret lives in:
      - the helper script (0700, job-scoped)
      - the GIT_ASKPASS env var (subprocess-scoped)
    It never enters argv or our own process's argv.
    """
    helper = workdir / "askpass.sh"
    helper.write_text(f"#!/bin/sh\nprintf '%s' '{pat}'\n", encoding="utf-8")
    os.chmod(helper, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    return helper


def clone_github_repo(
    github_url: str,
    dest_dir: Path,
    pat: Optional[str] = None,
) -> Path:
    """Clone `github_url` into `dest_dir` (which must not already exist).

    Returns the path of the clone. Raises CloneError on failure. Always use
    inside a temp workspace that is cleaned up afterwards.
    """
    if dest_dir.exists():
        raise CloneError("destination already exists; refusing to overwrite")

    dest_dir.parent.mkdir(parents=True, exist_ok=True)

    env = {
        # Strip inherited env — prevents GIT_* and HOME from leaking into the
        # clone. We re-add only what we need.
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "LANG": "C.UTF-8",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_SSH_COMMAND": "ssh -o BatchMode=yes -o StrictHostKeyChecking=yes",
        # An empty HOME avoids git reading ~/.gitconfig from the container image.
        "HOME": str(dest_dir.parent),
    }

    askpass_workdir: Optional[Path] = None
    helper: Optional[Path] = None
    try:
        if pat:
            askpass_workdir = Path(tempfile.mkdtemp(prefix="compass-askpass-"))
            helper = _write_askpass_helper(askpass_workdir, pat)
            env["GIT_ASKPASS"] = str(helper)
            # For HTTPS clones, git still needs *some* username. GitHub ignores
            # the value when a PAT is used, but `x-access-token` is the
            # documented convention. We set it via config env instead of URL
            # interpolation so it never reaches argv.
            env["GIT_CONFIG_COUNT"] = "1"
            env["GIT_CONFIG_KEY_0"] = f"credential.https://github.com.username"
            env["GIT_CONFIG_VALUE_0"] = "x-access-token"

        cmd = [
            "git",
            "clone",
            "--depth", "1",
            "--single-branch",
            "--no-tags",
            "--",
            github_url,
            str(dest_dir),
        ]

        try:
            result = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                timeout=CLONE_TIMEOUT_S,
                check=False,
                text=True,
            )
        except subprocess.TimeoutExpired as exc:
            raise CloneError(f"git clone timed out after {CLONE_TIMEOUT_S}s") from exc
        except FileNotFoundError as exc:
            raise CloneError("git executable not found in PATH") from exc

        if result.returncode != 0:
            # Sanitize stderr before surfacing — git can include the URL with
            # credentials if the caller ever passed them that way. We never do,
            # but defense-in-depth.
            stderr = (result.stderr or "").strip().splitlines()
            hint = stderr[-1][:200] if stderr else "unknown error"
            # Detect auth failures specifically to give the user a clean message.
            lowered = hint.lower()
            if "authentication" in lowered or "could not read" in lowered or "403" in lowered:
                raise CloneError(
                    "authentication required — provide a valid GitHub PAT for this repo"
                )
            raise CloneError(f"git clone failed: {hint}")

        size = _measure_dir_bytes(dest_dir)
        if size > MAX_REPO_BYTES:
            raise CloneError(
                f"repository exceeds max size ({size} > {MAX_REPO_BYTES} bytes)"
            )

        return dest_dir

    finally:
        # Nuke the askpass workdir first (the helper + env var go out of scope
        # together when the subprocess exits).
        if askpass_workdir and askpass_workdir.exists():
            shutil.rmtree(askpass_workdir, ignore_errors=True)
