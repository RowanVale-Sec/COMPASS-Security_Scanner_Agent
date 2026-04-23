"""
Streaming client for the orchestrator's SSE endpoint.

Forwards the user's per-request credentials (never persisted here), parses
`event:` / `data:` lines from the orchestrator, and yields parsed Python
dicts. The only thing this module knows how to do is pipe events — it does
not inspect bundles or credentials beyond what's needed to detect the end
of the stream.
"""

from __future__ import annotations

import json
import os
from typing import Any, AsyncIterator, Dict, Optional

import httpx

ORCHESTRATOR_URL = os.environ.get("ORCHESTRATOR_URL", "http://orchestrator:8093")
STREAM_TIMEOUT_S = int(os.environ.get("ORCHESTRATOR_STREAM_TIMEOUT_S", "3600"))


async def stream_pipeline(
    folder_path: str,
    credentials: Optional[Dict[str, Any]],
) -> AsyncIterator[Dict[str, Any]]:
    """POST to the orchestrator's /run/stream and yield parsed SSE events.

    Each yielded item is a dict: {"event": "<name>", "data": {...}}.
    Terminates after a `complete` or `error` event.
    """
    payload: Dict[str, Any] = {"folder_path": folder_path}
    if credentials:
        payload["credentials"] = credentials

    timeout = httpx.Timeout(STREAM_TIMEOUT_S, connect=30.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        async with client.stream(
            "POST",
            f"{ORCHESTRATOR_URL}/run/stream",
            json=payload,
            headers={"Accept": "text/event-stream"},
        ) as response:
            if response.status_code >= 400:
                body = await response.aread()
                try:
                    body_text = body.decode("utf-8", errors="replace")[:500]
                except Exception:
                    body_text = "<binary>"
                yield {
                    "event": "error",
                    "data": {"message": f"orchestrator HTTP {response.status_code}: {body_text}"},
                }
                return

            event_name: Optional[str] = None
            data_lines: list[str] = []
            async for raw_line in response.aiter_lines():
                line = raw_line.rstrip("\r")
                if line == "":
                    if event_name and data_lines:
                        try:
                            data = json.loads("\n".join(data_lines))
                        except json.JSONDecodeError:
                            data = {"raw": "\n".join(data_lines)}
                        yield {"event": event_name, "data": data}
                        if event_name in ("complete", "error"):
                            return
                    event_name = None
                    data_lines = []
                    continue
                if line.startswith("event:"):
                    event_name = line[len("event:"):].strip()
                elif line.startswith("data:"):
                    data_lines.append(line[len("data:"):].lstrip())
                # Ignore other lines (comments, id:, retry:)
