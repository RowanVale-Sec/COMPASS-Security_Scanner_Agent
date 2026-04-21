"""
Async helpers for talking to MCP servers over streamable HTTP.

Wraps the public `mcp` SDK so callers don't repeat the two-level context-manager
dance or the text-block JSON decoding. Use `mcp_session(url)` to get an
initialized `ClientSession`; use `call_tool_json(session, name, args)` to invoke
a tool and get back parsed JSON.

The MITRE MCP server (Montimage/mitre-mcp) returns tool results as a single
text block containing a JSON-encoded payload; newer servers may also populate
`structuredContent`. Both are handled here.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from typing import Any, Dict, Optional


@asynccontextmanager
async def mcp_session(url: str):
    """Yield an initialized `ClientSession` bound to the MCP server at `url`.

    The `streamablehttp_client` context manager yields a 3-tuple
    (read_stream, write_stream, get_session_id_callback); we discard the third
    because MITRE mapping does not need resumable session IDs.

    `mcp` is imported lazily so test environments that only exercise the
    `call_tool_json` parser don't need the SDK installed.
    """
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    async with streamablehttp_client(url) as (read_stream, write_stream, _):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            yield session


async def call_tool_json(
    session: Any,
    name: str,
    arguments: Optional[Dict[str, Any]] = None,
) -> Any:
    """Call an MCP tool and return its payload parsed as JSON.

    Prefers `structuredContent` when the server populates it; falls back to the
    first text content block. Raises `RuntimeError` if the tool reported an
    error or produced no parseable payload.
    """
    result = await session.call_tool(name, arguments or {})

    if getattr(result, "isError", False):
        raise RuntimeError(f"MCP tool {name!r} returned isError=True: {result.content!r}")

    structured = getattr(result, "structuredContent", None)
    if structured is not None:
        return structured

    for block in result.content or []:
        if getattr(block, "type", None) == "text":
            text = getattr(block, "text", "")
            return json.loads(text)

    raise RuntimeError(f"MCP tool {name!r} returned no text or structured content")
