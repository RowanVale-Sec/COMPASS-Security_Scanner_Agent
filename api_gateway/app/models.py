"""
Pydantic request/response models for the COMPASS API gateway.

`github_pat` uses `SecretStr` so a stray `repr(model)` does not leak a token
into logs. The nested `credentials` field stays a plain dict — its inner keys
are validated by `validators.py` before being forwarded to the orchestrator.
Models reject unknown fields (`extra='forbid'`) so clients cannot sneak extra
keys through to internal agents.
"""

from __future__ import annotations

from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, SecretStr


class ScanRequest(BaseModel):
    """POST /api/scan body."""

    model_config = ConfigDict(extra='forbid')

    github_url: str = Field(..., max_length=250)
    github_pat: Optional[SecretStr] = Field(default=None)

    provider: Literal["azure", "claude"]
    credentials: Dict[str, Any] = Field(
        ...,
        description="Provider credentials object; shape is validated per-provider.",
    )


class ScanCreateResponse(BaseModel):
    job_id: str
    events_url: str
    download_url: str
