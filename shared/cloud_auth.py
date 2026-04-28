"""Service-to-service authentication for Cloud Run.

When COMPASS runs on Cloud Run with ``--no-allow-unauthenticated``, every
internal call must carry a Google ID token whose ``aud`` claim matches the
callee's base URL. The token is minted from the running instance's metadata
server via Application Default Credentials, resolving to the per-service
runtime service account.

Off Cloud Run (docker-compose, pytest, local CLI runs) ``K_SERVICE`` is
unset and these helpers return ``None`` / ``{}`` so existing call sites
keep working without conditional branches at every call site.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Dict, Optional
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

_TOKEN_CACHE: Dict[str, tuple] = {}  # audience -> (token, expires_at_epoch)
_CACHE_LOCK = threading.Lock()

_REFRESH_LEEWAY_S = 300       # refresh 5 min before the cached token would expire
_DEFAULT_HOLD_S = 3300        # Google ID tokens last 1h; hold ours for ~55 min


def _audience_for(url: str) -> str:
    """Cloud Run accepts the scheme+host as the audience; strip path/query."""
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        return url
    return f"{parts.scheme}://{parts.netloc}"


def get_id_token(url: str) -> Optional[str]:
    """Mint a Google ID token for ``url``'s audience, or return None locally.

    Cached per audience so a busy instance doesn't hammer the metadata server.
    """
    if not os.environ.get("K_SERVICE"):
        return None

    audience = _audience_for(url)
    now = time.time()

    with _CACHE_LOCK:
        cached = _TOKEN_CACHE.get(audience)
        if cached and cached[1] - _REFRESH_LEEWAY_S > now:
            return cached[0]

    try:
        from google.auth.transport.requests import Request as GoogleAuthRequest
        from google.oauth2 import id_token as google_id_token
    except ImportError:
        logger.warning("google-auth not installed; cannot mint ID token for %s", audience)
        return None

    try:
        token = google_id_token.fetch_id_token(GoogleAuthRequest(), audience)
    except Exception:
        logger.exception("Failed to fetch ID token for audience=%s", audience)
        return None

    with _CACHE_LOCK:
        _TOKEN_CACHE[audience] = (token, now + _DEFAULT_HOLD_S)
    return token


def auth_headers(url: str) -> Dict[str, str]:
    """Return ``{'Authorization': 'Bearer <token>'}`` on Cloud Run, ``{}`` locally."""
    token = get_id_token(url)
    return {"Authorization": f"Bearer {token}"} if token else {}
