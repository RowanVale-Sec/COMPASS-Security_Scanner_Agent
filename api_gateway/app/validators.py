"""
Input validation for the COMPASS API gateway.

All validators here are *conservative* — they reject anything that doesn't
look like a well-formed value on the happy path, even if the upstream system
might have been permissive about it. The goal is to keep garbage out of
subprocess invocations, HTTP bodies forwarded to internal agents, and log
lines.
"""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlparse


# github.com only. Owner and repo names per GitHub's own charset: letters,
# digits, hyphen, underscore, and dot. Owners cannot start with a hyphen;
# repo names likewise. Trailing .git / trailing slash allowed.
_GITHUB_URL_RE = re.compile(
    r"^https://github\.com/"
    r"(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9._-]{0,38}[A-Za-z0-9])?)/"
    r"(?P<repo>[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99}[A-Za-z0-9])?)"
    r"(?:\.git)?/?$"
)

MAX_URL_LEN = 250
MAX_PAT_LEN = 255  # GitHub PATs top out well below this
MIN_PAT_LEN = 20

# GitHub PAT formats: classic `ghp_`, fine-grained `github_pat_`. Everything
# else we refuse — even if GitHub later introduces a new format, we want to
# whitelist explicitly.
_GITHUB_PAT_RE = re.compile(r"^(?:ghp_|github_pat_)[A-Za-z0-9_]{10,240}$")

# Azure OpenAI endpoints live under *.openai.azure.com. Other Microsoft AI
# endpoints do exist but we scope to this one subdomain for now.
_AZURE_ENDPOINT_RE = re.compile(
    r"^https://[A-Za-z0-9][A-Za-z0-9-]{0,62}\.openai\.azure\.com/?$"
)
_AZURE_KEY_RE = re.compile(r"^[A-Fa-f0-9]{32,64}$")
_AZURE_DEPLOYMENT_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_AZURE_API_VERSION_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}(?:-preview)?$")

# Anthropic Claude keys start with `sk-ant-`. Keep a generous length bound
# so new key formats still pass.
_CLAUDE_KEY_RE = re.compile(r"^sk-ant-[A-Za-z0-9_\-]{20,300}$")

# Allowlist of Claude model ids we forward. Keep this tight — anything else
# is either a typo or an attempt to hit an unintended endpoint.
CLAUDE_MODEL_ALLOWLIST = frozenset({
    "claude-opus-4-7",
    "claude-opus-4-6",
    "claude-opus-4-5",
    "claude-sonnet-4-6",
    "claude-sonnet-4-5",
    "claude-haiku-4-5",
    "claude-haiku-4-5-20251001",
})


class ValidationError(ValueError):
    """Raised for any invalid input at the API boundary."""


def validate_github_url(url: object) -> str:
    """Return the canonical HTTPS GitHub URL or raise ValidationError.

    Rejects: non-strings, non-HTTPS, wrong host, excess length, path traversal,
    query strings, fragments, userinfo, and anything the regex doesn't cover.
    """
    if not isinstance(url, str):
        raise ValidationError("github_url must be a string")
    if len(url) > MAX_URL_LEN:
        raise ValidationError("github_url is too long")
    if len(url.strip()) != len(url):
        raise ValidationError("github_url has leading/trailing whitespace")

    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValidationError("github_url must use https")
    if parsed.netloc != "github.com":
        raise ValidationError("github_url must point to github.com")
    if parsed.username or parsed.password:
        raise ValidationError("github_url must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ValidationError("github_url must not contain query or fragment")
    if ".." in parsed.path or "//" in parsed.path.lstrip("/"):
        raise ValidationError("github_url contains suspicious path segments")

    if not _GITHUB_URL_RE.match(url):
        raise ValidationError("github_url is not a well-formed GitHub repo URL")
    return url


def validate_github_pat(pat: Optional[object]) -> Optional[str]:
    """Validate optional GitHub PAT. Returns the pat string or None."""
    if pat is None or pat == "":
        return None
    if not isinstance(pat, str):
        raise ValidationError("github_pat must be a string")
    if not (MIN_PAT_LEN <= len(pat) <= MAX_PAT_LEN):
        raise ValidationError("github_pat length is out of range")
    if not _GITHUB_PAT_RE.match(pat):
        raise ValidationError("github_pat format is not recognized")
    return pat


def validate_azure_credentials(creds: dict) -> dict:
    """Validate an Azure credentials sub-object. Returns a *new* dict so
    callers don't mutate the Pydantic model's internals.
    """
    api_key = creds.get("api_key")
    endpoint = creds.get("endpoint")
    deployment = creds.get("deployment")
    api_version = creds.get("api_version") or "2024-08-01-preview"
    embedding = creds.get("embedding_deployment")

    if not isinstance(api_key, str) or not _AZURE_KEY_RE.match(api_key):
        raise ValidationError("azure api_key format is invalid")
    if not isinstance(endpoint, str) or not _AZURE_ENDPOINT_RE.match(endpoint):
        raise ValidationError("azure endpoint must be https://<name>.openai.azure.com/")
    if not isinstance(deployment, str) or not _AZURE_DEPLOYMENT_RE.match(deployment):
        raise ValidationError("azure deployment name is invalid")
    if not isinstance(api_version, str) or not _AZURE_API_VERSION_RE.match(api_version):
        raise ValidationError("azure api_version is invalid")
    if embedding is not None:
        if not isinstance(embedding, str) or not _AZURE_DEPLOYMENT_RE.match(embedding):
            raise ValidationError("azure embedding_deployment is invalid")

    out = {
        "provider": "azure",
        "api_key": api_key,
        "endpoint": endpoint,
        "deployment": deployment,
        "api_version": api_version,
    }
    if embedding:
        out["embedding_deployment"] = embedding
    return out


def validate_claude_credentials(creds: dict) -> dict:
    """Validate a Claude credentials sub-object."""
    api_key = creds.get("api_key")
    model = creds.get("model") or "claude-sonnet-4-6"
    max_tokens = creds.get("max_tokens", 8192)

    if not isinstance(api_key, str) or not _CLAUDE_KEY_RE.match(api_key):
        raise ValidationError("claude api_key format is invalid")
    if model not in CLAUDE_MODEL_ALLOWLIST:
        raise ValidationError("claude model is not in the allowlist")
    try:
        max_tokens_int = int(max_tokens)
    except (TypeError, ValueError):
        raise ValidationError("claude max_tokens must be an integer")
    if not 256 <= max_tokens_int <= 32768:
        raise ValidationError("claude max_tokens out of range (256..32768)")

    return {
        "provider": "claude",
        "api_key": api_key,
        "model": model,
        "max_tokens": max_tokens_int,
    }
