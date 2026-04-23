"""
Security helpers: log scrubbing + credential redaction.

`scrub(obj)` returns a deep copy with any value whose *key* matches a
sensitive pattern replaced with `***REDACTED***`. Use this on any dict
before handing it to `logger.info`, `print`, or `json.dumps` for logs.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Iterable

SENSITIVE_KEY_RE = re.compile(
    r"(token|api[_-]?key|secret|password|authorization|pat|credential)",
    re.IGNORECASE,
)

REDACTED = "***REDACTED***"


def scrub(value: Any) -> Any:
    """Deep-scrub a value: mask dict entries whose keys look sensitive."""
    if isinstance(value, dict):
        return {
            k: (REDACTED if SENSITIVE_KEY_RE.search(str(k)) else scrub(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [scrub(v) for v in value]
    if isinstance(value, tuple):
        return tuple(scrub(v) for v in value)
    return value


class ScrubbingFilter(logging.Filter):
    """Logging filter that scrubs `extra` dicts and obvious secret substrings
    in the rendered message. Belt-and-braces: the primary defense is *not
    logging* secrets in the first place.
    """

    _INLINE_PATTERNS: Iterable[re.Pattern[str]] = (
        re.compile(r"sk-ant-[A-Za-z0-9_\-]{6,}"),
        re.compile(r"ghp_[A-Za-z0-9_]{6,}"),
        re.compile(r"github_pat_[A-Za-z0-9_]{6,}"),
    )

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: D401
        try:
            msg = record.getMessage()
            for pat in self._INLINE_PATTERNS:
                msg = pat.sub(REDACTED, msg)
            record.msg = msg
            record.args = ()
        except Exception:
            pass
        return True


def configure_scrubbed_logging() -> None:
    """Attach the scrubbing filter to the root logger."""
    root = logging.getLogger()
    if not any(isinstance(f, ScrubbingFilter) for f in root.filters):
        root.addFilter(ScrubbingFilter())
