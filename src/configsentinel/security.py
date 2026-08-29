"""Security helpers for the SDK boundary.

These helpers are intentionally conservative. They are not a replacement for a
full secrets scanner, but they provide a safe default before LLM integration.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class RedactionResult:
    text: str
    redaction_count: int
    input_sha256: str


_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.I | re.S)),
    ("PASSWORD", re.compile(r"(?im)^(\s*(?:(?:username\s+\S+\s+)?(?:enable\s+secret|password|passwd|secret|community)\s+))(\S+)(.*)$")),
    ("TOKEN", re.compile(r"(?i)\b(?:token|api[_-]?key|access[_-]?key)\s*[:=]\s*[^\s]+")),
)


class SecretRedactor:
    """Redact common credential forms while retaining useful context."""

    def redact(self, text: str) -> RedactionResult:
        if not isinstance(text, str) or not text.strip():
            raise ValueError("text must be a non-empty string")
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        redactions = 0
        redacted = text
        for label, pattern in _PATTERNS:
            if label == "PASSWORD":
                def replace_password(match: re.Match[str]) -> str:
                    nonlocal redactions
                    redactions += 1
                    # group(1) = keyword prefix, group(2) = encryption type token,
                    # group(3) = the actual secret value — drop both group(2) and group(3)
                    return f"{match.group(1)}<REDACTED_{label}>"
                redacted = pattern.sub(replace_password, redacted)
            else:
                def replace_generic(match: re.Match[str], current_label: str = label) -> str:
                    nonlocal redactions
                    redactions += 1
                    return f"<REDACTED_{current_label}>"
                redacted = pattern.sub(replace_generic, redacted)
        return RedactionResult(redacted, redactions, digest)


def assert_safe_for_llm(text: str) -> None:
    """Fail closed if high-risk secret markers or unsafe bytes remain in text."""
    if "\x00" in text:
        raise ValueError("NUL bytes must be removed before LLM use")
    upper = text.upper()
    markers = ("BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY", "BEGIN EC PRIVATE KEY")
    if any(marker in upper for marker in markers):
        raise ValueError("private-key material must be redacted before LLM use")
