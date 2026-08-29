"""Expanded sensitive-data detection with redacted, line-based evidence only."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SensitiveHit:
    kind: str
    start_line: int
    end_line: int
    redacted_excerpt: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "redacted_excerpt": self.redacted_excerpt,
        }


@dataclass(frozen=True)
class SensitiveScan:
    input_sha256: str
    hits: tuple[SensitiveHit, ...]

    @property
    def count(self) -> int:
        return len(self.hits)

    def as_dict(self) -> dict[str, Any]:
        return {
            "input_sha256": self.input_sha256,
            "hit_count": self.count,
            "hits": [hit.as_dict() for hit in self.hits],
        }


_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    (
        "GCP_PRIVATE_KEY",
        re.compile(
            r"-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----", re.I | re.S
        ),
    ),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")),
    ("BEARER_TOKEN", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}")),
    ("BASIC_AUTH", re.compile(r"(?i)\bbasic\s+[A-Za-z0-9+/=]{12,}")),
    ("SNMP_COMMUNITY", re.compile(r"(?im)^\s*snmp-server\s+community\s+(\S+)")),
    (
        "CONNECTION_STRING",
        re.compile(r"(?i)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis)://[^\s]+"),
    ),
    (
        "CLOUD_SECRET_ASSIGNMENT",
        re.compile(
            r"(?i)\b(?:aws_secret_access_key|azure_client_secret|client_secret|secret_access_key)\s*[:=]\s*[^\s]+"
        ),
    ),
)


def scan_sensitive(text: str) -> SensitiveScan:
    if not isinstance(text, str) or not text.strip():
        raise ValueError("text must be a non-empty string")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    hits: list[SensitiveHit] = []
    for kind, pattern in _PATTERNS:
        for match in pattern.finditer(text):
            start_line = text.count("\n", 0, match.start()) + 1
            end_line = text.count("\n", 0, match.end()) + 1
            excerpt = text[match.start() : match.end()].replace("\n", " ")
            redacted_excerpt = pattern.sub("<REDACTED_SENSITIVE>", excerpt, count=1)
            hits.append(
                SensitiveHit(kind, start_line, end_line, redacted_excerpt[:240])
            )
    return SensitiveScan(
        digest, tuple(sorted(hits, key=lambda hit: (hit.start_line, hit.kind)))
    )


def render_sensitive_scan(scan: SensitiveScan) -> str:
    lines = [
        "# ConfigSentinel AI sensitive-data scan",
        "",
        f"Input SHA-256: `{scan.input_sha256}`",
        f"Detected hits: **{scan.count}**",
        "",
        "> Scan output contains redacted excerpts only; secrets are never printed.",
        "",
        "| Type | Lines | Redacted evidence |",
        "|---|---:|---|",
    ]
    lines.extend(
        f"| {hit.kind} | L{hit.start_line}-L{hit.end_line} | `{hit.redacted_excerpt}` |"
        for hit in scan.hits
    )
    if not scan.hits:
        lines.append("| None | — | No supported sensitive-data markers detected. |")
    return "\n".join(lines) + "\n"
