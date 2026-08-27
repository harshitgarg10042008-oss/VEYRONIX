"""Vendor-neutral configuration representation used by deterministic controls."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import EvidenceSpan


@dataclass(frozen=True)
class CanonicalConfig:
    vendor: str
    platform: str
    version: str | None = None
    management_ssh_enabled: bool | None = None
    management_ssh_version: str | None = None
    management_telnet_enabled: bool | None = None
    aaa_enabled: bool | None = None
    logging_enabled: bool | None = None
    ntp_enabled: bool | None = None
    snmp_secure: bool | None = None
    http_management_enabled: bool | None = None
    unused_services_disabled: bool | None = None
    evidence: dict[str, tuple[EvidenceSpan, ...]] = field(default_factory=dict)
    unknown_blocks: tuple[EvidenceSpan, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def spans_for(self, field_name: str) -> tuple[EvidenceSpan, ...]:
        return self.evidence.get(field_name, ())


@dataclass(frozen=True)
class ParseResult:
    config: CanonicalConfig
    warnings: tuple[str, ...] = ()
    parser_version: str = "3.0.0"


class ParserError(ValueError):
    """Raised when a configuration cannot be parsed safely."""
