"""Versioned framework registry and control-to-framework mappings."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .controls import CONTROL_PACK
from .models import Finding


@dataclass(frozen=True)
class FrameworkDefinition:
    framework_id: str
    title: str
    version: str
    source_url: str
    license_note: str


FRAMEWORKS: tuple[FrameworkDefinition, ...] = (
    FrameworkDefinition(
        "cis-network",
        "CIS network hardening profile",
        "mvp-1.0",
        "https://www.cisecurity.org/benchmarks",
        "Reference mapping; verify against the organization’s approved benchmark version.",
    ),
    FrameworkDefinition(
        "nist-800-53",
        "NIST SP 800-53 security and privacy controls",
        "rev5",
        "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
        "Informative mapping; assessor or system-owner verification is required.",
    ),
    FrameworkDefinition(
        "nist-csf-2",
        "NIST Cybersecurity Framework",
        "2.0",
        "https://www.nist.gov/cyberframework",
        "Informative mapping; CSF profiles and organizational outcomes require owner validation.",
    ),
    FrameworkDefinition(
        "pci-dss-4-0-1",
        "Payment Card Industry Data Security Standard",
        "4.0.1",
        "https://www.pcisecuritystandards.org/standards/pci-dss/",
        "Informative mapping; does not establish PCI compliance or replace a QSA assessment.",
    ),
    FrameworkDefinition(
        "iso-27001-2022",
        "ISO/IEC 27001 information security management systems",
        "2022",
        "https://www.iso.org/obp/ui/#iso:std:iso-iec:27001:ed-3:v1:en",
        "Informative mapping; certification assessment remains independent.",
    ),
    FrameworkDefinition(
        "hipaa-security-rule",
        "HIPAA Security Rule",
        "current-rule",
        "https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html",
        "Informative mapping; covered-entity and business-associate obligations require legal review.",
    ),
    FrameworkDefinition(
        "soc-2-tsc",
        "AICPA SOC 2 Trust Services Criteria",
        "current-criteria",
        "https://www.aicpa-cima.com/topic/audit-assurance/soc",
        "Informative mapping; SOC 2 reports are issued through an independent examination.",
    ),
)

FRAMEWORK_BY_ID = {item.framework_id: item for item in FRAMEWORKS}
CONTROL_BY_ID = {item.control.control_id: item.control for item in CONTROL_PACK}
REGISTRY_VERSION = "8.0.0"


def normalize_framework_id(value: str) -> str:
    aliases = {
        "cis": "cis-network",
        "nist": "nist-800-53",
        "nist_800_53": "nist-800-53",
        "csf": "nist-csf-2",
        "nist-csf": "nist-csf-2",
        "pci": "pci-dss-4-0-1",
        "pci-dss": "pci-dss-4-0-1",
        "iso27001": "iso-27001-2022",
        "iso-27001": "iso-27001-2022",
        "hipaa": "hipaa-security-rule",
        "soc2": "soc-2-tsc",
        "soc-2": "soc-2-tsc",
    }
    normalized = aliases.get(value.strip().lower(), value.strip().lower())
    if normalized not in FRAMEWORK_BY_ID:
        raise ValueError(f"unsupported framework: {value}")
    return normalized


def normalize_frameworks(values: Iterable[str] | None) -> tuple[str, ...]:
    selected = tuple(
        dict.fromkeys(
            normalize_framework_id(value) for value in (values or ("cis-network",))
        )
    )
    if not selected:
        raise ValueError("at least one framework is required")
    return selected


def get_framework(framework_id: str) -> FrameworkDefinition:
    return FRAMEWORK_BY_ID[normalize_framework_id(framework_id)]


def mappings_for_finding(
    finding: Finding, frameworks: Iterable[str]
) -> tuple[dict[str, object], ...]:
    control = CONTROL_BY_ID.get(finding.control_id)
    if control is None:
        return tuple()
    rows: list[dict[str, object]] = []
    for framework_id in normalize_frameworks(frameworks):
        framework = get_framework(framework_id)
        mapping_aliases = {"cis-network": "cis", "nist-800-53": "nist_800_53"}
        mapping_key = mapping_aliases.get(
            framework.framework_id, framework.framework_id
        )
        control_ids = tuple(
            control.framework_mappings.get(
                framework.framework_id, control.framework_mappings.get(mapping_key, ())
            )
        )
        rows.append(
            {
                "framework_id": framework.framework_id,
                "title": framework.title,
                "version": framework.version,
                "source_url": framework.source_url,
                "control_ids": control_ids,
                "status": "MAPPED" if control_ids else "UNVERIFIED",
                "confidence": "CONTROL_PACK" if control_ids else "UNVERIFIED",
            }
        )
    return tuple(rows)


def framework_catalog() -> tuple[FrameworkDefinition, ...]:
    return FRAMEWORKS


def framework_registry_snapshot(
    frameworks: Iterable[str],
) -> tuple[dict[str, str], ...]:
    return tuple(
        {
            "framework_id": item.framework_id,
            "version": item.version,
            "source_url": item.source_url,
        }
        for item in (get_framework(value) for value in normalize_frameworks(frameworks))
    )


__all__ = [
    "FrameworkDefinition",
    "FRAMEWORKS",
    "FRAMEWORK_BY_ID",
    "CONTROL_BY_ID",
    "REGISTRY_VERSION",
    "normalize_framework_id",
    "normalize_frameworks",
    "get_framework",
    "mappings_for_finding",
    "framework_catalog",
    "framework_registry_snapshot",
]
