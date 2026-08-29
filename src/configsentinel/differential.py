"""Cross-vendor semantic differential tests for normalized audit behavior."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any, Iterable, Mapping

from .canonical import ParseResult
from .controls import evaluate
from .ingestion import ConfigIngestionService, IngestionError
from .models import AuditRequest
from .parsers import detect_and_parse

DIFFERENTIAL_SCHEMA = "configsentinel.cross-vendor-differential.v1"
MAX_VARIANTS = 8
MAX_FIELDS = 16
SEMANTIC_FIELDS = (
    "management_ssh_enabled",
    "management_ssh_version",
    "management_telnet_enabled",
    "aaa_enabled",
    "logging_enabled",
    "ntp_enabled",
    "snmp_secure",
    "http_management_enabled",
    "unused_services_disabled",
)

SEMANTIC_CONTROL_MAP = {
    "management_ssh_enabled": "NET-MGMT-SSH-001",
    "management_ssh_version": "NET-MGMT-SSH-001",
    "management_telnet_enabled": "NET-MGMT-TELNET-001",
    "aaa_enabled": "NET-AUTH-AAA-001",
    "logging_enabled": "NET-LOG-001",
    "ntp_enabled": "NET-TIME-001",
    "snmp_secure": "NET-SNMP-001",
    "http_management_enabled": "NET-MGMT-HTTP-001",
}


class DifferentialError(ValueError):
    """Raised when a differential case is malformed or cannot be evaluated."""


def _bounded(value: Any, label: str, limit: int = 128) -> str:
    text = str(value or "").strip()
    if not text or len(text) > limit:
        raise DifferentialError(f"{label} is required and bounded")
    return text


def _semantic_projection(
    parsed: ParseResult, fields: tuple[str, ...]
) -> dict[str, Any]:
    return {field: getattr(parsed.config, field) for field in fields}


def _status_projection(parsed: ParseResult, vendor: str) -> dict[str, str]:
    findings = evaluate(parsed.config, audit_id=f"differential:{vendor}")
    return {finding.control_id: finding.status.value for finding in findings}


def run_differential_test(
    variants: Mapping[str, str],
    *,
    fields: Iterable[str] = SEMANTIC_FIELDS,
    case_id: str = "case-local",
) -> dict[str, Any]:
    """Compare explicit vendor variants; no variant is selected as authoritative."""
    if not isinstance(variants, Mapping) or not 2 <= len(variants) <= MAX_VARIANTS:
        raise DifferentialError(
            f"variants must contain 2-{MAX_VARIANTS} explicit vendor inputs"
        )
    selected_fields = tuple(
        dict.fromkeys(str(field).strip() for field in fields if str(field).strip())
    )
    if (
        not selected_fields
        or len(selected_fields) > MAX_FIELDS
        or any(field not in SEMANTIC_FIELDS for field in selected_fields)
    ):
        raise DifferentialError(
            "fields must be a non-empty subset of supported semantic fields"
        )
    case = _bounded(case_id, "case_id")
    ingestion = ConfigIngestionService()
    parsed_variants: list[dict[str, Any]] = []
    try:
        for vendor, source in sorted(variants.items()):
            vendor_name = _bounded(vendor, "vendor")
            if not isinstance(source, str) or not source.strip():
                raise DifferentialError(f"variant source is empty: {vendor_name}")
            ingested = ingestion.ingest_text(f"{vendor_name}.cfg", source)
            parsed = detect_and_parse(ingested.redacted_text, vendor=vendor_name)
            parsed_variants.append(
                {
                    "vendor": vendor_name,
                    "input_sha256": ingested.input_sha256,
                    "parser_version": parsed.parser_version,
                    "semantic": _semantic_projection(parsed, selected_fields),
                    "control_status": _status_projection(parsed, vendor_name),
                    "unknown_block_count": len(parsed.config.unknown_blocks),
                }
            )
    except (IngestionError, ValueError) as exc:
        raise DifferentialError(f"variant rejected: {exc}") from exc

    semantic_disagreements: list[dict[str, Any]] = []
    control_disagreements: list[dict[str, Any]] = []
    for field in selected_fields:
        values = {
            variant["vendor"]: variant["semantic"].get(field)
            for variant in parsed_variants
        }
        if len({json.dumps(value, sort_keys=True) for value in values.values()}) > 1:
            semantic_disagreements.append(
                {
                    "field": field,
                    "values": values,
                    "reason": "vendor parsers produced different normalized values",
                }
            )
    selected_control_ids = {
        SEMANTIC_CONTROL_MAP[field]
        for field in selected_fields
        if field in SEMANTIC_CONTROL_MAP
    }
    control_ids = sorted(selected_control_ids)
    for control_id in control_ids:
        values = {
            variant["vendor"]: variant["control_status"].get(control_id, "MISSING")
            for variant in parsed_variants
        }
        if len(set(values.values())) > 1:
            control_disagreements.append(
                {
                    "control_id": control_id,
                    "statuses": values,
                    "reason": "vendor variants produced different deterministic control statuses",
                }
            )
    equivalent = not semantic_disagreements and not control_disagreements
    return {
        "schema": DIFFERENTIAL_SCHEMA,
        "case_id": case,
        "semantic_fields": list(selected_fields),
        "variants": parsed_variants,
        "comparison": {
            "equivalent": equivalent,
            "semantic_disagreement_count": len(semantic_disagreements),
            "control_disagreement_count": len(control_disagreements),
            "semantic_disagreements": semantic_disagreements,
            "control_disagreements": control_disagreements,
        },
        "safety": {
            "raw_configuration_included": False,
            "authoritative_vendor_selected": False,
            "verdicts_changed": False,
            "network_access": False,
            "note": "Differential testing exposes parser disagreements for review; it does not choose a vendor winner or alter audit verdicts.",
        },
    }


def render_differential_report(report: Mapping[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=True) + "\n"


__all__ = [
    "DIFFERENTIAL_SCHEMA",
    "DifferentialError",
    "SEMANTIC_FIELDS",
    "SEMANTIC_CONTROL_MAP",
    "run_differential_test",
    "render_differential_report",
]
