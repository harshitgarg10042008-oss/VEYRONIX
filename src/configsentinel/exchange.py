"""Privacy-preserving audit exchange capsules for local or approved handoff."""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, Mapping

EXCHANGE_SCHEMA = "configsentinel.privacy-audit-capsule.v1"
EXCHANGE_VERIFY_SCHEMA = "configsentinel.privacy-audit-capsule-verify.v1"
MAX_FINDINGS = 10000
MAX_NOTE_LENGTH = 512


class ExchangeError(ValueError):
    """Raised when a privacy capsule is unsafe or malformed."""


def _text(value: Any, label: str, limit: int = 256) -> str:
    text = str(value or "").strip()
    if not text or len(text) > limit:
        raise ExchangeError(f"{label} is required and bounded")
    return text


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _report_metadata(report: Mapping[str, Any]) -> dict[str, Any]:
    if (
        not isinstance(report, Mapping)
        or not isinstance(report.get("audit"), Mapping)
        or not isinstance(report.get("findings"), list)
    ):
        raise ExchangeError("report must contain audit metadata and findings")
    audit = report["audit"]
    return {
        "audit_id": _text(audit.get("audit_id"), "audit.audit_id"),
        "vendor": _text(audit.get("vendor"), "audit.vendor"),
        "parser_version": _text(
            audit.get("parser_version", "unknown"), "audit.parser_version"
        ),
        "rule_pack_version": _text(
            audit.get("rule_pack_version", "unknown"), "audit.rule_pack_version"
        ),
        "input_sha256": _text(audit.get("input_sha256"), "audit.input_sha256", 128),
        "frameworks": (
            [str(item)[:128] for item in audit.get("frameworks", [])]
            if isinstance(audit.get("frameworks", []), list)
            else []
        ),
    }


def build_exchange_capsule(
    report: Mapping[str, Any],
    *,
    recipient: str = "local-review",
    purpose: str = "audit-review",
    key: bytes | None = None,
    include_risk: bool = True,
) -> dict[str, Any]:
    """Minimize an audit report into a hash-bound exchange capsule."""
    metadata = _report_metadata(report)
    findings = report["findings"]
    if len(findings) > MAX_FINDINGS:
        raise ExchangeError("report contains too many findings")
    redacted_findings: list[dict[str, Any]] = []
    for raw in findings:
        if not isinstance(raw, Mapping):
            raise ExchangeError("finding entries must be objects")
        status = _text(raw.get("status", "UNKNOWN"), "finding.status", 32).upper()
        if status == "PASS":
            continue
        evidence = raw.get("evidence", [])
        evidence_refs = []
        if isinstance(evidence, list):
            for span in evidence:
                if isinstance(span, Mapping):
                    excerpt = str(span.get("excerpt", ""))
                    evidence_refs.append(
                        {
                            "start_line": span.get("start_line"),
                            "end_line": span.get("end_line"),
                            "excerpt_sha256": hashlib.sha256(
                                excerpt.encode("utf-8")
                            ).hexdigest(),
                            "redacted": bool(span.get("redacted", True)),
                        }
                    )
        item = {
            "finding_id": _text(raw.get("finding_id"), "finding.finding_id"),
            "control_id": _text(raw.get("control_id"), "finding.control_id"),
            "status": status,
            "severity": str(raw.get("severity", "UNKNOWN"))[:32],
            "confidence": raw.get("confidence"),
            "evidence": evidence_refs,
            "finding_sha256": _digest(
                {
                    "finding_id": raw.get("finding_id"),
                    "control_id": raw.get("control_id"),
                    "status": status,
                    "evidence": evidence_refs,
                }
            ),
        }
        if include_risk and isinstance(raw.get("risk"), Mapping):
            item["risk"] = {
                key_name: raw["risk"].get(key_name)
                for key_name in ("priority", "asset_criticality", "score")
                if key_name in raw["risk"]
            }
        redacted_findings.append(item)
    payload = {
        "schema": EXCHANGE_SCHEMA,
        "recipient": _text(recipient, "recipient"),
        "purpose": _text(purpose, "purpose"),
        "source": metadata,
        "summary": {
            "finding_count": len(redacted_findings),
            "unknown_block_count": (
                len(report.get("unknown_blocks", []))
                if isinstance(report.get("unknown_blocks", []), list)
                else 0
            ),
        },
        "findings": sorted(redacted_findings, key=lambda item: item["finding_id"]),
        "provenance": {
            "source_report_sha256": _digest(report),
            "capsule_input_scope": "audit metadata, non-PASS finding summaries, evidence hashes, and optional risk fields",
        },
        "safety": {
            "raw_configuration_included": False,
            "raw_evidence_included": False,
            "passing_findings_included": False,
            "network_submission": False,
            "verdicts_changed": False,
        },
    }
    envelope = {
        "schema": EXCHANGE_SCHEMA,
        "payload": payload,
        "capsule_sha256": _digest(payload),
    }
    if key:
        envelope["integrity"] = {
            "algorithm": "HMAC-SHA256",
            "signature": hmac.new(key, _canonical(payload), hashlib.sha256).hexdigest(),
        }
    return envelope


def verify_exchange_capsule(
    capsule: Mapping[str, Any], *, key: bytes | None = None
) -> dict[str, Any]:
    if (
        not isinstance(capsule, Mapping)
        or capsule.get("schema") != EXCHANGE_SCHEMA
        or not isinstance(capsule.get("payload"), Mapping)
    ):
        raise ExchangeError("unsupported exchange capsule")
    payload = capsule["payload"]
    mismatches: list[str] = []
    if capsule.get("capsule_sha256") != _digest(payload):
        mismatches.append("capsule hash mismatch")
    integrity = capsule.get("integrity")
    if integrity is not None:
        if not key:
            mismatches.append("integrity key required")
        elif integrity.get("algorithm") != "HMAC-SHA256" or not hmac.compare_digest(
            str(integrity.get("signature", "")),
            hmac.new(key, _canonical(payload), hashlib.sha256).hexdigest(),
        ):
            mismatches.append("capsule signature mismatch")
    elif key:
        mismatches.append("capsule is not signed")
    return {
        "schema": EXCHANGE_VERIFY_SCHEMA,
        "capsule_sha256": str(capsule.get("capsule_sha256", "")),
        "verified": not mismatches,
        "mismatches": mismatches,
        "safety": {
            "raw_configuration_included": False,
            "network_submission": False,
            "note": "Verification checks capsule integrity only; it does not approve findings or submit data.",
        },
    }


def write_exchange_capsule(
    report: Mapping[str, Any],
    output: str | Path,
    *,
    recipient: str = "local-review",
    purpose: str = "audit-review",
    key: bytes | None = None,
) -> dict[str, Any]:
    capsule = build_exchange_capsule(
        report, recipient=recipient, purpose=purpose, key=key
    )
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(capsule, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return capsule


__all__ = [
    "EXCHANGE_SCHEMA",
    "EXCHANGE_VERIFY_SCHEMA",
    "ExchangeError",
    "build_exchange_capsule",
    "verify_exchange_capsule",
    "write_exchange_capsule",
]
