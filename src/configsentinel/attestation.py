"""Replayable, signed configuration assurance tokens for ConfigSentinel AI."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any, Mapping

ATTESTATION_SCHEMA = "configsentinel.configuration-attestation.v1"
ATTESTATION_ALGORITHM = "HMAC-SHA256"
DEFAULT_ISSUED_AT = "1970-01-01T00:00:00Z"


class AttestationError(ValueError):
    """Raised when a configuration attestation is invalid or unsafe."""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AttestationError("attestation payload must be JSON serializable") from exc


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _required_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AttestationError(f"{label} must be an object")
    return value


def _report_claim(report: Mapping[str, Any]) -> dict[str, Any]:
    audit = _required_mapping(report.get("audit"), "report.audit")
    summary = _required_mapping(report.get("summary"), "report.summary")
    findings = report.get("findings")
    unknown_blocks = report.get("unknown_blocks")
    reconciliation = _required_mapping(
        report.get("reconciliation"), "report.reconciliation"
    )
    if not isinstance(findings, list) or not isinstance(unknown_blocks, list):
        raise AttestationError("report findings and unknown_blocks must be arrays")
    if not report.get("report_version"):
        raise AttestationError("report_version is required")
    input_sha256 = str(audit.get("input_sha256", ""))
    if len(input_sha256) != 64 or any(
        char not in "0123456789abcdef" for char in input_sha256.lower()
    ):
        raise AttestationError(
            "report.audit.input_sha256 must be a lowercase SHA-256 digest"
        )
    if (
        not str(audit.get("audit_id", "")).strip()
        or not str(audit.get("vendor", "")).strip()
    ):
        raise AttestationError("report audit identity is incomplete")
    evidence_material = []
    finding_ids = []
    for finding in findings:
        item = _required_mapping(finding, "report.findings item")
        finding_id = str(item.get("finding_id", "")).strip()
        control_id = str(item.get("control_id", "")).strip()
        if not finding_id or not control_id:
            raise AttestationError("each finding must have finding_id and control_id")
        finding_ids.append(finding_id)
        evidence = item.get("evidence", [])
        if not isinstance(evidence, list):
            raise AttestationError("finding evidence must be an array")
        evidence_material.append(
            {
                "finding_id": finding_id,
                "control_id": control_id,
                "status": str(item.get("status", "")),
                "evidence": evidence,
            }
        )
    return {
        "report_version": str(report["report_version"]),
        "audit": {
            "audit_id": str(audit["audit_id"]),
            "vendor": str(audit["vendor"]),
            "parser_version": str(audit.get("parser_version", "")),
            "rule_pack_version": str(audit.get("rule_pack_version", "")),
            "framework_registry_version": str(
                audit.get("framework_registry_version", "")
            ),
            "frameworks": list(audit.get("frameworks", [])),
            "input_sha256": input_sha256,
        },
        "summary_digest": _digest(summary),
        "reconciliation_digest": _digest(reconciliation),
        "finding_ids": finding_ids,
        "finding_count": len(findings),
        "unknown_block_count": len(unknown_blocks),
        "evidence_sha256": _digest(evidence_material),
        "report_sha256": _digest(report),
    }


def _issued_at(value: str | None) -> str:
    if value is not None:
        if not value.endswith("Z") or len(value) < 11:
            raise AttestationError(
                "issued_at must be an ISO-8601 UTC string ending in Z"
            )
        return value
    raw_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if raw_epoch is not None:
        try:
            epoch = int(raw_epoch)
        except ValueError as exc:
            raise AttestationError("SOURCE_DATE_EPOCH must be an integer") from exc
        import datetime as _datetime

        return (
            _datetime.datetime.fromtimestamp(epoch, tz=_datetime.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
    return DEFAULT_ISSUED_AT


def build_attestation(
    report: Mapping[str, Any],
    key: bytes,
    *,
    reviewer_status: str = "REVIEW_REQUIRED",
    issued_at: str | None = None,
) -> dict[str, Any]:
    """Create a signed claim bound to the exact serialized redacted report."""
    if not key:
        raise AttestationError("attestation signing key cannot be empty")
    if reviewer_status not in {"REVIEW_REQUIRED", "APPROVED", "REJECTED"}:
        raise AttestationError("invalid reviewer_status")
    claim = _report_claim(report)
    payload = {
        "schema": ATTESTATION_SCHEMA,
        "issued_at": _issued_at(issued_at),
        "reviewer_status": reviewer_status,
        "source_kind": "redacted_audit_report",
        "claim": claim,
    }
    signature = hmac.new(key, _canonical(payload), hashlib.sha256).hexdigest()
    return {
        "schema": ATTESTATION_SCHEMA,
        "algorithm": ATTESTATION_ALGORITHM,
        "payload": payload,
        "signature": signature,
    }


def verify_attestation(
    attestation: Mapping[str, Any], report: Mapping[str, Any], key: bytes
) -> tuple[bool, str]:
    """Verify signature and replay the claim against the supplied report."""
    if not key:
        return False, "verification key cannot be empty"
    try:
        if (
            attestation.get("schema") != ATTESTATION_SCHEMA
            or attestation.get("algorithm") != ATTESTATION_ALGORITHM
        ):
            return False, "unsupported attestation schema or algorithm"
        payload = _required_mapping(attestation.get("payload"), "attestation.payload")
        signature = attestation.get("signature")
        if not isinstance(signature, str) or len(signature) != 64:
            return False, "attestation signature is invalid"
        expected = hmac.new(key, _canonical(payload), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return False, "attestation signature mismatch"
        expected_claim = _report_claim(report)
        claim = _required_mapping(payload.get("claim"), "attestation.payload.claim")
        if _canonical(claim) != _canonical(expected_claim):
            return False, "attestation claim does not match supplied report"
        return True, "attestation verified and replayed"
    except AttestationError as exc:
        return False, str(exc)


def load_attestation(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    if (
        source.is_symlink()
        or not source.is_file()
        or source.stat().st_size > 512 * 1024
    ):
        raise AttestationError(
            "attestation path is invalid or exceeds the 512 KiB limit"
        )
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AttestationError("attestation file is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise AttestationError("attestation root must be an object")
    return value


__all__ = [
    "ATTESTATION_ALGORITHM",
    "ATTESTATION_SCHEMA",
    "AttestationError",
    "build_attestation",
    "load_attestation",
    "verify_attestation",
]
