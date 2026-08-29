"""Proof-carrying remediation metadata for deterministic review-only previews."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from typing import Any, Mapping

from .models import AuditResult, EvidenceSpan, Finding, FindingStatus, Severity
from .remediation import RemediationError, generate_bundle

PROOF_SCHEMA = "configsentinel.proof-carrying-remediation.v1"
VERIFY_SCHEMA = "configsentinel.proof-verification.v1"
MAX_FINDINGS = 10000


class ProofError(ValueError):
    """Raised when a proof bundle cannot be built or verified safely."""


def _text(value: Any, label: str, limit: int = 256) -> str:
    text = str(value or "").strip()
    if not text or len(text) > limit:
        raise ProofError(f"{label} is required and bounded")
    return text


def _hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _excerpt_hash(span: EvidenceSpan) -> str:
    return hashlib.sha256(span.excerpt.encode("utf-8")).hexdigest()


def audit_from_report(report: Mapping[str, Any]) -> AuditResult:
    if not isinstance(report, Mapping) or not isinstance(report.get("audit"), Mapping) or not isinstance(report.get("findings"), list):
        raise ProofError("audit report must contain audit metadata and findings")
    if len(report["findings"]) > MAX_FINDINGS:
        raise ProofError("audit report contains too many findings")
    audit = report["audit"]
    audit_id = _text(audit.get("audit_id"), "audit.audit_id")
    vendor = _text(audit.get("vendor"), "audit.vendor")
    parser_version = _text(audit.get("parser_version", "unknown"), "audit.parser_version")
    rule_pack_version = _text(audit.get("rule_pack_version", "unknown"), "audit.rule_pack_version")
    input_sha256 = _text(audit.get("input_sha256"), "audit.input_sha256", 128)
    findings: list[Finding] = []
    for index, raw in enumerate(report["findings"]):
        if not isinstance(raw, Mapping):
            raise ProofError("finding entries must be objects")
        finding_id = _text(raw.get("finding_id", f"finding-{index}"), "finding.finding_id")
        control_id = _text(raw.get("control_id"), "finding.control_id")
        try:
            status = FindingStatus(str(raw.get("status", "UNKNOWN")).upper())
            severity = Severity(str(raw.get("severity", "INFO")).upper())
            confidence = float(raw.get("confidence", 0.0))
        except (TypeError, ValueError) as exc:
            raise ProofError(f"finding {finding_id} has invalid status, severity, or confidence") from exc
        evidence: list[EvidenceSpan] = []
        for raw_span in raw.get("evidence", []):
            if not isinstance(raw_span, Mapping):
                raise ProofError("evidence spans must be objects")
            try:
                evidence.append(EvidenceSpan(int(raw_span.get("start_line")), int(raw_span.get("end_line")), _text(raw_span.get("excerpt"), "evidence.excerpt", 4096), bool(raw_span.get("redacted", True))))
            except (TypeError, ValueError) as exc:
                raise ProofError(f"finding {finding_id} contains invalid evidence") from exc
        findings.append(Finding(finding_id, audit_id, control_id, status, severity, confidence, tuple(evidence), str(raw.get("observed_state", "")), str(raw.get("expected_state", "")), str(raw.get("rationale", "")), raw.get("remediation_preview"), bool(raw.get("llm_assisted", False))))
    unknown_blocks: list[EvidenceSpan] = []
    for raw_span in report.get("unknown_blocks", []):
        if isinstance(raw_span, Mapping):
            unknown_blocks.append(EvidenceSpan(int(raw_span.get("start_line")), int(raw_span.get("end_line")), _text(raw_span.get("excerpt"), "unknown_blocks.excerpt", 4096), bool(raw_span.get("redacted", True))))
    return AuditResult(audit_id, vendor, parser_version, rule_pack_version, tuple(findings), tuple(unknown_blocks), input_sha256)


def _source_contract(audit: AuditResult) -> dict[str, str]:
    return {"audit_id": audit.audit_id, "vendor": audit.vendor, "parser_version": audit.parser_version, "rule_pack_version": audit.rule_pack_version, "input_sha256": audit.input_sha256}


def build_proof_bundle(report: Mapping[str, Any]) -> dict[str, Any]:
    """Build review metadata; no command is executable and no device is contacted."""
    audit = audit_from_report(report)
    try:
        bundle = generate_bundle(audit)
    except RemediationError as exc:
        raise ProofError(str(exc)) from exc
    finding_by_id = {finding.finding_id: finding for finding in audit.findings}
    proofs: list[dict[str, Any]] = []
    for step in bundle.steps:
        finding = finding_by_id.get(step.finding_id)
        if finding is None:
            raise ProofError(f"remediation step references missing finding: {step.finding_id}")
        evidence = [{"start_line": span.start_line, "end_line": span.end_line, "excerpt_sha256": _excerpt_hash(span), "redacted": span.redacted} for span in finding.evidence]
        proof_material = {"finding_id": step.finding_id, "control_id": step.control_id, "vendor": step.vendor, "input_sha256": audit.input_sha256, "evidence": evidence, "command_sha256": hashlib.sha256(step.command.encode("utf-8")).hexdigest(), "rollback_sha256": hashlib.sha256(step.rollback.encode("utf-8")).hexdigest()}
        proofs.append({"proof_id": "proof_" + _hash(proof_material)[:20], "finding_id": step.finding_id, "control_id": step.control_id, "source": {"input_sha256": audit.input_sha256, "evidence": evidence}, "command_sha256": proof_material["command_sha256"], "rollback_sha256": proof_material["rollback_sha256"], "preconditions": [f"source_input_sha256 == {audit.input_sha256}", f"control_status == FAIL", "independent operator approval is present"], "post_change_verification": {"required": True, "expected_control_status": "PASS", "method": "rerun the deterministic audit against the resulting configuration and review evidence"}, "review": {"requires_human_approval": True, "executable": False}})
    proof_id = "remproof_" + _hash({"source": _source_contract(audit), "proof_ids": [item["proof_id"] for item in proofs], "warnings": list(bundle.warnings)})[:20]
    return {"schema": PROOF_SCHEMA, "proof_bundle_id": proof_id, "source": _source_contract(audit), "proofs": proofs, "warnings": list(bundle.warnings), "summary": {"proof_count": len(proofs), "warning_count": len(bundle.warnings), "state": "READY_FOR_REVIEW" if proofs and not bundle.warnings else ("NO_SAFE_STEP" if not proofs and not bundle.warnings else "REVIEW_REQUIRED")}, "safety": {"raw_configuration_included": False, "raw_evidence_included": False, "commands_included": False, "executable": False, "device_connection": False, "verdicts_changed": False, "note": "Proofs bind deterministic remediation previews to source hashes and evidence references; they do not authorize or execute changes."}}


def verify_proof_bundle(proof: Mapping[str, Any], report: Mapping[str, Any]) -> dict[str, Any]:
    """Verify source binding and proof integrity against a supplied report."""
    if not isinstance(proof, Mapping) or proof.get("schema") != PROOF_SCHEMA:
        raise ProofError("unsupported proof bundle schema")
    audit = audit_from_report(report)
    expected_source = _source_contract(audit)
    actual_source = proof.get("source")
    mismatches: list[str] = []
    if actual_source != expected_source:
        mismatches.append("source contract mismatch")
    finding_by_id = {finding.finding_id: finding for finding in audit.findings}
    proofs = proof.get("proofs")
    if not isinstance(proofs, list):
        proofs = []
    for item in proofs:
        if not isinstance(item, Mapping):
            mismatches.append("proof entry is not an object")
            continue
        finding = finding_by_id.get(str(item.get("finding_id", "")))
        if finding is None:
            mismatches.append(f"missing finding: {item.get('finding_id')}")
            continue
        expected_evidence = [{"start_line": span.start_line, "end_line": span.end_line, "excerpt_sha256": _excerpt_hash(span), "redacted": span.redacted} for span in finding.evidence]
        source = item.get("source")
        if not isinstance(source, Mapping):
            source = {}
        if source.get("input_sha256") != audit.input_sha256:
            mismatches.append(f"input hash mismatch: {item.get('finding_id')}")
        if source.get("evidence") != expected_evidence:
            mismatches.append(f"evidence binding mismatch: {item.get('finding_id')}")
        review = item.get("review")
        if not isinstance(review, Mapping):
            review = {}
        if review.get("executable") is not False or review.get("requires_human_approval") is not True:
            mismatches.append(f"unsafe review flags: {item.get('finding_id')}")
    return {"schema": VERIFY_SCHEMA, "proof_bundle_id": str(proof.get("proof_bundle_id", "")), "verified": not mismatches, "mismatches": mismatches, "safety": {"raw_configuration_included": False, "device_connection": False, "verdicts_changed": False, "note": "Verification checks hash and evidence bindings only; it does not execute commands or prove post-change state."}}


def write_proof(report: Mapping[str, Any], output: str) -> dict[str, Any]:
    from pathlib import Path
    proof = build_proof_bundle(report)
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    return proof


__all__ = ["PROOF_SCHEMA", "VERIFY_SCHEMA", "ProofError", "audit_from_report", "build_proof_bundle", "verify_proof_bundle", "write_proof"]
