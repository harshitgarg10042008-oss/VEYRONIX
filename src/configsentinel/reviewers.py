"""Deterministic reviewer disagreement analytics for evidence-first audits."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Mapping, Sequence

REVIEW_SCHEMA = "configsentinel.reviewer-disagreement.v1"
DECISIONS = ("ACCEPT", "CHALLENGE", "UNABLE")
EVIDENCE_QUALITIES = ("VERIFIED", "PARTIAL", "MISSING", "CONTRADICTED")
MAX_REVIEWERS = 128
MAX_FINDINGS = 10000
MAX_ENTRIES_PER_REVIEWER = 10000


class ReviewAnalyticsError(ValueError):
    """Raised when reviewer input is malformed or outside safe bounds."""


def _text(value: Any, label: str, limit: int = 128) -> str:
    text = str(value or "").strip()
    if not text or len(text) > limit:
        raise ReviewAnalyticsError(f"{label} is required and bounded")
    return text


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()


def _report_findings(report: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    findings = report.get("findings") if isinstance(report, Mapping) else None
    if not isinstance(findings, list) or len(findings) > MAX_FINDINGS:
        raise ReviewAnalyticsError("report.findings must be a bounded list")
    result: dict[str, Mapping[str, Any]] = {}
    for item in findings:
        if not isinstance(item, Mapping):
            raise ReviewAnalyticsError("report findings must be objects")
        finding_id = _text(item.get("finding_id"), "finding.finding_id")
        if finding_id in result:
            raise ReviewAnalyticsError(f"duplicate finding_id: {finding_id}")
        result[finding_id] = item
    return result


def _finding_snapshot(finding: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "finding_id": _text(finding.get("finding_id"), "finding.finding_id"),
        "control_id": _text(finding.get("control_id"), "finding.control_id"),
        "authoritative_status": _text(
            finding.get("status", "UNKNOWN"), "finding.status", 32
        ).upper(),
        "severity": str(finding.get("severity", "UNKNOWN"))[:32],
    }


def build_reviewer_analytics(
    report: Mapping[str, Any], reviews: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    """Compare bounded reviewer decisions while preserving the audit verdict as authoritative."""
    findings = _report_findings(report)
    if (
        not isinstance(reviews, Sequence)
        or isinstance(reviews, (str, bytes))
        or not reviews
        or len(reviews) > MAX_REVIEWERS
    ):
        raise ReviewAnalyticsError(
            "reviews must contain between one and 128 reviewer records"
        )
    reviewer_records: list[dict[str, Any]] = []
    seen_reviewers: set[str] = set()
    decisions_by_finding: dict[str, list[dict[str, Any]]] = {
        finding_id: [] for finding_id in findings
    }
    for review in reviews:
        if not isinstance(review, Mapping):
            raise ReviewAnalyticsError("reviewer records must be objects")
        reviewer_id = _text(review.get("reviewer_id"), "reviewer_id")
        if reviewer_id in seen_reviewers:
            raise ReviewAnalyticsError(f"duplicate reviewer_id: {reviewer_id}")
        seen_reviewers.add(reviewer_id)
        entries = review.get("findings", [])
        if not isinstance(entries, list) or len(entries) > MAX_ENTRIES_PER_REVIEWER:
            raise ReviewAnalyticsError("review.findings must be a bounded list")
        seen_finding_ids: set[str] = set()
        accepted_entries: list[dict[str, Any]] = []
        for entry in entries:
            if not isinstance(entry, Mapping):
                raise ReviewAnalyticsError("review finding entries must be objects")
            finding_id = _text(entry.get("finding_id"), "review.finding_id")
            if finding_id not in findings:
                raise ReviewAnalyticsError(
                    f"review references unknown finding: {finding_id}"
                )
            if finding_id in seen_finding_ids:
                raise ReviewAnalyticsError(f"review repeats finding: {finding_id}")
            seen_finding_ids.add(finding_id)
            decision = _text(entry.get("decision"), "review.decision", 32).upper()
            if decision not in DECISIONS:
                raise ReviewAnalyticsError(f"unsupported reviewer decision: {decision}")
            evidence_quality = _text(
                entry.get("evidence_quality", "MISSING"), "review.evidence_quality", 32
            ).upper()
            if evidence_quality not in EVIDENCE_QUALITIES:
                raise ReviewAnalyticsError(
                    f"unsupported evidence quality: {evidence_quality}"
                )
            challenge_code = (
                str(entry.get("challenge_code", ""))[:64].upper()
                if entry.get("challenge_code") is not None
                else ""
            )
            note = entry.get("note")
            note_hash = (
                hashlib.sha256(str(note).encode("utf-8")).hexdigest()
                if note is not None
                else None
            )
            summary = {
                "finding_id": finding_id,
                "decision": decision,
                "evidence_quality": evidence_quality,
                "challenge_code": challenge_code or None,
                "note_sha256": note_hash,
            }
            accepted_entries.append(summary)
            decisions_by_finding[finding_id].append(
                {"reviewer_id": reviewer_id, **summary}
            )
        reviewer_records.append(
            {
                "reviewer_id": reviewer_id,
                "entry_count": len(accepted_entries),
                "entries": sorted(
                    accepted_entries, key=lambda item: item["finding_id"]
                ),
                "review_sha256": _digest(
                    {"reviewer_id": reviewer_id, "entries": accepted_entries}
                ),
            }
        )
    per_finding: list[dict[str, Any]] = []
    for finding_id in sorted(findings):
        votes = sorted(
            decisions_by_finding[finding_id], key=lambda item: item["reviewer_id"]
        )
        counts = Counter(item["decision"] for item in votes)
        unique = sorted(counts)
        total = len(votes)
        max_votes = max(counts.values()) if counts else 0
        top_decisions = sorted(
            decision for decision, count in counts.items() if count == max_votes
        )
        consensus = top_decisions[0] if len(top_decisions) == 1 else "CONTESTED"
        pair_count = total * (total - 1) // 2
        matching_pairs = sum(count * (count - 1) // 2 for count in counts.values())
        pairwise = matching_pairs / pair_count if pair_count else None
        per_finding.append(
            {
                **_finding_snapshot(findings[finding_id]),
                "review_count": total,
                "decision_counts": {
                    decision: counts.get(decision, 0) for decision in DECISIONS
                },
                "consensus_decision": consensus if total else "INSUFFICIENT_REVIEW",
                "consensus_strength": max_votes / total if total else 0.0,
                "pairwise_agreement": pairwise,
                "disputed": len(unique) > 1,
                "reviewers": [
                    {
                        "reviewer_id": item["reviewer_id"],
                        "decision": item["decision"],
                        "evidence_quality": item["evidence_quality"],
                        "challenge_code": item["challenge_code"],
                    }
                    for item in votes
                ],
                "review_boundary": {
                    "audit_verdict_unchanged": True,
                    "consensus_is_not_authority": True,
                },
            }
        )
    reviewed = [item for item in per_finding if item["review_count"]]
    disputed = [item for item in per_finding if item["disputed"]]
    pairwise_values = [
        item["pairwise_agreement"]
        for item in reviewed
        if item["pairwise_agreement"] is not None
    ]
    unresolved = [
        item
        for item in per_finding
        if item["consensus_decision"] in {"UNABLE", "CONTESTED", "INSUFFICIENT_REVIEW"}
    ]

    payload = {
        "schema": REVIEW_SCHEMA,
        "source": {
            "audit_id": (
                str(report.get("audit", {}).get("audit_id", "unknown"))[:128]
                if isinstance(report.get("audit"), Mapping)
                else "unknown"
            ),
            "report_sha256": _digest(report),
            "finding_count": len(findings),
        },
        "reviewers": reviewer_records,
        "findings": per_finding,
        "summary": {
            "reviewer_count": len(reviewer_records),
            "reviewed_finding_count": len(reviewed),
            "disputed_finding_count": len(disputed),
            "unresolved_finding_count": len(unresolved),
            "disagreement_rate": len(disputed) / len(reviewed) if reviewed else 0.0,
            "mean_pairwise_agreement": (
                sum(pairwise_values) / len(pairwise_values) if pairwise_values else None
            ),
            "minimum_reviewer_count_for_consensus": 2,
        },
        "safety": {
            "authoritative_verdict_source": "original_deterministic_audit",
            "verdicts_changed": False,
            "raw_configuration_included": False,
            "raw_evidence_included": False,
            "reviewer_notes_included": False,
            "network_submission": False,
        },
    }
    payload["analytics_sha256"] = _digest(payload)
    return payload


def load_reviews(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    if (
        source.is_symlink()
        or not source.is_file()
        or source.stat().st_size > 1024 * 1024
    ):
        raise ReviewAnalyticsError("review input path is invalid or exceeds 1 MiB")
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReviewAnalyticsError("review input is not valid UTF-8 JSON") from exc
    if not isinstance(value, Mapping) or not isinstance(value.get("reviews"), list):
        raise ReviewAnalyticsError("review input must contain a reviews list")
    return dict(value)


__all__ = [
    "DECISIONS",
    "EVIDENCE_QUALITIES",
    "REVIEW_SCHEMA",
    "ReviewAnalyticsError",
    "build_reviewer_analytics",
    "load_reviews",
]
