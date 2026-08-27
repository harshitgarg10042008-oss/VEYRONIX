from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from configsentinel.reviewers import ReviewAnalyticsError, build_reviewer_analytics


REPORT = {
    "audit": {"audit_id": "review-audit"},
    "findings": [
        {"finding_id": "f-1", "control_id": "CTRL-1", "status": "FAIL", "severity": "HIGH"},
        {"finding_id": "f-2", "control_id": "CTRL-2", "status": "UNKNOWN", "severity": "MEDIUM"},
    ],
}

REVIEWS = [
    {"reviewer_id": "alice", "findings": [{"finding_id": "f-1", "decision": "ACCEPT", "evidence_quality": "VERIFIED", "note": "private reviewer note"}, {"finding_id": "f-2", "decision": "UNABLE", "evidence_quality": "MISSING"}]},
    {"reviewer_id": "bob", "findings": [{"finding_id": "f-1", "decision": "CHALLENGE", "evidence_quality": "PARTIAL", "challenge_code": "EVIDENCE_GAP"}]},
]


def test_analytics_is_deterministic_and_keeps_verdict_authoritative() -> None:
    first = build_reviewer_analytics(REPORT, REVIEWS)
    second = build_reviewer_analytics(REPORT, REVIEWS)
    assert first == second
    assert first["summary"]["disputed_finding_count"] == 1
    assert first["summary"]["unresolved_finding_count"] == 2
    finding = next(item for item in first["findings"] if item["finding_id"] == "f-1")
    assert finding["authoritative_status"] == "FAIL"
    assert finding["disputed"] is True
    assert finding["consensus_decision"] == "CONTESTED"
    assert first["safety"]["verdicts_changed"] is False
    assert first["safety"]["reviewer_notes_included"] is False
    serialized = json.dumps(first, sort_keys=True)
    assert "private reviewer note" not in serialized


def test_single_reviewer_has_no_fake_pairwise_agreement() -> None:
    result = build_reviewer_analytics(REPORT, [{"reviewer_id": "alice", "findings": [{"finding_id": "f-1", "decision": "ACCEPT", "evidence_quality": "VERIFIED"}]}])
    item = next(item for item in result["findings"] if item["finding_id"] == "f-1")
    assert item["pairwise_agreement"] is None
    assert item["consensus_strength"] == 1.0


def test_rejects_duplicate_unknown_or_invalid_review_entries() -> None:
    duplicate = copy.deepcopy(REVIEWS)
    duplicate[0]["findings"].append({"finding_id": "f-1", "decision": "ACCEPT"})
    with pytest.raises(ReviewAnalyticsError):
        build_reviewer_analytics(REPORT, duplicate)
    with pytest.raises(ReviewAnalyticsError):
        build_reviewer_analytics(REPORT, [{"reviewer_id": "a", "findings": [{"finding_id": "missing", "decision": "ACCEPT"}]}])
    with pytest.raises(ReviewAnalyticsError):
        build_reviewer_analytics(REPORT, [{"reviewer_id": "a", "findings": [{"finding_id": "f-1", "decision": "MAYBE"}]}])


def test_reviewer_analytics_cli(tmp_path: Path, capsys) -> None:
    from configsentinel.cli import main

    report_path = tmp_path / "report.json"
    reviews_path = tmp_path / "reviews.json"
    output_path = tmp_path / "analytics.json"
    report_path.write_text(json.dumps(REPORT), encoding="utf-8")
    reviews_path.write_text(json.dumps({"reviews": REVIEWS}), encoding="utf-8")
    assert main(["reviewer-analytics", str(report_path), str(reviews_path), "--out", str(output_path)]) == 0
    assert "verdicts_changed=False" in capsys.readouterr().out
    assert json.loads(output_path.read_text(encoding="utf-8"))["schema"].endswith("reviewer-disagreement.v1")
