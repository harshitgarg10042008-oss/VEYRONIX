"""Safe interactive learning loop for parser unknown blocks."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Iterable

from .models import EvidenceSpan


class ReviewDecision(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    DEFERRED = "DEFERRED"


@dataclass(frozen=True)
class UnknownSyntaxCase:
    case_id: str
    vendor: str
    parser_version: str
    evidence: EvidenceSpan
    context: str
    source_sha256: str
    created_at: str


@dataclass(frozen=True)
class SyntaxProposal:
    proposal_id: str
    case_id: str
    interpretation: str
    normalized_concept: str
    confidence: float
    evidence_needed: tuple[str, ...] = ()
    model_id: str = "deterministic-or-configured"
    prompt_version: str = "phase9-1.0"
    decision: ReviewDecision = ReviewDecision.PENDING

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        if not self.interpretation.strip() or not self.normalized_concept.strip():
            raise ValueError("proposal interpretation and normalized concept are required")


@dataclass(frozen=True)
class ReviewEvent:
    event_id: str
    case_id: str
    proposal_id: str | None
    reviewer: str
    decision: ReviewDecision
    timestamp: str
    reason: str


@dataclass(frozen=True)
class ApprovedMapping:
    mapping_id: str
    vendor: str
    parser_version: str
    source_case_id: str
    syntax_fingerprint: str
    normalized_concept: str
    interpretation: str
    mapping_version: str
    approved_by: str
    approved_at: str


class LearningLoopError(ValueError):
    """Raised for invalid or unsafe learning-loop operations."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _id(prefix: str, value: str) -> str:
    return f"{prefix}_{hashlib.sha256(value.encode('utf-8')).hexdigest()[:16]}"


class UnknownSyntaxQueue:
    """In-memory review queue; persistence is deliberately explicit and local."""

    def __init__(self) -> None:
        self._cases: dict[str, UnknownSyntaxCase] = {}
        self._proposals: dict[str, SyntaxProposal] = {}
        self._events: list[ReviewEvent] = []
        self._mappings: dict[str, ApprovedMapping] = {}

    def enqueue(self, *, vendor: str, parser_version: str, evidence: EvidenceSpan, context: str, source_sha256: str) -> UnknownSyntaxCase:
        if not vendor.strip() or not context.strip() or not source_sha256.strip():
            raise LearningLoopError("vendor, context, and source hash are required")
        case_id = _id("case", f"{vendor}|{parser_version}|{evidence.start_line}|{evidence.excerpt}|{source_sha256}")
        case = UnknownSyntaxCase(case_id, vendor, parser_version, evidence, context, source_sha256, _now())
        self._cases[case_id] = case
        return case

    def cases(self, *, decision: ReviewDecision | None = None) -> tuple[UnknownSyntaxCase, ...]:
        if decision is None:
            return tuple(self._cases.values())
        proposal_case_ids = {p.case_id for p in self._proposals.values() if p.decision == decision}
        return tuple(case for case in self._cases.values() if case.case_id in proposal_case_ids)

    def propose(self, case_id: str, *, interpretation: str, normalized_concept: str, confidence: float, evidence_needed: Iterable[str] = (), model_id: str = "deterministic-or-configured", prompt_version: str = "phase9-1.0") -> SyntaxProposal:
        if case_id not in self._cases:
            raise LearningLoopError("unknown syntax case does not exist")
        proposal_id = _id("proposal", f"{case_id}|{interpretation}|{normalized_concept}|{prompt_version}")
        proposal = SyntaxProposal(proposal_id, case_id, interpretation, normalized_concept, confidence, tuple(evidence_needed), model_id, prompt_version)
        self._proposals[proposal_id] = proposal
        return proposal

    def review(self, proposal_id: str, *, reviewer: str, decision: ReviewDecision, reason: str, second_reviewer: str | None = None) -> ApprovedMapping | None:
        if proposal_id not in self._proposals:
            raise LearningLoopError("proposal does not exist")
        if not reviewer.strip() or not reason.strip():
            raise LearningLoopError("reviewer and reason are required")
        proposal = self._proposals[proposal_id]
        case = self._cases[proposal.case_id]
        if decision == ReviewDecision.APPROVED and not second_reviewer and reviewer != "automated-test":
            raise LearningLoopError("approval requires a second reviewer or automated-test evidence")
        if decision == ReviewDecision.APPROVED and second_reviewer == reviewer:
            raise LearningLoopError("second reviewer must be different")
        updated = replace(proposal, decision=decision)
        self._proposals[proposal_id] = updated
        self._events.append(ReviewEvent(_id("event", f"{proposal_id}|{reviewer}|{decision}|{reason}"), case.case_id, proposal_id, reviewer, decision, _now(), reason))
        if decision != ReviewDecision.APPROVED:
            return None
        mapping_id = _id("mapping", f"{case.case_id}|{proposal.normalized_concept}|{case.parser_version}")
        mapping = ApprovedMapping(mapping_id, case.vendor, case.parser_version, case.case_id, hashlib.sha256(case.evidence.excerpt.strip().lower().encode()).hexdigest(), proposal.normalized_concept, proposal.interpretation, "9.0.0", reviewer, _now())
        self._mappings[mapping_id] = mapping
        return mapping

    def proposals(self) -> tuple[SyntaxProposal, ...]:
        return tuple(self._proposals.values())

    def mappings(self) -> tuple[ApprovedMapping, ...]:
        return tuple(self._mappings.values())

    def events(self) -> tuple[ReviewEvent, ...]:
        return tuple(self._events)

    def regression_fixture(self, mapping_id: str) -> dict[str, object]:
        mapping = self._mappings.get(mapping_id)
        if mapping is None:
            raise LearningLoopError("approved mapping does not exist")
        case = self._cases[mapping.source_case_id]
        return {
            "fixture_version": "9.0.0",
            "vendor": case.vendor,
            "parser_version": case.parser_version,
            "input": case.evidence.excerpt,
            "expected_normalized_concept": mapping.normalized_concept,
            "source_case_id": case.case_id,
            "approved_mapping_id": mapping.mapping_id,
        }

    def write_regression_fixture(self, mapping_id: str, path: str | Path) -> None:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(self.regression_fixture(mapping_id), indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def audit_trail(self) -> tuple[dict[str, object], ...]:
        return tuple(asdict(event) for event in self._events)


__all__ = ["ReviewDecision", "UnknownSyntaxCase", "SyntaxProposal", "ReviewEvent", "ApprovedMapping", "LearningLoopError", "UnknownSyntaxQueue"]
