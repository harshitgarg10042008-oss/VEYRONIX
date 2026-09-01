"""Parser differential and ambiguity analysis.

This module runs multiple parsing strategies on the same input and compares
the interpretations to identify ambiguities that affect control results.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class DisagreementType(str, Enum):
    """Type of parser disagreement."""
    CONTROL_STATUS = "CONTROL_STATUS"  # Different control pass/fail status
    EVIDENCE_SPAN = "EVIDENCE_SPAN"  # Different evidence locations
    SEVERITY = "SEVERITY"  # Different severity levels
    MISSING_CONTROL = "MISSING_CONTROL"  # Control found in one but not other
    EXTRA_CONTROL = "EXTRA_CONTROL"  # Control found in one but not other


@dataclass(frozen=True)
class ParserResult:
    """Result from a single parser run."""
    parser_id: str
    parser_version: str
    vendor: str
    syntax_family: str
    control_results: dict[str, dict[str, Any]]  # control_id -> result dict
    parse_success: bool
    parse_error: str | None = None


@dataclass(frozen=True)
class Disagreement:
    """A disagreement between two parser results."""
    control_id: str
    disagreement_type: DisagreementType
    parser_a_result: dict[str, Any] | None
    parser_b_result: dict[str, Any] | None
    parser_a_id: str
    parser_b_id: str
    rationale: str
    requires_review: bool


@dataclass(frozen=True)
class DifferentialAnalysis:
    """Result of comparing two parser results."""
    analysis_id: str
    input_id: str
    parser_a: ParserResult
    parser_b: ParserResult
    disagreements: tuple[Disagreement, ...]
    agreement_count: int
    disagreement_count: int
    requires_review_count: int
    analyzed_at: str
    limitations: tuple[str, ...]

    @property
    def has_critical_disagreements(self) -> bool:
        """Return True if any disagreement affects control status."""
        return any(
            d.disagreement_type == DisagreementType.CONTROL_STATUS
            for d in self.disagreements
        )


def compare_parser_results(
    parser_a: ParserResult,
    parser_b: ParserResult,
    input_id: str,
) -> DifferentialAnalysis:
    """Compare two parser results and identify disagreements.
    
    Args:
        parser_a: First parser result
        parser_b: Second parser result
        input_id: Identifier for the input being analyzed
    
    Returns:
        DifferentialAnalysis with all disagreements
    """
    from datetime import datetime, timezone
    import secrets
    
    disagreements: list[Disagreement] = []
    agreement_count = 0
    
    # Get all control IDs from both parsers
    all_controls = set(parser_a.control_results.keys()) | set(parser_b.control_results.keys())
    
    for control_id in all_controls:
        result_a = parser_a.control_results.get(control_id)
        result_b = parser_b.control_results.get(control_id)
        
        # Check for missing controls
        if result_a is None and result_b is not None:
            disagreements.append(Disagreement(
                control_id=control_id,
                disagreement_type=DisagreementType.MISSING_CONTROL,
                parser_a_result=None,
                parser_b_result=result_b,
                parser_a_id=parser_a.parser_id,
                parser_b_id=parser_b.parser_id,
                rationale=f"Control {control_id} found in {parser_b.parser_id} but not in {parser_a.parser_id}",
                requires_review=True,
            ))
            continue
        
        if result_a is not None and result_b is None:
            disagreements.append(Disagreement(
                control_id=control_id,
                disagreement_type=DisagreementType.EXTRA_CONTROL,
                parser_a_result=result_a,
                parser_b_result=None,
                parser_a_id=parser_a.parser_id,
                parser_b_id=parser_b.parser_id,
                rationale=f"Control {control_id} found in {parser_a.parser_id} but not in {parser_b.parser_id}",
                requires_review=True,
            ))
            continue
        
        # Both have the control, compare results
        if result_a is not None and result_b is not None:
            status_a = result_a.get("status")
            status_b = result_b.get("status")
            
            if status_a != status_b:
                disagreements.append(Disagreement(
                    control_id=control_id,
                    disagreement_type=DisagreementType.CONTROL_STATUS,
                    parser_a_result=result_a,
                    parser_b_result=result_b,
                    parser_a_id=parser_a.parser_id,
                    parser_b_id=parser_b.parser_id,
                    rationale=f"Control {control_id} status differs: {status_a} vs {status_b}",
                    requires_review=True,
                ))
            else:
                agreement_count += 1
            
            # Compare severity
            severity_a = result_a.get("severity")
            severity_b = result_b.get("severity")
            if severity_a != severity_b:
                disagreements.append(Disagreement(
                    control_id=control_id,
                    disagreement_type=DisagreementType.SEVERITY,
                    parser_a_result=result_a,
                    parser_b_result=result_b,
                    parser_a_id=parser_a.parser_id,
                    parser_b_id=parser_b.parser_id,
                    rationale=f"Control {control_id} severity differs: {severity_a} vs {severity_b}",
                    requires_review=False,  # Severity disagreement is less critical
                ))
    
    requires_review_count = sum(1 for d in disagreements if d.requires_review)
    
    limitations = (
        "Comparison based on control-level results only",
        "Does not analyze evidence span differences in detail",
        "Parser-specific normalization not considered",
        "False positives may occur due to benign differences",
    )
    
    analysis_id = f"diff_{secrets.token_hex(8)}"
    
    return DifferentialAnalysis(
        analysis_id=analysis_id,
        input_id=input_id,
        parser_a=parser_a,
        parser_b=parser_b,
        disagreements=tuple(disagreements),
        agreement_count=agreement_count,
        disagreement_count=len(disagreements),
        requires_review_count=requires_review_count,
        analyzed_at=datetime.now(timezone.utc).isoformat(),
        limitations=limitations,
    )


def track_disagreement_metrics(
    analyses: list[DifferentialAnalysis],
) -> dict[str, Any]:
    """Aggregate disagreement metrics across multiple analyses.
    
    Args:
        analyses: List of differential analyses
    
    Returns:
        Dictionary with metrics by vendor, syntax family, and parser version
    """
    metrics = {
        "total_analyses": len(analyses),
        "by_vendor": {},
        "by_syntax_family": {},
        "by_parser_version": {},
        "by_disagreement_type": {},
    }
    
    for analysis in analyses:
        # By vendor
        vendor = analysis.parser_a.vendor
        metrics["by_vendor"][vendor] = metrics["by_vendor"].get(vendor, 0) + analysis.disagreement_count
        
        # By syntax family
        syntax = analysis.parser_a.syntax_family
        metrics["by_syntax_family"][syntax] = metrics["by_syntax_family"].get(syntax, 0) + analysis.disagreement_count
        
        # By parser version
        version = analysis.parser_a.parser_version
        metrics["by_parser_version"][version] = metrics["by_parser_version"].get(version, 0) + analysis.disagreement_count
        
        # By disagreement type
        for disagreement in analysis.disagreements:
            dtype = disagreement.disagreement_type.value
            metrics["by_disagreement_type"][dtype] = metrics["by_disagreement_type"].get(dtype, 0) + 1
    
    return metrics


def create_ambiguity_finding(
    analysis: DifferentialAnalysis,
    control_id: str,
) -> dict[str, Any]:
    """Create an ambiguity finding for the review queue.
    
    Args:
        analysis: Differential analysis with disagreements
        control_id: Control ID with ambiguity
    
    Returns:
        Dictionary representing the ambiguity finding
    """
    disagreements_for_control = [d for d in analysis.disagreements if d.control_id == control_id]
    
    if not disagreements_for_control:
        raise ValueError(f"No disagreements found for control {control_id}")
    
    return {
        "finding_id": f"amb_{analysis.analysis_id}_{control_id}",
        "finding_type": "PARSER_AMBIGUITY",
        "control_id": control_id,
        "input_id": analysis.input_id,
        "analysis_id": analysis.analysis_id,
        "parser_a_id": analysis.parser_a.parser_id,
        "parser_b_id": analysis.parser_b.parser_id,
        "disagreement_types": [d.disagreement_type.value for d in disagreements_for_control],
        "rationale": "; ".join(d.rationale for d in disagreements_for_control),
        "requires_review": any(d.requires_review for d in disagreements_for_control),
        "created_at": analysis.analyzed_at,
    }
