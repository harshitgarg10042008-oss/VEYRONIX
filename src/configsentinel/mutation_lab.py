"""Control mutation quality lab for testing rule effectiveness.

This module generates controlled mutations from labeled fixtures, tests whether
controls change as expected, and reports missed mutations and coverage metrics.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class MutationType(str, Enum):
    """Type of mutation."""
    SAFE_TO_UNSAFE = "SAFE_TO_UNSAFE"  # Change from compliant to non-compliant
    UNSAFE_TO_SAFE = "UNSAFE_TO_SAFE"  # Change from non-compliant to compliant
    EQUIVALENT = "EQUIVALENT"  # No change in compliance status


class MutationOutcome(str, Enum):
    """Outcome of mutation test."""
    EXPECTED = "EXPECTED"  # Control changed as expected
    MISSED = "MISSED"  # Control should have changed but didn't
    UNEXPECTED_FAILURE = "UNEXPECTED_FAILURE"  # Control changed unexpectedly
    UNEXPECTED_PASS = "UNEXPECTED_PASS"  # Control passed unexpectedly


@dataclass(frozen=True)
class Mutation:
    """A single mutation to a configuration."""
    mutation_id: str
    control_id: str
    mutation_type: MutationType
    original_config: str
    mutated_config: str
    description: str
    expected_status_before: str  # "PASS" or "FAIL"
    expected_status_after: str  # "PASS" or "FAIL"


@dataclass(frozen=True)
class MutationResult:
    """Result of testing a mutation."""
    mutation: Mutation
    actual_status_before: str
    actual_status_after: str
    outcome: MutationOutcome
    passed: bool


@dataclass(frozen=True)
class MutationLabReport:
    """Report from mutation quality lab run."""
    lab_id: str
    fixture_id: str
    mutations_tested: int
    expected_count: int
    missed_count: int
    unexpected_failure_count: int
    unexpected_pass_count: int
    control_coverage: dict[str, int]  # control_id -> number of mutations tested
    results: tuple[MutationResult, ...]
    generated_at: str
    limitations: tuple[str, ...]

    @property
    def success_rate(self) -> float:
        """Calculate success rate (expected / total)."""
        if self.mutations_tested == 0:
            return 0.0
        return self.expected_count / self.mutations_tested


def generate_safe_to_unsafe_mutation(
    control_id: str,
    original_config: str,
    mutation_description: str,
    mutated_config: str,
) -> Mutation:
    """Generate a safe-to-unsafe mutation."""
    import secrets
    
    return Mutation(
        mutation_id=f"mut_{secrets.token_hex(8)}",
        control_id=control_id,
        mutation_type=MutationType.SAFE_TO_UNSAFE,
        original_config=original_config,
        mutated_config=mutated_config,
        description=mutation_description,
        expected_status_before="PASS",
        expected_status_after="FAIL",
    )


def generate_unsafe_to_safe_mutation(
    control_id: str,
    original_config: str,
    mutation_description: str,
    mutated_config: str,
) -> Mutation:
    """Generate an unsafe-to-safe mutation."""
    import secrets
    
    return Mutation(
        mutation_id=f"mut_{secrets.token_hex(8)}",
        control_id=control_id,
        mutation_type=MutationType.UNSAFE_TO_SAFE,
        original_config=original_config,
        mutated_config=mutated_config,
        description=mutation_description,
        expected_status_before="FAIL",
        expected_status_after="PASS",
    )


def evaluate_mutation(
    mutation: Mutation,
    audit_func: callable,  # Function that takes config and returns status
) -> MutationResult:
    """Test a mutation by auditing both original and mutated configs.
    
    Args:
        mutation: The mutation to test
        audit_func: Function that takes config text and returns status ("PASS" or "FAIL")
    
    Returns:
        MutationResult with actual outcomes
    """
    # Audit original config
    original_result = audit_func(mutation.original_config)
    actual_status_before = original_result.get("status", "UNKNOWN")
    
    # Audit mutated config
    mutated_result = audit_func(mutation.mutated_config)
    actual_status_after = mutated_result.get("status", "UNKNOWN")
    
    # Determine outcome
    expected_before = mutation.expected_status_before
    expected_after = mutation.expected_status_after
    
    if actual_status_before == expected_before and actual_status_after == expected_after:
        outcome = MutationOutcome.EXPECTED
        passed = True
    elif mutation.mutation_type == MutationType.SAFE_TO_UNSAFE:
        if actual_status_before == "PASS" and actual_status_after == "PASS":
            outcome = MutationOutcome.MISSED
            passed = False
        elif actual_status_before == "FAIL" and actual_status_after == "FAIL":
            outcome = MutationOutcome.UNEXPECTED_FAILURE
            passed = False
        elif actual_status_before == "FAIL" and actual_status_after == "PASS":
            outcome = MutationOutcome.UNEXPECTED_PASS
            passed = False
        else:
            outcome = MutationOutcome.EXPECTED
            passed = True
    elif mutation.mutation_type == MutationType.UNSAFE_TO_SAFE:
        if actual_status_before == "FAIL" and actual_status_after == "FAIL":
            outcome = MutationOutcome.MISSED
            passed = False
        elif actual_status_before == "PASS" and actual_status_after == "PASS":
            outcome = MutationOutcome.UNEXPECTED_PASS
            passed = False
        elif actual_status_before == "PASS" and actual_status_after == "FAIL":
            outcome = MutationOutcome.UNEXPECTED_FAILURE
            passed = False
        else:
            outcome = MutationOutcome.EXPECTED
            passed = True
    else:
        outcome = MutationOutcome.EXPECTED
        passed = True
    
    return MutationResult(
        mutation=mutation,
        actual_status_before=actual_status_before,
        actual_status_after=actual_status_after,
        outcome=outcome,
        passed=passed,
    )


def run_mutation_lab(
    mutations: list[Mutation],
    audit_func: callable,
    fixture_id: str,
) -> MutationLabReport:
    """Run mutation quality lab on a set of mutations.
    
    Args:
        mutations: List of mutations to test
        audit_func: Function that takes config and returns status
        fixture_id: Identifier for the fixture being tested
    
    Returns:
        MutationLabReport with aggregate results
    """
    from datetime import datetime, timezone
    import secrets
    
    results: list[MutationResult] = []
    control_coverage: dict[str, int] = {}
    
    for mutation in mutations:
        result = evaluate_mutation(mutation, audit_func)
        results.append(result)
        
        # Track coverage
        control_coverage[mutation.control_id] = control_coverage.get(mutation.control_id, 0) + 1
    
    # Count outcomes
    expected_count = sum(1 for r in results if r.outcome == MutationOutcome.EXPECTED)
    missed_count = sum(1 for r in results if r.outcome == MutationOutcome.MISSED)
    unexpected_failure_count = sum(1 for r in results if r.outcome == MutationOutcome.UNEXPECTED_FAILURE)
    unexpected_pass_count = sum(1 for r in results if r.outcome == MutationOutcome.UNEXPECTED_PASS)
    
    limitations = (
        "Mutation testing depends on audit function accuracy",
        "Only tests mutations that are explicitly defined",
        "Does not discover new mutations automatically",
        "May miss edge cases not covered by test mutations",
        "Success rate depends on mutation quality, not just rule quality",
    )
    
    lab_id = f"lab_{secrets.token_hex(8)}"
    
    return MutationLabReport(
        lab_id=lab_id,
        fixture_id=fixture_id,
        mutations_tested=len(results),
        expected_count=expected_count,
        missed_count=missed_count,
        unexpected_failure_count=unexpected_failure_count,
        unexpected_pass_count=unexpected_pass_count,
        control_coverage=control_coverage,
        results=tuple(results),
        generated_at=datetime.now(timezone.utc).isoformat(),
        limitations=limitations,
    )


def get_missed_mutations(report: MutationLabReport) -> tuple[MutationResult, ...]:
    """Get all missed mutations from a report."""
    return tuple(r for r in report.results if r.outcome == MutationOutcome.MISSED)


def get_unexpected_failures(report: MutationLabReport) -> tuple[MutationResult, ...]:
    """Get all unexpected failures from a report."""
    return tuple(r for r in report.results if r.outcome == MutationOutcome.UNEXPECTED_FAILURE)


def get_control_quality_metrics(report: MutationLabReport) -> dict[str, dict[str, Any]]:
    """Get quality metrics per control."""
    metrics: dict[str, dict[str, Any]] = {}
    
    for result in report.results:
        control_id = result.mutation.control_id
        if control_id not in metrics:
            metrics[control_id] = {
                "total": 0,
                "expected": 0,
                "missed": 0,
                "unexpected_failure": 0,
                "unexpected_pass": 0,
            }
        
        metrics[control_id]["total"] += 1
        metrics[control_id]["expected"] += 1 if result.outcome == MutationOutcome.EXPECTED else 0
        metrics[control_id]["missed"] += 1 if result.outcome == MutationOutcome.MISSED else 0
        metrics[control_id]["unexpected_failure"] += 1 if result.outcome == MutationOutcome.UNEXPECTED_FAILURE else 0
        metrics[control_id]["unexpected_pass"] += 1 if result.outcome == MutationOutcome.UNEXPECTED_PASS else 0
    
    # Calculate success rate per control
    for control_id, data in metrics.items():
        if data["total"] > 0:
            data["success_rate"] = data["expected"] / data["total"]
        else:
            data["success_rate"] = 0.0
    
    return metrics
