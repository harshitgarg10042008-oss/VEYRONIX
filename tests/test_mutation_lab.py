"""Tests for control mutation quality lab."""

import pytest

from configsentinel.mutation_lab import (
    Mutation,
    MutationLabReport,
    MutationOutcome,
    MutationResult,
    MutationType,
    evaluate_mutation,
    generate_safe_to_unsafe_mutation,
    generate_unsafe_to_safe_mutation,
    get_control_quality_metrics,
    get_missed_mutations,
    get_unexpected_failures,
    run_mutation_lab,
)


def mock_audit_pass(config: str) -> dict:
    """Mock audit function that always passes."""
    return {"status": "PASS"}


def mock_audit_fail(config: str) -> dict:
    """Mock audit function that always fails."""
    return {"status": "FAIL"}


def mock_audit_ssh(config: str) -> dict:
    """Mock audit function that checks for SSH configuration."""
    if "ssh version 2" in config.lower():
        return {"status": "PASS"}
    return {"status": "FAIL"}


def test_generate_safe_to_unsafe_mutation():
    """Test generation of safe-to-unsafe mutation."""
    mutation = generate_safe_to_unsafe_mutation(
        control_id="NET-MGMT-SSH-001",
        original_config="ssh version 2\n",
        mutation_description="Remove SSH version 2",
        mutated_config="ssh version 1\n",
    )
    
    assert mutation.mutation_id.startswith("mut_")
    assert mutation.control_id == "NET-MGMT-SSH-001"
    assert mutation.mutation_type == MutationType.SAFE_TO_UNSAFE
    assert mutation.expected_status_before == "PASS"
    assert mutation.expected_status_after == "FAIL"


def test_generate_unsafe_to_safe_mutation():
    """Test generation of unsafe-to-safe mutation."""
    mutation = generate_unsafe_to_safe_mutation(
        control_id="NET-MGMT-SSH-001",
        original_config="ssh version 1\n",
        mutation_description="Enable SSH version 2",
        mutated_config="ssh version 2\n",
    )
    
    assert mutation.mutation_id.startswith("mut_")
    assert mutation.control_id == "NET-MGMT-SSH-001"
    assert mutation.mutation_type == MutationType.UNSAFE_TO_SAFE
    assert mutation.expected_status_before == "FAIL"
    assert mutation.expected_status_after == "PASS"


def test_mutation_immutable():
    """Test that Mutation is immutable."""
    mutation = generate_safe_to_unsafe_mutation(
        control_id="NET-MGMT-SSH-001",
        original_config="ssh version 2\n",
        mutation_description="Test",
        mutated_config="ssh version 1\n",
    )
    
    with pytest.raises(Exception):  # FrozenInstanceError
        mutation.control_id = "NET-MGMT-SSH-002"


def test_mutation_result_immutable():
    """Test that MutationResult is immutable."""
    mutation = generate_safe_to_unsafe_mutation(
        control_id="NET-MGMT-SSH-001",
        original_config="ssh version 2\n",
        mutation_description="Test",
        mutated_config="ssh version 1\n",
    )
    
    result = evaluate_mutation(mutation, mock_audit_ssh)
    
    with pytest.raises(Exception):  # FrozenInstanceError
        result.outcome = MutationOutcome.MISSED


def test_mutation_lab_report_immutable():
    """Test that MutationLabReport is immutable."""
    mutation = generate_safe_to_unsafe_mutation(
        control_id="NET-MGMT-SSH-001",
        original_config="ssh version 2\n",
        mutation_description="Test",
        mutated_config="ssh version 1\n",
    )
    
    report = run_mutation_lab([mutation], mock_audit_ssh, "fixture-001")
    
    with pytest.raises(Exception):  # FrozenInstanceError
        report.mutations_tested = 10


def test_mutation_expected_outcome():
    """Test mutation with expected outcome."""
    mutation = generate_safe_to_unsafe_mutation(
        control_id="NET-MGMT-SSH-001",
        original_config="ssh version 2\n",
        mutation_description="Remove SSH version 2",
        mutated_config="ssh version 1\n",
    )
    
    result = evaluate_mutation(mutation, mock_audit_ssh)
    
    assert result.actual_status_before == "PASS"
    assert result.actual_status_after == "FAIL"
    assert result.outcome == MutationOutcome.EXPECTED
    assert result.passed is True


def test_mutation_missed():
    """Test mutation that is missed (control doesn't detect change)."""
    mutation = generate_safe_to_unsafe_mutation(
        control_id="NET-MGMT-SSH-001",
        original_config="ssh version 2\n",
        mutation_description="Remove SSH version 2",
        mutated_config="ssh version 1\n",
    )
    
    # Mock audit that always passes (misses the mutation)
    result = evaluate_mutation(mutation, mock_audit_pass)
    
    assert result.actual_status_before == "PASS"
    assert result.actual_status_after == "PASS"
    assert result.outcome == MutationOutcome.MISSED
    assert result.passed is False


def test_mutation_unexpected_failure():
    """Test mutation with unexpected failure."""
    mutation = generate_safe_to_unsafe_mutation(
        control_id="NET-MGMT-SSH-001",
        original_config="ssh version 2\n",
        mutation_description="Remove SSH version 2",
        mutated_config="ssh version 1\n",
    )
    
    # Mock audit that always fails (original config fails unexpectedly)
    result = evaluate_mutation(mutation, mock_audit_fail)
    
    assert result.actual_status_before == "FAIL"
    assert result.actual_status_after == "FAIL"
    assert result.outcome == MutationOutcome.UNEXPECTED_FAILURE
    assert result.passed is False


def test_unsafe_to_safe_expected():
    """Test unsafe-to-safe mutation with expected outcome."""
    mutation = generate_unsafe_to_safe_mutation(
        control_id="NET-MGMT-SSH-001",
        original_config="ssh version 1\n",
        mutation_description="Enable SSH version 2",
        mutated_config="ssh version 2\n",
    )
    
    result = evaluate_mutation(mutation, mock_audit_ssh)
    
    assert result.actual_status_before == "FAIL"
    assert result.actual_status_after == "PASS"
    assert result.outcome == MutationOutcome.EXPECTED
    assert result.passed is True


def test_run_mutation_lab():
    """Test running mutation lab with multiple mutations."""
    mutations = [
        generate_safe_to_unsafe_mutation(
            control_id="NET-MGMT-SSH-001",
            original_config="ssh version 2\n",
            mutation_description="Remove SSH version 2",
            mutated_config="ssh version 1\n",
        ),
        generate_unsafe_to_safe_mutation(
            control_id="NET-MGMT-SSH-001",
            original_config="ssh version 1\n",
            mutation_description="Enable SSH version 2",
            mutated_config="ssh version 2\n",
        ),
    ]
    
    report = run_mutation_lab(mutations, mock_audit_ssh, "fixture-001")
    
    assert report.lab_id.startswith("lab_")
    assert report.fixture_id == "fixture-001"
    assert report.mutations_tested == 2
    assert report.expected_count == 2
    assert report.missed_count == 0
    assert report.success_rate == 1.0
    assert len(report.results) == 2


def test_run_mutation_lab_with_missed():
    """Test mutation lab with missed mutations."""
    mutations = [
        generate_safe_to_unsafe_mutation(
            control_id="NET-MGMT-SSH-001",
            original_config="ssh version 2\n",
            mutation_description="Remove SSH version 2",
            mutated_config="ssh version 1\n",
        ),
    ]
    
    report = run_mutation_lab(mutations, mock_audit_pass, "fixture-001")
    
    assert report.mutations_tested == 1
    assert report.expected_count == 0
    assert report.missed_count == 1
    assert report.success_rate == 0.0


def test_get_missed_mutations():
    """Test filtering missed mutations."""
    mutations = [
        generate_safe_to_unsafe_mutation(
            control_id="NET-MGMT-SSH-001",
            original_config="ssh version 2\n",
            mutation_description="Remove SSH version 2",
            mutated_config="ssh version 1\n",
        ),
    ]
    
    report = run_mutation_lab(mutations, mock_audit_pass, "fixture-001")
    
    missed = get_missed_mutations(report)
    
    assert len(missed) == 1
    assert missed[0].outcome == MutationOutcome.MISSED


def test_get_unexpected_failures():
    """Test filtering unexpected failures."""
    mutations = [
        generate_safe_to_unsafe_mutation(
            control_id="NET-MGMT-SSH-001",
            original_config="ssh version 2\n",
            mutation_description="Remove SSH version 2",
            mutated_config="ssh version 1\n",
        ),
    ]
    
    report = run_mutation_lab(mutations, mock_audit_fail, "fixture-001")
    
    failures = get_unexpected_failures(report)
    
    assert len(failures) == 1
    assert failures[0].outcome == MutationOutcome.UNEXPECTED_FAILURE


def test_control_coverage():
    """Test that control coverage is tracked."""
    mutations = [
        generate_safe_to_unsafe_mutation(
            control_id="NET-MGMT-SSH-001",
            original_config="ssh version 2\n",
            mutation_description="Remove SSH version 2",
            mutated_config="ssh version 1\n",
        ),
        generate_safe_to_unsafe_mutation(
            control_id="NET-MGMT-SSH-001",
            original_config="ssh version 2\n",
            mutation_description="Remove SSH version 2",
            mutated_config="ssh version 1\n",
        ),
        generate_safe_to_unsafe_mutation(
            control_id="NET-MGMT-TELNET-001",
            original_config="no telnet\n",
            mutation_description="Enable telnet",
            mutated_config="telnet\n",
        ),
    ]
    
    report = run_mutation_lab(mutations, mock_audit_ssh, "fixture-001")
    
    assert report.control_coverage["NET-MGMT-SSH-001"] == 2
    assert report.control_coverage["NET-MGMT-TELNET-001"] == 1


def test_get_control_quality_metrics():
    """Test per-control quality metrics."""
    mutations = [
        generate_safe_to_unsafe_mutation(
            control_id="NET-MGMT-SSH-001",
            original_config="ssh version 2\n",
            mutation_description="Remove SSH version 2",
            mutated_config="ssh version 1\n",
        ),
        generate_safe_to_unsafe_mutation(
            control_id="NET-MGMT-SSH-001",
            original_config="ssh version 2\n",
            mutation_description="Remove SSH version 2",
            mutated_config="ssh version 1\n",
        ),
    ]
    
    report = run_mutation_lab(mutations, mock_audit_ssh, "fixture-001")
    
    metrics = get_control_quality_metrics(report)
    
    assert "NET-MGMT-SSH-001" in metrics
    assert metrics["NET-MGMT-SSH-001"]["total"] == 2
    assert metrics["NET-MGMT-SSH-001"]["expected"] == 2
    assert metrics["NET-MGMT-SSH-001"]["missed"] == 0
    assert metrics["NET-MGMT-SSH-001"]["success_rate"] == 1.0


def test_lab_report_limitations():
    """Test that lab report includes limitations."""
    mutation = generate_safe_to_unsafe_mutation(
        control_id="NET-MGMT-SSH-001",
        original_config="ssh version 2\n",
        mutation_description="Remove SSH version 2",
        mutated_config="ssh version 1\n",
    )
    
    report = run_mutation_lab([mutation], mock_audit_ssh, "fixture-001")
    
    assert len(report.limitations) > 0
    assert "audit function" in report.limitations[0].lower()


def test_empty_mutation_lab():
    """Test mutation lab with no mutations."""
    report = run_mutation_lab([], mock_audit_ssh, "fixture-001")
    
    assert report.mutations_tested == 0
    assert report.expected_count == 0
    assert report.missed_count == 0
    assert report.success_rate == 0.0
