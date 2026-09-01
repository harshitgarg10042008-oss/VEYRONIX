"""Tests for pre-change blast-radius simulation."""

import pytest

from configsentinel.simulation import (
    Impact,
    ImpactLabel,
    ProposedChange,
    SimulationResult,
    simulate_blast_radius,
    simulate_remediation_blast_radius,
)


def test_simulate_blast_radius_basic():
    """Test basic blast-radius simulation."""
    proposed_change = ProposedChange(
        change_id="change-001",
        change_type="remediation",
        target_resource_id="router-001",
        description="Enable SSH version 2",
        affected_controls=("NET-MGMT-SSH-001",),
    )
    
    result = simulate_blast_radius(proposed_change)
    
    assert result.simulation_id.startswith("sim_")
    assert result.proposed_change_id == "change-001"
    assert result.total_affected == 1
    assert result.direct_impact_count == 1
    assert result.dependent_impact_count == 0
    assert len(result.impacts) == 1
    assert result.impacts[0].target_id == "NET-MGMT-SSH-001"
    assert result.impacts[0].impact_label == ImpactLabel.DIRECT
    assert result.impacts[0].evidence_required is True
    assert len(result.limitations) > 0


def test_simulate_blast_radius_with_dependencies():
    """Test simulation with control dependencies."""
    proposed_change = ProposedChange(
        change_id="change-002",
        change_type="remediation",
        target_resource_id="router-001",
        description="Disable Telnet",
        affected_controls=("NET-MGMT-TELNET-001",),
    )
    
    control_dependencies = {
        "NET-MGMT-TELNET-001": ("NET-MGMT-SSH-001", "NET-AUTH-AAA-001"),
    }
    
    result = simulate_blast_radius(
        proposed_change,
        control_dependencies=control_dependencies,
    )
    
    assert result.total_affected == 3
    assert result.direct_impact_count == 1
    assert result.dependent_impact_count == 2
    assert len(result.impacts) == 3
    
    # Check direct impact
    direct_impacts = [i for i in result.impacts if i.impact_label == ImpactLabel.DIRECT]
    assert len(direct_impacts) == 1
    assert direct_impacts[0].target_id == "NET-MGMT-TELNET-001"
    
    # Check dependent impacts
    dependent_impacts = [i for i in result.impacts if i.impact_label == ImpactLabel.DEPENDENT]
    assert len(dependent_impacts) == 2
    dependent_ids = {i.target_id for i in dependent_impacts}
    assert dependent_ids == {"NET-MGMT-SSH-001", "NET-AUTH-AAA-001"}


def test_simulate_blast_radius_with_assets():
    """Test simulation with asset dependencies."""
    proposed_change = ProposedChange(
        change_id="change-003",
        change_type="config_update",
        target_resource_id="firewall-001",
        description="Update firewall rules",
        affected_controls=(),
        affected_assets=("firewall-001",),
    )
    
    asset_dependencies = {
        "firewall-001": ("dmz-server-001", "internal-server-001"),
    }
    
    result = simulate_blast_radius(
        proposed_change,
        asset_dependencies=asset_dependencies,
    )
    
    assert result.total_affected == 3
    assert result.direct_impact_count == 1
    assert result.dependent_impact_count == 2
    
    # Check asset impacts
    asset_impacts = [i for i in result.impacts if i.target_type == "asset"]
    assert len(asset_impacts) == 3


def test_simulate_blast_radius_multiple_controls():
    """Test simulation with multiple affected controls."""
    proposed_change = ProposedChange(
        change_id="change-004",
        change_type="remediation",
        target_resource_id="router-001",
        description="Multiple remediation steps",
        affected_controls=("NET-MGMT-SSH-001", "NET-MGMT-HTTP-001", "NET-MGMT-TELNET-001"),
    )
    
    result = simulate_blast_radius(proposed_change)
    
    assert result.total_affected == 3
    assert result.direct_impact_count == 3
    assert len(result.required_post_change_checks) == 3


def test_high_confidence_impacts():
    """Test filtering high-confidence impacts."""
    proposed_change = ProposedChange(
        change_id="change-005",
        change_type="remediation",
        target_resource_id="router-001",
        description="Test change",
        affected_controls=("NET-MGMT-SSH-001",),
    )
    
    control_dependencies = {
        "NET-MGMT-SSH-001": ("NET-MGMT-TELNET-001",),
    }
    
    result = simulate_blast_radius(
        proposed_change,
        control_dependencies=control_dependencies,
    )
    
    high_confidence = result.high_confidence_impacts
    assert len(high_confidence) == 2  # DIRECT + DEPENDENT
    
    impact_labels = {i.impact_label for i in high_confidence}
    assert impact_labels == {ImpactLabel.DIRECT, ImpactLabel.DEPENDENT}


def test_required_post_change_checks():
    """Test that required post-change checks are identified."""
    proposed_change = ProposedChange(
        change_id="change-006",
        change_type="remediation",
        target_resource_id="router-001",
        description="Test change",
        affected_controls=("NET-MGMT-SSH-001", "NET-MGMT-HTTP-001"),
    )
    
    result = simulate_blast_radius(proposed_change)
    
    assert len(result.required_post_change_checks) == 2
    assert "NET-MGMT-SSH-001" in result.required_post_change_checks
    assert "NET-MGMT-HTTP-001" in result.required_post_change_checks


def test_simulate_remediation_blast_radius_convenience():
    """Test convenience function for remediation simulation."""
    result = simulate_remediation_blast_radius(
        remediation_bundle_id="rem_xyz123",
        affected_controls=("NET-MGMT-SSH-001",),
    )
    
    assert result.proposed_change_id == "rem_xyz123"
    assert result.total_affected == 1
    assert result.direct_impact_count == 1


def test_simulation_limitations():
    """Test that simulation includes limitations."""
    proposed_change = ProposedChange(
        change_id="change-007",
        change_type="remediation",
        target_resource_id="router-001",
        description="Test change",
        affected_controls=("NET-MGMT-SSH-001",),
    )
    
    result = simulate_blast_radius(proposed_change)
    
    assert len(result.limitations) > 0
    assert "static dependency analysis" in result.limitations[0].lower()
    assert "never apply changes" in " ".join(result.limitations).lower()


def test_proposed_change_metadata():
    """Test proposed change with metadata."""
    proposed_change = ProposedChange(
        change_id="change-008",
        change_type="config_update",
        target_resource_id="router-001",
        description="Test change",
        affected_controls=(),
        metadata={"priority": "high", "risk_level": "medium"},
    )
    
    result = simulate_blast_radius(proposed_change)
    
    assert result.proposed_change_id == "change-008"


def test_empty_affected_controls():
    """Test simulation with no affected controls."""
    proposed_change = ProposedChange(
        change_id="change-009",
        change_type="config_update",
        target_resource_id="router-001",
        description="Test change",
        affected_controls=(),
    )
    
    result = simulate_blast_radius(proposed_change)
    
    assert result.total_affected == 0
    assert result.direct_impact_count == 0
    assert len(result.impacts) == 0


def test_complex_dependency_chain():
    """Test simulation with complex dependency chain."""
    proposed_change = ProposedChange(
        change_id="change-010",
        change_type="remediation",
        target_resource_id="router-001",
        description="Test change",
        affected_controls=("NET-MGMT-SSH-001",),
    )
    
    # A -> B -> C chain
    control_dependencies = {
        "NET-MGMT-SSH-001": ("NET-MGMT-TELNET-001",),
        "NET-MGMT-TELNET-001": ("NET-AUTH-AAA-001",),
    }
    
    result = simulate_blast_radius(
        proposed_change,
        control_dependencies=control_dependencies,
    )
    
    # Should only include direct dependencies (one level)
    assert result.total_affected == 2  # SSH-001 + TELNET-001
    assert result.dependent_impact_count == 1


def test_impact_immutable():
    """Test that Impact is immutable."""
    impact = Impact(
        target_id="control-001",
        target_type="control",
        impact_label=ImpactLabel.DIRECT,
        rationale="Test",
        evidence_required=True,
    )
    
    # Should be frozen
    with pytest.raises(Exception):  # FrozenInstanceError
        impact.target_id = "control-002"


def test_simulation_result_immutable():
    """Test that SimulationResult is immutable."""
    proposed_change = ProposedChange(
        change_id="change-011",
        change_type="remediation",
        target_resource_id="router-001",
        description="Test",
        affected_controls=("NET-MGMT-SSH-001",),
    )
    
    result = simulate_blast_radius(proposed_change)
    
    # Should be frozen
    with pytest.raises(Exception):  # FrozenInstanceError
        result.total_affected = 10
