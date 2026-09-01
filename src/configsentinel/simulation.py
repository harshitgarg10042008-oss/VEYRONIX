"""Pre-change blast-radius simulation for safe remediation review.

This module analyzes proposed changes and predicts impact on controls,
assets, trust boundaries, and evidence without applying any changes.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class ImpactLabel(str, Enum):
    """Confidence level of impact prediction."""
    DIRECT = "DIRECT"  # Directly affected by the change
    DEPENDENT = "DEPENDENT"  # Depends on changed component
    POSSIBLE = "POSSIBLE"  # May be affected (uncertain)
    UNKNOWN = "UNKNOWN"  # Cannot determine impact


@dataclass(frozen=True)
class Impact:
    """Single impact prediction."""
    target_id: str  # Control ID, asset ID, or service ID
    target_type: str  # "control", "asset", "service", "trust_boundary"
    impact_label: ImpactLabel
    rationale: str
    evidence_required: bool  # Whether post-change verification is required


@dataclass(frozen=True)
class SimulationResult:
    """Complete blast-radius simulation result."""
    simulation_id: str
    proposed_change_id: str
    proposed_at: str
    impacts: tuple[Impact, ...]
    total_affected: int
    direct_impact_count: int
    dependent_impact_count: int
    possible_impact_count: int
    unknown_impact_count: int
    required_post_change_checks: tuple[str, ...]
    limitations: tuple[str, ...]

    @property
    def high_confidence_impacts(self) -> tuple[Impact, ...]:
        """Return impacts with high confidence (DIRECT, DEPENDENT)."""
        return tuple(
            i for i in self.impacts
            if i.impact_label in {ImpactLabel.DIRECT, ImpactLabel.DEPENDENT}
        )


@dataclass(frozen=True)
class ProposedChange:
    """Structured representation of a proposed change."""
    change_id: str
    change_type: str  # "remediation", "config_update", "service_change"
    target_resource_id: str
    description: str
    affected_controls: tuple[str, ...]
    affected_assets: tuple[str, ...] = ()
    metadata: dict[str, Any] | None = None


def simulate_blast_radius(
    proposed_change: ProposedChange,
    *,
    control_dependencies: dict[str, tuple[str, ...]] | None = None,
    asset_dependencies: dict[str, tuple[str, ...]] | None = None,
) -> SimulationResult:
    """Simulate blast radius for a proposed change.
    
    Args:
        proposed_change: The proposed change to analyze
        control_dependencies: Mapping of control ID to dependent control IDs
        asset_dependencies: Mapping of asset ID to dependent asset IDs
    
    Returns:
        SimulationResult with impact predictions
    """
    from datetime import datetime, timezone
    import secrets
    
    control_deps = control_dependencies or {}
    asset_deps = asset_dependencies or {}
    
    impacts: list[Impact] = []
    
    # Direct impacts on controls
    for control_id in proposed_change.affected_controls:
        impacts.append(Impact(
            target_id=control_id,
            target_type="control",
            impact_label=ImpactLabel.DIRECT,
            rationale=f"Directly targeted by proposed change {proposed_change.change_id}",
            evidence_required=True,
        ))
        
        # Dependent controls
        for dep_id in control_deps.get(control_id, ()):
            impacts.append(Impact(
                target_id=dep_id,
                target_type="control",
                impact_label=ImpactLabel.DEPENDENT,
                rationale=f"Depends on control {control_id} which is directly affected",
                evidence_required=True,
            ))
    
    # Direct impacts on assets
    for asset_id in proposed_change.affected_assets:
        impacts.append(Impact(
            target_id=asset_id,
            target_type="asset",
            impact_label=ImpactLabel.DIRECT,
            rationale=f"Directly targeted by proposed change {proposed_change.change_id}",
            evidence_required=True,
        ))
        
        # Dependent assets
        for dep_id in asset_deps.get(asset_id, ()):
            impacts.append(Impact(
                target_id=dep_id,
                target_type="asset",
                impact_label=ImpactLabel.DEPENDENT,
                rationale=f"Depends on asset {asset_id} which is directly affected",
                evidence_required=True,
            ))
    
    # Count impacts by label
    direct_count = sum(1 for i in impacts if i.impact_label == ImpactLabel.DIRECT)
    dependent_count = sum(1 for i in impacts if i.impact_label == ImpactLabel.DEPENDENT)
    possible_count = sum(1 for i in impacts if i.impact_label == ImpactLabel.POSSIBLE)
    unknown_count = sum(1 for i in impacts if i.impact_label == ImpactLabel.UNKNOWN)
    
    # Required post-change checks
    required_checks = tuple(
        i.target_id for i in impacts if i.evidence_required
    )
    
    # Limitations
    limitations = (
        "Simulation based on static dependency analysis only",
        "Runtime dependencies not considered",
        "Cross-organization dependencies not analyzed",
        "Impact predictions are estimates, not guarantees",
        "Never apply changes without independent review and testing",
    )
    
    simulation_id = f"sim_{secrets.token_hex(8)}"
    
    return SimulationResult(
        simulation_id=simulation_id,
        proposed_change_id=proposed_change.change_id,
        proposed_at=datetime.now(timezone.utc).isoformat(),
        impacts=tuple(impacts),
        total_affected=len(impacts),
        direct_impact_count=direct_count,
        dependent_impact_count=dependent_count,
        possible_impact_count=possible_count,
        unknown_impact_count=unknown_count,
        required_post_change_checks=required_checks,
        limitations=limitations,
    )


def simulate_remediation_blast_radius(
    remediation_bundle_id: str,
    affected_controls: tuple[str, ...],
    *,
    control_dependencies: dict[str, tuple[str, ...]] | None = None,
) -> SimulationResult:
    """Convenience function for remediation-specific simulation."""
    proposed_change = ProposedChange(
        change_id=remediation_bundle_id,
        change_type="remediation",
        target_resource_id="multiple",
        description=f"Remediation bundle {remediation_bundle_id}",
        affected_controls=affected_controls,
    )
    
    return simulate_blast_radius(
        proposed_change,
        control_dependencies=control_dependencies,
    )
