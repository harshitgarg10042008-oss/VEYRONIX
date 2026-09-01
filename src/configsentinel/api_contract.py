"""API contract-to-observation conformance analysis.

This module compares declared API contracts (OpenAPI/GraphQL) with safe
runtime observations to identify contract drift and missing security declarations.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class ConformanceStatus(str, Enum):
    """Status of contract conformance check."""
    CONFORMANT = "CONFORMANT"
    DRIFTED = "DRIFTED"
    MISSING_DECLARATION = "MISSING_DECLARATION"
    UNKNOWN = "UNKNOWN"


class SecuritySchemeType(str, Enum):
    """Types of security schemes."""
    API_KEY = "API_KEY"
    HTTP = "HTTP"
    OAUTH2 = "OAUTH2"
    OPENID_CONNECT = "OPENID_CONNECT"
    NONE = "NONE"


@dataclass(frozen=True)
class SecurityScheme:
    """Declared security scheme in contract."""
    scheme_id: str
    scheme_type: SecuritySchemeType
    location: str  # "header", "query", "cookie"
    name: str
    description: str | None = None


@dataclass(frozen=True)
class EndpointDeclaration:
    """Declared endpoint in contract."""
    path: str
    method: str
    operation_id: str | None = None
    security_schemes: tuple[str, ...] = ()  # scheme_ids
    sensitive_fields: tuple[str, ...] = ()
    requires_auth: bool = False


@dataclass(frozen=True)
class EndpointObservation:
    """Observed endpoint from runtime."""
    path: str
    method: str
    observed_security: str | None = None  # "Bearer", "Basic", etc.
    observed_headers: tuple[str, ...] = ()
    response_status_range: str = "2XX"  # "2XX", "4XX", "5XX"


@dataclass(frozen=True)
class ConformanceFinding:
    """Finding from contract conformance analysis."""
    finding_id: str
    endpoint_path: str
    endpoint_method: str
    conformance_status: ConformanceStatus
    description: str
    declared_scheme: str | None = None
    observed_scheme: str | None = None
    severity: str = "MEDIUM"


@dataclass(frozen=True)
class ContractConformanceReport:
    """Complete contract conformance analysis report."""
    report_id: str
    contract_id: str
    observation_id: str
    analyzed_at: str
    findings: tuple[ConformanceFinding, ...]
    total_endpoints: int
    conformant_count: int
    drifted_count: int
    missing_declaration_count: int
    limitations: tuple[str, ...]

    @property
    def conformance_rate(self) -> float:
        """Calculate conformance rate."""
        if self.total_endpoints == 0:
            return 0.0
        return self.conformant_count / self.total_endpoints


def analyze_endpoint_security_conformance(
    declared: EndpointDeclaration,
    observed: EndpointObservation,
) -> ConformanceFinding:
    """Analyze security conformance for a single endpoint.
    
    Args:
        declared: Declared endpoint from contract
        observed: Observed endpoint from runtime
    
    Returns:
        ConformanceFinding with analysis result
    """
    import secrets
    
    finding_id = f"cf_{secrets.token_hex(8)}"
    
    # Check if auth is declared
    if declared.requires_auth:
        if observed.observed_security is None:
            return ConformanceFinding(
                finding_id=finding_id,
                endpoint_path=declared.path,
                endpoint_method=declared.method,
                conformance_status=ConformanceStatus.DRIFTED,
                description="Endpoint requires auth but no security observed",
                declared_scheme="required",
                observed_scheme=None,
                severity="HIGH",
            )
        return ConformanceFinding(
            finding_id=finding_id,
            endpoint_path=declared.path,
            endpoint_method=declared.method,
            conformance_status=ConformanceStatus.CONFORMANT,
            description="Auth requirement matches observation",
            declared_scheme="required",
            observed_scheme=observed.observed_security,
            severity="LOW",
        )
    else:
        if observed.observed_security is not None:
            return ConformanceFinding(
                finding_id=finding_id,
                endpoint_path=declared.path,
                endpoint_method=declared.method,
                conformance_status=ConformanceStatus.MISSING_DECLARATION,
                description="Endpoint uses auth but not declared in contract",
                declared_scheme=None,
                observed_scheme=observed.observed_security,
                severity="MEDIUM",
            )
        return ConformanceFinding(
            finding_id=finding_id,
            endpoint_path=declared.path,
            endpoint_method=declared.method,
            conformance_status=ConformanceStatus.CONFORMANT,
            description="No auth required and none observed",
            declared_scheme=None,
            observed_scheme=None,
            severity="LOW",
        )


def analyze_contract_conformance(
    contract_endpoints: list[EndpointDeclaration],
    observed_endpoints: list[EndpointObservation],
    contract_id: str,
    observation_id: str,
) -> ContractConformanceReport:
    """Analyze conformance between contract and observations.
    
    Args:
        contract_endpoints: Declared endpoints from contract
        observed_endpoints: Observed endpoints from runtime
        contract_id: Identifier for the contract
        observation_id: Identifier for the observation
    
    Returns:
        ContractConformanceReport with aggregate findings
    """
    from datetime import datetime, timezone
    import secrets
    
    findings: list[ConformanceFinding] = []
    
    # Create lookup for observed endpoints
    observed_lookup = {
        (obs.path.lower(), obs.method.upper()): obs
        for obs in observed_endpoints
    }
    
    for declared in contract_endpoints:
        key = (declared.path.lower(), declared.method.upper())
        observed = observed_lookup.get(key)
        
        if observed is None:
            # Endpoint declared but not observed
            findings.append(ConformanceFinding(
                finding_id=f"cf_{secrets.token_hex(8)}",
                endpoint_path=declared.path,
                endpoint_method=declared.method,
                conformance_status=ConformanceStatus.UNKNOWN,
                description="Endpoint declared but not observed",
                severity="LOW",
            ))
        else:
            # Analyze conformance
            finding = analyze_endpoint_security_conformance(declared, observed)
            findings.append(finding)
    
    # Check for observed but not declared endpoints
    declared_paths = {
        (decl.path.lower(), decl.method.upper())
        for decl in contract_endpoints
    }
    for observed in observed_endpoints:
        key = (observed.path.lower(), observed.method.upper())
        if key not in declared_paths:
            findings.append(ConformanceFinding(
                finding_id=f"cf_{secrets.token_hex(8)}",
                endpoint_path=observed.path,
                endpoint_method=observed.method,
                conformance_status=ConformanceStatus.MISSING_DECLARATION,
                description="Endpoint observed but not declared in contract",
                severity="MEDIUM",
            ))
    
    # Count findings by status
    conformant_count = sum(
        1 for f in findings
        if f.conformance_status == ConformanceStatus.CONFORMANT
    )
    drifted_count = sum(
        1 for f in findings
        if f.conformance_status == ConformanceStatus.DRIFTED
    )
    missing_declaration_count = sum(
        1 for f in findings
        if f.conformance_status == ConformanceStatus.MISSING_DECLARATION
    )
    
    limitations = (
        "Analysis based on declared vs observed endpoints only",
        "Does not validate request/response body schemas",
        "Does not check parameter types or formats",
        "Security scheme comparison is basic (presence/absence)",
        "Does not validate OAuth2 scopes or permissions",
    )
    
    report_id = f"report_{secrets.token_hex(8)}"
    
    return ContractConformanceReport(
        report_id=report_id,
        contract_id=contract_id,
        observation_id=observation_id,
        analyzed_at=datetime.now(timezone.utc).isoformat(),
        findings=tuple(findings),
        total_endpoints=len(findings),
        conformant_count=conformant_count,
        drifted_count=drifted_count,
        missing_declaration_count=missing_declaration_count,
        limitations=limitations,
    )


def get_security_drift_findings(report: ContractConformanceReport) -> tuple[ConformanceFinding, ...]:
    """Get all security drift findings from report."""
    return tuple(
        f for f in report.findings
        if f.conformance_status == ConformanceStatus.DRIFTED
    )


def get_missing_declaration_findings(report: ContractConformanceReport) -> tuple[ConformanceFinding, ...]:
    """Get all missing declaration findings from report."""
    return tuple(
        f for f in report.findings
        if f.conformance_status == ConformanceStatus.MISSING_DECLARATION
    )
