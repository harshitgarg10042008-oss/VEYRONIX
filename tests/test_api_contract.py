"""Tests for API contract-to-observation conformance analysis."""

import pytest

from configsentinel.api_contract import (
    ConformanceFinding,
    ConformanceStatus,
    ContractConformanceReport,
    EndpointDeclaration,
    EndpointObservation,
    SecurityScheme,
    SecuritySchemeType,
    analyze_contract_conformance,
    analyze_endpoint_security_conformance,
    get_missing_declaration_findings,
    get_security_drift_findings,
)


def test_analyze_endpoint_conformant_with_auth():
    """Test conformant endpoint with auth."""
    declared = EndpointDeclaration(
        path="/api/users",
        method="GET",
        operation_id="getUsers",
        requires_auth=True,
    )
    
    observed = EndpointObservation(
        path="/api/users",
        method="GET",
        observed_security="Bearer",
    )
    
    finding = analyze_endpoint_security_conformance(declared, observed)
    
    assert finding.conformance_status == ConformanceStatus.CONFORMANT
    assert finding.severity == "LOW"
    assert "matches observation" in finding.description.lower()


def test_analyze_endpoint_drifted_missing_auth():
    """Test drifted endpoint - requires auth but none observed."""
    declared = EndpointDeclaration(
        path="/api/users",
        method="GET",
        operation_id="getUsers",
        requires_auth=True,
    )
    
    observed = EndpointObservation(
        path="/api/users",
        method="GET",
        observed_security=None,
    )
    
    finding = analyze_endpoint_security_conformance(declared, observed)
    
    assert finding.conformance_status == ConformanceStatus.DRIFTED
    assert finding.severity == "HIGH"
    assert "requires auth but no security observed" in finding.description.lower()


def test_analyze_endpoint_missing_declaration():
    """Test endpoint uses auth but not declared."""
    declared = EndpointDeclaration(
        path="/api/users",
        method="GET",
        operation_id="getUsers",
        requires_auth=False,
    )
    
    observed = EndpointObservation(
        path="/api/users",
        method="GET",
        observed_security="Bearer",
    )
    
    finding = analyze_endpoint_security_conformance(declared, observed)
    
    assert finding.conformance_status == ConformanceStatus.MISSING_DECLARATION
    assert finding.severity == "MEDIUM"
    assert "uses auth but not declared" in finding.description.lower()


def test_analyze_endpoint_conformant_no_auth():
    """Test conformant endpoint without auth."""
    declared = EndpointDeclaration(
        path="/api/users",
        method="GET",
        operation_id="getUsers",
        requires_auth=False,
    )
    
    observed = EndpointObservation(
        path="/api/users",
        method="GET",
        observed_security=None,
    )
    
    finding = analyze_endpoint_security_conformance(declared, observed)
    
    assert finding.conformance_status == ConformanceStatus.CONFORMANT
    assert finding.severity == "LOW"
    assert "no auth required" in finding.description.lower()


def test_analyze_contract_conformance():
    """Test full contract conformance analysis."""
    contract_endpoints = [
        EndpointDeclaration(
            path="/api/users",
            method="GET",
            requires_auth=True,
        ),
        EndpointDeclaration(
            path="/api/posts",
            method="GET",
            requires_auth=False,
        ),
    ]
    
    observed_endpoints = [
        EndpointObservation(
            path="/api/users",
            method="GET",
            observed_security="Bearer",
        ),
        EndpointObservation(
            path="/api/posts",
            method="GET",
            observed_security=None,
        ),
    ]
    
    report = analyze_contract_conformance(
        contract_endpoints,
        observed_endpoints,
        "contract-001",
        "observation-001",
    )
    
    assert report.contract_id == "contract-001"
    assert report.observation_id == "observation-001"
    assert report.total_endpoints == 2
    assert report.conformant_count == 2
    assert report.drifted_count == 0
    assert report.conformance_rate == 1.0


def test_contract_with_drift():
    """Test contract with security drift."""
    contract_endpoints = [
        EndpointDeclaration(
            path="/api/users",
            method="GET",
            requires_auth=True,
        ),
    ]
    
    observed_endpoints = [
        EndpointObservation(
            path="/api/users",
            method="GET",
            observed_security=None,
        ),
    ]
    
    report = analyze_contract_conformance(
        contract_endpoints,
        observed_endpoints,
        "contract-002",
        "observation-002",
    )
    
    assert report.drifted_count == 1
    assert report.conformance_rate == 0.0


def test_contract_with_missing_declarations():
    """Test contract with missing declarations."""
    contract_endpoints = [
        EndpointDeclaration(
            path="/api/users",
            method="GET",
            requires_auth=False,
        ),
    ]
    
    observed_endpoints = [
        EndpointObservation(
            path="/api/users",
            method="GET",
            observed_security="Bearer",
        ),
    ]
    
    report = analyze_contract_conformance(
        contract_endpoints,
        observed_endpoints,
        "contract-003",
        "observation-003",
    )
    
    assert report.missing_declaration_count == 1


def test_endpoint_declared_not_observed():
    """Test endpoint declared but not observed."""
    contract_endpoints = [
        EndpointDeclaration(
            path="/api/users",
            method="GET",
            requires_auth=True,
        ),
    ]
    
    observed_endpoints = []
    
    report = analyze_contract_conformance(
        contract_endpoints,
        observed_endpoints,
        "contract-004",
        "observation-004",
    )
    
    assert report.total_endpoints == 1
    assert any(f.conformance_status == ConformanceStatus.UNKNOWN for f in report.findings)


def test_endpoint_observed_not_declared():
    """Test endpoint observed but not declared."""
    contract_endpoints = []
    
    observed_endpoints = [
        EndpointObservation(
            path="/api/users",
            method="GET",
            observed_security="Bearer",
        ),
    ]
    
    report = analyze_contract_conformance(
        contract_endpoints,
        observed_endpoints,
        "contract-005",
        "observation-005",
    )
    
    assert report.missing_declaration_count == 1
    assert "observed but not declared" in report.findings[0].description.lower()


def test_case_insensitive_path_matching():
    """Test that path matching is case-insensitive."""
    contract_endpoints = [
        EndpointDeclaration(
            path="/API/Users",
            method="GET",
            requires_auth=True,
        ),
    ]
    
    observed_endpoints = [
        EndpointObservation(
            path="/api/users",
            method="GET",
            observed_security="Bearer",
        ),
    ]
    
    report = analyze_contract_conformance(
        contract_endpoints,
        observed_endpoints,
        "contract-006",
        "observation-006",
    )
    
    assert report.conformant_count == 1


def test_case_insensitive_method_matching():
    """Test that method matching is case-insensitive."""
    contract_endpoints = [
        EndpointDeclaration(
            path="/api/users",
            method="get",
            requires_auth=True,
        ),
    ]
    
    observed_endpoints = [
        EndpointObservation(
            path="/api/users",
            method="GET",
            observed_security="Bearer",
        ),
    ]
    
    report = analyze_contract_conformance(
        contract_endpoints,
        observed_endpoints,
        "contract-007",
        "observation-007",
    )
    
    assert report.conformant_count == 1


def test_get_security_drift_findings():
    """Test filtering security drift findings."""
    contract_endpoints = [
        EndpointDeclaration(
            path="/api/users",
            method="GET",
            requires_auth=True,
        ),
    ]
    
    observed_endpoints = [
        EndpointObservation(
            path="/api/users",
            method="GET",
            observed_security=None,
        ),
    ]
    
    report = analyze_contract_conformance(
        contract_endpoints,
        observed_endpoints,
        "contract-008",
        "observation-008",
    )
    
    drift_findings = get_security_drift_findings(report)
    
    assert len(drift_findings) == 1
    assert drift_findings[0].conformance_status == ConformanceStatus.DRIFTED


def test_get_missing_declaration_findings():
    """Test filtering missing declaration findings."""
    contract_endpoints = []
    
    observed_endpoints = [
        EndpointObservation(
            path="/api/users",
            method="GET",
            observed_security="Bearer",
        ),
    ]
    
    report = analyze_contract_conformance(
        contract_endpoints,
        observed_endpoints,
        "contract-009",
        "observation-009",
    )
    
    missing_findings = get_missing_declaration_findings(report)
    
    assert len(missing_findings) == 1
    assert missing_findings[0].conformance_status == ConformanceStatus.MISSING_DECLARATION


def test_conformance_finding_immutable():
    """Test that ConformanceFinding is immutable."""
    finding = ConformanceFinding(
        finding_id="cf_001",
        endpoint_path="/api/users",
        endpoint_method="GET",
        conformance_status=ConformanceStatus.CONFORMANT,
        description="Test",
    )
    
    with pytest.raises(Exception):  # FrozenInstanceError
        finding.conformance_status = ConformanceStatus.DRIFTED


def test_endpoint_declaration_immutable():
    """Test that EndpointDeclaration is immutable."""
    declared = EndpointDeclaration(
        path="/api/users",
        method="GET",
    )
    
    with pytest.raises(Exception):  # FrozenInstanceError
        declared.path = "/api/posts"


def test_endpoint_observation_immutable():
    """Test that EndpointObservation is immutable."""
    observed = EndpointObservation(
        path="/api/users",
        method="GET",
    )
    
    with pytest.raises(Exception):  # FrozenInstanceError
        observed.path = "/api/posts"


def test_contract_report_immutable():
    """Test that ContractConformanceReport is immutable."""
    report = analyze_contract_conformance(
        [],
        [],
        "contract-010",
        "observation-010",
    )
    
    with pytest.raises(Exception):  # FrozenInstanceError
        report.conformant_count = 10


def test_report_limitations():
    """Test that report includes limitations."""
    report = analyze_contract_conformance(
        [],
        [],
        "contract-011",
        "observation-011",
    )
    
    assert len(report.limitations) > 0
    assert "declared vs observed" in report.limitations[0].lower()


def test_security_scheme():
    """Test SecurityScheme dataclass."""
    scheme = SecurityScheme(
        scheme_id="scheme-001",
        scheme_type=SecuritySchemeType.API_KEY,
        location="header",
        name="X-API-Key",
        description="API key authentication",
    )
    
    assert scheme.scheme_id == "scheme-001"
    assert scheme.scheme_type == SecuritySchemeType.API_KEY
    assert scheme.location == "header"


def test_empty_contract():
    """Test analysis with empty contract."""
    report = analyze_contract_conformance(
        [],
        [],
        "contract-012",
        "observation-012",
    )
    
    assert report.total_endpoints == 0
    assert report.conformant_count == 0
    assert report.conformance_rate == 0.0
