"""Tests for parser differential and ambiguity analysis."""

import pytest

from configsentinel.parser_differential import (
    Disagreement,
    DisagreementType,
    DifferentialAnalysis,
    ParserResult,
    compare_parser_results,
    create_ambiguity_finding,
    track_disagreement_metrics,
)


def test_compare_parser_results_identical():
    """Test comparison when parsers produce identical results."""
    parser_a = ParserResult(
        parser_id="parser-1",
        parser_version="1.0.0",
        vendor="cisco_ios",
        syntax_family="ios",
        control_results={
            "NET-MGMT-SSH-001": {"status": "PASS", "severity": "LOW"},
            "NET-MGMT-TELNET-001": {"status": "FAIL", "severity": "HIGH"},
        },
        parse_success=True,
    )
    
    parser_b = ParserResult(
        parser_id="parser-2",
        parser_version="1.0.0",
        vendor="cisco_ios",
        syntax_family="ios",
        control_results={
            "NET-MGMT-SSH-001": {"status": "PASS", "severity": "LOW"},
            "NET-MGMT-TELNET-001": {"status": "FAIL", "severity": "HIGH"},
        },
        parse_success=True,
    )
    
    analysis = compare_parser_results(parser_a, parser_b, "input-001")
    
    assert analysis.agreement_count == 2
    assert analysis.disagreement_count == 0
    assert analysis.requires_review_count == 0
    assert not analysis.has_critical_disagreements


def test_compare_parser_results_status_disagreement():
    """Test comparison when parsers disagree on control status."""
    parser_a = ParserResult(
        parser_id="parser-1",
        parser_version="1.0.0",
        vendor="cisco_ios",
        syntax_family="ios",
        control_results={
            "NET-MGMT-SSH-001": {"status": "PASS", "severity": "LOW"},
        },
        parse_success=True,
    )
    
    parser_b = ParserResult(
        parser_id="parser-2",
        parser_version="1.0.0",
        vendor="cisco_ios",
        syntax_family="ios",
        control_results={
            "NET-MGMT-SSH-001": {"status": "FAIL", "severity": "HIGH"},
        },
        parse_success=True,
    )
    
    analysis = compare_parser_results(parser_a, parser_b, "input-001")
    
    # Both status and severity differ, so 2 disagreements
    assert analysis.disagreement_count == 2
    assert analysis.requires_review_count == 1  # Only status disagreement requires review
    assert analysis.has_critical_disagreements
    
    status_disagreement = [d for d in analysis.disagreements if d.disagreement_type == DisagreementType.CONTROL_STATUS][0]
    assert status_disagreement.control_id == "NET-MGMT-SSH-001"
    assert status_disagreement.requires_review is True


def test_compare_parser_results_severity_disagreement():
    """Test comparison when parsers disagree on severity."""
    parser_a = ParserResult(
        parser_id="parser-1",
        parser_version="1.0.0",
        vendor="cisco_ios",
        syntax_family="ios",
        control_results={
            "NET-MGMT-SSH-001": {"status": "FAIL", "severity": "HIGH"},
        },
        parse_success=True,
    )
    
    parser_b = ParserResult(
        parser_id="parser-2",
        parser_version="1.0.0",
        vendor="cisco_ios",
        syntax_family="ios",
        control_results={
            "NET-MGMT-SSH-001": {"status": "FAIL", "severity": "MEDIUM"},
        },
        parse_success=True,
    )
    
    analysis = compare_parser_results(parser_a, parser_b, "input-001")
    
    assert analysis.disagreement_count == 1
    assert analysis.requires_review_count == 0  # Severity disagreement doesn't require review
    
    disagreement = analysis.disagreements[0]
    assert disagreement.disagreement_type == DisagreementType.SEVERITY


def test_compare_parser_results_missing_control():
    """Test comparison when one parser misses a control."""
    parser_a = ParserResult(
        parser_id="parser-1",
        parser_version="1.0.0",
        vendor="cisco_ios",
        syntax_family="ios",
        control_results={
            "NET-MGMT-SSH-001": {"status": "PASS", "severity": "LOW"},
        },
        parse_success=True,
    )
    
    parser_b = ParserResult(
        parser_id="parser-2",
        parser_version="1.0.0",
        vendor="cisco_ios",
        syntax_family="ios",
        control_results={
            "NET-MGMT-SSH-001": {"status": "PASS", "severity": "LOW"},
            "NET-MGMT-TELNET-001": {"status": "FAIL", "severity": "HIGH"},
        },
        parse_success=True,
    )
    
    analysis = compare_parser_results(parser_a, parser_b, "input-001")
    
    assert analysis.disagreement_count == 1
    assert analysis.requires_review_count == 1
    
    disagreement = analysis.disagreements[0]
    assert disagreement.disagreement_type == DisagreementType.MISSING_CONTROL


def test_compare_parser_results_extra_control():
    """Test comparison when one parser has an extra control."""
    parser_a = ParserResult(
        parser_id="parser-1",
        parser_version="1.0.0",
        vendor="cisco_ios",
        syntax_family="ios",
        control_results={
            "NET-MGMT-SSH-001": {"status": "PASS", "severity": "LOW"},
            "NET-MGMT-TELNET-001": {"status": "FAIL", "severity": "HIGH"},
        },
        parse_success=True,
    )
    
    parser_b = ParserResult(
        parser_id="parser-2",
        parser_version="1.0.0",
        vendor="cisco_ios",
        syntax_family="ios",
        control_results={
            "NET-MGMT-SSH-001": {"status": "PASS", "severity": "LOW"},
        },
        parse_success=True,
    )
    
    analysis = compare_parser_results(parser_a, parser_b, "input-001")
    
    assert analysis.disagreement_count == 1
    assert analysis.requires_review_count == 1
    
    disagreement = analysis.disagreements[0]
    assert disagreement.disagreement_type == DisagreementType.EXTRA_CONTROL


def test_compare_parser_results_multiple_disagreements():
    """Test comparison with multiple types of disagreements."""
    parser_a = ParserResult(
        parser_id="parser-1",
        parser_version="1.0.0",
        vendor="cisco_ios",
        syntax_family="ios",
        control_results={
            "NET-MGMT-SSH-001": {"status": "PASS", "severity": "LOW"},
            "NET-MGMT-TELNET-001": {"status": "FAIL", "severity": "HIGH"},
        },
        parse_success=True,
    )
    
    parser_b = ParserResult(
        parser_id="parser-2",
        parser_version="1.0.0",
        vendor="cisco_ios",
        syntax_family="ios",
        control_results={
            "NET-MGMT-SSH-001": {"status": "FAIL", "severity": "MEDIUM"},
            "NET-MGMT-HTTP-001": {"status": "FAIL", "severity": "HIGH"},
        },
        parse_success=True,
    )
    
    analysis = compare_parser_results(parser_a, parser_b, "input-001")
    
    # SSH: status + severity (2), TELNET: missing (1), HTTP: extra (1) = 4 total
    assert analysis.disagreement_count == 4
    assert analysis.requires_review_count >= 1


def test_track_disagreement_metrics():
    """Test aggregation of disagreement metrics."""
    parser_a = ParserResult(
        parser_id="parser-1",
        parser_version="1.0.0",
        vendor="cisco_ios",
        syntax_family="ios",
        control_results={"NET-MGMT-SSH-001": {"status": "PASS"}},
        parse_success=True,
    )
    
    parser_b = ParserResult(
        parser_id="parser-2",
        parser_version="1.0.0",
        vendor="cisco_ios",
        syntax_family="ios",
        control_results={"NET-MGMT-SSH-001": {"status": "FAIL"}},
        parse_success=True,
    )
    
    analysis1 = compare_parser_results(parser_a, parser_b, "input-001")
    analysis2 = compare_parser_results(parser_a, parser_b, "input-002")
    
    metrics = track_disagreement_metrics([analysis1, analysis2])
    
    assert metrics["total_analyses"] == 2
    assert metrics["by_vendor"]["cisco_ios"] == 2
    assert metrics["by_syntax_family"]["ios"] == 2
    assert metrics["by_parser_version"]["1.0.0"] == 2
    assert metrics["by_disagreement_type"]["CONTROL_STATUS"] == 2


def test_create_ambiguity_finding():
    """Test creation of ambiguity finding for review queue."""
    parser_a = ParserResult(
        parser_id="parser-1",
        parser_version="1.0.0",
        vendor="cisco_ios",
        syntax_family="ios",
        control_results={"NET-MGMT-SSH-001": {"status": "PASS"}},
        parse_success=True,
    )
    
    parser_b = ParserResult(
        parser_id="parser-2",
        parser_version="1.0.0",
        vendor="cisco_ios",
        syntax_family="ios",
        control_results={"NET-MGMT-SSH-001": {"status": "FAIL"}},
        parse_success=True,
    )
    
    analysis = compare_parser_results(parser_a, parser_b, "input-001")
    
    finding = create_ambiguity_finding(analysis, "NET-MGMT-SSH-001")
    
    assert finding["finding_type"] == "PARSER_AMBIGUITY"
    assert finding["control_id"] == "NET-MGMT-SSH-001"
    assert finding["input_id"] == "input-001"
    assert finding["parser_a_id"] == "parser-1"
    assert finding["parser_b_id"] == "parser-2"
    assert finding["requires_review"] is True
    assert len(finding["disagreement_types"]) == 1


def test_create_ambiguity_finding_no_disagreement():
    """Test that creating finding for control without disagreement raises error."""
    parser_a = ParserResult(
        parser_id="parser-1",
        parser_version="1.0.0",
        vendor="cisco_ios",
        syntax_family="ios",
        control_results={"NET-MGMT-SSH-001": {"status": "PASS"}},
        parse_success=True,
    )
    
    parser_b = ParserResult(
        parser_id="parser-2",
        parser_version="1.0.0",
        vendor="cisco_ios",
        syntax_family="ios",
        control_results={"NET-MGMT-SSH-001": {"status": "PASS"}},
        parse_success=True,
    )
    
    analysis = compare_parser_results(parser_a, parser_b, "input-001")
    
    with pytest.raises(ValueError, match="No disagreements found"):
        create_ambiguity_finding(analysis, "NET-MGMT-SSH-001")


def test_parser_result_immutable():
    """Test that ParserResult is immutable."""
    result = ParserResult(
        parser_id="parser-1",
        parser_version="1.0.0",
        vendor="cisco_ios",
        syntax_family="ios",
        control_results={},
        parse_success=True,
    )
    
    with pytest.raises(Exception):  # FrozenInstanceError
        result.parser_id = "parser-2"


def test_disagreement_immutable():
    """Test that Disagreement is immutable."""
    disagreement = Disagreement(
        control_id="control-001",
        disagreement_type=DisagreementType.CONTROL_STATUS,
        parser_a_result={"status": "PASS"},
        parser_b_result={"status": "FAIL"},
        parser_a_id="parser-1",
        parser_b_id="parser-2",
        rationale="Test",
        requires_review=True,
    )
    
    with pytest.raises(Exception):  # FrozenInstanceError
        disagreement.control_id = "control-002"


def test_differential_analysis_immutable():
    """Test that DifferentialAnalysis is immutable."""
    parser_a = ParserResult(
        parser_id="parser-1",
        parser_version="1.0.0",
        vendor="cisco_ios",
        syntax_family="ios",
        control_results={},
        parse_success=True,
    )
    
    parser_b = ParserResult(
        parser_id="parser-2",
        parser_version="1.0.0",
        vendor="cisco_ios",
        syntax_family="ios",
        control_results={},
        parse_success=True,
    )
    
    analysis = compare_parser_results(parser_a, parser_b, "input-001")
    
    with pytest.raises(Exception):  # FrozenInstanceError
        analysis.disagreement_count = 10


def test_analysis_limitations():
    """Test that analysis includes limitations."""
    parser_a = ParserResult(
        parser_id="parser-1",
        parser_version="1.0.0",
        vendor="cisco_ios",
        syntax_family="ios",
        control_results={},
        parse_success=True,
    )
    
    parser_b = ParserResult(
        parser_id="parser-2",
        parser_version="1.0.0",
        vendor="cisco_ios",
        syntax_family="ios",
        control_results={},
        parse_success=True,
    )
    
    analysis = compare_parser_results(parser_a, parser_b, "input-001")
    
    assert len(analysis.limitations) > 0
    assert "control-level results" in analysis.limitations[0].lower()


def test_parse_error_handling():
    """Test that parse errors are recorded."""
    parser_a = ParserResult(
        parser_id="parser-1",
        parser_version="1.0.0",
        vendor="cisco_ios",
        syntax_family="ios",
        control_results={},
        parse_success=False,
        parse_error="Syntax error at line 10",
    )
    
    parser_b = ParserResult(
        parser_id="parser-2",
        parser_version="1.0.0",
        vendor="cisco_ios",
        syntax_family="ios",
        control_results={},
        parse_success=True,
    )
    
    analysis = compare_parser_results(parser_a, parser_b, "input-001")
    
    assert parser_a.parse_error == "Syntax error at line 10"
    assert parser_a.parse_success is False
