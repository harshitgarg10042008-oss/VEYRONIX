import pytest

from configsentinel.client import ConfigSentinelClient
from configsentinel.engine import DeterministicComplianceEngine
from configsentinel.evidence_graph import EvidenceGraphError, build_evidence_graph
from configsentinel.reporting import report_dict


def test_evidence_graph_links_audit_findings_controls_frameworks_and_evidence():
    result = ConfigSentinelClient(engine=DeterministicComplianceEngine()).audit_text(
        "version 17.9\nline vty 0 4\n transport input telnet\n", vendor="cisco_ios"
    )
    graph = build_evidence_graph(report_dict(result))
    types = {node["type"] for node in graph["nodes"]}
    relations = {edge["relation"] for edge in graph["edges"]}
    assert {"audit", "finding", "control", "framework", "evidence"} <= types
    assert {"produces", "evaluates", "maps_to", "supported_by"} <= relations
    evidence = [node for node in graph["nodes"] if node["type"] == "evidence"]
    assert evidence and evidence[0]["redacted"] is True
    assert "transport input telnet" in evidence[0]["excerpt"]


def test_evidence_graph_rejects_malformed_report():
    with pytest.raises(EvidenceGraphError):
        build_evidence_graph({"audit": {}, "findings": "invalid"})
