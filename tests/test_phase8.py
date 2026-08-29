from __future__ import annotations

import json
from pathlib import Path

from configsentinel import ConfigSentinelClient, DeterministicComplianceEngine
from configsentinel.frameworks import mappings_for_finding, normalize_frameworks
from configsentinel.reporting import report_dict, render_json, render_markdown

CISCO = """version 17.9
hostname edge-1
line vty 0 4
 transport input telnet
 username admin password 0 SuperSecret123
"""


def make_result():
    client = ConfigSentinelClient(engine=DeterministicComplianceEngine())
    return client.audit_text(CISCO, vendor="cisco_ios", frameworks=("cis", "nist"))


def test_framework_aliases_are_normalized():
    assert normalize_frameworks(("cis", "nist", "cis-network")) == (
        "cis-network",
        "nist-800-53",
    )


def test_mapping_contains_provenance_and_status():
    result = make_result()
    finding = next(
        item for item in result.findings if item.control_id == "NET-MGMT-TELNET-001"
    )
    rows = mappings_for_finding(finding, ("cis-network", "nist-800-53"))
    assert rows[0]["status"] == "MAPPED"
    assert rows[0]["source_url"].startswith("https://")
    assert rows[0]["version"]


def test_json_report_reconciles_totals_and_preserves_redaction():
    result = make_result()
    document = report_dict(result, ("cis-network", "nist-800-53"))
    serialized = render_json(result, ("cis-network", "nist-800-53"))
    assert document["reconciliation"]["matches_finding_count"] is True
    assert document["reconciliation"]["failed_count_matches"] is True
    assert "SuperSecret123" not in serialized
    assert document["audit"]["input_sha256"]


def test_markdown_report_has_evidence_and_frameworks():
    report = render_markdown(make_result(), ("cis-network", "nist-800-53"))
    assert "## Findings" in report
    assert "NET-MGMT-TELNET-001" in report
    assert "cis-network" in report
    assert "Evidence" in report
    assert "SuperSecret123" not in report


def test_client_report_methods_match_report_module():
    result = make_result()
    client = ConfigSentinelClient(engine=DeterministicComplianceEngine())
    assert client.report_json(result, frameworks=("cis-network",)) == render_json(
        result, ("cis-network",)
    )
    assert client.report_markdown(
        result, frameworks=("cis-network",)
    ) == render_markdown(result, ("cis-network",))


def test_report_can_be_written_to_files(tmp_path: Path):
    result = make_result()
    from configsentinel.reporting import write_report

    markdown_path = tmp_path / "audit.md"
    json_path = tmp_path / "audit.json"
    write_report(
        result, str(markdown_path), format="markdown", frameworks=("cis-network",)
    )
    write_report(result, str(json_path), format="json", frameworks=("cis-network",))
    assert markdown_path.exists()
    assert json.loads(json_path.read_text(encoding="utf-8"))["summary"][
        "finding_count"
    ] == len(result.findings)
