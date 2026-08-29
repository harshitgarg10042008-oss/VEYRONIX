import json

from configsentinel.client import ConfigSentinelClient
from configsentinel.engine import DeterministicComplianceEngine
from configsentinel.executive import (
    build_executive_report,
    render_executive_json,
    render_executive_markdown,
)


def test_executive_report_summarizes_evidence_backed_posture():
    result = ConfigSentinelClient(engine=DeterministicComplianceEngine()).audit_text(
        "version 17.9\nline vty 0 4\n transport input telnet\n", vendor="cisco_ios"
    )
    report = build_executive_report(result)
    assert report.posture == "CRITICAL"
    assert report.failed >= 1
    assert report.severity_counts["CRITICAL"] >= 1
    assert report.top_risks[0]["evidence_lines"]


def test_executive_renderers_are_machine_and_human_readable():
    result = ConfigSentinelClient(engine=DeterministicComplianceEngine()).audit_text(
        "version 17.9\nno ip http server\n", vendor="cisco_ios"
    )
    report = build_executive_report(result)
    assert "ConfigSentinel AI executive posture report" in render_executive_markdown(
        report
    )
    payload = json.loads(render_executive_json(report))
    assert payload["audit_id"] == result.audit_id
