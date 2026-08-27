from configsentinel.client import ConfigSentinelClient
from configsentinel.engine import DeterministicComplianceEngine
from configsentinel.remediation import build_diffs, generate_bundle, render_diffs


def test_remediation_diff_links_redacted_evidence_to_safe_command():
    result = ConfigSentinelClient(engine=DeterministicComplianceEngine()).audit_text("version 17.9\nline vty 0 4\n transport input telnet\n", vendor="cisco_ios")
    bundle = generate_bundle(result)
    diffs = build_diffs(result, bundle)
    telnet = next(item for item in diffs if item.control_id == "NET-MGMT-TELNET-001")
    assert telnet.before == ("transport input telnet",)
    assert telnet.after == ("transport input ssh",)
    assert "not executable" in telnet.unified_preview
    assert "Restore the approved" in telnet.rollback


def test_rendered_diff_has_safety_header_and_audit_hash():
    result = ConfigSentinelClient(engine=DeterministicComplianceEngine()).audit_text("version 17.9\nline vty 0 4\n transport input telnet\n", vendor="cisco_ios")
    rendered = render_diffs(result)
    assert "Preview only" in rendered
    assert result.input_sha256 in rendered
    assert "NET-MGMT-TELNET-001" in rendered
