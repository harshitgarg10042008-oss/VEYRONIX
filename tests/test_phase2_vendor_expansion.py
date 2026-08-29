from configsentinel.client import ConfigSentinelClient
from configsentinel.engine import DeterministicComplianceEngine
from configsentinel.parsers import detect_and_parse


def test_arista_eos_detects_and_normalizes_management_controls():
    text = "! Arista\nversion 4.28.0F\nmanagement api http-commands\ninterface Ethernet1\n transport input telnet ssh\n"
    parsed = detect_and_parse(text, vendor="arista_eos")
    assert parsed.config.vendor == "arista"
    assert parsed.config.platform == "eos"
    assert parsed.config.management_telnet_enabled is True
    assert parsed.config.spans_for("management_telnet_enabled")[0].start_line == 5


def test_linux_nftables_detects_secure_and_insecure_service_rules():
    text = "table inet filter {\n chain input {\n  tcp dport 22 accept\n  tcp dport 23 accept\n }\n}\n"
    parsed = detect_and_parse(text, vendor="linux_nftables")
    assert parsed.config.vendor == "linux"
    assert parsed.config.platform == "nftables"
    assert parsed.config.management_ssh_enabled is True
    assert parsed.config.management_telnet_enabled is True
    assert parsed.config.spans_for("management_telnet_enabled")[0].start_line == 4


def test_expanded_vendor_reports_use_real_control_evidence():
    text = "table inet filter {\n chain input {\n  tcp dport 23 accept\n }\n}\n"
    result = ConfigSentinelClient(engine=DeterministicComplianceEngine()).audit_text(
        text, vendor="linux_nftables"
    )
    telnet = next(
        finding
        for finding in result.findings
        if finding.control_id == "NET-MGMT-TELNET-001"
    )
    assert telnet.status.value == "FAIL"
    assert telnet.evidence[0].excerpt == "tcp dport 23 accept"
