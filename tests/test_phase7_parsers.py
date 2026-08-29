"""Phase 7: Control and parser expansion – fixture tests for accuracy measurement.

Tests verify parser accuracy across supported vendors:
1. Cisco IOS
2. Junos
3. Arista EOS
4. Linux nftables
5. Generic Firewall
"""

from configsentinel.parsers import detect_and_parse
from configsentinel.canonical import CanonicalConfig


def test_parser_cisco_ios_accuracy():
    text = (
        "! Cisco IOS Software\n"
        "version 15.2\n"
        "hostname rtr-core\n"
        "aaa new-model\n"
        "ip ssh version 2\n"
        "line vty 0 4\n"
        " transport input ssh\n"
        " logging trap debugging\n"
        "ntp server 10.0.0.1\n"
        "no ip http server\n"
    )
    parsed = detect_and_parse(text, vendor="cisco_ios")
    config: CanonicalConfig = parsed.config
    assert config.vendor == "cisco"
    assert config.platform == "ios"
    assert config.aaa_enabled is True
    assert config.management_ssh_version == "2"
    assert config.management_ssh_enabled is True
    assert config.management_telnet_enabled is None
    assert config.ntp_enabled is True
    assert config.http_management_enabled is False
    assert config.logging_enabled is True


def test_parser_junos_accuracy():
    text = (
        "## Last commit: 2023-01-01 12:00:00 UTC by admin\n"
        "set system services ssh protocol-version v2\n"
        "set system services telnet\n"
        "delete system services telnet\n"
        "set system authentication-order [ radius password ]\n"
        "set system syslog host 10.0.0.2 any warning\n"
        "set system ntp server 10.0.0.1\n"
        "set snmp v3\n"
    )
    parsed = detect_and_parse(text, vendor="junos")
    config = parsed.config
    assert config.vendor == "juniper"
    assert config.platform == "junos"
    assert config.management_ssh_enabled is True
    assert config.management_ssh_version == "2"
    assert config.management_telnet_enabled is False
    assert config.aaa_enabled is True
    assert config.logging_enabled is True
    assert config.ntp_enabled is True
    assert config.snmp_secure is True


def test_parser_arista_eos_accuracy():
    text = (
        "! Arista EOS\n"
        "version 4.28.0F\n"
        "management api http-commands\n"
        "  protocol https\n"
        "  no shutdown\n"
        "interface Ethernet1\n"
        " transport input telnet ssh\n"
    )
    parsed = detect_and_parse(text, vendor="arista_eos")
    config = parsed.config
    assert config.vendor == "arista"
    assert config.platform == "eos"
    assert config.management_telnet_enabled is True
    assert config.management_ssh_enabled is True


def test_parser_linux_nftables_accuracy():
    text = (
        "table inet filter {\n"
        " chain input {\n"
        "  type filter hook input priority filter; policy drop;\n"
        "  tcp dport 22 accept\n"
        "  tcp dport 80 accept\n"
        '  log prefix "nftables-drop: "\n'
        " }\n"
        "}\n"
    )
    parsed = detect_and_parse(text, vendor="linux_nftables")
    config = parsed.config
    assert config.vendor == "linux"
    assert config.platform == "nftables"
    assert config.management_ssh_enabled is True
    assert config.http_management_enabled is True
    assert config.logging_enabled is True


def test_parser_generic_firewall_accuracy():
    text = (
        "# Generic Policy\n"
        "rule 1 allow tcp dport telnet\n"
        "rule 2 allow tcp dport ssh\n"
        "rule 3 allow tcp dport https admin\n"
    )
    parsed = detect_and_parse(text, vendor="firewall_generic")
    config = parsed.config
    assert config.vendor == "firewall"
    assert config.platform == "generic"
    assert config.management_telnet_enabled is True
    assert config.management_ssh_enabled is True
    assert config.http_management_enabled is True


def test_parser_auto_detection():
    # Test auto detection of Arista
    text = "! Arista\n" "management api http-commands\n"
    parsed = detect_and_parse(text, vendor="auto")
    assert parsed.config.vendor == "arista"
