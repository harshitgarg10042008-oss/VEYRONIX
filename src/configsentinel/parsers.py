"""Deterministic vendor parser plugins — Phase 4 MVP scope.

Parser registry version: 4.0.0
Supported vendors: Cisco IOS/IOS-XE, Juniper Junos, Arista EOS,
                   Fortinet FortiGate (FortiOS), Palo Alto PAN-OS,
                   Linux nftables, Generic Firewall fallback.

Every parser must:
  1. Declare plugin_id and parser_version.
  2. Implement detect(text) -> float [0.0–1.0 confidence].
  3. Implement parse(text) -> ParseResult with evidence spans.
  4. Report unrecognised syntax as unknown_blocks (never silently drop).
  5. Declare supported and unsupported syntax in capabilities.py metadata.
"""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Protocol

from .canonical import CanonicalConfig, ParseResult
from .models import EvidenceSpan


class VendorParser(Protocol):
    plugin_id: str
    parser_version: str

    def detect(self, text: str) -> float: ...
    def parse(self, text: str) -> ParseResult: ...


def _span(line_no: int, line: str) -> EvidenceSpan:
    return EvidenceSpan(line_no, line_no, line.strip() or "<blank>")


def _add(
    evidence: dict[str, list[EvidenceSpan]], key: str, line_no: int, line: str
) -> None:
    evidence.setdefault(key, []).append(_span(line_no, line))


# ---------------------------------------------------------------------------
# Cisco IOS / IOS-XE
# ---------------------------------------------------------------------------

class CiscoIOSParser:
    plugin_id = "cisco_ios"
    parser_version = "4.0.0"

    # Lines that are known-good Cisco structural keywords — skip without flagging
    _KNOWN_PREFIXES = (
        "hostname ", "version ", "interface ", "line ", "router ",
        "ip ", "service ", "username ", "enable ", "banner ",
        "access-list ", "crypto ", "login ", "exec-timeout ",
        "transport ", "access-class ", "end", "!", "spanning-tree",
        "vlan ", "spanning ", "no spanning", "mac ", "do ", "exit",
        "description ", "boot ", "memory ", "clock ", "redundancy",
        "cdp ", "lldp ", "policy-map ", "class-map ", "class ",
        "monitor ", "flow ", "isakmp ", "archive ", "log config",
        "maximum ", "notify ", "rollback ", "hidekeys", "dot1x ",
        "subscriber ", "no ", "default ", "snmp-server ", "ntp ",
        "logging ", "tacacs ", "radius ", "aaa ", "privilege ",
    )

    def detect(self, text: str) -> float:
        score = 0.0
        lowered = text.lower()
        if "version " in lowered and (
            "hostname " in lowered or "interface " in lowered
        ):
            score += 0.45
        if "line vty" in lowered or "transport input" in lowered:
            score += 0.35
        if "service password-encryption" in lowered or "aaa new-model" in lowered:
            score += 0.2
        return min(score, 1.0)

    def parse(self, text: str) -> ParseResult:  # noqa: C901 — deliberate complexity
        evidence: dict[str, list[EvidenceSpan]] = {}
        unknown: list[EvidenceSpan] = []

        ssh = telnet = aaa = logging = ntp = snmp = http = unused = None
        restconf = mgmt_acl = local_fallback = passwd_policy = priv_sep = None
        tls_ver: str | None = None
        weak_ciphers = plaintext_creds = pk_in_config = None
        backup_enabled = anti_spoof = acl_hygiene = None
        snmp_community = None
        ssh_version: str | None = None

        lines = text.splitlines()
        for no, raw in enumerate(lines, 1):
            line = raw.strip().lower()
            if not line or line.startswith("!"):
                continue

            # SSH
            if re.match(r"^ip ssh version 2$", line):
                ssh = True
                ssh_version = "2"
                _add(evidence, "management_ssh_version", no, raw)
            elif re.match(r"^ip ssh version 1(?:\.\d+)?$", line):
                ssh = True
                ssh_version = "1"
                _add(evidence, "management_ssh_version", no, raw)
            elif "transport input" in line:
                if "telnet" in line:
                    telnet = True
                    _add(evidence, "management_telnet_enabled", no, raw)
                if "ssh" in line:
                    ssh = True
                    _add(evidence, "management_ssh_enabled", no, raw)
            elif "transport input none" in line:
                telnet = False
                ssh = False
                _add(evidence, "management_ssh_enabled", no, raw)

            # HTTP management
            elif line == "no ip http server":
                http = False
                _add(evidence, "http_management_enabled", no, raw)
            elif line == "ip http server":
                http = True
                _add(evidence, "http_management_enabled", no, raw)
            elif "ip http secure-server" in line:
                _add(evidence, "http_management_enabled", no, raw)
            elif "no ip http secure-server" in line:
                _add(evidence, "http_management_enabled", no, raw)

            # RESTCONF / NETCONF
            elif "restconf" in line or "netconf-yang" in line or "netconf ssh" in line:
                restconf = True
                _add(evidence, "restconf_enabled", no, raw)

            # AAA
            elif line == "aaa new-model":
                aaa = True
                _add(evidence, "aaa_enabled", no, raw)
            elif "aaa authentication login" in line:
                aaa = True
                _add(evidence, "aaa_enabled", no, raw)

            # Local auth fallback
            elif re.match(r"^username\s+\S+\s+privilege\s+\d+", line):
                local_fallback = True
                _add(evidence, "local_auth_fallback", no, raw)

            # Password policy
            elif "password min-length" in line or "password complexity" in line:
                passwd_policy = True
                _add(evidence, "password_policy_enabled", no, raw)
            elif re.match(r"^security password.*min-length", line):
                passwd_policy = True
                _add(evidence, "password_policy_enabled", no, raw)

            # Privilege separation
            elif re.match(r"^privilege\s+", line):
                priv_sep = True
                _add(evidence, "privilege_separation", no, raw)

            # Plaintext credentials check
            elif re.match(r"^username\s+\S+\s+password\s+0\s+", line):
                plaintext_creds = True
                _add(evidence, "plaintext_credentials_found", no, raw)
            elif re.match(r"^enable password\s+", line) and "enable secret" not in line:
                plaintext_creds = True
                _add(evidence, "plaintext_credentials_found", no, raw)

            # TLS / crypto weak ciphers
            elif "ip ssh dh-min-size" in line:
                _add(evidence, "ssh_key_minimum_bits", no, raw)
            elif re.match(r"^crypto pki", line):
                _add(evidence, "tls_minimum_version", no, raw)
            elif "ssl-version" in line or "tls1.0" in line or "ssl3" in line:
                tls_ver = "1.0"
                weak_ciphers = True
                _add(evidence, "weak_ciphers_found", no, raw)
            elif "tls1.2" in line or "tls-version 1.2" in line:
                tls_ver = "1.2"
                _add(evidence, "tls_minimum_version", no, raw)

            # Logging
            elif line.startswith("logging "):
                logging = True
                _add(evidence, "logging_enabled", no, raw)

            # NTP
            elif line.startswith("ntp server "):
                ntp = True
                _add(evidence, "ntp_enabled", no, raw)

            # SNMP
            elif line.startswith("snmp-server group ") and " v3" in line:
                snmp = True
                _add(evidence, "snmp_secure", no, raw)
            elif re.match(r"^snmp-server community\s+\S+\s+(ro|rw)", line):
                snmp_community = True
                _add(evidence, "snmp_community_exposed", no, raw)

            # Unused services
            elif line == "no cdp run" or line == "no service pad":
                unused = True
                _add(evidence, "unused_services_disabled", no, raw)

            # Config backup
            elif line.startswith("archive") or "log config" in line:
                backup_enabled = True
                _add(evidence, "config_backup_enabled", no, raw)

            # Anti-spoofing / uRPF
            elif "ip verify unicast source" in line or "ip verify unicast reverse-path" in line:
                anti_spoof = True
                _add(evidence, "anti_spoofing_enabled", no, raw)

            # Management ACL
            elif "access-class" in line and ("vty" in text.lower() or no > 0):
                mgmt_acl = True
                _add(evidence, "mgmt_acl_enabled", no, raw)

            elif line.startswith(self._KNOWN_PREFIXES):
                continue
            else:
                unknown.append(_span(no, raw))

        config = CanonicalConfig(
            vendor="cisco",
            platform="ios",
            management_ssh_enabled=ssh,
            management_ssh_version=ssh_version,
            management_telnet_enabled=telnet,
            aaa_enabled=aaa,
            local_auth_fallback=local_fallback,
            password_policy_enabled=passwd_policy,
            privilege_separation=priv_sep,
            logging_enabled=logging,
            ntp_enabled=ntp,
            snmp_secure=snmp,
            snmp_community_exposed=snmp_community,
            http_management_enabled=http,
            restconf_enabled=restconf,
            mgmt_acl_enabled=mgmt_acl,
            weak_ciphers_found=weak_ciphers,
            tls_minimum_version=tls_ver,
            plaintext_credentials_found=plaintext_creds,
            unused_services_disabled=unused,
            config_backup_enabled=backup_enabled,
            anti_spoofing_enabled=anti_spoof,
            evidence={k: tuple(v) for k, v in evidence.items()},
            unknown_blocks=tuple(unknown),
            metadata={"plugin_id": self.plugin_id},
        )
        return ParseResult(
            config=config,
            warnings=tuple(
                f"Unsupported Cisco line at {s.start_line}" for s in unknown
            ),
            parser_version=self.parser_version,
        )


# ---------------------------------------------------------------------------
# Juniper Junos
# ---------------------------------------------------------------------------

class JunosParser:
    plugin_id = "junos"
    parser_version = "4.0.0"

    _KNOWN_PREFIXES = (
        "set ", "delete ", "replace ", "system {", "services {",
        "authentication-order", "ssh {", "telnet {", "syslog {",
        "ntp {", "snmp {", "}", "inactive:", "deactivate ",
        "interfaces {", "routing-options {", "protocols {",
        "security {", "firewall {", "apply-groups", "version ",
        "groups {", "chassis {", "class-of-service {", "vlans {",
        "bridge-domains {", "logical-systems {",
    )

    def detect(self, text: str) -> float:
        lowered = text.lower()
        score = 0.0
        if "system {" in lowered and "services {" in lowered:
            score += 0.55
        if (
            "set system services ssh" in lowered
            or "set system services telnet" in lowered
        ):
            score += 0.35
        if any(
            line.strip().lower().startswith(("set ", "delete ", "replace "))
            for line in text.splitlines()
        ):
            score += 0.2
        if "set system authentication-order" in lowered:
            score += 0.1
        return min(score, 1.0)

    def parse(self, text: str) -> ParseResult:  # noqa: C901
        evidence: dict[str, list[EvidenceSpan]] = {}
        unknown: list[EvidenceSpan] = []

        ssh = telnet = aaa = logging = ntp = snmp = http = None
        ssh_version: str | None = None
        local_fallback = passwd_policy = priv_sep = None
        weak_ciphers = plaintext_creds = None
        snmp_community = mgmt_acl = anti_spoof = None
        tls_ver: str | None = None

        for no, raw in enumerate(text.splitlines(), 1):
            line = raw.strip().lower()
            if not line or line.startswith("#"):
                continue

            # SSH
            if line.startswith("set system services ssh"):
                ssh = True
                _add(evidence, "management_ssh_enabled", no, raw)
                if "protocol-version v2" in line:
                    ssh_version = "2"
                    _add(evidence, "management_ssh_version", no, raw)
            elif line.startswith("delete system services ssh"):
                ssh = False
                _add(evidence, "management_ssh_enabled", no, raw)

            # Telnet
            elif line.startswith("set system services telnet"):
                telnet = True
                _add(evidence, "management_telnet_enabled", no, raw)
            elif line.startswith("delete system services telnet"):
                telnet = False
                _add(evidence, "management_telnet_enabled", no, raw)

            # AAA
            elif line.startswith("set system authentication-order"):
                aaa = True
                _add(evidence, "aaa_enabled", no, raw)
            elif line.startswith("set system tacplus-server") or line.startswith("set system radius-server"):
                aaa = True
                _add(evidence, "aaa_enabled", no, raw)

            # Local fallback
            elif "login class" in line and "permissions" in line:
                local_fallback = True
                _add(evidence, "local_auth_fallback", no, raw)

            # Password policy
            elif "set system login password" in line:
                passwd_policy = True
                _add(evidence, "password_policy_enabled", no, raw)

            # Privilege separation
            elif "set system login class" in line:
                priv_sep = True
                _add(evidence, "privilege_separation", no, raw)

            # Logging
            elif line.startswith("set system syslog"):
                logging = True
                _add(evidence, "logging_enabled", no, raw)

            # NTP
            elif line.startswith("set system ntp"):
                ntp = True
                _add(evidence, "ntp_enabled", no, raw)

            # SNMP v3
            elif line.startswith("set snmp v3"):
                snmp = True
                _add(evidence, "snmp_secure", no, raw)
            elif re.match(r"^set snmp community\s+\S+", line):
                snmp_community = True
                _add(evidence, "snmp_community_exposed", no, raw)

            # HTTP management
            elif line.startswith("set system services web-management"):
                http = True
                _add(evidence, "http_management_enabled", no, raw)
            elif line.startswith("delete system services web-management"):
                http = False
                _add(evidence, "http_management_enabled", no, raw)

            # TLS / ciphers
            elif "ssl profile" in line or "tls-version" in line:
                _add(evidence, "tls_minimum_version", no, raw)
            elif "ssh ciphers" in line:
                _add(evidence, "weak_ciphers_found", no, raw)

            # Plaintext credentials
            elif "plain-text-password-value" in line:
                plaintext_creds = True
                _add(evidence, "plaintext_credentials_found", no, raw)

            # Firewall filter (anti-spoofing proxy)
            elif "firewall family inet filter" in line and "reject" in line:
                anti_spoof = True
                _add(evidence, "anti_spoofing_enabled", no, raw)

            elif line.startswith(self._KNOWN_PREFIXES):
                continue
            else:
                unknown.append(_span(no, raw))

        config = CanonicalConfig(
            vendor="juniper",
            platform="junos",
            management_ssh_enabled=ssh,
            management_ssh_version=ssh_version,
            management_telnet_enabled=telnet,
            aaa_enabled=aaa,
            local_auth_fallback=local_fallback,
            password_policy_enabled=passwd_policy,
            privilege_separation=priv_sep,
            logging_enabled=logging,
            ntp_enabled=ntp,
            snmp_secure=snmp,
            snmp_community_exposed=snmp_community,
            http_management_enabled=http,
            weak_ciphers_found=weak_ciphers,
            tls_minimum_version=tls_ver,
            plaintext_credentials_found=plaintext_creds,
            anti_spoofing_enabled=anti_spoof,
            mgmt_acl_enabled=mgmt_acl,
            evidence={k: tuple(v) for k, v in evidence.items()},
            unknown_blocks=tuple(unknown),
            metadata={"plugin_id": self.plugin_id},
        )
        return ParseResult(
            config=config,
            warnings=tuple(
                f"Unsupported Junos line at {s.start_line}" for s in unknown
            ),
            parser_version=self.parser_version,
        )


# ---------------------------------------------------------------------------
# Generic Firewall (conservative fallback)
# ---------------------------------------------------------------------------

class GenericFirewallParser:
    plugin_id = "firewall_generic"
    parser_version = "4.0.0"

    def detect(self, text: str) -> float:
        lowered = text.lower()
        return (
            0.75
            if any(
                token in lowered
                for token in ("firewall", "security-policy", "policy rule", "zone ")
            )
            else 0.0
        )

    def parse(self, text: str) -> ParseResult:
        evidence: dict[str, list[EvidenceSpan]] = {}
        unknown: list[EvidenceSpan] = []
        telnet = ssh = http = None
        for no, raw in enumerate(text.splitlines(), 1):
            line = raw.strip().lower()
            if not line or line.startswith(("#", "!")):
                continue
            if "telnet" in line and ("enable" in line or "allow" in line):
                telnet = True
                _add(evidence, "management_telnet_enabled", no, raw)
            elif "ssh" in line and ("enable" in line or "allow" in line):
                ssh = True
                _add(evidence, "management_ssh_enabled", no, raw)
            elif "https" in line and "admin" in line:
                http = True
                _add(evidence, "http_management_enabled", no, raw)
            else:
                unknown.append(_span(no, raw))
        config = CanonicalConfig(
            vendor="firewall",
            platform="generic",
            management_telnet_enabled=telnet,
            management_ssh_enabled=ssh,
            http_management_enabled=http,
            evidence={k: tuple(v) for k, v in evidence.items()},
            unknown_blocks=tuple(unknown),
            metadata={"plugin_id": self.plugin_id},
        )
        return ParseResult(
            config=config,
            warnings=tuple(
                f"Unsupported firewall line at {s.start_line}" for s in unknown
            ),
            parser_version=self.parser_version,
        )


# ---------------------------------------------------------------------------
# Arista EOS
# ---------------------------------------------------------------------------

class AristaEOSParser(CiscoIOSParser):
    plugin_id = "arista_eos"
    parser_version = "4.0.0"

    def detect(self, text: str) -> float:
        lowered = text.lower()
        score = 0.0
        if "management api http-commands" in lowered or "daemon terminattr" in lowered:
            score += 0.6
        if (
            re.search(r"^interface ethernet", lowered, re.MULTILINE)
            or "arista" in lowered
        ):
            score += 0.3
        if "router bgp" in lowered:
            score += 0.1
        return min(score, 1.0)

    def parse(self, text: str) -> ParseResult:
        result = super().parse(text)
        config = replace(
            result.config,
            vendor="arista",
            platform="eos",
            metadata={"plugin_id": self.plugin_id},
        )
        return replace(result, config=config, parser_version=self.parser_version)


# ---------------------------------------------------------------------------
# Linux nftables / iptables
# ---------------------------------------------------------------------------

class LinuxNftablesParser:
    plugin_id = "linux_nftables"
    parser_version = "4.0.0"

    _KNOWN_PREFIXES = (
        "table ", "chain ", "type ", "policy ", "hook ",
        "priority ", "nft ", "flush ", "counter", "comment ",
        "ct ", "iif ", "oif ", "ip ", "ip6 ", "tcp ", "udp ",
        "accept", "drop", "return", "jump ", "include ", "}",
        "icmp ", "icmpv6 ", "meta ", "iifname ", "oifname ",
        "saddr ", "daddr ", "sport ", "dport ", "reject",
        "masquerade", "snat", "dnat", "queue ", "mark ",
    )

    def detect(self, text: str) -> float:
        lowered = text.lower()
        score = 0.0
        if "table inet " in lowered or "chain input" in lowered:
            score += 0.55
        if "nft add rule" in lowered or "tcp dport" in lowered:
            score += 0.35
        if "iptables" in lowered:
            score += 0.1
        return min(score, 1.0)

    def parse(self, text: str) -> ParseResult:
        evidence: dict[str, list[EvidenceSpan]] = {}
        unknown: list[EvidenceSpan] = []
        ssh = telnet = http = logging = None
        for no, raw in enumerate(text.splitlines(), 1):
            line = raw.strip().lower()
            if not line or line.startswith(("#", "//")):
                continue
            if "tcp dport 22" in line and ("accept" in line or "allow" in line):
                ssh = True
                _add(evidence, "management_ssh_enabled", no, raw)
            elif "tcp dport 23" in line and ("accept" in line or "allow" in line):
                telnet = True
                _add(evidence, "management_telnet_enabled", no, raw)
            elif ("tcp dport 80" in line or "tcp dport 443" in line) and (
                "accept" in line or "allow" in line
            ):
                http = True
                _add(evidence, "http_management_enabled", no, raw)
            elif " log" in f" {line}" or line.startswith("log "):
                logging = True
                _add(evidence, "logging_enabled", no, raw)
            elif line.startswith(self._KNOWN_PREFIXES):
                continue
            else:
                unknown.append(_span(no, raw))
        config = CanonicalConfig(
            vendor="linux",
            platform="nftables",
            management_ssh_enabled=ssh,
            management_telnet_enabled=telnet,
            logging_enabled=logging,
            http_management_enabled=http,
            evidence={k: tuple(v) for k, v in evidence.items()},
            unknown_blocks=tuple(unknown),
            metadata={"plugin_id": self.plugin_id},
        )
        return ParseResult(
            config=config,
            warnings=tuple(
                f"Unsupported nftables line at {s.start_line}" for s in unknown
            ),
            parser_version=self.parser_version,
        )


# ---------------------------------------------------------------------------
# Fortinet FortiGate (FortiOS)
# Scope: Management plane and identity controls only.
# Full policy evaluation is out of scope — all policy sections → UNKNOWN.
# ---------------------------------------------------------------------------

class FortiGateParser:
    plugin_id = "fortigate"
    parser_version = "1.0.0"

    _KNOWN_PREFIXES = (
        "config ", "end", "next", "edit ", "set ", "unset ",
        "#", "get ", "show ", "diagnose ", "execute ",
    )

    def detect(self, text: str) -> float:
        lowered = text.lower()
        score = 0.0
        if "config system global" in lowered:
            score += 0.5
        if "set admin-telnet" in lowered or "set admin-ssh" in lowered:
            score += 0.3
        if "fortigate" in lowered or "fortios" in lowered or "fgt" in lowered:
            score += 0.2
        if "config system admin" in lowered:
            score += 0.1
        return min(score, 1.0)

    def parse(self, text: str) -> ParseResult:  # noqa: C901
        evidence: dict[str, list[EvidenceSpan]] = {}
        unknown: list[EvidenceSpan] = []

        ssh = telnet = http = aaa = logging = ntp = None
        ssh_version: str | None = None
        passwd_policy = priv_sep = local_fallback = None
        plaintext_creds = None
        mgmt_acl = None
        snmp = snmp_community = None

        in_system_global = False
        in_system_admin = False
        in_system_snmp = False

        for no, raw in enumerate(text.splitlines(), 1):
            line = raw.strip().lower()
            if not line:
                continue

            # Context tracking
            if line == "config system global":
                in_system_global = True
                continue
            elif line == "config system admin":
                in_system_admin = True
                continue
            elif line.startswith("config system snmp"):
                in_system_snmp = True
                continue
            elif line == "end":
                in_system_global = False
                in_system_admin = False
                in_system_snmp = False
                continue
            elif line == "next":
                continue

            if in_system_global:
                # Telnet
                if "set admin-telnet enable" in line:
                    telnet = True
                    _add(evidence, "management_telnet_enabled", no, raw)
                elif "set admin-telnet disable" in line:
                    telnet = False
                    _add(evidence, "management_telnet_enabled", no, raw)
                # SSH
                elif "set admin-ssh enable" in line or "set admintimeout" in line:
                    ssh = True
                    _add(evidence, "management_ssh_enabled", no, raw)
                elif re.match(r"set admin-ssh-port\s+\d+", line):
                    ssh = True
                    _add(evidence, "management_ssh_enabled", no, raw)
                # HTTP / HTTPS
                elif "set admin-https enable" in line or "set admin-server-cert" in line:
                    http = False  # HTTPS only → plain HTTP disabled
                    _add(evidence, "http_management_enabled", no, raw)
                elif "set admin-http enable" in line:
                    http = True
                    _add(evidence, "http_management_enabled", no, raw)
                # Password policy
                elif "set password-policy" in line or "set pwd-policy" in line:
                    passwd_policy = True
                    _add(evidence, "password_policy_enabled", no, raw)
                # Logging
                elif "set syslog-server" in line or "set log-facility" in line:
                    logging = True
                    _add(evidence, "logging_enabled", no, raw)
                # NTP
                elif "set ntpserver" in line or "set ntp-server" in line:
                    ntp = True
                    _add(evidence, "ntp_enabled", no, raw)
                else:
                    # Known FortiOS global keys not relevant to controls
                    _known = ("set hostname", "set timezone", "set language", "set gui-",
                              "set fortiextender", "set optimize", "set admin-port",
                              "set admin-concurrent", "set admin-lockout", "set alias")
                    if not any(line.startswith(k) for k in _known):
                        unknown.append(_span(no, raw))

            elif in_system_admin:
                if "set password" in line and "set password-expire" not in line:
                    # Plain passwords in admin block
                    _add(evidence, "local_auth_fallback", no, raw)
                    local_fallback = True
                elif "set accprofile" in line:
                    priv_sep = True
                    _add(evidence, "privilege_separation", no, raw)
                elif "set trusthost" in line:
                    mgmt_acl = True
                    _add(evidence, "mgmt_acl_enabled", no, raw)

            elif in_system_snmp:
                if "set query-v1-status enable" in line or "set query-v2c-status enable" in line:
                    snmp_community = True
                    _add(evidence, "snmp_community_exposed", no, raw)
                elif "set trap-v1-status enable" in line:
                    snmp_community = True
                    _add(evidence, "snmp_community_exposed", no, raw)
                elif "set status enable" in line and "v3" in raw.lower():
                    snmp = True
                    _add(evidence, "snmp_secure", no, raw)

            elif line.startswith(self._KNOWN_PREFIXES):
                # Non-global config sections → not evaluated, not unknown
                continue
            else:
                unknown.append(_span(no, raw))

        config = CanonicalConfig(
            vendor="fortinet",
            platform="fortios",
            management_ssh_enabled=ssh,
            management_ssh_version=ssh_version,
            management_telnet_enabled=telnet,
            aaa_enabled=aaa,
            local_auth_fallback=local_fallback,
            password_policy_enabled=passwd_policy,
            privilege_separation=priv_sep,
            logging_enabled=logging,
            ntp_enabled=ntp,
            snmp_secure=snmp,
            snmp_community_exposed=snmp_community,
            http_management_enabled=http,
            mgmt_acl_enabled=mgmt_acl,
            evidence={k: tuple(v) for k, v in evidence.items()},
            unknown_blocks=tuple(unknown),
            metadata={"plugin_id": self.plugin_id},
        )
        return ParseResult(
            config=config,
            warnings=tuple(
                f"Unsupported FortiOS line at {s.start_line}" for s in unknown
            ),
            parser_version=self.parser_version,
        )


# ---------------------------------------------------------------------------
# Palo Alto PAN-OS
# Scope: device/system management settings only. High unknown rate by design.
# Security policy rules, App-ID, GlobalProtect: explicitly out of scope.
# ---------------------------------------------------------------------------

class PaloAltoParser:
    plugin_id = "paloalto"
    parser_version = "1.0.0"

    # PAN-OS set-form keywords that are out of scope (not unknown — explicitly acknowledged)
    _OUT_OF_SCOPE = (
        "set rulebase", "set address", "set application", "set service",
        "set zone", "set profiles", "set log-settings", "set shared",
        "set global-protect", "set panorama", "set predefined",
        "set network", "set routing", "set authentication-profile",
    )

    def detect(self, text: str) -> float:
        lowered = text.lower()
        score = 0.0
        if "set deviceconfig system" in lowered or "set mgt-config" in lowered:
            score += 0.55
        if "pan-os" in lowered or "palo-alto" in lowered or "pa-" in lowered:
            score += 0.25
        if re.search(r"<config>.*<devices>", lowered, re.DOTALL):
            score += 0.2
        if "set deviceconfig" in lowered:
            score += 0.15
        return min(score, 1.0)

    def parse(self, text: str) -> ParseResult:  # noqa: C901
        evidence: dict[str, list[EvidenceSpan]] = {}
        unknown: list[EvidenceSpan] = []

        ssh = telnet = http = ntp = logging = None
        mgmt_acl = passwd_policy = priv_sep = None
        snmp = None
        tls_ver: str | None = None

        for no, raw in enumerate(text.splitlines(), 1):
            line = raw.strip().lower()
            if not line or line.startswith("#"):
                continue

            # Skip explicitly out-of-scope sections
            if any(line.startswith(oos) for oos in self._OUT_OF_SCOPE):
                continue

            # SSH (PAN-OS set form)
            if "set deviceconfig system service disable-ssh yes" in line:
                ssh = False
                _add(evidence, "management_ssh_enabled", no, raw)
            elif "set deviceconfig system service disable-ssh no" in line:
                ssh = True
                _add(evidence, "management_ssh_enabled", no, raw)
            elif "set deviceconfig system service" in line and "ssh" in line and "disable-ssh" not in line:
                ssh = True
                _add(evidence, "management_ssh_enabled", no, raw)

            # Telnet
            elif "set deviceconfig system service disable-telnet yes" in line:
                telnet = False
                _add(evidence, "management_telnet_enabled", no, raw)
            elif "set deviceconfig system service disable-telnet no" in line:
                telnet = True
                _add(evidence, "management_telnet_enabled", no, raw)
            elif "set deviceconfig system service" in line and "telnet" in line and "disable-telnet" not in line:
                telnet = True
                _add(evidence, "management_telnet_enabled", no, raw)

            # HTTP management
            elif "set deviceconfig system service disable-http yes" in line:
                http = False
                _add(evidence, "http_management_enabled", no, raw)
            elif "set deviceconfig system service disable-http no" in line:
                http = True
                _add(evidence, "http_management_enabled", no, raw)
            elif "set deviceconfig system service" in line and "http" in line and "disable-http" not in line:
                http = True
                _add(evidence, "http_management_enabled", no, raw)

            # NTP
            elif "set deviceconfig system ntp-servers" in line:
                ntp = True
                _add(evidence, "ntp_enabled", no, raw)

            # Logging
            elif "set deviceconfig system log-export-schedule" in line:
                logging = True
                _add(evidence, "logging_enabled", no, raw)

            # TLS minimum version
            elif "set deviceconfig system ssl-tls-service-profile" in line:
                _add(evidence, "tls_minimum_version", no, raw)
            elif "tls1-0" in line or "tls1-1" in line:
                tls_ver = "1.0"
                _add(evidence, "weak_ciphers_found", no, raw)
            elif "tls1-2" in line:
                tls_ver = "1.2"
                _add(evidence, "tls_minimum_version", no, raw)

            # Management ACL
            elif "set deviceconfig system permitted-ip" in line:
                mgmt_acl = True
                _add(evidence, "mgmt_acl_enabled", no, raw)

            # Password policy
            elif "set mgt-config password-complexity" in line:
                passwd_policy = True
                _add(evidence, "password_policy_enabled", no, raw)

            # SNMP
            elif "set deviceconfig system snmpv3" in line:
                snmp = True
                _add(evidence, "snmp_secure", no, raw)

            # Known structural keywords — skip without flagging
            elif line.startswith((
                "set deviceconfig system hostname",
                "set deviceconfig system dns",
                "set deviceconfig system update-schedule",
                "set deviceconfig system timezone",
                "set deviceconfig system panorama",
                "set deviceconfig high-availability",
                "set deviceconfig setting",
            )):
                continue

            elif line.startswith("set deviceconfig"):
                # Catch-all for device config entries: not evaluated but not unknown
                continue

            else:
                unknown.append(_span(no, raw))

        config = CanonicalConfig(
            vendor="paloalto",
            platform="pan-os",
            management_ssh_enabled=ssh,
            management_telnet_enabled=telnet,
            http_management_enabled=http,
            ntp_enabled=ntp,
            logging_enabled=logging,
            snmp_secure=snmp,
            mgmt_acl_enabled=mgmt_acl,
            password_policy_enabled=passwd_policy,
            tls_minimum_version=tls_ver,
            evidence={k: tuple(v) for k, v in evidence.items()},
            unknown_blocks=tuple(unknown),
            metadata={"plugin_id": self.plugin_id},
        )
        return ParseResult(
            config=config,
            warnings=tuple(
                f"Unsupported PAN-OS line at {s.start_line}" for s in unknown
            ),
            parser_version=self.parser_version,
        )


# ---------------------------------------------------------------------------
# Parser Registry
# ---------------------------------------------------------------------------

PARSER_REGISTRY: tuple[VendorParser, ...] = (
    CiscoIOSParser(),
    JunosParser(),
    AristaEOSParser(),
    FortiGateParser(),
    PaloAltoParser(),
    LinuxNftablesParser(),
    GenericFirewallParser(),  # Must remain last — lowest-priority fallback
)


def detect_and_parse(text: str, vendor: str = "auto") -> ParseResult:
    candidates = [
        p for p in PARSER_REGISTRY if vendor == "auto" or p.plugin_id == vendor
    ]
    if not candidates:
        raise ValueError(f"unsupported vendor parser: {vendor}")
    if vendor == "auto":
        from .detection import detect_vendor

        detection = detect_vendor(text)
        if detection.selected_vendor is None:
            raise ValueError(f"unable to identify vendor safely: {detection.reason}")
        parser = next(
            item for item in candidates if item.plugin_id == detection.selected_vendor
        )
    else:
        parser = max(candidates, key=lambda p: p.detect(text))
    return parser.parse(text)
