"""Deterministic vendor parser plugins for the Phase 3 MVP scope."""

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


def _add(evidence: dict[str, list[EvidenceSpan]], key: str, line_no: int, line: str) -> None:
    evidence.setdefault(key, []).append(_span(line_no, line))


class CiscoIOSParser:
    plugin_id = "cisco_ios"
    parser_version = "3.0.0"

    def detect(self, text: str) -> float:
        score = 0.0
        lowered = text.lower()
        if "version " in lowered and ("hostname " in lowered or "interface " in lowered):
            score += 0.45
        if "line vty" in lowered or "transport input" in lowered:
            score += 0.35
        if "service password-encryption" in lowered or "aaa new-model" in lowered:
            score += 0.2
        return min(score, 1.0)

    def parse(self, text: str) -> ParseResult:
        evidence: dict[str, list[EvidenceSpan]] = {}
        unknown: list[EvidenceSpan] = []
        ssh = telnet = aaa = logging = ntp = snmp = http = unused = None
        ssh_version: str | None = None
        lines = text.splitlines()
        for no, raw in enumerate(lines, 1):
            line = raw.strip().lower()
            if not line or line.startswith("!"):
                continue
            if re.match(r"^ip ssh version 2$", line):
                ssh = True; ssh_version = "2"; _add(evidence, "management_ssh_version", no, raw)
            elif re.match(r"^ip ssh version 1(?:\.\d+)?$", line):
                ssh = True; ssh_version = "1"; _add(evidence, "management_ssh_version", no, raw)
            elif "transport input" in line:
                if "telnet" in line:
                    telnet = True; _add(evidence, "management_telnet_enabled", no, raw)
                if "ssh" in line:
                    ssh = True; _add(evidence, "management_ssh_enabled", no, raw)
            elif line == "no ip http server":
                http = False; _add(evidence, "http_management_enabled", no, raw)
            elif line == "ip http server":
                http = True; _add(evidence, "http_management_enabled", no, raw)
            elif line == "aaa new-model":
                aaa = True; _add(evidence, "aaa_enabled", no, raw)
            elif line.startswith("logging "):
                logging = True; _add(evidence, "logging_enabled", no, raw)
            elif line.startswith("ntp server "):
                ntp = True; _add(evidence, "ntp_enabled", no, raw)
            elif line.startswith("snmp-server group ") and " v3" in line:
                snmp = True; _add(evidence, "snmp_secure", no, raw)
            elif line == "no cdp run" or line == "no service pad":
                unused = True; _add(evidence, "unused_services_disabled", no, raw)
            elif line.startswith(("hostname ", "version ", "interface ", "line ", "router ", "ip ", "service ", "username ", "enable ", "banner ", "access-list ", "crypto ", "login ", "exec-timeout ", "transport ", "access-class ")):
                continue
            else:
                unknown.append(_span(no, raw))
        config = CanonicalConfig(
            vendor="cisco", platform="ios", management_ssh_enabled=ssh,
            management_ssh_version=ssh_version, management_telnet_enabled=telnet,
            aaa_enabled=aaa, logging_enabled=logging, ntp_enabled=ntp,
            snmp_secure=snmp, http_management_enabled=http,
            unused_services_disabled=unused, evidence={k: tuple(v) for k, v in evidence.items()},
            unknown_blocks=tuple(unknown), metadata={"plugin_id": self.plugin_id},
        )
        return ParseResult(config=config, warnings=tuple(f"Unsupported Cisco line at {s.start_line}" for s in unknown), parser_version=self.parser_version)


class JunosParser:
    plugin_id = "junos"
    parser_version = "3.0.0"

    def detect(self, text: str) -> float:
        lowered = text.lower()
        score = 0.0
        if "system {" in lowered and "services {" in lowered:
            score += 0.55
        if "set system services ssh" in lowered or "set system services telnet" in lowered:
            score += 0.35
        if any(line.strip().lower().startswith(("set ", "delete ", "replace ")) for line in text.splitlines()):
            score += 0.2
        if "set system authentication-order" in lowered:
            score += 0.1
        return min(score, 1.0)

    def parse(self, text: str) -> ParseResult:
        evidence: dict[str, list[EvidenceSpan]] = {}
        unknown: list[EvidenceSpan] = []
        ssh = telnet = aaa = logging = ntp = snmp = http = None
        ssh_version: str | None = None
        for no, raw in enumerate(text.splitlines(), 1):
            line = raw.strip().lower()
            if not line or line.startswith("#"):
                continue
            if line.startswith("set system services ssh"):
                ssh = True; _add(evidence, "management_ssh_enabled", no, raw)
                if "protocol-version v2" in line:
                    ssh_version = "2"; _add(evidence, "management_ssh_version", no, raw)
            elif line.startswith("set system services telnet"):
                telnet = True; _add(evidence, "management_telnet_enabled", no, raw)
            elif line.startswith("delete system services telnet"):
                telnet = False; _add(evidence, "management_telnet_enabled", no, raw)
            elif line.startswith("set system authentication-order"):
                aaa = True; _add(evidence, "aaa_enabled", no, raw)
            elif line.startswith("set system syslog"):
                logging = True; _add(evidence, "logging_enabled", no, raw)
            elif line.startswith("set system ntp"):
                ntp = True; _add(evidence, "ntp_enabled", no, raw)
            elif line.startswith("set snmp v3"):
                snmp = True; _add(evidence, "snmp_secure", no, raw)
            elif line.startswith("set system services web-management"):
                http = True; _add(evidence, "http_management_enabled", no, raw)
            elif line.startswith(("set ", "delete ", "replace ", "system {", "services {", "authentication-order", "ssh {", "telnet {", "syslog {", "ntp {", "snmp {", "}")):
                continue
            else:
                unknown.append(_span(no, raw))
        config = CanonicalConfig(
            vendor="juniper", platform="junos", management_ssh_enabled=ssh,
            management_ssh_version=ssh_version, management_telnet_enabled=telnet,
            aaa_enabled=aaa, logging_enabled=logging, ntp_enabled=ntp,
            snmp_secure=snmp, http_management_enabled=http,
            evidence={k: tuple(v) for k, v in evidence.items()}, unknown_blocks=tuple(unknown),
            metadata={"plugin_id": self.plugin_id},
        )
        return ParseResult(config=config, warnings=tuple(f"Unsupported Junos line at {s.start_line}" for s in unknown), parser_version=self.parser_version)


class GenericFirewallParser:
    plugin_id = "firewall_generic"
    parser_version = "3.0.0"

    def detect(self, text: str) -> float:
        lowered = text.lower()
        return 0.75 if any(token in lowered for token in ("firewall", "security-policy", "policy rule", "zone ")) else 0.0

    def parse(self, text: str) -> ParseResult:
        evidence: dict[str, list[EvidenceSpan]] = {}
        unknown: list[EvidenceSpan] = []
        telnet = ssh = http = None
        for no, raw in enumerate(text.splitlines(), 1):
            line = raw.strip().lower()
            if not line or line.startswith(("#", "!")):
                continue
            if "telnet" in line and ("enable" in line or "allow" in line):
                telnet = True; _add(evidence, "management_telnet_enabled", no, raw)
            elif "ssh" in line and ("enable" in line or "allow" in line):
                ssh = True; _add(evidence, "management_ssh_enabled", no, raw)
            elif "https" in line and "admin" in line:
                http = True; _add(evidence, "http_management_enabled", no, raw)
            else:
                unknown.append(_span(no, raw))
        config = CanonicalConfig(
            vendor="firewall", platform="generic", 
            management_telnet_enabled=telnet, management_ssh_enabled=ssh,
            http_management_enabled=http, evidence={k: tuple(v) for k, v in evidence.items()},
            unknown_blocks=tuple(unknown), metadata={"plugin_id": self.plugin_id},
        )
        return ParseResult(config=config, warnings=tuple(f"Unsupported firewall line at {s.start_line}" for s in unknown), parser_version=self.parser_version)


class AristaEOSParser(CiscoIOSParser):
    plugin_id = "arista_eos"
    parser_version = "3.1.0"

    def detect(self, text: str) -> float:
        lowered = text.lower()
        score = 0.0
        if "management api http-commands" in lowered or "daemon terminattr" in lowered:
            score += 0.6
        if re.search(r"^interface ethernet", lowered, re.MULTILINE) or "arista" in lowered:
            score += 0.3
        if "router bgp" in lowered:
            score += 0.1
        return min(score, 1.0)

    def parse(self, text: str) -> ParseResult:
        result = super().parse(text)
        config = replace(result.config, vendor="arista", platform="eos", metadata={"plugin_id": self.plugin_id})
        return replace(result, config=config, parser_version=self.parser_version)


class LinuxNftablesParser:
    plugin_id = "linux_nftables"
    parser_version = "3.1.0"

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
                ssh = True; _add(evidence, "management_ssh_enabled", no, raw)
            elif "tcp dport 23" in line and ("accept" in line or "allow" in line):
                telnet = True; _add(evidence, "management_telnet_enabled", no, raw)
            elif ("tcp dport 80" in line or "tcp dport 443" in line) and ("accept" in line or "allow" in line):
                http = True; _add(evidence, "http_management_enabled", no, raw)
            elif " log" in f" {line}" or line.startswith("log "):
                logging = True; _add(evidence, "logging_enabled", no, raw)
            elif line.startswith(("table ", "chain ", "type ", "policy ", "hook ", "priority ", "nft ", "flush ", "counter", "comment ", "ct ", "iif ", "oif ", "ip ", "ip6 ", "tcp ", "udp ", "accept", "drop", "return", "jump ", "include ", "}")):
                continue
            else:
                unknown.append(_span(no, raw))
        config = CanonicalConfig(
            vendor="linux", platform="nftables", management_ssh_enabled=ssh,
            management_telnet_enabled=telnet, logging_enabled=logging,
            http_management_enabled=http, evidence={k: tuple(v) for k, v in evidence.items()},
            unknown_blocks=tuple(unknown), metadata={"plugin_id": self.plugin_id},
        )
        return ParseResult(config=config, warnings=tuple(f"Unsupported nftables line at {s.start_line}" for s in unknown), parser_version=self.parser_version)


PARSER_REGISTRY: tuple[VendorParser, ...] = (CiscoIOSParser(), JunosParser(), GenericFirewallParser(), AristaEOSParser(), LinuxNftablesParser())


def detect_and_parse(text: str, vendor: str = "auto") -> ParseResult:
    candidates = [p for p in PARSER_REGISTRY if vendor == "auto" or p.plugin_id == vendor]
    if not candidates:
        raise ValueError(f"unsupported vendor parser: {vendor}")
    if vendor == "auto":
        from .detection import detect_vendor
        detection = detect_vendor(text)
        if detection.selected_vendor is None:
            raise ValueError(f"unable to identify vendor safely: {detection.reason}")
        parser = next(item for item in candidates if item.plugin_id == detection.selected_vendor)
    else:
        parser = max(candidates, key=lambda p: p.detect(text))
    return parser.parse(text)
