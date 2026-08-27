"""Deterministic compliance control engine and initial control pack."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .canonical import CanonicalConfig
from .models import Control, EvidenceSpan, Finding, FindingStatus, Severity


@dataclass(frozen=True)
class ControlDefinition:
    control: Control
    check: Callable[[CanonicalConfig], tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]]
    remediation: str


def _check_ssh(config: CanonicalConfig) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    spans = config.spans_for("management_ssh_enabled") + config.spans_for("management_ssh_version")
    if config.management_ssh_enabled is True and config.management_ssh_version in {None, "1"}:
        return FindingStatus.FAIL, "SSH is enabled without an explicitly secure SSH version.", spans
    if config.management_ssh_enabled is True and config.management_ssh_version == "2":
        return FindingStatus.PASS, "SSH is enabled with SSH version 2 evidence.", spans
    return FindingStatus.UNKNOWN, "Secure SSH state could not be determined from parsed configuration.", spans


def _check_telnet(config: CanonicalConfig) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    spans = config.spans_for("management_telnet_enabled")
    if config.management_telnet_enabled is True:
        return FindingStatus.FAIL, "Telnet management access is enabled.", spans
    if config.management_telnet_enabled is False:
        return FindingStatus.PASS, "Telnet is explicitly disabled.", spans
    return FindingStatus.UNKNOWN, "Telnet state could not be determined from parsed configuration.", spans


def _check_aaa(config: CanonicalConfig) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    spans = config.spans_for("aaa_enabled")
    if config.aaa_enabled is True:
        return FindingStatus.PASS, "AAA configuration evidence was found.", spans
    if config.aaa_enabled is False:
        return FindingStatus.FAIL, "AAA is explicitly disabled.", spans
    return FindingStatus.UNKNOWN, "AAA state could not be determined.", spans


def _check_logging(config: CanonicalConfig) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    spans = config.spans_for("logging_enabled")
    if config.logging_enabled is True:
        return FindingStatus.PASS, "Logging configuration evidence was found.", spans
    return FindingStatus.UNKNOWN, "Centralized logging state could not be determined.", spans


def _check_ntp(config: CanonicalConfig) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    spans = config.spans_for("ntp_enabled")
    if config.ntp_enabled is True:
        return FindingStatus.PASS, "NTP configuration evidence was found.", spans
    return FindingStatus.UNKNOWN, "NTP state could not be determined.", spans


def _check_snmp(config: CanonicalConfig) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    spans = config.spans_for("snmp_secure")
    if config.snmp_secure is True:
        return FindingStatus.PASS, "Secure SNMP evidence was found.", spans
    return FindingStatus.UNKNOWN, "Secure SNMP state could not be determined.", spans


def _check_http(config: CanonicalConfig) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    spans = config.spans_for("http_management_enabled")
    if config.http_management_enabled is True:
        return FindingStatus.FAIL, "Plain HTTP management is enabled.", spans
    if config.http_management_enabled is False:
        return FindingStatus.PASS, "Plain HTTP management is explicitly disabled.", spans
    return FindingStatus.UNKNOWN, "HTTP management state could not be determined.", spans


CONTROL_PACK_VERSION = "3.0.0"

CONTROL_PACK: tuple[ControlDefinition, ...] = (
    ControlDefinition(Control("NET-MGMT-SSH-001", "Secure remote administration", "Require secure SSH management and SSHv2.", Severity.HIGH, {"cis": ("NET-MGMT-SSH-001",), "nist_800_53": ("AC-17", "SC-8")}, ("cisco_ios", "junos", "firewall_generic"), CONTROL_PACK_VERSION), _check_ssh, "Enable SSHv2 and remove legacy SSH versions after change review."),
    ControlDefinition(Control("NET-MGMT-TELNET-001", "Disable Telnet management", "Prohibit insecure Telnet administration.", Severity.CRITICAL, {"cis": ("NET-MGMT-TELNET-001",), "nist_800_53": ("AC-17",)}, ("cisco_ios", "junos", "firewall_generic"), CONTROL_PACK_VERSION), _check_telnet, "Disable Telnet and retain secure management access."),
    ControlDefinition(Control("NET-AUTH-AAA-001", "Centralized authentication", "Use AAA or an approved centralized access-control mechanism.", Severity.HIGH, {"nist_800_53": ("IA-2", "AC-2")}, ("cisco_ios", "junos"), CONTROL_PACK_VERSION), _check_aaa, "Configure approved AAA with a tested break-glass process."),
    ControlDefinition(Control("NET-LOG-001", "Security logging", "Enable security-relevant logging for auditability.", Severity.MEDIUM, {"nist_800_53": ("AU-2", "AU-12")}, ("cisco_ios", "junos"), CONTROL_PACK_VERSION), _check_logging, "Enable approved logging and route events to a protected collector."),
    ControlDefinition(Control("NET-TIME-001", "Consistent network time", "Configure network time for reliable event correlation.", Severity.MEDIUM, {"nist_800_53": ("AU-8",)}, ("cisco_ios", "junos"), CONTROL_PACK_VERSION), _check_ntp, "Configure approved NTP sources and authentication where supported."),
    ControlDefinition(Control("NET-SNMP-001", "Secure monitoring protocol", "Avoid insecure SNMP configurations.", Severity.HIGH, {"nist_800_53": ("SC-8",)}, ("cisco_ios", "junos"), CONTROL_PACK_VERSION), _check_snmp, "Use SNMPv3 or an approved secure telemetry alternative."),
    ControlDefinition(Control("NET-MGMT-HTTP-001", "Disable plain HTTP administration", "Prohibit unencrypted web management.", Severity.HIGH, {"cis": ("NET-MGMT-HTTP-001",), "nist_800_53": ("SC-8",)}, ("cisco_ios", "junos", "firewall_generic"), CONTROL_PACK_VERSION), _check_http, "Disable plain HTTP management and use approved TLS settings."),
)


def evaluate(config: CanonicalConfig, audit_id: str) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for definition in CONTROL_PACK:
        if config.platform not in {"ios", "junos", "generic"}:
            status = FindingStatus.NOT_APPLICABLE
            rationale = "Platform is outside the control pack applicability set."
            spans: tuple[EvidenceSpan, ...] = ()
        else:
            status, rationale, spans = definition.check(config)
        confidence = 1.0 if status in {FindingStatus.PASS, FindingStatus.FAIL} else 0.0
        findings.append(Finding(
            finding_id=f"{audit_id}:{definition.control.control_id}", audit_id=audit_id,
            control_id=definition.control.control_id, status=status,
            severity=definition.control.severity, confidence=confidence,
            evidence=spans, observed_state=rationale,
            expected_state=definition.control.intent, rationale=rationale,
            remediation_preview=definition.remediation,
        ))
    return tuple(findings)
