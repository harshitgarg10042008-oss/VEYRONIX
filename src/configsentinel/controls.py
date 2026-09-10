"""Deterministic compliance control engine — Phase 4 expanded control pack.

Control pack version: 4.0.0
Control families:
  - Management plane (NET-MGMT-*)
  - Identity and access (NET-AUTH-*)
  - Cryptography (NET-CRYPTO-*)
  - Network protection (NET-PROT-*)
  - Logging and monitoring (NET-LOG-*)
  - SNMP and telemetry (NET-SNMP-*)
  - Segmentation (NET-SEG-*)
  - Resilience (NET-RES-*)
  - Change governance (NET-GOV-*)
  - Secrets (NET-SEC-*)

Design invariants:
  - Every check returns (FindingStatus, rationale, evidence_spans).
  - UNKNOWN is semantically different from PASS/FAIL — do not conflate.
  - AI may not change the status returned by any check function.
  - Adding a control requires positive, negative, unknown, and NA fixtures.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .canonical import CanonicalConfig
from .models import Control, EvidenceSpan, Finding, FindingStatus, Severity


@dataclass(frozen=True)
class ControlDefinition:
    control: Control
    check: Callable[
        [CanonicalConfig], tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]
    ]
    remediation: str


CONTROL_PACK_VERSION = "4.0.0"

# All vendors currently in the parser registry
_ALL_VENDORS = (
    "cisco_ios", "junos", "arista_eos", "fortigate", "paloalto",
    "linux_nftables", "firewall_generic",
)
_ROUTED_VENDORS = ("cisco_ios", "junos", "arista_eos", "fortigate", "paloalto")
_LINUX_VENDORS = ("linux_nftables",)


# ===========================================================================
# Helper
# ===========================================================================

def _u(rationale: str, spans: tuple[EvidenceSpan, ...]) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    return FindingStatus.UNKNOWN, rationale, spans


def _p(rationale: str, spans: tuple[EvidenceSpan, ...]) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    return FindingStatus.PASS, rationale, spans


def _f(rationale: str, spans: tuple[EvidenceSpan, ...]) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    return FindingStatus.FAIL, rationale, spans


# ===========================================================================
# Management plane checks
# ===========================================================================

def _check_ssh(config: CanonicalConfig) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    spans = config.spans_for("management_ssh_enabled") + config.spans_for("management_ssh_version")
    if config.management_ssh_enabled is True and config.management_ssh_version in {None, "1"}:
        return _f("SSH is enabled without an explicitly secure SSH version (SSHv2 not confirmed).", spans)
    if config.management_ssh_enabled is True and config.management_ssh_version == "2":
        return _p("SSH is enabled with SSHv2 evidence.", spans)
    return _u("Secure SSH state could not be determined from parsed configuration.", spans)


def _check_telnet(config: CanonicalConfig) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    spans = config.spans_for("management_telnet_enabled")
    if config.management_telnet_enabled is True:
        return _f("Telnet management access is enabled — unencrypted protocol.", spans)
    if config.management_telnet_enabled is False:
        return _p("Telnet is explicitly disabled.", spans)
    return _u("Telnet state could not be determined from parsed configuration.", spans)


def _check_http(config: CanonicalConfig) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    spans = config.spans_for("http_management_enabled")
    if config.http_management_enabled is True:
        return _f("Plain HTTP management is enabled — unencrypted access channel.", spans)
    if config.http_management_enabled is False:
        return _p("Plain HTTP management is explicitly disabled.", spans)
    return _u("HTTP management state could not be determined.", spans)


def _check_restconf(config: CanonicalConfig) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    spans = config.spans_for("restconf_enabled")
    if config.restconf_enabled is True:
        # RESTCONF/NETCONF presence is informational — flag for review, not auto-fail
        return FindingStatus.REVIEW_REQUIRED, "RESTCONF/NETCONF is enabled. Verify TLS and access control.", spans
    return _u("RESTCONF/NETCONF state could not be determined from parsed configuration.", spans)


def _check_mgmt_acl(config: CanonicalConfig) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    spans = config.spans_for("mgmt_acl_enabled")
    if config.mgmt_acl_enabled is True:
        return _p("Management ACL or source restriction is configured.", spans)
    return _u("Management ACL state could not be determined. Consider adding source restrictions.", spans)


# ===========================================================================
# Identity and access checks
# ===========================================================================

def _check_aaa(config: CanonicalConfig) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    spans = config.spans_for("aaa_enabled")
    if config.aaa_enabled is True:
        return _p("AAA configuration evidence was found.", spans)
    if config.aaa_enabled is False:
        return _f("AAA is explicitly disabled.", spans)
    return _u("AAA state could not be determined.", spans)


def _check_local_fallback(config: CanonicalConfig) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    spans = config.spans_for("local_auth_fallback")
    if config.local_auth_fallback is True:
        return _p("Local authentication fallback (break-glass) account evidence found.", spans)
    return _u("Local authentication fallback state could not be determined.", spans)


def _check_password_policy(config: CanonicalConfig) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    spans = config.spans_for("password_policy_enabled")
    if config.password_policy_enabled is True:
        return _p("Password policy configuration evidence found.", spans)
    return _u("Password policy state could not be determined from configuration.", spans)


def _check_privilege_separation(config: CanonicalConfig) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    spans = config.spans_for("privilege_separation")
    if config.privilege_separation is True:
        return _p("Privilege separation evidence found.", spans)
    return _u("Privilege separation state could not be determined.", spans)


# ===========================================================================
# Cryptography checks
# ===========================================================================

def _check_tls_version(config: CanonicalConfig) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    spans = config.spans_for("tls_minimum_version") + config.spans_for("weak_ciphers_found")
    if config.tls_minimum_version in {"1.0", "1.1"}:
        return _f(f"TLS minimum version is {config.tls_minimum_version} — deprecated and insecure.", spans)
    if config.tls_minimum_version in {"1.2", "1.3"}:
        return _p(f"TLS minimum version is {config.tls_minimum_version} — acceptable.", spans)
    return _u("TLS minimum version could not be determined.", spans)


def _check_weak_ciphers(config: CanonicalConfig) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    spans = config.spans_for("weak_ciphers_found")
    if config.weak_ciphers_found is True:
        return _f("Weak or deprecated cipher/protocol references found (DES/3DES/RC4/MD5/SSLv3/TLS1.0).", spans)
    if config.weak_ciphers_found is False:
        return _p("No weak cipher evidence found.", spans)
    return _u("Cipher configuration could not be determined.", spans)


# ===========================================================================
# Logging and monitoring checks
# ===========================================================================

def _check_logging(config: CanonicalConfig) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    spans = config.spans_for("logging_enabled")
    if config.logging_enabled is True:
        return _p("Logging configuration evidence was found.", spans)
    return _u("Centralized logging state could not be determined.", spans)


def _check_ntp(config: CanonicalConfig) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    spans = config.spans_for("ntp_enabled")
    if config.ntp_enabled is True:
        return _p("NTP configuration evidence was found.", spans)
    return _u("NTP state could not be determined.", spans)


# ===========================================================================
# SNMP and telemetry checks
# ===========================================================================

def _check_snmp(config: CanonicalConfig) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    spans = config.spans_for("snmp_secure")
    if config.snmp_secure is True:
        return _p("Secure SNMP evidence was found (SNMPv3 or encrypted telemetry).", spans)
    return _u("Secure SNMP state could not be determined.", spans)


def _check_snmp_community(config: CanonicalConfig) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    spans = config.spans_for("snmp_community_exposed")
    if config.snmp_community_exposed is True:
        return _f("Plaintext SNMP community string is configured — SNMPv1/v2c exposure.", spans)
    if config.snmp_community_exposed is False:
        return _p("No plaintext SNMP community strings found.", spans)
    return _u("SNMP community string state could not be determined.", spans)


# ===========================================================================
# Network protection checks
# ===========================================================================

def _check_anti_spoofing(config: CanonicalConfig) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    spans = config.spans_for("anti_spoofing_enabled")
    if config.anti_spoofing_enabled is True:
        return _p("Anti-spoofing (uRPF or equivalent) evidence found.", spans)
    return _u("Anti-spoofing configuration could not be determined.", spans)


def _check_acl_hygiene(config: CanonicalConfig) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    spans = config.spans_for("acl_hygiene")
    if config.acl_hygiene is False:
        return _f("ACL contains overly permissive rules (e.g., permit any any).", spans)
    if config.acl_hygiene is True:
        return _p("ACL hygiene evidence found — no obvious permit any any.", spans)
    return _u("ACL hygiene could not be assessed.", spans)


# ===========================================================================
# Segmentation checks
# ===========================================================================

def _check_mgmt_plane_separation(config: CanonicalConfig) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    spans = config.spans_for("mgmt_plane_separated")
    if config.mgmt_plane_separated is True:
        return _p("Management/data-plane separation evidence found.", spans)
    return _u("Management plane separation could not be determined.", spans)


def _check_default_deny(config: CanonicalConfig) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    spans = config.spans_for("default_deny_posture")
    if config.default_deny_posture is True:
        return _p("Default-deny posture evidence found.", spans)
    if config.default_deny_posture is False:
        return _f("No default-deny posture found — implicit permit may exist.", spans)
    return _u("Default-deny posture could not be determined.", spans)


# ===========================================================================
# Resilience checks
# ===========================================================================

def _check_backup(config: CanonicalConfig) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    spans = config.spans_for("config_backup_enabled")
    if config.config_backup_enabled is True:
        return _p("Configuration backup mechanism evidence found.", spans)
    return _u("Configuration backup state could not be determined.", spans)


def _check_unused_services(config: CanonicalConfig) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    spans = config.spans_for("unused_services_disabled")
    if config.unused_services_disabled is True:
        return _p("Unused services (e.g., CDP, pad) are disabled.", spans)
    return _u("Unused service state could not be determined.", spans)


# ===========================================================================
# Secrets checks
# ===========================================================================

def _check_plaintext_credentials(config: CanonicalConfig) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    spans = config.spans_for("plaintext_credentials_found")
    if config.plaintext_credentials_found is True:
        return _f("Plaintext credentials or unsalted passwords found in configuration.", spans)
    if config.plaintext_credentials_found is False:
        return _p("No plaintext credential evidence found.", spans)
    return _u("Credential encryption state could not be determined.", spans)


def _check_private_key(config: CanonicalConfig) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    spans = config.spans_for("private_key_in_config")
    if config.private_key_in_config is True:
        return _f("Private key material found embedded in configuration — must be removed.", spans)
    if config.private_key_in_config is False:
        return _p("No private key material found in configuration.", spans)
    return _u("Private key presence could not be determined.", spans)


# ===========================================================================
# Change governance checks
# ===========================================================================

def _check_config_owner(config: CanonicalConfig) -> tuple[FindingStatus, str, tuple[EvidenceSpan, ...]]:
    spans = config.spans_for("config_owner_metadata")
    if config.config_owner_metadata is True:
        return _p("Configuration owner metadata evidence found.", spans)
    return _u("Configuration owner/contact metadata could not be determined.", spans)


# ===========================================================================
# Control Pack Definition
# ===========================================================================

CONTROL_PACK: tuple[ControlDefinition, ...] = (
    # --- Management plane ---
    ControlDefinition(
        Control(
            "NET-MGMT-SSH-001",
            "Secure remote administration (SSHv2)",
            "Require SSHv2 for all remote management sessions.",
            Severity.HIGH,
            {
                "cis-network": ("NET-MGMT-SSH-001",),
                "nist-800-53": ("AC-17", "SC-8"),
                "iso-27001-2022": ("A.8.19",),
                "pci-dss-4-0-1": ("4.2.1", "8.2.1"),
                "nist-csf-2": ("PR.DS-02",),
            },
            _ALL_VENDORS,
            CONTROL_PACK_VERSION,
        ),
        _check_ssh,
        "Enable SSHv2 explicitly. Disable SSHv1. Restrict VTY lines to SSH only after change review.",
    ),
    ControlDefinition(
        Control(
            "NET-MGMT-TELNET-001",
            "Disable Telnet management",
            "Prohibit insecure Telnet administration on all interfaces.",
            Severity.CRITICAL,
            {
                "cis-network": ("NET-MGMT-TELNET-001",),
                "nist-800-53": ("AC-17",),
                "iso-27001-2022": ("A.8.19",),
                "pci-dss-4-0-1": ("4.2.1", "2.2.3"),
                "hipaa-security-rule": ("164.312(e)(1)",),
            },
            _ALL_VENDORS,
            CONTROL_PACK_VERSION,
        ),
        _check_telnet,
        "Disable Telnet on all interfaces and VTY lines. Confirm break-glass access is preserved via SSH.",
    ),
    ControlDefinition(
        Control(
            "NET-MGMT-HTTP-001",
            "Disable plain HTTP administration",
            "Prohibit unencrypted web management access.",
            Severity.HIGH,
            {
                "cis-network": ("NET-MGMT-HTTP-001",),
                "nist-800-53": ("SC-8",),
                "iso-27001-2022": ("A.8.19",),
                "pci-dss-4-0-1": ("4.2.1", "2.2.3"),
                "nist-csf-2": ("PR.DS-02",),
            },
            _ALL_VENDORS,
            CONTROL_PACK_VERSION,
        ),
        _check_http,
        "Disable plain HTTP management. Enable HTTPS-only with approved TLS settings.",
    ),
    ControlDefinition(
        Control(
            "NET-MGMT-RESTCONF-001",
            "Restrict REST/NETCONF management access",
            "RESTCONF and NETCONF must use TLS and be access-controlled.",
            Severity.MEDIUM,
            {
                "nist-800-53": ("AC-17", "SC-8"),
                "iso-27001-2022": ("A.8.19",),
                "nist-csf-2": ("PR.DS-02",),
            },
            ("cisco_ios", "arista_eos", "paloalto"),
            CONTROL_PACK_VERSION,
        ),
        _check_restconf,
        "Verify RESTCONF/NETCONF uses TLS 1.2+ and is bound to a management ACL.",
    ),
    ControlDefinition(
        Control(
            "NET-MGMT-ACL-001",
            "Management source restriction (ACL)",
            "Restrict management plane access to approved source addresses.",
            Severity.HIGH,
            {
                "cis-network": ("NET-MGMT-ACL-001",),
                "nist-800-53": ("AC-3", "AC-17"),
                "iso-27001-2022": ("A.9.4.2",),
                "pci-dss-4-0-1": ("1.2.1",),
            },
            _ROUTED_VENDORS,
            CONTROL_PACK_VERSION,
        ),
        _check_mgmt_acl,
        "Apply an access-class or trusted-host list to all management interfaces and VTY lines.",
    ),
    # --- Identity and access ---
    ControlDefinition(
        Control(
            "NET-AUTH-AAA-001",
            "Centralized authentication (AAA)",
            "Use AAA or an approved centralized authentication mechanism.",
            Severity.HIGH,
            {
                "nist-800-53": ("IA-2", "AC-2"),
                "iso-27001-2022": ("A.9.2.1",),
                "pci-dss-4-0-1": ("8.2.1",),
                "nist-csf-2": ("PR.AA-01",),
            },
            ("cisco_ios", "junos", "arista_eos", "fortigate"),
            CONTROL_PACK_VERSION,
        ),
        _check_aaa,
        "Configure approved AAA (TACACS+ or RADIUS). Test break-glass local access before deployment.",
    ),
    ControlDefinition(
        Control(
            "NET-AUTH-LOCAL-001",
            "Local authentication fallback",
            "Maintain a tested break-glass local account for recovery.",
            Severity.MEDIUM,
            {
                "nist-800-53": ("IA-2", "CP-10"),
                "iso-27001-2022": ("A.9.2.3",),
                "nist-csf-2": ("PR.AA-01",),
            },
            _ROUTED_VENDORS,
            CONTROL_PACK_VERSION,
        ),
        _check_local_fallback,
        "Configure a local privileged account with a strong password stored in a secrets vault.",
    ),
    ControlDefinition(
        Control(
            "NET-AUTH-PWPOL-001",
            "Password complexity and length policy",
            "Enforce minimum password complexity, length, and rotation.",
            Severity.MEDIUM,
            {
                "nist-800-53": ("IA-5",),
                "iso-27001-2022": ("A.9.4.3",),
                "pci-dss-4-0-1": ("8.3.6",),
                "nist-csf-2": ("PR.AA-01",),
            },
            _ROUTED_VENDORS,
            CONTROL_PACK_VERSION,
        ),
        _check_password_policy,
        "Configure minimum password length ≥ 12, complexity rules, and account lockout.",
    ),
    ControlDefinition(
        Control(
            "NET-AUTH-PRIV-001",
            "Privilege separation and least privilege",
            "Assign distinct privilege levels; avoid shared admin accounts.",
            Severity.HIGH,
            {
                "nist-800-53": ("AC-6",),
                "iso-27001-2022": ("A.9.2.3",),
                "pci-dss-4-0-1": ("7.2.1",),
                "nist-csf-2": ("PR.AA-05",),
            },
            _ROUTED_VENDORS,
            CONTROL_PACK_VERSION,
        ),
        _check_privilege_separation,
        "Define operator, read-only, and admin privilege levels. Remove shared accounts.",
    ),
    # --- Cryptography ---
    ControlDefinition(
        Control(
            "NET-CRYPTO-TLS-001",
            "Minimum TLS version",
            "Enforce TLS 1.2 or higher for all management and data channels.",
            Severity.HIGH,
            {
                "nist-800-53": ("SC-8", "SC-28"),
                "iso-27001-2022": ("A.8.24",),
                "pci-dss-4-0-1": ("4.2.1",),
                "nist-csf-2": ("PR.DS-02",),
            },
            _ROUTED_VENDORS,
            CONTROL_PACK_VERSION,
        ),
        _check_tls_version,
        "Set minimum TLS to 1.2. Disable TLS 1.0/1.1 and all SSL versions.",
    ),
    ControlDefinition(
        Control(
            "NET-CRYPTO-CIPHER-001",
            "No weak ciphers or deprecated protocols",
            "Disable DES, 3DES, RC4, MD5, SSLv3, TLS 1.0, and TLS 1.1.",
            Severity.HIGH,
            {
                "nist-800-53": ("SC-8", "SC-13"),
                "iso-27001-2022": ("A.8.24",),
                "pci-dss-4-0-1": ("4.2.1",),
                "nist-csf-2": ("PR.DS-02",),
            },
            _ROUTED_VENDORS,
            CONTROL_PACK_VERSION,
        ),
        _check_weak_ciphers,
        "Remove weak cipher suites. Enforce AES-128+ with SHA-256+ for HMAC.",
    ),
    # --- Logging and monitoring ---
    ControlDefinition(
        Control(
            "NET-LOG-001",
            "Security logging enabled",
            "Enable security-relevant logging to a protected remote collector.",
            Severity.MEDIUM,
            {
                "nist-800-53": ("AU-2", "AU-12"),
                "iso-27001-2022": ("A.12.4.1",),
                "pci-dss-4-0-1": ("10.2.1",),
                "nist-csf-2": ("DE.AE-03",),
                "hipaa-security-rule": ("164.312(b)",),
            },
            tuple(v for v in _ALL_VENDORS if v != "firewall_generic"),
            CONTROL_PACK_VERSION,
        ),
        _check_logging,
        "Enable logging to a remote syslog server. Set minimum severity. Protect the collector.",
    ),
    ControlDefinition(
        Control(
            "NET-TIME-001",
            "Consistent network time (NTP)",
            "Configure authenticated NTP for reliable event correlation.",
            Severity.MEDIUM,
            {
                "nist-800-53": ("AU-8",),
                "iso-27001-2022": ("A.12.4.4",),
                "pci-dss-4-0-1": ("10.4",),
            },
            _ROUTED_VENDORS,
            CONTROL_PACK_VERSION,
        ),
        _check_ntp,
        "Configure approved NTP sources. Enable NTP authentication where supported.",
    ),
    # --- SNMP and telemetry ---
    ControlDefinition(
        Control(
            "NET-SNMP-001",
            "Secure monitoring protocol (SNMPv3)",
            "Use SNMPv3 with authentication and encryption, or a secure telemetry alternative.",
            Severity.HIGH,
            {
                "nist-800-53": ("SC-8",),
                "iso-27001-2022": ("A.8.19",),
                "pci-dss-4-0-1": ("4.2.1",),
            },
            _ROUTED_VENDORS,
            CONTROL_PACK_VERSION,
        ),
        _check_snmp,
        "Migrate to SNMPv3 with authPriv mode or disable SNMP and use encrypted telemetry.",
    ),
    ControlDefinition(
        Control(
            "NET-SNMP-COMMUNITY-001",
            "No plaintext SNMP community strings",
            "Remove or restrict SNMPv1/v2c community strings.",
            Severity.CRITICAL,
            {
                "nist-800-53": ("SC-8", "IA-3"),
                "iso-27001-2022": ("A.8.19",),
                "pci-dss-4-0-1": ("4.2.1",),
                "nist-csf-2": ("PR.DS-02",),
            },
            _ROUTED_VENDORS,
            CONTROL_PACK_VERSION,
        ),
        _check_snmp_community,
        "Remove all SNMPv1/v2c community strings. If SNMP is needed, use SNMPv3 authPriv.",
    ),
    # --- Network protection ---
    ControlDefinition(
        Control(
            "NET-PROT-SPOOF-001",
            "Anti-spoofing (uRPF or equivalent)",
            "Enable unicast reverse-path forwarding or equivalent to prevent spoofed traffic.",
            Severity.MEDIUM,
            {
                "nist-800-53": ("SC-5",),
                "iso-27001-2022": ("A.8.20",),
                "nist-csf-2": ("PR.DS-01",),
            },
            ("cisco_ios", "arista_eos", "junos"),
            CONTROL_PACK_VERSION,
        ),
        _check_anti_spoofing,
        "Enable `ip verify unicast source` (Cisco) or equivalent on all WAN-facing interfaces.",
    ),
    ControlDefinition(
        Control(
            "NET-PROT-ACL-001",
            "ACL hygiene — no implicit permit all",
            "Access control lists must not contain overly permissive permit any any rules.",
            Severity.HIGH,
            {
                "nist-800-53": ("AC-3", "AC-4"),
                "iso-27001-2022": ("A.8.20",),
                "pci-dss-4-0-1": ("1.2.1",),
            },
            _ROUTED_VENDORS,
            CONTROL_PACK_VERSION,
        ),
        _check_acl_hygiene,
        "Review all ACLs. Remove or narrow overly permissive entries. End with an explicit deny.",
    ),
    # --- Segmentation ---
    ControlDefinition(
        Control(
            "NET-SEG-MGMT-001",
            "Management / data-plane separation",
            "Separate management traffic from production traffic via VRF or dedicated interface.",
            Severity.HIGH,
            {
                "nist-800-53": ("SC-3", "SC-32"),
                "iso-27001-2022": ("A.8.22",),
                "nist-csf-2": ("PR.PS-04",),
            },
            ("cisco_ios", "junos", "arista_eos"),
            CONTROL_PACK_VERSION,
        ),
        _check_mgmt_plane_separation,
        "Use a dedicated management VRF or out-of-band management network.",
    ),
    ControlDefinition(
        Control(
            "NET-SEG-DENY-001",
            "Default-deny network posture",
            "Firewall and ACL policies must end with an implicit or explicit deny-all.",
            Severity.HIGH,
            {
                "nist-800-53": ("AC-4",),
                "iso-27001-2022": ("A.8.20",),
                "pci-dss-4-0-1": ("1.2.1",),
                "nist-csf-2": ("PR.DS-01",),
            },
            ("fortigate", "paloalto", "linux_nftables", "firewall_generic"),
            CONTROL_PACK_VERSION,
        ),
        _check_default_deny,
        "Ensure all policy sets end with an explicit deny-all rule.",
    ),
    # --- Resilience ---
    ControlDefinition(
        Control(
            "NET-RES-BACKUP-001",
            "Configuration backup enabled",
            "Automated configuration backup must be configured and tested.",
            Severity.MEDIUM,
            {
                "nist-800-53": ("CP-9",),
                "iso-27001-2022": ("A.12.3.1",),
                "nist-csf-2": ("PR.DS-11",),
            },
            ("cisco_ios", "junos", "arista_eos"),
            CONTROL_PACK_VERSION,
        ),
        _check_backup,
        "Enable archive/log config or integrate with an approved configuration management system.",
    ),
    ControlDefinition(
        Control(
            "NET-RES-UNUSED-001",
            "Unused services disabled",
            "Disable unnecessary protocols and services to reduce attack surface.",
            Severity.LOW,
            {
                "cis-network": ("NET-RES-UNUSED-001",),
                "nist-800-53": ("CM-7",),
                "iso-27001-2022": ("A.8.19",),
                "pci-dss-4-0-1": ("2.2.1",),
            },
            ("cisco_ios", "arista_eos"),
            CONTROL_PACK_VERSION,
        ),
        _check_unused_services,
        "Disable CDP, IP source route, PAD, and other unused services.",
    ),
    # --- Secrets ---
    ControlDefinition(
        Control(
            "NET-SEC-PLAIN-001",
            "No plaintext credentials in configuration",
            "Passwords and shared secrets must be encrypted or hashed in stored configuration.",
            Severity.CRITICAL,
            {
                "cis-network": ("NET-SEC-PLAIN-001",),
                "nist-800-53": ("IA-5", "SC-28"),
                "iso-27001-2022": ("A.9.4.3",),
                "pci-dss-4-0-1": ("8.3.1",),
                "nist-csf-2": ("PR.DS-01",),
            },
            _ROUTED_VENDORS,
            CONTROL_PACK_VERSION,
        ),
        _check_plaintext_credentials,
        "Enable `service password-encryption` (Cisco) or equivalent. Migrate to hashed secrets (type 9).",
    ),
    ControlDefinition(
        Control(
            "NET-SEC-KEY-001",
            "No private key material in configuration",
            "Private keys must not be stored in device running-configuration exports.",
            Severity.CRITICAL,
            {
                "nist-800-53": ("SC-28", "SC-12"),
                "iso-27001-2022": ("A.8.24",),
                "pci-dss-4-0-1": ("3.5.1",),
                "nist-csf-2": ("PR.DS-01",),
            },
            _ROUTED_VENDORS,
            CONTROL_PACK_VERSION,
        ),
        _check_private_key,
        "Remove private key material from configuration exports. Store keys in a hardware security module.",
    ),
    # --- Change governance ---
    ControlDefinition(
        Control(
            "NET-GOV-OWNER-001",
            "Configuration owner metadata",
            "Every configuration must declare an owner, team, and contact for accountability.",
            Severity.INFO,
            {
                "nist-800-53": ("PL-2",),
                "iso-27001-2022": ("A.5.9",),
            },
            _ALL_VENDORS,
            CONTROL_PACK_VERSION,
        ),
        _check_config_owner,
        "Add an owner banner or comment block to the configuration header with team and contact.",
    ),
)


def evaluate(config: CanonicalConfig, audit_id: str) -> tuple[Finding, ...]:
    """Evaluate all applicable controls against a canonical configuration.

    Controls not applicable to the detected platform are marked NOT_APPLICABLE.
    This function never calls AI and never changes UNKNOWN to PASS or FAIL.
    """
    findings: list[Finding] = []
    platform = config.platform

    for definition in CONTROL_PACK:
        applies = (
            config.metadata.get("plugin_id", "") in definition.control.applies_to
            or platform in {"ios", "junos", "generic", "eos", "nftables", "fortios", "pan-os"}
        ) and (
            config.metadata.get("plugin_id", "") in definition.control.applies_to
        )

        if not applies:
            status = FindingStatus.NOT_APPLICABLE
            rationale = "Control is not applicable to this vendor/platform."
            spans: tuple[EvidenceSpan, ...] = ()
        else:
            status, rationale, spans = definition.check(config)

        confidence = 1.0 if status in {FindingStatus.PASS, FindingStatus.FAIL} else 0.0
        findings.append(
            Finding(
                finding_id=f"{audit_id}:{definition.control.control_id}",
                audit_id=audit_id,
                control_id=definition.control.control_id,
                status=status,
                severity=definition.control.severity,
                confidence=confidence,
                evidence=spans,
                observed_state=rationale,
                expected_state=definition.control.intent,
                rationale=rationale,
                remediation_preview=definition.remediation,
            )
        )
    return tuple(findings)
