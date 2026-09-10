"""Vendor-neutral configuration representation used by deterministic controls.

Schema version 4.0.0 — adds cryptography, ACL, segmentation, secrets, and
resilience fields to support the expanded Phase 2 control pack.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import EvidenceSpan


@dataclass(frozen=True)
class CanonicalConfig:
    # --- Core identity ---
    vendor: str
    platform: str
    version: str | None = None

    # --- Management plane ---
    management_ssh_enabled: bool | None = None
    management_ssh_version: str | None = None
    management_telnet_enabled: bool | None = None
    http_management_enabled: bool | None = None
    restconf_enabled: bool | None = None          # REST/NETCONF/YANG management
    mgmt_acl_enabled: bool | None = None          # Source restriction ACL on mgmt interfaces

    # --- Identity and access ---
    aaa_enabled: bool | None = None
    local_auth_fallback: bool | None = None       # Break-glass local account
    password_policy_enabled: bool | None = None   # Minimum complexity/length
    privilege_separation: bool | None = None      # Distinct privilege levels configured
    inactive_accounts_removed: bool | None = None

    # --- Cryptography ---
    tls_minimum_version: str | None = None        # "1.0", "1.1", "1.2", "1.3"
    weak_ciphers_found: bool | None = None        # DES, RC4, MD5, etc. present
    ssh_key_minimum_bits: int | None = None       # RSA key length

    # --- Logging and monitoring ---
    logging_enabled: bool | None = None
    ntp_enabled: bool | None = None
    log_severity_configured: bool | None = None   # Explicit severity threshold set
    secure_telemetry: bool | None = None          # SNMPv3 or encrypted telemetry

    # --- SNMP ---
    snmp_secure: bool | None = None               # SNMPv3 or no SNMP
    snmp_community_exposed: bool | None = None    # Plaintext community strings present

    # --- Network protection ---
    anti_spoofing_enabled: bool | None = None     # uRPF or equivalent
    acl_hygiene: bool | None = None              # ACLs free of permit any any

    # --- Segmentation ---
    mgmt_plane_separated: bool | None = None     # VRF or dedicated mgmt interface
    default_deny_posture: bool | None = None     # Implicit deny at end of policy

    # --- Resilience ---
    config_backup_enabled: bool | None = None    # Archive or RANCID/oxidized export
    unused_services_disabled: bool | None = None

    # --- Secrets ---
    plaintext_credentials_found: bool | None = None  # Unencrypted passwords/secrets
    private_key_in_config: bool | None = None         # Private key material embedded

    # --- Change governance ---
    config_owner_metadata: bool | None = None    # Owner/contact in config header

    # --- Evidence ---
    evidence: dict[str, tuple[EvidenceSpan, ...]] = field(default_factory=dict)
    unknown_blocks: tuple[EvidenceSpan, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def spans_for(self, field_name: str) -> tuple[EvidenceSpan, ...]:
        return self.evidence.get(field_name, ())


@dataclass(frozen=True)
class ParseResult:
    config: CanonicalConfig
    warnings: tuple[str, ...] = ()
    parser_version: str = "4.0.0"


class ParserError(ValueError):
    """Raised when a configuration cannot be parsed safely."""
