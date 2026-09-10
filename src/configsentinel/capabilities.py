"""Versioned capability manifest for ConfigSentinel AI.

This module is the single authoritative source for all metadata displayed in the UI.
The frontend must consume GET /api/capabilities rather than hardcoding any of these values.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


APP_VERSION = "0.4.0-sih"
CAPABILITIES_SCHEMA_VERSION = "1.0.0"

MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MiB


@dataclass(frozen=True)
class VendorCapability:
    vendor_id: str
    display_name: str
    parser_version: str
    supported_platforms: tuple[str, ...]
    supported_syntax_forms: tuple[str, ...]
    unsupported_syntax: tuple[str, ...]
    control_ids: tuple[str, ...]
    confidence_behavior: str
    notes: str = ""


@dataclass(frozen=True)
class CapabilityManifest:
    app_version: str
    schema_version: str
    control_pack_version: str
    framework_pack_version: str
    parser_registry_version: str
    vendors: tuple[VendorCapability, ...]
    framework_ids: tuple[str, ...]
    max_upload_bytes: int
    ai_available: bool
    ai_mode: str  # "offline" | "external" | "disabled"
    persistence_mode: str  # "memory" | "sqlite" | "postgresql"
    auth_mode: str  # "local" | "token" | "oidc"
    total_control_count: int
    vendor_count: int
    features: dict[str, bool] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "app_version": self.app_version,
            "schema_version": self.schema_version,
            "control_pack_version": self.control_pack_version,
            "framework_pack_version": self.framework_pack_version,
            "parser_registry_version": self.parser_registry_version,
            "vendors": [
                {
                    "vendor_id": v.vendor_id,
                    "display_name": v.display_name,
                    "parser_version": v.parser_version,
                    "supported_platforms": list(v.supported_platforms),
                    "supported_syntax_forms": list(v.supported_syntax_forms),
                    "unsupported_syntax": list(v.unsupported_syntax),
                    "control_ids": list(v.control_ids),
                    "confidence_behavior": v.confidence_behavior,
                    "notes": v.notes,
                }
                for v in self.vendors
            ],
            "framework_ids": list(self.framework_ids),
            "max_upload_bytes": self.max_upload_bytes,
            "max_upload_mb": round(self.max_upload_bytes / 1024 / 1024, 1),
            "ai_available": self.ai_available,
            "ai_mode": self.ai_mode,
            "persistence_mode": self.persistence_mode,
            "auth_mode": self.auth_mode,
            "total_control_count": self.total_control_count,
            "vendor_count": self.vendor_count,
            "features": self.features,
        }


def build_capabilities() -> CapabilityManifest:
    """Build the authoritative capability manifest from registered parsers and controls.

    This function imports lazily to avoid circular imports and to allow the
    manifest to always reflect the current runtime state.
    """
    from .parsers import PARSER_REGISTRY
    from .controls import CONTROL_PACK, CONTROL_PACK_VERSION
    from .frameworks import FRAMEWORKS, REGISTRY_VERSION as FRAMEWORK_REGISTRY_VERSION
    from .llm import LLMConfig

    llm_cfg = LLMConfig.from_environment()
    ai_mode = (
        "external"
        if llm_cfg.enabled and llm_cfg.endpoint
        else "offline"
        if not llm_cfg.enabled
        else "disabled"
    )

    # Build per-vendor capability info
    vendor_caps: list[VendorCapability] = []
    for parser in PARSER_REGISTRY:
        control_ids = tuple(
            cd.control.control_id
            for cd in CONTROL_PACK
            if parser.plugin_id in cd.control.applies_to
        )
        cap = _VENDOR_METADATA.get(parser.plugin_id)
        if cap is None:
            # Auto-generate minimal entry for unregistered parsers
            vendor_caps.append(
                VendorCapability(
                    vendor_id=parser.plugin_id,
                    display_name=parser.plugin_id.replace("_", " ").title(),
                    parser_version=parser.parser_version,
                    supported_platforms=(),
                    supported_syntax_forms=(),
                    unsupported_syntax=("All syntax not explicitly parsed is reported UNKNOWN",),
                    control_ids=control_ids,
                    confidence_behavior="Unknown syntax lines are reported as UNKNOWN evidence blocks",
                )
            )
        else:
            vendor_caps.append(
                VendorCapability(
                    vendor_id=parser.plugin_id,
                    display_name=cap["display_name"],
                    parser_version=parser.parser_version,
                    supported_platforms=tuple(cap.get("platforms", [])),
                    supported_syntax_forms=tuple(cap.get("syntax_forms", [])),
                    unsupported_syntax=tuple(cap.get("unsupported", [])),
                    control_ids=control_ids,
                    confidence_behavior=cap.get(
                        "confidence_behavior",
                        "Unknown syntax lines are reported as UNKNOWN evidence blocks",
                    ),
                    notes=cap.get("notes", ""),
                )
            )

    persistence = os.getenv("CONFIGSENTINEL_PERSISTENCE", "memory")
    auth = os.getenv("CONFIGSENTINEL_AUTH_MODE", "local")

    return CapabilityManifest(
        app_version=APP_VERSION,
        schema_version=CAPABILITIES_SCHEMA_VERSION,
        control_pack_version=CONTROL_PACK_VERSION,
        framework_pack_version=FRAMEWORK_REGISTRY_VERSION,
        parser_registry_version="4.0.0",
        vendors=tuple(vendor_caps),
        framework_ids=tuple(f.framework_id for f in FRAMEWORKS),
        max_upload_bytes=MAX_UPLOAD_BYTES,
        ai_available=llm_cfg.enabled,
        ai_mode=ai_mode,
        persistence_mode=persistence,
        auth_mode=auth,
        total_control_count=len(CONTROL_PACK),
        vendor_count=len(PARSER_REGISTRY),
        features={
            "vendor_detection": True,
            "deterministic_audit": True,
            "evidence_spans": True,
            "framework_mappings": True,
            "approval_workflow": True,
            "verification_loop": True,
            "remediation_preview": True,
            "notarization": True,
            "gitops_diff": True,
            "mutation_lab": True,
            "website_scanner": True,
            "ai_classify_unknown": llm_cfg.enabled,
            "ai_explain_finding": True,  # offline explanation always available
            "blast_radius": True,
            "evidence_exchange": True,
            "supply_chain_sbom": True,
            "oidc_sso": False,  # Phase 5
            "postgresql_persistence": persistence == "postgresql",
            "multi_tenant": False,  # Phase 5
        },
    )


# Static vendor metadata not derivable from parser classes
_VENDOR_METADATA: dict[str, dict] = {
    "cisco_ios": {
        "display_name": "Cisco IOS / IOS-XE",
        "platforms": ["ios", "ios-xe", "ios-xr"],
        "syntax_forms": ["show running-config", "text export"],
        "unsupported": [
            "ROMMON configuration",
            "IOS-XR specific syntax",
            "Encrypted password blocks (type 8/9)",
            "TCL scripts embedded in config",
        ],
        "confidence_behavior": "High-confidence detection via version/hostname/interface markers. Unknown lines reported as UNKNOWN.",
        "notes": "IOS-XE RestConf/NETCONF markers detected; crypto PKI blocks noted but not evaluated.",
    },
    "junos": {
        "display_name": "Juniper Junos",
        "platforms": ["junos", "junos-evo"],
        "syntax_forms": ["set form (flat)", "hierarchical (braces) form"],
        "unsupported": [
            "YANG model output",
            "Junos Space XML exports",
            "Inactive statement blocks (deactivate)",
            "Routing policy match conditions",
        ],
        "confidence_behavior": "Detects set-form and hierarchical form. Inactive statements not evaluated (reported UNKNOWN).",
        "notes": "Both `set system services ssh` and hierarchical `ssh { ... }` forms are parsed.",
    },
    "arista_eos": {
        "display_name": "Arista EOS",
        "platforms": ["eos"],
        "syntax_forms": ["show running-config", "text export"],
        "unsupported": [
            "EOS eAPI JSON output",
            "GNMI/gRPC telemetry config",
            "CloudVision-specific extensions",
        ],
        "confidence_behavior": "Management API and TerminAttr markers provide high-confidence detection.",
        "notes": "Inherits Cisco IOS parser with EOS-specific vendor override.",
    },
    "firewall_generic": {
        "display_name": "Generic Firewall",
        "platforms": ["generic"],
        "syntax_forms": ["generic policy text"],
        "unsupported": [
            "Vendor-specific policy objects",
            "NAT rules",
            "VPN configuration",
            "Complex ACL objects",
        ],
        "confidence_behavior": "Conservative fallback. High unknown rate by design. Use vendor-specific parsers for accurate results.",
        "notes": "Intentionally conservative. Designed as a catch-all; reports high unknown rate.",
    },
    "linux_nftables": {
        "display_name": "Linux nftables / iptables",
        "platforms": ["nftables", "iptables"],
        "syntax_forms": ["nft list ruleset", "iptables-save format"],
        "unsupported": [
            "eBPF programs",
            "tc (traffic control) rules",
            "ipset definitions",
            "Complex verdict maps",
        ],
        "confidence_behavior": "TCP port-based detection; complex nftables verdict maps not evaluated.",
        "notes": "Both nftables native syntax and iptables-save format partially supported.",
    },
    "fortigate": {
        "display_name": "Fortinet FortiGate (FortiOS)",
        "platforms": ["fortios"],
        "syntax_forms": ["FortiOS CLI export (config/end blocks)"],
        "unsupported": [
            "FortiManager batch config",
            "VDOM-specific sub-contexts beyond management",
            "SD-WAN rules",
            "Security fabric config",
            "FortiOS REST API JSON export",
        ],
        "confidence_behavior": "Detects config/end block structure and FortiOS-specific system global markers. Unsupported sections are explicitly UNKNOWN.",
        "notes": "Scoped to management plane and identity controls. Full policy evaluation is out of scope for this parser version.",
    },
    "paloalto": {
        "display_name": "Palo Alto PAN-OS",
        "platforms": ["pan-os"],
        "syntax_forms": ["PAN-OS CLI set-form", "XML config (partial)"],
        "unsupported": [
            "Security policy rules evaluation",
            "GlobalProtect configuration",
            "Panorama-managed device config",
            "App-ID and Content-ID specific controls",
            "Full XML config beyond device/system sections",
        ],
        "confidence_behavior": "Conservative. Only device system and management settings evaluated. All policy sections reported UNKNOWN. High unknown rate by design.",
        "notes": "Scope explicitly limited to management plane. Security policy evaluation requires full commercial PAN-OS support.",
    },
}
