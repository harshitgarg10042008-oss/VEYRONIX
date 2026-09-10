"""Tests for the versioned capability manifest — Phase 1 acceptance criteria.

A judge must be able to confirm that all displayed UI metadata comes from this
manifest rather than from frontend hardcoded values.
"""

from __future__ import annotations

import pytest

from configsentinel.capabilities import build_capabilities, APP_VERSION
from configsentinel.parsers import PARSER_REGISTRY
from configsentinel.controls import CONTROL_PACK, CONTROL_PACK_VERSION
from configsentinel.frameworks import FRAMEWORKS


class TestCapabilityManifest:
    def setup_method(self):
        self.manifest = build_capabilities()

    def test_manifest_builds_without_error(self):
        assert self.manifest is not None

    def test_vendor_count_matches_parser_registry(self):
        assert self.manifest.vendor_count == len(PARSER_REGISTRY)

    def test_total_control_count_matches_pack(self):
        assert self.manifest.total_control_count == len(CONTROL_PACK)

    def test_all_parser_ids_present_in_vendors(self):
        manifest_ids = {v.vendor_id for v in self.manifest.vendors}
        for parser in PARSER_REGISTRY:
            assert parser.plugin_id in manifest_ids, (
                f"Parser {parser.plugin_id} not in capability manifest vendors"
            )

    def test_all_framework_ids_present(self):
        manifest_fwks = set(self.manifest.framework_ids)
        for fw in FRAMEWORKS:
            assert fw.framework_id in manifest_fwks, (
                f"Framework {fw.framework_id} missing from capability manifest"
            )

    def test_control_pack_version_matches(self):
        assert self.manifest.control_pack_version == CONTROL_PACK_VERSION

    def test_app_version_present(self):
        assert self.manifest.app_version == APP_VERSION
        assert len(self.manifest.app_version) > 0

    def test_max_upload_bytes_is_positive(self):
        assert self.manifest.max_upload_bytes > 0

    def test_features_dict_is_present(self):
        assert isinstance(self.manifest.features, dict)
        assert "deterministic_audit" in self.manifest.features
        assert self.manifest.features["deterministic_audit"] is True

    def test_as_dict_is_json_serialisable(self):
        import json
        d = self.manifest.as_dict()
        serialised = json.dumps(d)
        parsed = json.loads(serialised)
        assert parsed["vendor_count"] == len(PARSER_REGISTRY)
        assert parsed["total_control_count"] == len(CONTROL_PACK)

    def test_each_vendor_has_control_ids_or_notes(self):
        for vendor in self.manifest.vendors:
            assert vendor.vendor_id, "vendor_id must not be empty"
            assert vendor.display_name, f"display_name missing for {vendor.vendor_id}"
            assert vendor.parser_version, f"parser_version missing for {vendor.vendor_id}"
            # Vendors with no controls should at least declare that fact in notes or unsupported
            assert vendor.control_ids or vendor.unsupported_syntax or vendor.notes, (
                f"Vendor {vendor.vendor_id} has no control_ids, unsupported_syntax, or notes"
            )

    def test_fortigate_in_manifest(self):
        ids = [v.vendor_id for v in self.manifest.vendors]
        assert "fortigate" in ids

    def test_paloalto_in_manifest(self):
        ids = [v.vendor_id for v in self.manifest.vendors]
        assert "paloalto" in ids

    def test_minimum_six_vendors(self):
        assert self.manifest.vendor_count >= 6, (
            f"Expected at least 6 vendors, got {self.manifest.vendor_count}"
        )

    def test_minimum_twenty_controls(self):
        assert self.manifest.total_control_count >= 20, (
            f"Expected at least 20 controls, got {self.manifest.total_control_count}"
        )

    def test_ai_mode_is_valid_string(self):
        assert self.manifest.ai_mode in {"offline", "external", "disabled"}

    def test_persistence_mode_is_valid(self):
        assert self.manifest.persistence_mode in {"memory", "sqlite", "postgresql"}


class TestCapabilityManifestControlCoverage:
    """Verify control-to-vendor applicability mapping integrity."""

    def setup_method(self):
        from configsentinel.controls import CONTROL_PACK
        self.control_pack = CONTROL_PACK

    def test_all_controls_have_framework_mappings(self):
        for cd in self.control_pack:
            assert cd.control.framework_mappings, (
                f"Control {cd.control.control_id} has no framework mappings"
            )

    def test_all_controls_have_applies_to(self):
        for cd in self.control_pack:
            assert cd.control.applies_to, (
                f"Control {cd.control.control_id} has no applies_to vendors"
            )

    def test_all_controls_have_remediation(self):
        for cd in self.control_pack:
            assert cd.remediation.strip(), (
                f"Control {cd.control.control_id} has empty remediation"
            )

    def test_all_controls_have_unique_ids(self):
        ids = [cd.control.control_id for cd in self.control_pack]
        assert len(ids) == len(set(ids)), "Duplicate control IDs found"

    def test_critical_and_high_controls_present(self):
        from configsentinel.models import Severity
        severities = {cd.control.severity for cd in self.control_pack}
        assert Severity.CRITICAL in severities
        assert Severity.HIGH in severities

    def test_nist_800_53_mappings_present(self):
        for cd in self.control_pack:
            has_nist = any(
                k in ("nist-800-53", "nist_800_53")
                for k in cd.control.framework_mappings
            )
            if cd.control.severity.value in ("CRITICAL", "HIGH"):
                assert has_nist, (
                    f"CRITICAL/HIGH control {cd.control.control_id} missing NIST 800-53 mapping"
                )
