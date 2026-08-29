from configsentinel.frameworks import (
    get_framework,
    normalize_framework_id,
    normalize_frameworks,
)


def test_expanded_framework_aliases():
    assert normalize_framework_id("csf") == "nist-csf-2"
    assert normalize_framework_id("pci") == "pci-dss-4-0-1"
    assert normalize_framework_id("iso27001") == "iso-27001-2022"
    assert normalize_frameworks(["hipaa", "soc2"]) == (
        "hipaa-security-rule",
        "soc-2-tsc",
    )


def test_framework_metadata_is_explicitly_informative():
    framework = get_framework("pci-dss-4-0-1")
    assert framework.version == "4.0.1"
    assert framework.source_url.startswith("https://")
    assert "does not establish" in framework.license_note
