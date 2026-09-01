"""Tests for supply-chain evidence ingestion and statement generation."""

import pytest

from configsentinel.supplychain import (
    SupplyChainError,
    build_supply_chain_statement,
    parse_cyclonedx,
    parse_requirements_lockfile,
    parse_vex,
)


def test_parse_cyclonedx_valid():
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": "urn:uuid:1234",
        "components": [
            {
                "bom-ref": "pkg:pypi/requests@2.28.1",
                "name": "requests",
                "version": "2.28.1",
                "purl": "pkg:pypi/requests@2.28.1",
            }
        ],
    }
    result = parse_cyclonedx(payload)
    assert result["format"] == "CycloneDX"
    assert result["component_count"] == 1
    assert result["components"][0]["name"] == "requests"


def test_parse_cyclonedx_invalid():
    with pytest.raises(SupplyChainError, match="unsupported or invalid CycloneDX payload"):
        parse_cyclonedx({"bomFormat": "SPDX"})


def test_parse_vex_valid():
    payload = {
        "vulnerabilities": [
            {
                "id": "CVE-2021-44228",
                "analysis": {
                    "state": "not_affected",
                    "justification": "code_not_reachable",
                },
            }
        ]
    }
    result = parse_vex(payload)
    assert result["format"] == "VEX"
    assert result["statement_count"] == 1
    assert result["statements"][0]["vulnerability_id"] == "CVE-2021-44228"
    assert result["statements"][0]["status"] == "not_affected"


def test_parse_requirements_lockfile():
    content = """
# This is a comment
requests==2.28.1; python_version >= '3.7'
urllib3==1.26.12
"""
    result = parse_requirements_lockfile(content)
    assert result["format"] == "requirements.txt"
    assert result["package_count"] == 2
    assert result["packages"][0]["name"] == "requests"
    assert result["packages"][0]["version"] == "2.28.1"
    assert result["packages"][1]["name"] == "urllib3"


def test_build_supply_chain_statement():
    statement = build_supply_chain_statement(
        verification_loop_id="loop_123",
        evidence_chain_digest="sha256:abc",
        sbom_digest="sha256:def",
    )
    assert statement["statement"]["schema"] == "configsentinel.supply-chain-statement.v1"
    assert statement["statement"]["verification_loop_id"] == "loop_123"
    assert statement["statement"]["linked_assets"]["sbom_sha256"] == "sha256:def"
    assert statement["statement_sha256"] is not None
