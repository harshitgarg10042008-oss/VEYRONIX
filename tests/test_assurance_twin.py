import json
from pathlib import Path

import pytest

from configsentinel.assurance_twin import AssuranceTwinError, build_assurance_twin, render_assurance_twin_html


GRAPH = {
    "source_sha256": "c" * 64,
    "nodes": [
        {"id": "edge", "name": "Edge", "vendor": "cisco_ios", "role": "boundary"},
        {"id": "core", "name": "Core", "vendor": "arista_eos", "role": "transit"},
        {"id": "db", "name": "Database", "vendor": "linux_nftables", "role": "data"},
    ],
    "links": [{"source": "edge", "target": "core", "kind": "connected"}, {"source": "core", "target": "db", "kind": "connected"}],
}

REPORT = {
    "audit": {"audit_id": "audit_twin", "vendor": "cisco_ios", "input_sha256": "d" * 64},
    "findings": [
        {"finding_id": "finding-1", "control_id": "NET-MGMT-TELNET-001", "status": "FAIL", "severity": "CRITICAL"},
        {"finding_id": "finding-2", "control_id": "NET-AAA-001", "status": "UNKNOWN", "severity": "HIGH"},
    ],
}


def test_twin_separates_imported_facts_from_derived_impacts():
    twin = build_assurance_twin(GRAPH, report=REPORT, finding_assets={"finding-1": "edge"}, depth=2)

    assert twin["schema"] == "configsentinel.assurance-twin.v1"
    assert twin["facts"]["nodes"][0]["provenance"] == "imported"
    assert twin["finding_links"] == [{"finding_id": "finding-1", "asset_id": "edge", "provenance": "operator_provided"}]
    assert twin["analyses"][0]["impacted_node_ids"] == ["core", "db", "edge"]
    assert twin["unlinked_finding_ids"] == ["finding-2"]
    assert twin["safety"]["traffic_inference"] is False
    assert twin["safety"]["unknown_relations_preserved"] is True


def test_twin_counterfactual_is_bounded_and_deterministic():
    first = build_assurance_twin(GRAPH, finding_assets={"finding-1": "edge"}, depth=1, counterfactual_add=[("edge", "db")])
    second = build_assurance_twin(GRAPH, finding_assets={"finding-1": "edge"}, depth=1, counterfactual_add=[("edge", "db")])

    assert first == second
    assert first["counterfactual"]["enabled"] is True
    assert first["counterfactual"]["analyses"][0]["newly_impacted_node_ids"] == ["db"]

    with pytest.raises(AssuranceTwinError):
        build_assurance_twin(GRAPH, finding_assets={"finding-1": "missing"})
    with pytest.raises(AssuranceTwinError):
        build_assurance_twin(GRAPH, finding_assets={"finding-1": "edge"}, depth=6)


def test_twin_html_is_self_contained_and_does_not_load_external_resources():
    html = render_assurance_twin_html(build_assurance_twin(GRAPH, finding_assets={"finding-1": "edge"}))

    assert "ConfigSentinel AI assurance twin" in html
    assert "Imported facts and bounded graph consequences" in html
    assert "addEventListener('click'" in html
    assert "https://" not in html


def test_twin_cli_writes_json_and_html(tmp_path: Path, capsys):
    from configsentinel.cli import main

    graph_path = tmp_path / "graph.json"
    out_path = tmp_path / "twin.json"
    html_path = tmp_path / "twin.html"
    graph_path.write_text(json.dumps(GRAPH), encoding="utf-8")

    assert main(["assurance-twin", str(graph_path), "--finding-asset", "finding-1=edge", "--add-link", "edge=db", "--depth", "1", "--out", str(out_path), "--html-out", str(html_path)]) == 0
    assert "assurance_twin=" in capsys.readouterr().out
    assert json.loads(out_path.read_text(encoding="utf-8"))["counterfactual"]["enabled"] is True
    assert html_path.read_text(encoding="utf-8").startswith("<!doctype html>")
