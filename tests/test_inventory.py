import json
from pathlib import Path

import pytest

from configsentinel.inventory import InventoryError, import_inventory, import_inventory_file


def test_json_inventory_builds_topology():
    graph = import_inventory(json.dumps({"nodes": [{"name": "edge-1", "vendor": "cisco_ios"}, {"name": "core-1", "role": "router"}], "links": [{"source": "edge-1", "target": "core-1", "kind": "uplink"}]}))
    assert len(graph.nodes) == 2
    assert graph.links[0]["kind"] == "uplink"
    assert len(graph.source_sha256) == 64
    assert graph.as_dict()["discovery"] == "import_only"


def test_csv_inventory_import(tmp_path: Path):
    source = tmp_path / "inventory.csv"
    source.write_text("name,vendor,role\nedge-1,junos,firewall\n", encoding="utf-8")
    graph = import_inventory_file(str(source))
    assert graph.nodes[0]["vendor"] == "junos"


def test_links_cannot_reference_unknown_nodes():
    with pytest.raises(InventoryError):
        import_inventory(json.dumps({"nodes": [{"name": "edge-1"}], "links": [{"source": "edge-1", "target": "missing"}]}))
