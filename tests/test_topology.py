import json
from pathlib import Path

from configsentinel.topology import analyze_topology, blast_radius, render_topology_html

GRAPH = {
    "source_sha256": "a" * 64,
    "nodes": [{"id": "edge"}, {"id": "core"}, {"id": "db"}],
    "links": [{"source": "edge", "target": "core"}, {"source": "core", "target": "db"}],
}


def test_blast_radius_is_bounded_and_deterministic():
    result = blast_radius(GRAPH, asset_id="edge", depth=2)
    assert result["impacted_node_ids"] == ["core", "db", "edge"]


def test_analysis_links_finding_to_impacted_assets():
    result = analyze_topology(GRAPH, finding_assets={"finding-1": "edge"}, depth=1)
    assert result["analyses"]["finding-1"]["impacted_node_ids"] == ["core", "edge"]
    assert (
        "does not infer traffic flow" in result["analyses"]["finding-1"]["safety_note"]
    )


def test_html_explorer_is_self_contained():
    html = render_topology_html(GRAPH, analyze_topology(GRAPH))
    assert "ConfigSentinel AI topology review" in html
    assert "addEventListener('click'" in html
    assert "https://" not in html
