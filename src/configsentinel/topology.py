"""Deterministic topology analysis and local interactive HTML rendering."""
from __future__ import annotations

import html
import json
from collections import deque
from pathlib import Path
from typing import Any, Mapping


class TopologyError(ValueError):
    """Raised when a topology graph is malformed or exceeds safe bounds."""


def blast_radius(graph: Mapping[str, Any], *, asset_id: str, depth: int = 1) -> dict[str, Any]:
    if not 0 <= depth <= 5:
        raise TopologyError("depth must be between 0 and 5")
    nodes, links = graph.get("nodes"), graph.get("links")
    if not isinstance(nodes, list) or not isinstance(links, list) or len(nodes) > 5000 or len(links) > 10000:
        raise TopologyError("topology graph is invalid or exceeds limits")
    node_ids = {str(node.get("id")) for node in nodes if isinstance(node, Mapping)}
    if asset_id not in node_ids:
        raise TopologyError("asset_id is not present in topology")
    adjacency: dict[str, set[str]] = {node_id: set() for node_id in node_ids}
    for link in links:
        if not isinstance(link, Mapping):
            raise TopologyError("each link must be an object")
        source, target = str(link.get("source", "")), str(link.get("target", ""))
        if source not in node_ids or target not in node_ids:
            raise TopologyError("link references unknown node")
        adjacency[source].add(target)
        adjacency[target].add(source)
    distances = {asset_id: 0}
    queue = deque([asset_id])
    while queue:
        current = queue.popleft()
        if distances[current] >= depth:
            continue
        for neighbor in sorted(adjacency[current]):
            if neighbor not in distances:
                distances[neighbor] = distances[current] + 1
                queue.append(neighbor)
    return {"root_asset": asset_id, "depth": depth, "impacted_node_ids": sorted(distances), "distances": distances, "safety_note": "Blast radius is a graph-neighborhood review aid; it does not infer traffic flow or exploitability."}


def analyze_topology(graph: Mapping[str, Any], *, finding_assets: Mapping[str, str] | None = None, depth: int = 1) -> dict[str, Any]:
    finding_assets = finding_assets or {}
    roots = sorted(set(finding_assets.values()))
    results = {finding_id: blast_radius(graph, asset_id=asset_id, depth=depth) for finding_id, asset_id in sorted(finding_assets.items())}
    impacted = sorted({node_id for item in results.values() for node_id in item["impacted_node_ids"]})
    return {"schema": "configsentinel.topology-analysis.v1", "source_sha256": graph.get("source_sha256", ""), "roots": roots, "analyses": results, "impacted_node_ids": impacted, "safety_note": "Topology is imported or operator-provided; no live discovery, path inference, or remediation is performed."}


def render_topology_html(graph: Mapping[str, Any], analysis: Mapping[str, Any] | None = None) -> str:
    nodes = [node for node in graph.get("nodes", []) if isinstance(node, Mapping)]
    links = [link for link in graph.get("links", []) if isinstance(link, Mapping)]
    node_json = json.dumps(nodes, sort_keys=True).replace("</", "<\\/")
    link_json = json.dumps(links, sort_keys=True).replace("</", "<\\/")
    analysis_json = json.dumps(analysis or {}, sort_keys=True).replace("</", "<\\/")
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ConfigSentinel AI topology review</title><style>body{{font:15px system-ui,sans-serif;background:#0b1220;color:#e6edf7;margin:0}}main{{max-width:1100px;margin:auto;padding:24px}}h1{{color:#74c0fc}}#graph{{position:relative;min-height:480px;border:1px solid #30445f;background:#111b2e;overflow:auto}}.node{{position:absolute;min-width:130px;padding:10px;border:1px solid #74c0fc;background:#172b46;color:#fff;cursor:pointer}}.node:focus{{outline:3px solid #ffd166}}svg{{position:absolute;inset:0;width:100%;height:100%;pointer-events:none}}.meta{{color:#a7b6ca}}#details{{margin-top:16px;white-space:pre-wrap}}</style></head><body><main><h1>ConfigSentinel AI topology review</h1><p class="meta">Imported graph only. Select a node to inspect local connections. Blast-radius output remains a review aid.</p><section id="graph" aria-label="Interactive topology graph"><svg id="edges" aria-hidden="true"></svg></section><pre id="details">Select a node.</pre></main><script>const nodes={node_json};const links={link_json};const analysis={analysis_json};const root=document.getElementById('graph');const details=document.getElementById('details');const positions={{}};nodes.forEach((node,index)=>{{const el=document.createElement('button');el.className='node';el.textContent=node.name||node.id;el.dataset.id=node.id;el.style.left=(24+(index%4)*220)+'px';el.style.top=(30+Math.floor(index/4)*110)+'px';el.addEventListener('click',()=>{{const neighbors=links.filter(l=>l.source===node.id||l.target===node.id).map(l=>l.source===node.id?l.target:l.source);details.textContent=JSON.stringify({{node,neighbors,blast_radius:Object.values(analysis.analyses||{{}}).filter(a=>a.impacted_node_ids.includes(node.id))}},null,2)}});root.appendChild(el);positions[node.id]=el}});</script></body></html>'''


def write_topology_html(graph: Mapping[str, Any], output: str | Path, analysis: Mapping[str, Any] | None = None) -> None:
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_topology_html(graph, analysis), encoding="utf-8")
