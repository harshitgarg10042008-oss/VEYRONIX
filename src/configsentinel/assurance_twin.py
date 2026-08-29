"""Evidence-first, local assurance twin built from imported topology facts."""

from __future__ import annotations

import json
from collections import deque
from pathlib import Path
from typing import Any, Mapping

from .topology import TopologyError, analyze_topology

TWIN_SCHEMA = "configsentinel.assurance-twin.v1"
MAX_NODES = 5000
MAX_LINKS = 10000
MAX_FINDING_LINKS = 1000


class AssuranceTwinError(ValueError):
    """Raised when an assurance-twin input is malformed or unsafe."""


def _object(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AssuranceTwinError(f"{label} must be an object")
    return value


def _validate_graph(
    graph: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], set[str]]:
    nodes = graph.get("nodes")
    links = graph.get("links")
    if (
        not isinstance(nodes, list)
        or not isinstance(links, list)
        or len(nodes) > MAX_NODES
        or len(links) > MAX_LINKS
    ):
        raise AssuranceTwinError("topology graph is invalid or exceeds limits")
    normalized_nodes: list[dict[str, Any]] = []
    node_ids: set[str] = set()
    for raw in nodes:
        node = _object(raw, "topology node")
        node_id = str(node.get("id", "")).strip()
        if not node_id or len(node_id) > 128 or node_id in node_ids:
            raise AssuranceTwinError("topology nodes require unique bounded ids")
        node_ids.add(node_id)
        normalized_nodes.append(
            {
                "id": node_id,
                "name": str(node.get("name", node_id))[:128],
                "vendor": str(node.get("vendor", "unknown"))[:64],
                "role": str(node.get("role", "unknown"))[:64],
                "provenance": "imported",
            }
        )
    normalized_links: list[dict[str, Any]] = []
    for raw in links:
        link = _object(raw, "topology link")
        source, target = (
            str(link.get("source", "")).strip(),
            str(link.get("target", "")).strip(),
        )
        if source not in node_ids or target not in node_ids or source == target:
            raise AssuranceTwinError(
                "topology links must reference two distinct imported nodes"
            )
        normalized_links.append(
            {
                "source": source,
                "target": target,
                "kind": str(link.get("kind", "connected"))[:64],
                "provenance": "imported",
            }
        )
    return normalized_nodes, normalized_links, node_ids


def _mapping_pairs(items: list[str], node_ids: set[str]) -> dict[str, str]:
    if len(items) > MAX_FINDING_LINKS:
        raise AssuranceTwinError("finding-to-asset mappings exceed the safety limit")
    mapping: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise AssuranceTwinError("finding-asset mapping must use FINDING=ASSET")
        finding_id, asset_id = (part.strip() for part in item.split("=", 1))
        if not finding_id or asset_id not in node_ids:
            raise AssuranceTwinError(
                "finding-asset mapping references an unknown asset"
            )
        mapping[finding_id] = asset_id
    return mapping


def _report_findings(report: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    if report is None:
        return []
    findings = report.get("findings", [])
    if not isinstance(findings, list) or len(findings) > MAX_FINDING_LINKS:
        raise AssuranceTwinError("report findings are invalid or exceed limits")
    result: list[dict[str, Any]] = []
    for raw in findings:
        finding = _object(raw, "report finding")
        finding_id, control_id = (
            str(finding.get("finding_id", "")).strip(),
            str(finding.get("control_id", "")).strip(),
        )
        if not finding_id or not control_id:
            raise AssuranceTwinError(
                "report findings require finding_id and control_id"
            )
        result.append(
            {
                "finding_id": finding_id,
                "control_id": control_id,
                "status": str(finding.get("status", "UNKNOWN")),
                "severity": str(finding.get("severity", "INFO")),
                "provenance": "imported_report",
            }
        )
    return result


def _neighborhood(
    node_ids: set[str], links: list[dict[str, Any]], root: str, depth: int
) -> dict[str, int]:
    if not 0 <= depth <= 5:
        raise AssuranceTwinError("depth must be between 0 and 5")
    adjacency: dict[str, set[str]] = {node_id: set() for node_id in node_ids}
    for link in links:
        adjacency[link["source"]].add(link["target"])
        adjacency[link["target"]].add(link["source"])
    distances = {root: 0}
    queue = deque([root])
    while queue:
        current = queue.popleft()
        if distances[current] >= depth:
            continue
        for neighbor in sorted(adjacency[current]):
            if neighbor not in distances:
                distances[neighbor] = distances[current] + 1
                queue.append(neighbor)
    return distances


def build_assurance_twin(
    graph: Mapping[str, Any],
    *,
    report: Mapping[str, Any] | None = None,
    finding_assets: Mapping[str, str] | None = None,
    depth: int = 1,
    counterfactual_add: list[tuple[str, str]] | None = None,
    counterfactual_remove: list[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    """Build a bounded fact/derivation model; no live discovery or traffic inference is performed."""
    nodes, links, node_ids = _validate_graph(graph)
    supplied_mapping = dict(finding_assets or {})
    for finding_id, asset_id in supplied_mapping.items():
        if not str(finding_id).strip() or asset_id not in node_ids:
            raise AssuranceTwinError(
                "finding-asset mapping references an unknown asset"
            )
    findings = _report_findings(report)
    finding_ids = {item["finding_id"] for item in findings}
    supplied_mapping = {str(key): str(value) for key, value in supplied_mapping.items()}
    mapping = {
        item["finding_id"]: supplied_mapping[item["finding_id"]]
        for item in findings
        if item["finding_id"] in supplied_mapping
    }
    mapping.update(
        {
            key: value
            for key, value in supplied_mapping.items()
            if key not in finding_ids
        }
    )

    analyses: list[dict[str, Any]] = []
    for finding_id, asset_id in sorted(mapping.items()):
        distances = _neighborhood(node_ids, links, asset_id, depth)
        analyses.append(
            {
                "finding_id": finding_id,
                "root_asset": asset_id,
                "impacted_node_ids": sorted(distances),
                "distances": dict(sorted(distances.items())),
                "provenance": "derived_neighborhood",
                "confidence": "bounded_graph_only",
            }
        )

    add_edges = counterfactual_add or []
    remove_edges = counterfactual_remove or []
    if len(add_edges) + len(remove_edges) > MAX_LINKS:
        raise AssuranceTwinError("counterfactual link changes exceed limits")
    for source, target in [*add_edges, *remove_edges]:
        if source not in node_ids or target not in node_ids or source == target:
            raise AssuranceTwinError(
                "counterfactual links must reference two distinct known nodes"
            )
    changed_links = [
        link
        for link in links
        if (link["source"], link["target"]) not in set(remove_edges)
        and (link["target"], link["source"]) not in set(remove_edges)
    ]
    for source, target in add_edges:
        changed_links.append(
            {
                "source": source,
                "target": target,
                "kind": "counterfactual",
                "provenance": "counterfactual",
            }
        )
    counterfactual: dict[str, Any] = {
        "enabled": bool(add_edges or remove_edges),
        "added_links": [
            {"source": source, "target": target} for source, target in add_edges
        ],
        "removed_links": [
            {"source": source, "target": target} for source, target in remove_edges
        ],
        "analyses": [],
    }
    if counterfactual["enabled"]:
        for finding_id, asset_id in sorted(mapping.items()):
            distances = _neighborhood(node_ids, changed_links, asset_id, depth)
            baseline = next(
                item for item in analyses if item["finding_id"] == finding_id
            )
            counterfactual["analyses"].append(
                {
                    "finding_id": finding_id,
                    "root_asset": asset_id,
                    "impacted_node_ids": sorted(distances),
                    "newly_impacted_node_ids": sorted(
                        set(distances) - set(baseline["impacted_node_ids"])
                    ),
                    "provenance": "derived_counterfactual_neighborhood",
                }
            )

    unlinked = sorted(
        finding_id for finding_id in finding_ids if finding_id not in mapping
    )
    return {
        "schema": TWIN_SCHEMA,
        "source_sha256": str(graph.get("source_sha256", "")),
        "facts": {
            "nodes": nodes,
            "links": links,
            "node_count": len(nodes),
            "link_count": len(links),
        },
        "finding_links": [
            {
                "finding_id": item["finding_id"],
                "asset_id": mapping[item["finding_id"]],
                "provenance": "operator_provided",
            }
            for item in findings
            if item["finding_id"] in mapping
        ],
        "findings": findings,
        "analyses": analyses,
        "unlinked_finding_ids": unlinked,
        "counterfactual": counterfactual,
        "safety": {
            "live_discovery": False,
            "traffic_inference": False,
            "exploitability_inference": False,
            "remediation_applied": False,
            "raw_configuration_included": False,
            "unknown_relations_preserved": True,
            "note": "Imported facts and bounded graph-derived consequences are labeled separately; absence of a link is not proof of isolation.",
        },
    }


def render_assurance_twin_html(twin: Mapping[str, Any]) -> str:
    payload = json.dumps(twin, sort_keys=True).replace("</", "<\\/")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ConfigSentinel AI assurance twin</title><style>body{{font:15px system-ui,sans-serif;background:#0b1220;color:#e6edf7;margin:0}}main{{max-width:1120px;margin:auto;padding:24px}}h1{{color:#74c0fc}}.meta{{color:#a7b6ca}}#graph{{position:relative;min-height:520px;border:1px solid #30445f;background:#111b2e;overflow:auto}}.node{{position:absolute;min-width:140px;padding:10px;border:1px solid #74c0fc;background:#172b46;color:#fff;cursor:pointer}}.node.derived{{border-color:#ffd166;background:#3b3140}}.node:focus{{outline:3px solid #ffd166}}#details{{margin-top:16px;white-space:pre-wrap;background:#111b2e;padding:12px}}.legend{{display:flex;gap:18px;color:#a7b6ca}}</style></head><body><main><h1>ConfigSentinel AI assurance twin</h1><p class="meta">Imported facts and bounded graph consequences are shown separately. This is not live discovery, traffic inference, or a device control plane.</p><p class="legend"><span>Blue: imported fact</span><span>Gold: derived neighborhood</span></p><section id="graph" aria-label="Assurance twin graph"></section><pre id="details">Select a node.</pre></main><script>const twin={payload};const root=document.getElementById('graph');const details=document.getElementById('details');const nodes=(twin.facts&&twin.facts.nodes)||[];const derived=new Set([].concat(...(twin.analyses||[]).map(a=>a.impacted_node_ids||[])));nodes.forEach((node,index)=>{{const el=document.createElement('button');el.className='node'+(derived.has(node.id)?' derived':'');el.textContent=node.name||node.id;el.style.left=(24+(index%4)*230)+'px';el.style.top=(30+Math.floor(index/4)*115)+'px';el.addEventListener('click',()=>{{const impacts=(twin.analyses||[]).filter(a=>(a.impacted_node_ids||[]).includes(node.id));details.textContent=JSON.stringify({{node,imported_links:(twin.facts.links||[]).filter(l=>l.source===node.id||l.target===node.id),derived_impacts:impacts,safety:twin.safety}},null,2)}});root.appendChild(el)}});</script></body></html>"""


def write_assurance_twin_html(twin: Mapping[str, Any], output: str | Path) -> None:
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_assurance_twin_html(twin), encoding="utf-8")


__all__ = [
    "AssuranceTwinError",
    "TWIN_SCHEMA",
    "build_assurance_twin",
    "render_assurance_twin_html",
    "write_assurance_twin_html",
]
