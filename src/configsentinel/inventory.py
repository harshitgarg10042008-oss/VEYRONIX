"""Local inventory/topology import; live network discovery is intentionally unsupported."""
from __future__ import annotations

import csv
import hashlib
import io
import json
from dataclasses import dataclass
from typing import Any


class InventoryError(ValueError):
    """Raised when an inventory source is malformed or exceeds safe bounds."""


@dataclass(frozen=True)
class InventoryGraph:
    source_sha256: str
    nodes: tuple[dict[str, str], ...]
    links: tuple[dict[str, str], ...]

    def as_dict(self) -> dict[str, Any]:
        return {"source_sha256": self.source_sha256, "discovery": "import_only", "nodes": list(self.nodes), "links": list(self.links)}


def _node(raw: dict[str, Any]) -> dict[str, str]:
    name = str(raw.get("name", raw.get("id", ""))).strip()
    if not name or len(name) > 128:
        raise InventoryError("each node requires a bounded name")
    return {"id": name, "name": name, "vendor": str(raw.get("vendor", "unknown"))[:64], "role": str(raw.get("role", "unknown"))[:64]}


def import_inventory(data: bytes | str, *, fmt: str = "json") -> InventoryGraph:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    if len(raw) > 2 * 1024 * 1024:
        raise InventoryError("inventory exceeds the 2 MiB limit")
    digest = hashlib.sha256(raw).hexdigest()
    try:
        if fmt == "json":
            document = json.loads(raw.decode("utf-8"))
            node_rows, link_rows = document.get("nodes", []), document.get("links", document.get("edges", []))
        elif fmt == "csv":
            rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8"))))
            node_rows = rows
            link_rows = []
        else:
            raise InventoryError("format must be json or csv")
    except (UnicodeDecodeError, json.JSONDecodeError, AttributeError) as exc:
        raise InventoryError("inventory is not valid UTF-8 structured data") from exc
    if not isinstance(node_rows, list) or not isinstance(link_rows, list) or len(node_rows) > 5000 or len(link_rows) > 10000:
        raise InventoryError("inventory node or link limits exceeded")
    nodes = tuple(_node(row) for row in node_rows if isinstance(row, dict))
    known = {item["id"] for item in nodes}
    links: list[dict[str, str]] = []
    for row in link_rows:
        if not isinstance(row, dict):
            raise InventoryError("each link must be an object")
        source, target = str(row.get("source", row.get("from", ""))).strip(), str(row.get("target", row.get("to", ""))).strip()
        if not source or not target or source not in known or target not in known:
            raise InventoryError("links must reference imported nodes")
        links.append({"source": source, "target": target, "kind": str(row.get("kind", "connected"))[:64]})
    return InventoryGraph(digest, nodes, tuple(links))


def import_inventory_file(path: str) -> InventoryGraph:
    from pathlib import Path
    file_path = Path(path)
    if file_path.is_symlink() or not file_path.is_file():
        raise InventoryError("inventory path must be a regular file")
    suffix = file_path.suffix.lower()
    if suffix not in {".json", ".csv"}:
        raise InventoryError("inventory file must use .json or .csv")
    return import_inventory(file_path.read_bytes(), fmt=suffix[1:])
