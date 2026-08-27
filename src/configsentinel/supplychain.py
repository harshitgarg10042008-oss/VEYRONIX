"""Release manifest helpers for local artifact integrity checks."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


class SupplyChainError(ValueError):
    """Raised when a release manifest is unsafe or inconsistent."""


def build_manifest(root: str | Path, *, include_suffixes: tuple[str, ...] = (".py", ".toml", ".md", ".json", ".yml", ".yaml")) -> dict[str, Any]:
    base = Path(root).resolve()
    if not base.is_dir():
        raise SupplyChainError("manifest root must be a directory")
    files: dict[str, str] = {}
    for path in sorted(base.rglob("*")):
        if not path.is_file() or path.is_symlink() or path.suffix.lower() not in include_suffixes or any(part in {".git", ".pytest_cache", "__pycache__", "node_modules"} for part in path.relative_to(base).parts):
            continue
        relative = path.relative_to(base).as_posix()
        files[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return {"schema": "configsentinel.release-manifest.v1", "algorithm": "sha256", "files": files}


def verify_manifest(root: str | Path, manifest: dict[str, Any]) -> tuple[str, ...]:
    if manifest.get("schema") != "configsentinel.release-manifest.v1" or manifest.get("algorithm") != "sha256" or not isinstance(manifest.get("files"), dict):
        raise SupplyChainError("unsupported release manifest")
    base = Path(root).resolve()
    failures: list[str] = []
    for relative, expected in manifest["files"].items():
        path = (base / str(relative)).resolve()
        try:
            path.relative_to(base)
        except ValueError as exc:
            raise SupplyChainError("manifest contains path traversal") from exc
        if not path.is_file() or path.is_symlink():
            failures.append(f"missing:{relative}")
        elif hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            failures.append(f"changed:{relative}")
    return tuple(failures)


def write_manifest(root: str | Path, output: str | Path) -> None:
    payload = build_manifest(root)
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
