"""Release manifest helpers for local artifact integrity checks."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


class SupplyChainError(ValueError):
    """Raised when a release manifest is unsafe or inconsistent."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def build_manifest(
    root: str | Path,
    *,
    include_suffixes: tuple[str, ...] = (
        ".py",
        ".toml",
        ".md",
        ".json",
        ".yml",
        ".yaml",
    ),
) -> dict[str, Any]:
    base = Path(root).resolve()
    if not base.is_dir():
        raise SupplyChainError("manifest root must be a directory")
    files: dict[str, str] = {}
    for path in sorted(base.rglob("*")):
        if (
            not path.is_file()
            or path.is_symlink()
            or path.suffix.lower() not in include_suffixes
            or any(
                part in {".git", ".pytest_cache", "__pycache__", "node_modules"}
                for part in path.relative_to(base).parts
            )
        ):
            continue
        relative = path.relative_to(base).as_posix()
        files[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return {
        "schema": "configsentinel.release-manifest.v1",
        "algorithm": "sha256",
        "files": files,
    }


def verify_manifest(root: str | Path, manifest: dict[str, Any]) -> tuple[str, ...]:
    if (
        manifest.get("schema") != "configsentinel.release-manifest.v1"
        or manifest.get("algorithm") != "sha256"
        or not isinstance(manifest.get("files"), dict)
    ):
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
    destination.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def parse_cyclonedx(payload: dict[str, Any]) -> dict[str, Any]:
    """Ingest a CycloneDX SBOM and extract components."""
    if not isinstance(payload, dict) or payload.get("bomFormat") != "CycloneDX":
        raise SupplyChainError("unsupported or invalid CycloneDX payload")
    
    components = []
    for comp in payload.get("components", []):
        components.append({
            "bom_ref": str(comp.get("bom-ref", "")),
            "name": str(comp.get("name", "")),
            "version": str(comp.get("version", "")),
            "purl": str(comp.get("purl", "")),
        })
        
    return {
        "format": "CycloneDX",
        "spec_version": str(payload.get("specVersion", "")),
        "serial_number": str(payload.get("serialNumber", "")),
        "component_count": len(components),
        "components": components,
        "digest": _digest(payload),
    }


def parse_vex(payload: dict[str, Any]) -> dict[str, Any]:
    """Ingest a VEX (Vulnerability Exploitability eXchange) document."""
    # Simplified VEX parsing for OpenVEX or CycloneDX VEX
    if not isinstance(payload, dict):
        raise SupplyChainError("invalid VEX payload")
        
    statements = []
    for stmt in payload.get("statements", []) or payload.get("vulnerabilities", []):
        statements.append({
            "vulnerability_id": str(stmt.get("vulnerability", {}).get("name", stmt.get("id", ""))),
            "status": str(stmt.get("status", stmt.get("analysis", {}).get("state", ""))),
            "justification": str(stmt.get("justification", stmt.get("analysis", {}).get("justification", ""))),
        })
        
    return {
        "format": "VEX",
        "statement_count": len(statements),
        "statements": statements,
        "digest": _digest(payload),
    }


def parse_requirements_lockfile(content: str) -> dict[str, Any]:
    """Parse a pip requirements.txt lockfile."""
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "==" in line:
            name, version = line.split("==", 1)
            # handle markers
            version = version.split(";")[0].strip()
            packages.append({"name": name.strip(), "version": version, "purl": f"pkg:pypi/{name.strip()}@{version}"})
            
    return {
        "format": "requirements.txt",
        "package_count": len(packages),
        "packages": packages,
        "digest": hashlib.sha256(content.encode("utf-8")).hexdigest(),
    }


def build_supply_chain_statement(
    verification_loop_id: str,
    evidence_chain_digest: str,
    sbom_digest: str | None = None,
    vex_digest: str | None = None,
    lockfile_digest: str | None = None,
) -> dict[str, Any]:
    """Emit a cryptographically bound statement linking a verification loop to supply chain assets."""
    payload = {
        "schema": "configsentinel.supply-chain-statement.v1",
        "verification_loop_id": verification_loop_id,
        "evidence_chain_digest": evidence_chain_digest,
        "linked_assets": {
            "sbom_sha256": sbom_digest,
            "vex_sha256": vex_digest,
            "lockfile_sha256": lockfile_digest,
        },
        "timestamp": json.dumps(None), # Placeholder for JSON compatibility without datetime import, actually will use isoformat below if imported
    }
    from datetime import datetime, timezone
    payload["timestamp"] = datetime.now(timezone.utc).isoformat()
    
    return {
        "statement": payload,
        "statement_sha256": _digest(payload),
    }
