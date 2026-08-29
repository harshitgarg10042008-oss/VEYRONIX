"""Deterministic SBOM and release metadata helpers."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import tomllib
from pathlib import Path
from typing import Any


class ReleaseError(ValueError):
    """Raised when release metadata inputs are invalid."""


def _project(root: Path) -> dict[str, Any]:
    path = root / "pyproject.toml"
    try:
        with path.open("rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ReleaseError("pyproject.toml is unavailable or invalid") from exc
    project = document.get("project")
    if (
        not isinstance(project, dict)
        or not project.get("name")
        or not project.get("version")
    ):
        raise ReleaseError("project name and version are required")
    return project


def build_sbom(root: str | Path) -> dict[str, Any]:
    base = Path(root).resolve()
    project = _project(base)
    components: list[dict[str, str]] = []
    for name, requirements in sorted(
        (project.get("optional-dependencies") or {}).items()
    ):
        if not isinstance(requirements, list):
            continue
        for requirement in requirements:
            components.append(
                {
                    "name": str(requirement)
                    .split(">=", 1)[0]
                    .split("==", 1)[0]
                    .strip(),
                    "requirement": str(requirement),
                    "scope": str(name),
                }
            )
    return {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{project['name']}-{project['version']}",
        "documentNamespace": "https://veyronix.local/configsentinel/sbom",
        "creationInfo": {
            "created": "1970-01-01T00:00:00Z",
            "creator": "Tool: ConfigSentinel AI",
        },
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-configsentinel",
                "name": str(project["name"]),
                "versionInfo": str(project["version"]),
                "downloadLocation": "NOASSERTION",
            }
        ],
        "externalDocumentRefs": [],
        "relationships": [],
        "components": components,
    }


def build_release_metadata(
    root: str | Path, *, manifest: dict[str, Any] | None = None
) -> dict[str, Any]:
    base = Path(root).resolve()
    project = _project(base)
    pyproject_hash = hashlib.sha256((base / "pyproject.toml").read_bytes()).hexdigest()
    return {
        "schema": "configsentinel.reproducible-release.v1",
        "project": str(project["name"]),
        "version": str(project["version"]),
        "source_date_epoch": int(os.environ.get("SOURCE_DATE_EPOCH", "0")),
        "python_requires": str(project.get("requires-python", "")),
        "pyproject_sha256": pyproject_hash,
        "platform": "source-reproducible",
        "manifest_sha256": hashlib.sha256(
            json.dumps(manifest or {}, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }


def write_release_artifacts(
    root: str | Path,
    sbom_output: str | Path,
    metadata_output: str | Path,
    *,
    manifest: dict[str, Any] | None = None,
) -> None:
    sbom = build_sbom(root)
    metadata = build_release_metadata(root, manifest=manifest)
    sbom_path, metadata_path = Path(sbom_output), Path(metadata_output)
    sbom_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    sbom_path.write_text(
        json.dumps(sbom, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    metadata_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
