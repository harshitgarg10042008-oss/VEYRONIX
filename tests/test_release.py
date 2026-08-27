import json
from pathlib import Path

from configsentinel.release import build_release_metadata, build_sbom, write_release_artifacts


def test_sbom_contains_project_and_declared_components():
    sbom = build_sbom(Path(__file__).parents[1])
    assert sbom["spdxVersion"] == "SPDX-2.3"
    assert sbom["packages"][0]["name"] == "configsentinel-sdk"
    assert any(item["name"] == "cryptography" for item in sbom["components"])


def test_release_metadata_is_stable_for_same_inputs(tmp_path: Path):
    root = Path(__file__).parents[1]
    first = build_release_metadata(root, manifest={"files": {"README.md": "a"}})
    second = build_release_metadata(root, manifest={"files": {"README.md": "a"}})
    assert first == second
    write_release_artifacts(root, tmp_path / "sbom.json", tmp_path / "release.json")
    assert json.loads((tmp_path / "release.json").read_text(encoding="utf-8"))["schema"] == "configsentinel.reproducible-release.v1"
