import json
from pathlib import Path

import pytest

from configsentinel.supplychain import (
    SupplyChainError,
    build_manifest,
    verify_manifest,
    write_manifest,
)


def test_manifest_round_trip_and_tamper_detection(tmp_path: Path):
    source = tmp_path / "sample.py"
    source.write_text("print('safe')\n", encoding="utf-8")
    manifest_path = tmp_path / "manifest.json"
    write_manifest(tmp_path, manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert verify_manifest(tmp_path, manifest) == ()
    source.write_text("print('changed')\n", encoding="utf-8")
    assert "changed:sample.py" in verify_manifest(tmp_path, manifest)


def test_manifest_rejects_path_traversal():
    with pytest.raises(SupplyChainError):
        verify_manifest(
            "/tmp",
            {
                "schema": "configsentinel.release-manifest.v1",
                "algorithm": "sha256",
                "files": {"../outside": "a"},
            },
        )


def test_manifest_build_has_schema(tmp_path: Path):
    assert build_manifest(tmp_path)["schema"] == "configsentinel.release-manifest.v1"
