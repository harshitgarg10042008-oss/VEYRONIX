from pathlib import Path
import json
import zipfile

import pytest

from configsentinel.client import ConfigSentinelClient
from configsentinel.engine import DeterministicComplianceEngine
from configsentinel.sources import SourceDiscoveryError, SourcePolicy, discover_sources


CISCO = "version 17.9\nline vty 0 4\n transport input telnet\n"
JUNOS = "set system services ssh\nset system services telnet\n"


def test_discovers_supported_files_in_directory(tmp_path: Path):
    (tmp_path / "edge.conf").write_text(CISCO, encoding="utf-8")
    (tmp_path / "notes.md").write_text("ignore", encoding="utf-8")
    docs = list(discover_sources(tmp_path))
    assert [doc.name for doc in docs] == ["edge.conf"]
    assert docs[0].content.decode() == CISCO


def test_discovers_zip_members_and_rejects_traversal(tmp_path: Path):
    archive = tmp_path / "configs.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("edge.conf", CISCO)
        bundle.writestr("../escape.conf", JUNOS)
    docs = list(discover_sources(archive))
    assert [doc.name for doc in docs] == ["edge.conf"]


def test_source_policy_limits_file_count(tmp_path: Path):
    (tmp_path / "one.conf").write_text(CISCO, encoding="utf-8")
    (tmp_path / "two.conf").write_text(CISCO, encoding="utf-8")
    with pytest.raises(SourceDiscoveryError, match="too many"):
        list(discover_sources(tmp_path, policy=SourcePolicy(max_files=1)))


def test_client_audits_directory(tmp_path: Path):
    (tmp_path / "edge.conf").write_text(CISCO, encoding="utf-8")
    (tmp_path / "junos.conf").write_text(JUNOS, encoding="utf-8")
    client = ConfigSentinelClient(engine=DeterministicComplianceEngine())
    reports = client.audit_sources(str(tmp_path), vendor="cisco_ios")
    assert [name for name, _ in reports] == ["edge.conf", "junos.conf"]
    assert all(result.input_sha256 for _, result in reports)


def test_single_file_source_has_no_archive_requirement(tmp_path: Path):
    config = tmp_path / "edge.conf"
    config.write_text(CISCO, encoding="utf-8")
    docs = list(discover_sources(config))
    assert len(docs) == 1
    assert docs[0].source == str(config)
