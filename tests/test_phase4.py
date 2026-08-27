from pathlib import Path

import pytest

from configsentinel import (
    ConfigIngestionService,
    ConfigSentinelClient,
    DeterministicComplianceEngine,
    IngestionError,
    IngestionPolicy,
)


def test_ingestion_redacts_and_hashes_without_exposing_secret(tmp_path: Path):
    service = ConfigIngestionService(tmp_path / "quarantine")
    result = service.ingest_text("edge.conf", "enable secret top-secret\nline vty 0 4\n transport input telnet\n")
    assert result.byte_count > 0
    assert result.redaction_count == 1
    assert "top-secret" not in result.redacted_text
    assert len(result.input_sha256) == 64
    assert Path(result.quarantine_path).exists()


def test_ingestion_rejects_traversal_and_unsupported_extension():
    service = ConfigIngestionService()
    with pytest.raises(IngestionError):
        service.ingest_text("../escape.conf", "hostname edge")
    with pytest.raises(IngestionError):
        service.ingest_text("config.exe", "hostname edge")


def test_ingestion_rejects_nul_invalid_utf8_and_empty():
    service = ConfigIngestionService()
    with pytest.raises(IngestionError):
        service.ingest_bytes("config.conf", b"hostname edge\x00")
    with pytest.raises(IngestionError):
        service.ingest_bytes("config.conf", b"\xff\xfe")
    with pytest.raises(IngestionError):
        service.ingest_bytes("config.conf", b"")


def test_ingestion_enforces_size_and_line_limits():
    service = ConfigIngestionService(policy=IngestionPolicy(max_bytes=10, max_line_bytes=5))
    with pytest.raises(IngestionError):
        service.ingest_text("config.conf", "01234567890")
    with pytest.raises(IngestionError):
        service.ingest_text("config.conf", "123456")


def test_ingestion_rejects_symlinks(tmp_path: Path):
    source = tmp_path / "source.conf"
    source.write_text("hostname edge", encoding="utf-8")
    link = tmp_path / "link.conf"
    link.symlink_to(source)
    with pytest.raises(IngestionError):
        ConfigIngestionService().ingest_file(link)


def test_sdk_audit_file_uses_secure_ingestion(tmp_path: Path):
    config = tmp_path / "edge.conf"
    config.write_text("version 17.9\nline vty 0 4\n transport input telnet\n", encoding="utf-8")
    client = ConfigSentinelClient(engine=DeterministicComplianceEngine())
    result = client.audit_file(str(config), vendor="cisco_ios")
    telnet = next(item for item in result.findings if item.control_id == "NET-MGMT-TELNET-001")
    assert telnet.status.value == "FAIL"
    assert result.input_sha256
