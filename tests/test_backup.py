import json
from pathlib import Path

import pytest

from configsentinel.backup import BackupError, backup_file, decrypt_backup, encrypt_backup, restore_file


def test_encrypted_backup_round_trip(tmp_path: Path):
    source = tmp_path / "report.json"
    encrypted = tmp_path / "report.backup"
    restored = tmp_path / "restored.json"
    source.write_text(json.dumps({"audit": {"audit_id": "a-1"}, "findings": []}), encoding="utf-8")
    backup_file(source, encrypted, "a-strong-passphrase")
    assert b"a-1" not in encrypted.read_bytes()
    restore_file(encrypted, restored, "a-strong-passphrase")
    assert json.loads(restored.read_text(encoding="utf-8"))["audit"]["audit_id"] == "a-1"


def test_wrong_passphrase_rejected():
    encrypted = encrypt_backup({"safe": True}, "a-strong-passphrase")
    with pytest.raises(BackupError):
        decrypt_backup(encrypted, "wrong-passphrase")


def test_short_passphrase_rejected():
    with pytest.raises(BackupError):
        encrypt_backup({"safe": True}, "short")
