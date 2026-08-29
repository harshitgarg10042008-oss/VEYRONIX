"""Authenticated encrypted local backup envelopes."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any, Mapping

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False
    Fernet = None
    InvalidToken = Exception
    hashes = None
    PBKDF2HMAC = None

def _require_crypto() -> None:
    if not HAS_CRYPTOGRAPHY:
        raise RuntimeError("Install the 'backup' extra to use encrypted backups")


class BackupError(ValueError):
    """Raised when an encrypted backup is invalid or cannot be decrypted."""


def _key(passphrase: str, salt: bytes) -> bytes:
    _require_crypto()
    if not passphrase or len(passphrase) < 12 or len(passphrase) > 4096:
        raise BackupError("backup passphrase must be 12 to 4096 characters")
    derivation = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)
    return base64.urlsafe_b64encode(derivation.derive(passphrase.encode("utf-8")))


def encrypt_backup(payload: Mapping[str, Any], passphrase: str) -> bytes:
    _require_crypto()
    if not isinstance(payload, Mapping):
        raise BackupError("backup payload must be an object")
    raw = json.dumps(dict(payload), sort_keys=True, separators=(",", ":")).encode("utf-8")
    salt = os.urandom(16)
    token = Fernet(_key(passphrase, salt)).encrypt(raw)
    envelope = {"schema": "configsentinel.encrypted-backup.v1", "kdf": "PBKDF2-HMAC-SHA256", "iterations": 600000, "salt": base64.urlsafe_b64encode(salt).decode("ascii"), "ciphertext": token.decode("ascii")}
    return (json.dumps(envelope, sort_keys=True) + "\n").encode("utf-8")


def decrypt_backup(data: bytes, passphrase: str) -> dict[str, Any]:
    _require_crypto()
    try:
        envelope = json.loads(data.decode("utf-8"))
        if envelope.get("schema") != "configsentinel.encrypted-backup.v1" or envelope.get("kdf") != "PBKDF2-HMAC-SHA256" or envelope.get("iterations") != 600000:
            raise BackupError("unsupported backup envelope")
        salt = base64.urlsafe_b64decode(str(envelope["salt"]).encode("ascii"))
        ciphertext = str(envelope["ciphertext"]).encode("ascii")
        payload = json.loads(Fernet(_key(passphrase, salt)).decrypt(ciphertext).decode("utf-8"))
    except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError, InvalidToken) as exc:
        raise BackupError("backup authentication or parsing failed") from exc
    if not isinstance(payload, dict):
        raise BackupError("decrypted backup payload must be an object")
    return payload


def backup_file(input_path: str | Path, output_path: str | Path, passphrase: str) -> None:
    source = Path(input_path)
    if source.is_symlink() or not source.is_file() or source.stat().st_size > 16 * 1024 * 1024:
        raise BackupError("backup input must be a regular file no larger than 16 MiB")
    payload = {"source_name": source.name, "source_sha256": __import__("hashlib").sha256(source.read_bytes()).hexdigest(), "document": json.loads(source.read_text(encoding="utf-8"))}
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(encrypt_backup(payload, passphrase))


def restore_file(input_path: str | Path, output_path: str | Path, passphrase: str) -> None:
    payload = decrypt_backup(Path(input_path).read_bytes(), passphrase)
    if "document" not in payload or not isinstance(payload["document"], dict):
        raise BackupError("backup does not contain a JSON document")
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload["document"], indent=2, sort_keys=True) + "\n", encoding="utf-8")
