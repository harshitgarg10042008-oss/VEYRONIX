"""Secure configuration ingestion for local and API callers.

The service validates and quarantines input before parsing. It never trusts the
client-provided filename and never sends raw content to downstream LLM code.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
from dataclasses import dataclass
from pathlib import Path

from .security import RedactionResult, SecretRedactor


class IngestionError(ValueError):
    """Raised when configuration input fails a fail-closed validation."""


@dataclass(frozen=True)
class IngestionPolicy:
    max_bytes: int = 5 * 1024 * 1024
    max_line_bytes: int = 256 * 1024
    allowed_extensions: tuple[str, ...] = (".cfg", ".conf", ".config", ".txt", ".log")
    reject_nul: bool = True


@dataclass(frozen=True)
class IngestedConfig:
    ingestion_id: str
    original_name: str
    safe_name: str
    input_sha256: str
    byte_count: int
    line_count: int
    redaction_count: int
    redacted_text: str
    quarantine_path: str | None = None


class ConfigIngestionService:
    def __init__(self, quarantine_dir: str | os.PathLike[str] | None = None, *, policy: IngestionPolicy | None = None, redactor: SecretRedactor | None = None) -> None:
        self.policy = policy or IngestionPolicy()
        self.redactor = redactor or SecretRedactor()
        self.quarantine_dir = Path(quarantine_dir).resolve() if quarantine_dir else None
        if self.quarantine_dir:
            self.quarantine_dir.mkdir(parents=True, exist_ok=True)

    def ingest_file(self, path: str | os.PathLike[str]) -> IngestedConfig:
        candidate = Path(path)
        if candidate.is_symlink():
            raise IngestionError("symbolic-link inputs are not accepted")
        if not candidate.is_file():
            raise IngestionError("input path is not a regular file")
        return self.ingest_bytes(candidate.name, candidate.read_bytes())

    def ingest_text(self, filename: str, text: str) -> IngestedConfig:
        if not isinstance(text, str):
            raise IngestionError("text input must be a string")
        return self.ingest_bytes(filename, text.encode("utf-8"))

    def ingest_bytes(self, filename: str, content: bytes) -> IngestedConfig:
        if not isinstance(content, bytes):
            raise IngestionError("content must be bytes")
        original_name = filename or "unnamed.config"
        self._validate_name(original_name)
        self._validate_bytes(content)
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise IngestionError("configuration must be valid UTF-8") from exc
        for line in text.splitlines(keepends=True):
            if len(line.encode("utf-8")) > self.policy.max_line_bytes:
                raise IngestionError("configuration line exceeds the safety limit")
        redacted: RedactionResult = self.redactor.redact(text)
        ingestion_id = f"ing_{secrets.token_hex(12)}"
        safe_name = self._safe_name(original_name, ingestion_id)
        quarantine_path = None
        if self.quarantine_dir:
            target = (self.quarantine_dir / f"{ingestion_id}.bin").resolve()
            if target.parent != self.quarantine_dir:
                raise IngestionError("quarantine path escaped configured directory")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            fd = os.open(target, flags, 0o600)
            try:
                os.write(fd, content)
            finally:
                os.close(fd)
            quarantine_path = str(target)
        return IngestedConfig(
            ingestion_id=ingestion_id,
            original_name=original_name,
            safe_name=safe_name,
            input_sha256=redacted.input_sha256,
            byte_count=len(content),
            line_count=len(text.splitlines()),
            redaction_count=redacted.redaction_count,
            redacted_text=redacted.text,
            quarantine_path=quarantine_path,
        )

    def delete_quarantine(self, ingested: IngestedConfig) -> None:
        if not ingested.quarantine_path:
            return
        target = Path(ingested.quarantine_path).resolve()
        if not self.quarantine_dir or target.parent != self.quarantine_dir:
            raise IngestionError("refusing to delete outside quarantine directory")
        target.unlink(missing_ok=True)

    def _validate_name(self, filename: str) -> None:
        if "\x00" in filename or Path(filename).name != filename:
            raise IngestionError("filename must be a simple basename")
        suffix = Path(filename).suffix.lower()
        if suffix not in self.policy.allowed_extensions:
            raise IngestionError(f"unsupported configuration extension: {suffix or '<none>'}")

    def _validate_bytes(self, content: bytes) -> None:
        if len(content) == 0:
            raise IngestionError("empty configuration is not accepted")
        if len(content) > self.policy.max_bytes:
            raise IngestionError("configuration exceeds the maximum size")
        if self.policy.reject_nul and b"\x00" in content:
            raise IngestionError("NUL bytes are not accepted")

    @staticmethod
    def _safe_name(filename: str, ingestion_id: str) -> str:
        stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", Path(filename).stem).strip("._") or "config"
        suffix = Path(filename).suffix.lower()
        return f"{ingestion_id}_{stem[:64]}{suffix}"
