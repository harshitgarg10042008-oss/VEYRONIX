"""Secure discovery of configuration sources for local batch audits.

The discovery layer is deliberately content-preserving and fail-closed. It only
returns supported regular files or archive members; parsing and redaction remain
owned by ConfigIngestionService.
"""

from __future__ import annotations

import os
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .ingestion import ConfigIngestionService, IngestionError, IngestedConfig


@dataclass(frozen=True)
class SourceDocument:
    name: str
    content: bytes
    source: str


@dataclass(frozen=True)
class SourcePolicy:
    max_files: int = 100
    max_total_bytes: int = 25 * 1024 * 1024
    archive_extensions: tuple[str, ...] = (".zip", ".tar", ".tgz", ".tar.gz")


class SourceDiscoveryError(ValueError):
    """Raised when a source cannot be expanded safely."""


def discover_sources(
    path: str | os.PathLike[str],
    *,
    ingestion: ConfigIngestionService | None = None,
    policy: SourcePolicy | None = None,
) -> Iterator[SourceDocument]:
    """Yield supported configuration documents from a file, directory, or archive."""
    candidate = Path(path)
    if candidate.is_symlink():
        raise SourceDiscoveryError("symbolic-link sources are not accepted")
    if not candidate.exists():
        raise SourceDiscoveryError("source path does not exist")
    ingestion = ingestion or ConfigIngestionService()
    policy = policy or SourcePolicy()
    if (
        candidate.is_file()
        and candidate.suffix.lower() in policy.archive_extensions
        or candidate.name.lower().endswith(".tar.gz")
    ):
        yield from _archive_documents(candidate, ingestion, policy)
    elif candidate.is_dir():
        yield from _directory_documents(candidate, ingestion, policy)
    elif candidate.is_file():
        try:
            accepted = ingestion.ingest_file(candidate)
        except IngestionError as exc:
            raise SourceDiscoveryError(str(exc)) from exc
        yield SourceDocument(
            accepted.original_name, candidate.read_bytes(), str(candidate)
        )
    else:
        raise SourceDiscoveryError("source path is not a regular file or directory")


def _directory_documents(
    root: Path, ingestion: ConfigIngestionService, policy: SourcePolicy
) -> Iterator[SourceDocument]:
    total = 0
    count = 0
    for item in sorted(root.rglob("*")):
        if item.is_symlink() or not item.is_file():
            continue
        try:
            ingested = ingestion.ingest_file(item)
        except IngestionError:
            continue
        content = item.read_bytes()
        count, total = _account(count, total, len(content), policy)
        yield SourceDocument(ingested.original_name, content, str(item))


def _archive_documents(
    archive: Path, ingestion: ConfigIngestionService, policy: SourcePolicy
) -> Iterator[SourceDocument]:
    count = 0
    total = 0
    try:
        if archive.name.lower().endswith(policy.archive_extensions[0]):
            with zipfile.ZipFile(archive) as bundle:
                for member in sorted(
                    bundle.infolist(), key=lambda entry: entry.filename
                ):
                    if member.is_dir() or not _safe_member(member.filename):
                        continue
                    name = Path(member.filename).name
                    try:
                        content = bundle.read(member)
                        ingestion.ingest_bytes(name, content)
                    except (IngestionError, KeyError):
                        continue
                    count, total = _account(count, total, len(content), policy)
                    yield SourceDocument(name, content, f"{archive}!{member.filename}")
        else:
            with tarfile.open(archive, mode="r:*") as bundle:
                for member in sorted(bundle.getmembers(), key=lambda entry: entry.name):
                    if not member.isfile() or not _safe_member(member.name):
                        continue
                    name = Path(member.name).name
                    stream = bundle.extractfile(member)
                    if stream is None:
                        continue
                    content = stream.read()
                    try:
                        ingestion.ingest_bytes(name, content)
                    except IngestionError:
                        continue
                    count, total = _account(count, total, len(content), policy)
                    yield SourceDocument(name, content, f"{archive}!{member.name}")
    except (OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        raise SourceDiscoveryError(f"unable to read archive: {exc}") from exc


def _account(
    count: int, total: int, size: int, policy: SourcePolicy
) -> tuple[int, int]:
    if count + 1 > policy.max_files:
        raise SourceDiscoveryError("source contains too many configuration files")
    if total + size > policy.max_total_bytes:
        raise SourceDiscoveryError("source exceeds aggregate configuration size limit")
    return count + 1, total + size


def _safe_member(name: str) -> bool:
    path = Path(name)
    return (
        bool(name)
        and not path.is_absolute()
        and ".." not in path.parts
        and "\x00" not in name
    )
