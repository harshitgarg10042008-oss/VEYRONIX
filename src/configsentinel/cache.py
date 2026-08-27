"""Content-addressed local cache for deterministic serialized audit reports."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Callable


class CacheError(ValueError):
    """Raised when cache input or storage is unsafe."""


class AuditCache:
    def __init__(self, root: str | Path, *, max_entries: int = 5000) -> None:
        self.root = Path(root)
        self.max_entries = max_entries
        if max_entries < 1 or max_entries > 100000:
            raise CacheError("max_entries must be between 1 and 100000")

    @staticmethod
    def key(redacted_text: str, *, vendor: str, frameworks: tuple[str, ...], rule_pack_version: str) -> str:
        if not redacted_text.strip() or not vendor.strip() or not frameworks or not rule_pack_version.strip():
            raise CacheError("cache key inputs are incomplete")
        canonical = json.dumps({"redacted_text": redacted_text, "vendor": vendor, "frameworks": list(frameworks), "rule_pack_version": rule_pack_version}, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def _path(self, key: str) -> Path:
        if len(key) != 64 or any(character not in "0123456789abcdef" for character in key):
            raise CacheError("cache key must be a SHA-256 hex digest")
        return self.root / key[:2] / f"{key}.json"

    def get(self, key: str) -> dict[str, Any] | None:
        path = self._path(key)
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CacheError("cache entry is unreadable") from exc
        if not isinstance(payload, dict) or payload.get("cache_key") != key or not isinstance(payload.get("report"), dict):
            raise CacheError("cache entry failed integrity checks")
        return payload["report"]

    def put(self, key: str, report: dict[str, Any]) -> None:
        if not isinstance(report, dict):
            raise CacheError("cached report must be an object")
        path = self._path(key)
        if not path.exists() and sum(1 for item in self.root.glob("**/*.json") if item.is_file()) >= self.max_entries:
            raise CacheError("cache entry limit exceeded")
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps({"cache_key": key, "report": report}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(path)

    def get_or_compute(self, key: str, compute: Callable[[], dict[str, Any]]) -> tuple[dict[str, Any], bool]:
        cached = self.get(key)
        if cached is not None:
            return cached, True
        report = compute()
        self.put(key, report)
        return report, False
