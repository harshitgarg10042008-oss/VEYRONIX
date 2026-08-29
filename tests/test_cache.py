from pathlib import Path

import pytest

from configsentinel.cache import AuditCache, CacheError


def test_cache_key_changes_with_audit_inputs():
    first = AuditCache.key(
        "redacted",
        vendor="cisco_ios",
        frameworks=("cis-network",),
        rule_pack_version="1",
    )
    second = AuditCache.key(
        "redacted", vendor="junos", frameworks=("cis-network",), rule_pack_version="1"
    )
    assert len(first) == 64 and first != second


def test_cache_get_or_compute_hits_after_first_write(tmp_path: Path):
    cache = AuditCache(tmp_path / "cache")
    key = AuditCache.key(
        "redacted",
        vendor="cisco_ios",
        frameworks=("cis-network",),
        rule_pack_version="1",
    )
    calls = []

    def compute():
        calls.append(True)
        return {"audit": {"audit_id": "a-1"}, "findings": []}

    first, first_hit = cache.get_or_compute(key, compute)
    second, second_hit = cache.get_or_compute(key, compute)
    assert first == second and not first_hit and second_hit and len(calls) == 1


def test_cache_rejects_tampered_entry(tmp_path: Path):
    cache = AuditCache(tmp_path / "cache")
    with pytest.raises(CacheError):
        cache.get("not-a-sha256-key")
