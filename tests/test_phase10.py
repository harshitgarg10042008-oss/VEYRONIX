from pathlib import Path

import pytest

from configsentinel.hardening import (
    HardeningError,
    ResourceBudget,
    benchmark_call,
    safe_output_path,
    sha256_text,
)


def test_resource_budget_rejects_oversized_input():
    budget = ResourceBudget(max_input_bytes=4)
    with pytest.raises(HardeningError):
        budget.validate_text("12345")


def test_resource_budget_rejects_long_lines_and_unknown_overflow():
    budget = ResourceBudget(max_line_bytes=3, max_unknown_blocks=1)
    with pytest.raises(HardeningError):
        budget.validate_text("abcd")
    with pytest.raises(HardeningError):
        budget.validate_unknown_count(2)


def test_safe_output_path_stays_inside_root(tmp_path: Path):
    path = safe_output_path("reports/audit.json", tmp_path)
    assert path.parent == tmp_path / "reports"
    with pytest.raises(HardeningError):
        safe_output_path("../outside.json", tmp_path)
    with pytest.raises(HardeningError):
        safe_output_path(str(tmp_path / "absolute.json"), tmp_path)


def test_benchmark_is_bounded_and_hash_is_deterministic():
    stats = benchmark_call(lambda: sha256_text("fixture"), iterations=3)
    assert stats["iterations"] == 3.0
    assert stats["min_ms"] <= stats["p95_ms"] <= stats["max_ms"]
    assert sha256_text("fixture") == sha256_text("fixture")


def test_budget_rejects_invalid_values():
    with pytest.raises(ValueError):
        ResourceBudget(timeout_seconds=0)
