"""Phase 10 hardening and performance instrumentation utilities."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Callable, TypeVar

T = TypeVar("T")


class HardeningError(ValueError):
    """Raised when a resource or safety budget is violated."""


@dataclass(frozen=True)
class ResourceBudget:
    max_input_bytes: int = 5 * 1024 * 1024
    max_lines: int = 100_000
    max_line_bytes: int = 256 * 1024
    max_unknown_blocks: int = 10_000
    max_report_bytes: int = 10 * 1024 * 1024
    timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        if any(
            value <= 0
            for value in (
                self.max_input_bytes,
                self.max_lines,
                self.max_line_bytes,
                self.max_unknown_blocks,
                self.max_report_bytes,
            )
        ):
            raise ValueError("resource budgets must be positive")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")

    def validate_text(self, text: str) -> None:
        encoded = text.encode("utf-8")
        if len(encoded) > self.max_input_bytes:
            raise HardeningError("input exceeds configured byte budget")
        lines = text.splitlines()
        if len(lines) > self.max_lines:
            raise HardeningError("input exceeds configured line budget")
        if any(len(line.encode("utf-8")) > self.max_line_bytes for line in lines):
            raise HardeningError("input contains a line exceeding configured budget")

    def validate_unknown_count(self, count: int) -> None:
        if count > self.max_unknown_blocks:
            raise HardeningError("unknown-block count exceeds configured budget")

    def validate_report(self, content: str) -> None:
        if len(content.encode("utf-8")) > self.max_report_bytes:
            raise HardeningError("report exceeds configured byte budget")


@dataclass(frozen=True)
class AuditMetrics:
    audit_id: str
    vendor: str
    input_sha256: str
    duration_ms: float
    finding_count: int
    failed_count: int
    unknown_count: int
    parser_version: str
    rule_pack_version: str

    def as_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def safe_output_path(path: str | Path, root: str | Path) -> Path:
    root_path = Path(root).resolve()
    candidate = Path(path)
    if candidate.is_absolute():
        raise HardeningError("absolute output paths are not allowed")
    resolved = (root_path / candidate).resolve()
    if resolved != root_path and root_path not in resolved.parents:
        raise HardeningError("output path escapes the permitted root")
    if resolved.exists() and resolved.is_symlink():
        raise HardeningError("symlink output paths are not allowed")
    return resolved


def timed(operation: Callable[[], T]) -> tuple[T, float]:
    started = time.perf_counter()
    value = operation()
    return value, (time.perf_counter() - started) * 1000


def metrics_for(result: Any, duration_ms: float) -> AuditMetrics:
    return AuditMetrics(
        audit_id=result.audit_id,
        vendor=result.vendor,
        input_sha256=result.input_sha256,
        duration_ms=round(duration_ms, 3),
        finding_count=len(result.findings),
        failed_count=result.failed_count,
        unknown_count=len(result.unknown_blocks),
        parser_version=result.parser_version,
        rule_pack_version=result.rule_pack_version,
    )


def benchmark_call(
    operation: Callable[[], T], *, iterations: int = 5
) -> dict[str, float]:
    if iterations < 1 or iterations > 1000:
        raise HardeningError("iterations must be between 1 and 1000")
    samples: list[float] = []
    for _ in range(iterations):
        _, elapsed = timed(operation)
        samples.append(elapsed)
    ordered = sorted(samples)
    return {
        "iterations": float(iterations),
        "min_ms": round(ordered[0], 3),
        "max_ms": round(ordered[-1], 3),
        "mean_ms": round(sum(samples) / len(samples), 3),
        "p95_ms": round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))], 3),
    }


__all__ = [
    "HardeningError",
    "ResourceBudget",
    "AuditMetrics",
    "sha256_text",
    "safe_output_path",
    "timed",
    "metrics_for",
    "benchmark_call",
]
