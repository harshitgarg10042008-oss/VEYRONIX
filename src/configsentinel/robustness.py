"""Bounded adversarial robustness checks for supported configuration parsers."""

from __future__ import annotations

import hashlib
from dataclasses import asdict
from typing import Any

from .canonical import CanonicalConfig, ParseResult
from .parsers import PARSER_REGISTRY, VendorParser

ROBUSTNESS_SCHEMA = "configsentinel.adversarial-parser-robustness.v1"
MAX_INPUT_BYTES = 1024 * 1024
MAX_CASES = 32
SEMANTIC_FIELDS = (
    "management_ssh_enabled",
    "management_ssh_version",
    "management_telnet_enabled",
    "aaa_enabled",
    "logging_enabled",
    "ntp_enabled",
    "snmp_secure",
    "http_management_enabled",
    "unused_services_disabled",
)


class RobustnessError(ValueError):
    """Raised when a robustness pack request is unsafe or unsupported."""


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()


def _parser(vendor: str) -> VendorParser:
    selected = next(
        (parser for parser in PARSER_REGISTRY if parser.plugin_id == vendor), None
    )
    if selected is None:
        raise RobustnessError(f"unsupported robustness vendor: {vendor}")
    return selected


def _semantic(config: CanonicalConfig) -> dict[str, Any]:
    return {field: getattr(config, field) for field in SEMANTIC_FIELDS}


def _case_variants(text: str) -> list[tuple[str, str]]:
    variants = [
        ("baseline", text),
        ("crlf_line_endings", text.replace("\n", "\r\n")),
        ("missing_final_newline", text.rstrip("\r\n")),
        ("leading_bom", "\ufeff" + text),
        ("long_unknown_line", text + "\n" + ("x" * 4096)),
        ("embedded_nul_suffix", text + "\n\x00"),
        ("unicode_confusable_suffix", text + "\n＃ robustness marker"),
        ("duplicate_payload", text + "\n" + text),
    ]
    unique: list[tuple[str, str]] = []
    seen: set[str] = set()
    for case_id, value in variants:
        digest = _sha256(value)
        if digest not in seen:
            unique.append((case_id, value))
            seen.add(digest)
    return unique


def _result(
    case_id: str, mutated: str, parsed: ParseResult, baseline: dict[str, Any] | None
) -> dict[str, Any]:
    semantic = _semantic(parsed.config)
    changed = sorted(
        field
        for field in SEMANTIC_FIELDS
        if baseline is not None and baseline.get(field) != semantic[field]
    )
    return {
        "case_id": case_id,
        "input_sha256": _sha256(mutated),
        "input_bytes": len(mutated.encode("utf-8", errors="surrogatepass")),
        "outcome": "ACCEPTED",
        "parser_version": parsed.parser_version,
        "unknown_block_count": len(parsed.config.unknown_blocks),
        "warning_count": len(parsed.warnings),
        "semantic": semantic,
        "semantic_fields_changed_vs_baseline": changed,
    }


def run_robustness_pack(
    text: str, *, vendor: str, max_cases: int = MAX_CASES
) -> dict[str, Any]:
    """Run deterministic parser abuse cases; raw inputs and exception messages never leave the process."""
    if not isinstance(text, str) or not text:
        raise RobustnessError("robustness input must be a non-empty string")
    if len(text.encode("utf-8", errors="surrogatepass")) > MAX_INPUT_BYTES:
        raise RobustnessError("robustness input exceeds 1 MiB")
    if max_cases < 1 or max_cases > MAX_CASES:
        raise RobustnessError(f"max_cases must be between 1 and {MAX_CASES}")
    parser = _parser(vendor)
    cases = _case_variants(text)[:max_cases]
    baseline_semantic: dict[str, Any] | None = None
    outputs: list[dict[str, Any]] = []
    for case_id, mutated in cases:
        if len(mutated.encode("utf-8", errors="surrogatepass")) > MAX_INPUT_BYTES:
            outputs.append(
                {
                    "case_id": case_id,
                    "input_sha256": _sha256(mutated),
                    "input_bytes": len(mutated.encode("utf-8", errors="surrogatepass")),
                    "outcome": "REJECTED_BOUNDED",
                    "reason_code": "INPUT_LIMIT",
                }
            )
            continue
        try:
            parsed = parser.parse(mutated)
            if baseline_semantic is None:
                baseline_semantic = _semantic(parsed.config)
            outputs.append(_result(case_id, mutated, parsed, baseline_semantic))
        except (Exception,) as exc:
            outputs.append(
                {
                    "case_id": case_id,
                    "input_sha256": _sha256(mutated),
                    "input_bytes": len(mutated.encode("utf-8", errors="surrogatepass")),
                    "outcome": "CRASHED",
                    "exception_type": type(exc).__name__,
                }
            )
    crashed = [item for item in outputs if item["outcome"] == "CRASHED"]
    bounded = [item for item in outputs if item["outcome"] == "REJECTED_BOUNDED"]
    accepted = [item for item in outputs if item["outcome"] == "ACCEPTED"]
    return {
        "schema": ROBUSTNESS_SCHEMA,
        "vendor": parser.plugin_id,
        "parser_version": parser.parser_version,
        "input_sha256": _sha256(text),
        "cases": outputs,
        "summary": {
            "case_count": len(outputs),
            "accepted_count": len(accepted),
            "bounded_rejection_count": len(bounded),
            "crash_count": len(crashed),
            "semantic_deviation_case_count": sum(
                bool(item.get("semantic_fields_changed_vs_baseline"))
                for item in accepted
            ),
            "passed": not crashed,
            "pass_criteria": [
                "no parser crash",
                "oversized mutations are bounded",
                "all outputs are hash-only and semantic summaries",
            ],
            "failure_policy": "a crash is a robustness failure; a semantic deviation is review-visible and not normalized away",
        },
        "safety": {
            "raw_configuration_included": False,
            "exception_messages_included": False,
            "network_access": False,
            "parser_registry_changed": False,
            "verdicts_changed": False,
            "autonomous_patch_generation": False,
        },
    }


__all__ = ["MAX_CASES", "ROBUSTNESS_SCHEMA", "RobustnessError", "run_robustness_pack"]
