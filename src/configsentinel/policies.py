"""Validated, local custom policy packs for organization-specific controls."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import EvidenceSpan, Finding, FindingStatus, Severity


class PolicyValidationError(ValueError):
    """Raised when a custom policy pack is invalid or unsafe."""


@dataclass(frozen=True)
class CustomRule:
    control_id: str
    title: str
    intent: str
    severity: Severity
    pattern: re.Pattern[str]
    mode: str
    applies_to: tuple[str, ...]
    remediation: str
    framework_mappings: dict[str, tuple[str, ...]]


@dataclass(frozen=True)
class CustomPolicyPack:
    pack_id: str
    version: str
    rules: tuple[CustomRule, ...]

    @classmethod
    def from_file(cls, path: str | Path) -> "CustomPolicyPack":
        candidate = Path(path)
        if candidate.is_symlink() or not candidate.is_file():
            raise PolicyValidationError("policy path must be a regular file")
        if candidate.stat().st_size > 256 * 1024:
            raise PolicyValidationError("policy pack exceeds the 256 KiB limit")
        try:
            payload = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PolicyValidationError("policy pack must be valid UTF-8 JSON") from exc
        return cls.from_dict(payload)

    @classmethod
    def from_dict(cls, payload: Any) -> "CustomPolicyPack":
        if not isinstance(payload, dict):
            raise PolicyValidationError("policy pack must be an object")
        pack_id = _text(payload.get("pack_id"), "pack_id", 64)
        version = _text(payload.get("version"), "version", 32)
        controls = payload.get("controls")
        if not isinstance(controls, list) or not controls or len(controls) > 100:
            raise PolicyValidationError(
                "controls must contain between 1 and 100 entries"
            )
        rules: list[CustomRule] = []
        seen: set[str] = set()
        for item in controls:
            if not isinstance(item, dict):
                raise PolicyValidationError("each control must be an object")
            control_id = _text(item.get("control_id"), "control_id", 80)
            if control_id in seen or not re.fullmatch(
                r"[A-Z0-9][A-Z0-9._-]+", control_id
            ):
                raise PolicyValidationError(
                    f"invalid or duplicate control_id: {control_id}"
                )
            seen.add(control_id)
            severity_text = _text(item.get("severity"), "severity", 16).upper()
            try:
                severity = Severity(severity_text)
            except ValueError as exc:
                raise PolicyValidationError(
                    f"invalid severity: {severity_text}"
                ) from exc
            match = item.get("match")
            if not isinstance(match, dict):
                raise PolicyValidationError(f"{control_id}: match must be an object")
            pattern_text = _text(match.get("regex"), "match.regex", 300)
            try:
                pattern = re.compile(pattern_text, re.IGNORECASE | re.MULTILINE)
            except re.error as exc:
                raise PolicyValidationError(f"{control_id}: invalid regex") from exc
            mode = _text(match.get("mode"), "match.mode", 16).lower()
            if mode not in {"require", "forbid"}:
                raise PolicyValidationError(
                    f"{control_id}: mode must be require or forbid"
                )
            applies_to = item.get("applies_to", [])
            if not isinstance(applies_to, list) or any(
                not isinstance(value, str) or not value.strip() for value in applies_to
            ):
                raise PolicyValidationError(
                    f"{control_id}: applies_to must be a list of strings"
                )
            mappings = item.get("framework_mappings", {})
            if not isinstance(mappings, dict):
                raise PolicyValidationError(
                    f"{control_id}: framework_mappings must be an object"
                )
            normalized_mappings = {
                str(key): tuple(str(value) for value in values)
                for key, values in mappings.items()
                if isinstance(values, list)
            }
            rules.append(
                CustomRule(
                    control_id,
                    _text(item.get("title"), "title", 160),
                    _text(item.get("intent"), "intent", 300),
                    severity,
                    pattern,
                    mode,
                    tuple(applies_to),
                    _text(
                        item.get(
                            "remediation",
                            "Review and remediate after operator approval.",
                        ),
                        "remediation",
                        500,
                    ),
                    normalized_mappings,
                )
            )
        return cls(pack_id, version, tuple(rules))


def evaluate_custom(
    pack: CustomPolicyPack, text: str, *, audit_id: str, vendor: str
) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    lines = text.splitlines()
    for rule in pack.rules:
        if rule.applies_to and vendor not in rule.applies_to:
            continue
        spans = tuple(
            EvidenceSpan(index, index, line.strip())
            for index, line in enumerate(lines, 1)
            if line.strip() and rule.pattern.search(line)
        )
        matched = bool(spans)
        if rule.mode == "forbid":
            status = FindingStatus.FAIL if matched else FindingStatus.UNKNOWN
            rationale = (
                f"Forbidden pattern matched {len(spans)} source line(s)."
                if matched
                else "No explicit evidence proves the forbidden pattern is absent."
            )
        else:
            status = FindingStatus.PASS if matched else FindingStatus.UNKNOWN
            rationale = (
                f"Required pattern matched {len(spans)} source line(s)."
                if matched
                else "Required pattern was not found in the supplied configuration."
            )
        findings.append(
            Finding(
                f"{audit_id}:{rule.control_id}",
                audit_id,
                rule.control_id,
                status,
                rule.severity,
                1.0 if matched else 0.0,
                spans,
                rationale,
                rule.intent,
                rationale,
                rule.remediation,
            )
        )
    return tuple(findings)


def _text(value: Any, field: str, max_length: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        raise PolicyValidationError(
            f"{field} must be a non-empty string of at most {max_length} characters"
        )
    return value.strip()
