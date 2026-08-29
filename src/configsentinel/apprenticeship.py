"""Governed unknown-syntax apprenticeship contracts for parser extension review."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .security import SecretRedactor

APPRENTICESHIP_SCHEMA = "configsentinel.parser-apprenticeship-contract.v1"
MAX_EXAMPLES = 8
MAX_EXAMPLE_BYTES = 2048


class ApprenticeshipError(ValueError):
    """Raised when an unknown-syntax contract is unsafe or malformed."""


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if is_dataclass(value):
        value = asdict(value)
    if not isinstance(value, Mapping):
        raise ApprenticeshipError(f"{label} must be an object")
    return value


def _text(value: Any, label: str, limit: int = 256) -> str:
    text = str(value or "").strip()
    if not text or len(text) > limit:
        raise ApprenticeshipError(f"{label} is required and bounded")
    return text


def _examples(
    values: Sequence[str], label: str, redactor: SecretRedactor
) -> tuple[list[str], list[str]]:
    if not isinstance(values, (list, tuple)) or not 1 <= len(values) <= MAX_EXAMPLES:
        raise ApprenticeshipError(f"{label} requires 1-{MAX_EXAMPLES} examples")
    stored: list[str] = []
    digests: list[str] = []
    for value in values:
        if (
            not isinstance(value, str)
            or not value.strip()
            or len(value.encode("utf-8")) > MAX_EXAMPLE_BYTES
            or "\x00" in value
        ):
            raise ApprenticeshipError(
                f"{label} contains an invalid or oversized example"
            )
        redacted = redactor.redact(value)
        stored.append(redacted.text)
        digests.append(redacted.input_sha256)
    return stored, digests


def _fingerprint(digests: Sequence[str]) -> str:
    return hashlib.sha256("|".join(sorted(digests)).encode("ascii")).hexdigest()


def create_contract(
    mapping: Mapping[str, Any] | Any,
    *,
    positive_examples: Sequence[str],
    counterexamples: Sequence[str],
) -> dict[str, Any]:
    """Create a redacted contract from an already-approved mapping."""
    source = _mapping(mapping, "approved mapping")
    required = (
        "mapping_id",
        "vendor",
        "parser_version",
        "source_case_id",
        "syntax_fingerprint",
        "normalized_concept",
        "interpretation",
        "approved_by",
        "approved_at",
    )
    missing = [name for name in required if not str(source.get(name, "")).strip()]
    if missing:
        raise ApprenticeshipError(f"approved mapping is missing: {', '.join(missing)}")
    redactor = SecretRedactor()
    positive, positive_digests = _examples(
        positive_examples, "positive_examples", redactor
    )
    negative, negative_digests = _examples(counterexamples, "counterexamples", redactor)
    contract = {
        "schema": APPRENTICESHIP_SCHEMA,
        "contract_id": "contract_"
        + hashlib.sha256(
            f"{source['mapping_id']}|{source['normalized_concept']}|{source['parser_version']}".encode()
        ).hexdigest()[:16],
        "mapping": {name: str(source[name]) for name in required},
        "examples": {
            "positive": positive,
            "counterexamples": negative,
            "positive_input_digests": positive_digests,
            "counterexample_input_digests": negative_digests,
            "syntax_fingerprint": str(source["syntax_fingerprint"]),
            "redacted": True,
        },
        "promotion": {
            "status": "PENDING_CONTRACT_TESTS",
            "human_review_required": True,
            "promoted_into_parser": False,
        },
        "safety": {
            "redacted_examples_included": True,
            "raw_secrets_included": False,
            "verdicts_changed": False,
            "parser_registry_changed": False,
            "network_access": False,
            "note": "This contract is a review artifact. It cannot modify parser behavior or compliance verdicts without a separately reviewed promotion process.",
        },
    }
    return contract


def _observe(example: str) -> str | None:
    """Small deterministic semantic recognizer used only to test contract fixtures."""
    lowered = example.lower()
    if "telnet" in lowered and any(
        token in lowered for token in ("enable", "allow", "transport", "services")
    ):
        return "management_telnet_enabled"
    if "ssh" in lowered and any(
        token in lowered
        for token in ("enable", "allow", "transport", "services", "version")
    ):
        return "management_ssh_enabled"
    if any(token in lowered for token in ("logging ", "syslog", " log", "log ")):
        return "logging_enabled"
    if "ntp" in lowered:
        return "ntp_enabled"
    return None


def evaluate_contract(contract: Mapping[str, Any]) -> dict[str, Any]:
    """Run deterministic positive/counterexample checks; never promote automatically."""
    root = _mapping(contract, "contract")
    if root.get("schema") != APPRENTICESHIP_SCHEMA:
        raise ApprenticeshipError("unsupported apprenticeship contract schema")
    mapping = _mapping(root.get("mapping"), "contract.mapping")
    expected = _text(mapping.get("normalized_concept"), "mapping.normalized_concept")
    examples = _mapping(root.get("examples"), "contract.examples")
    positive = examples.get("positive")
    negative = examples.get("counterexamples")
    if not isinstance(positive, list) or not isinstance(negative, list):
        raise ApprenticeshipError("contract examples must be arrays")
    positive_observed = [_observe(str(example)) for example in positive]
    negative_observed = [_observe(str(example)) for example in negative]
    positive_pass = all(observed == expected for observed in positive_observed)
    negative_pass = all(observed != expected for observed in negative_observed)
    ready = positive_pass and negative_pass
    return {
        "schema": "configsentinel.parser-apprenticeship-test.v1",
        "contract_id": str(root.get("contract_id", "")),
        "expected_normalized_concept": expected,
        "positive": {
            "count": len(positive),
            "observed": positive_observed,
            "passed": positive_pass,
        },
        "counterexamples": {
            "count": len(negative),
            "observed": negative_observed,
            "passed": negative_pass,
        },
        "promotion": {
            "status": "READY_FOR_HUMAN_REVIEW" if ready else "REJECTED",
            "promoted_into_parser": False,
            "requires_human_approval": True,
        },
        "safety": {
            "redacted_examples_included": True,
            "raw_secrets_included": False,
            "verdicts_changed": False,
            "parser_registry_changed": False,
            "note": "A passing contract only qualifies a mapping for independent human review; it never changes parser behavior automatically.",
        },
    }


def write_contract(contract: Mapping[str, Any], output: str | Path) -> None:
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(contract, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


__all__ = [
    "APPRENTICESHIP_SCHEMA",
    "ApprenticeshipError",
    "create_contract",
    "evaluate_contract",
    "write_contract",
]
