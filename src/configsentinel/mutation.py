"""Deterministic semantic mutation testing for the ConfigSentinel AI engine."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable

from .client import ConfigSentinelClient
from .engine import DeterministicComplianceEngine
from .frameworks import normalize_frameworks
from .ingestion import ConfigIngestionService, IngestionError
from .models import AuditResult

MUTATION_SCHEMA = "configsentinel.semantic-mutation-lab.v1"
MAX_MUTATIONS = 16


class MutationError(ValueError):
    """Raised when mutation testing cannot be performed safely."""


class MutationRelation(str, Enum):
    PRESERVE = "PRESERVE"
    CHANGE = "CHANGE"


@dataclass(frozen=True)
class MutationSpec:
    mutation_id: str
    description: str
    relation: MutationRelation
    target_control_id: str | None = None
    expected_status: str | None = None


@dataclass(frozen=True)
class MutationOutcome:
    mutation_id: str
    description: str
    relation: str
    passed: bool
    baseline_sha256: str
    mutated_sha256: str
    changed_controls: tuple[str, ...]
    target_control_id: str | None
    expected_status: str | None
    observed_status: str | None
    failure_reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "mutation_id": self.mutation_id,
            "description": self.description,
            "relation": self.relation,
            "passed": self.passed,
            "baseline_sha256": self.baseline_sha256,
            "mutated_sha256": self.mutated_sha256,
            "changed_controls": list(self.changed_controls),
            "target_control_id": self.target_control_id,
            "expected_status": self.expected_status,
            "observed_status": self.observed_status,
            "failure_reason": self.failure_reason,
        }


def _status_map(result: AuditResult) -> dict[str, str]:
    return {finding.control_id: finding.status.value for finding in result.findings}


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _comment_for(vendor: str) -> str:
    return "# ConfigSentinel semantic-preservation mutation"


def _target_mutations(vendor: str) -> tuple[tuple[str, str], ...]:
    if vendor in {"cisco_ios", "arista_eos"}:
        return (
            ("enable_telnet", "line vty 0 4\n transport input telnet"),
            ("enable_plain_http", "ip http server"),
        )
    if vendor == "junos":
        return (
            ("enable_telnet", "set system services telnet"),
            ("enable_plain_http", "set system services web-management http"),
        )
    if vendor == "linux_nftables":
        return (
            ("enable_telnet", "tcp dport 23 accept"),
            ("enable_plain_http", "tcp dport 80 accept"),
        )
    return (
        ("enable_telnet", "firewall\nallow telnet enable"),
        ("enable_plain_http", "firewall\nadmin https enable"),
    )


def mutation_specs(vendor: str) -> tuple[MutationSpec, ...]:
    target = _target_mutations(vendor)
    return (
        MutationSpec(
            "trailing_whitespace",
            "Add trailing spaces to non-empty source lines; semantics must be preserved.",
            MutationRelation.PRESERVE,
        ),
        MutationSpec(
            "comment_insertion",
            "Insert an ignored vendor-neutral comment; semantics must be preserved.",
            MutationRelation.PRESERVE,
        ),
        MutationSpec(
            "final_newline",
            "Normalize the final newline; semantics must be preserved.",
            MutationRelation.PRESERVE,
        ),
        MutationSpec(
            "enable_telnet",
            "Add an explicit insecure Telnet-management directive; Telnet control must fail.",
            MutationRelation.CHANGE,
            "NET-MGMT-TELNET-001",
            "FAIL",
        ),
        MutationSpec(
            "enable_plain_http",
            "Add an explicit plain-HTTP management directive; HTTP control must fail.",
            MutationRelation.CHANGE,
            "NET-MGMT-HTTP-001",
            "FAIL",
        ),
    )


def _apply(text: str, spec: MutationSpec, vendor: str) -> str:
    if spec.mutation_id == "trailing_whitespace":
        lines = text.splitlines()
        return "\n".join(line + ("   " if line.strip() else "") for line in lines) + (
            "\n" if text.endswith(("\n", "\r")) else ""
        )
    if spec.mutation_id == "comment_insertion":
        comment = _comment_for(vendor)
        return comment + "\n" + text
    if spec.mutation_id == "final_newline":
        return text.rstrip("\r\n") + "\n"
    for mutation_id, directive in _target_mutations(vendor):
        if mutation_id == spec.mutation_id:
            base = text.rstrip("\r\n")
            return base + "\n" + directive + "\n"
    raise MutationError(f"unsupported mutation: {spec.mutation_id}")


def _audit(
    client: ConfigSentinelClient, text: str, vendor: str, frameworks: tuple[str, ...]
) -> AuditResult:
    try:
        return client.audit_text(
            text,
            vendor=vendor,
            frameworks=frameworks,
            project_id="semantic-mutation-lab",
        )
    except (ValueError, RuntimeError) as exc:
        raise MutationError(f"mutation audit rejected: {exc}") from exc


def run_mutation_lab(
    config_text: str,
    *,
    vendor: str,
    frameworks: Iterable[str] = ("cis-network",),
    max_mutations: int = MAX_MUTATIONS,
) -> dict[str, Any]:
    """Run bounded mutations against redacted content and return no raw configuration."""
    if max_mutations < 1 or max_mutations > MAX_MUTATIONS:
        raise MutationError(f"max_mutations must be between 1 and {MAX_MUTATIONS}")
    if vendor == "auto":
        raise MutationError("semantic mutation lab requires an explicit vendor")
    try:
        ingested = ConfigIngestionService().ingest_text("mutation.cfg", config_text)
    except IngestionError as exc:
        raise MutationError(str(exc)) from exc
    selected = normalize_frameworks(frameworks)
    redacted = ingested.redacted_text
    client = ConfigSentinelClient(engine=DeterministicComplianceEngine())
    baseline = _audit(client, redacted, vendor, selected)
    baseline_status = _status_map(baseline)
    outcomes: list[MutationOutcome] = []
    for spec in mutation_specs(vendor)[:max_mutations]:
        mutated = _apply(redacted, spec, vendor)
        mutated_result = _audit(client, mutated, vendor, selected)
        mutated_status = _status_map(mutated_result)
        changed = tuple(
            sorted(
                control
                for control in set(baseline_status) | set(mutated_status)
                if baseline_status.get(control) != mutated_status.get(control)
            )
        )
        observed = (
            mutated_status.get(spec.target_control_id)
            if spec.target_control_id
            else None
        )
        if spec.relation is MutationRelation.PRESERVE:
            passed = not changed
            reason = (
                None if passed else "semantics changed under a preservation mutation"
            )
        else:
            passed = bool(
                spec.target_control_id
                and observed == spec.expected_status
                and spec.target_control_id in changed
            )
            reason = (
                None
                if passed
                else "targeted control did not reach the expected changed status"
            )
        outcomes.append(
            MutationOutcome(
                spec.mutation_id,
                spec.description,
                spec.relation.value,
                passed,
                baseline.input_sha256,
                mutated_result.input_sha256,
                changed,
                spec.target_control_id,
                spec.expected_status,
                observed,
                reason,
            )
        )
    passed = all(outcome.passed for outcome in outcomes)
    return {
        "schema": MUTATION_SCHEMA,
        "vendor": vendor,
        "frameworks": list(selected),
        "baseline": {
            "input_sha256": baseline.input_sha256,
            "status_map": baseline_status,
            "finding_count": len(baseline.findings),
        },
        "mutations": [outcome.as_dict() for outcome in outcomes],
        "summary": {
            "passed": passed,
            "mutation_count": len(outcomes),
            "passed_count": sum(outcome.passed for outcome in outcomes),
            "failed_count": sum(not outcome.passed for outcome in outcomes),
        },
        "safety": {
            "raw_configuration_included": False,
            "network_access": False,
            "bounded": True,
            "verdicts_modified": False,
            "note": "Mutation results test parser/control behavior; they do not change the source audit verdict or apply configuration.",
        },
    }


def render_mutation_report(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=True) + "\n"


__all__ = [
    "MAX_MUTATIONS",
    "MUTATION_SCHEMA",
    "MutationError",
    "MutationRelation",
    "MutationSpec",
    "run_mutation_lab",
    "render_mutation_report",
    "mutation_specs",
]
