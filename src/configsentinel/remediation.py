"""Safe, deterministic remediation artifact generation.

Generated artifacts are previews only. This module never connects to devices or
executes returned commands; an operator must review and apply them separately.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from .models import AuditResult, FindingStatus, RemediationPreview


class RemediationError(ValueError):
    """Raised when a remediation cannot be generated safely."""


@dataclass(frozen=True)
class RemediationStep:
    finding_id: str
    control_id: str
    vendor: str
    command: str
    rollback: str


@dataclass(frozen=True)
class RemediationDiff:
    finding_id: str
    control_id: str
    before: tuple[str, ...]
    after: tuple[str, ...]
    rollback: str
    unified_preview: str


@dataclass(frozen=True)
class RemediationBundle:
    bundle_id: str
    vendor: str
    input_sha256: str
    generated_at: str
    steps: tuple[RemediationStep, ...]
    script: str
    warnings: tuple[str, ...] = ()

    @property
    def step_count(self) -> int:
        return len(self.steps)


_COMMANDS: dict[tuple[str, str], tuple[str, str]] = {
    ("cisco_ios", "NET-MGMT-SSH-001"): (
        "ip ssh version 2",
        "Review SSH version compatibility before restoring the previous SSH setting.",
    ),
    ("cisco_ios", "NET-MGMT-TELNET-001"): (
        "transport input ssh",
        "Restore the approved VTY transport configuration after change review.",
    ),
    ("cisco_ios", "NET-MGMT-HTTP-001"): (
        "no ip http server",
        "Restore only through an approved change window if required.",
    ),
    ("cisco_ios", "NET-AUTH-AAA-001"): (
        "aaa new-model",
        "Restore the previous AAA mode only with a tested break-glass account.",
    ),
    ("junos", "NET-MGMT-SSH-001"): (
        "set system services ssh protocol-version v2",
        "Delete the SSH protocol-version override after review.",
    ),
    ("junos", "NET-MGMT-TELNET-001"): (
        "delete system services telnet",
        "Restore Telnet only under an approved exception; prefer secure management.",
    ),
    ("junos", "NET-MGMT-HTTP-001"): (
        "delete system services web-management http",
        "Restore web management only through an approved change window.",
    ),
}

_DANGEROUS = re.compile(
    r"(?i)(reload|erase|delete\\s+configuration|format|write\\s+erase|shell|bash|curl|wget|python|tclsh|run\\s+command|configure\\s+replace)"
)


def _validate_command(command: str) -> None:
    if not command.strip() or len(command) > 300:
        raise RemediationError("remediation command is empty or too long")
    if any(ord(ch) < 32 and ch not in "\t" for ch in command):
        raise RemediationError("control characters are not allowed in remediation")
    if _DANGEROUS.search(command):
        raise RemediationError("remediation command contains a blocked token")


def generate_bundle(
    audit: AuditResult, *, vendor: str | None = None
) -> RemediationBundle:
    target = vendor or audit.vendor
    if target not in {"cisco_ios", "junos"}:
        raise RemediationError(f"no safe remediation catalog for vendor: {target}")
    steps: list[RemediationStep] = []
    warnings: list[str] = []
    for finding in audit.findings:
        if finding.status != FindingStatus.FAIL:
            continue
        template = _COMMANDS.get((target, finding.control_id))
        if template is None:
            warnings.append(
                f"No deterministic template for {finding.control_id}; manual review required."
            )
            continue
        command, rollback = template
        _validate_command(command)
        steps.append(
            RemediationStep(
                finding.finding_id, finding.control_id, target, command, rollback
            )
        )
    digest = hashlib.sha256(
        (audit.audit_id + audit.input_sha256 + target).encode()
    ).hexdigest()[:16]
    bundle_id = f"rem_{digest}"
    generated_at = datetime.now(timezone.utc).isoformat()
    header = [
        "# ConfigSentinel AI remediation preview",
        f"# bundle_id: {bundle_id}",
        f"# vendor: {target}",
        f"# source_audit: {audit.audit_id}",
        f"# input_sha256: {audit.input_sha256}",
        f"# generated_at: {generated_at}",
        "# SAFETY: preview only; do not execute without independent operator review.",
        "# SAFETY: no device connection or execution is performed by this artifact.",
        "",
    ]
    body: list[str] = []
    for step in steps:
        body.extend(
            [
                f"# finding: {step.finding_id} ({step.control_id})",
                f"# rollback: {step.rollback}",
                step.command,
                "",
            ]
        )
    if not steps:
        body.append("# No safe deterministic remediation steps were generated.")
    return RemediationBundle(
        bundle_id,
        target,
        audit.input_sha256,
        generated_at,
        tuple(steps),
        "\n".join(header + body),
        tuple(warnings),
    )


def build_diffs(
    audit: AuditResult, bundle: RemediationBundle | None = None
) -> tuple[RemediationDiff, ...]:
    """Build evidence-backed unified previews; never return executable patches."""
    bundle = bundle or generate_bundle(audit)
    finding_by_id = {finding.finding_id: finding for finding in audit.findings}
    diffs: list[RemediationDiff] = []
    for step in bundle.steps:
        finding = finding_by_id.get(step.finding_id)
        before = tuple(span.excerpt for span in finding.evidence) if finding else ()
        before_lines = (
            "\n".join(f"- {line}" for line in before)
            or "- <no redacted evidence excerpt>"
        )
        after_lines = f"+ {step.command}"
        unified = (
            "--- evidence (redacted)\n+++ remediation preview (not executable)\n"
            + before_lines
            + "\n"
            + after_lines
        )
        diffs.append(
            RemediationDiff(
                step.finding_id,
                step.control_id,
                before,
                (step.command,),
                step.rollback,
                unified,
            )
        )
    return tuple(diffs)


def render_diffs(audit: AuditResult, bundle: RemediationBundle | None = None) -> str:
    diffs = build_diffs(audit, bundle)
    lines = [
        "# ConfigSentinel AI remediation diff preview",
        "",
        f"Audit: `{audit.audit_id}`",
        f"Input SHA-256: `{audit.input_sha256}`",
        "",
        "> Preview only. Evidence is redacted. No patch is executable and no device is contacted.",
        "",
    ]
    if not diffs:
        lines.append("No safe deterministic remediation diff is available.")
    for diff in diffs:
        lines.extend(
            [
                f"## {diff.control_id}",
                "",
                "```diff",
                diff.unified_preview,
                "```",
                f"Rollback preview: {diff.rollback}",
                "",
            ]
        )
    return "\n".join(lines)


def previews(bundle: RemediationBundle) -> tuple[RemediationPreview, ...]:
    return tuple(
        RemediationPreview(
            step.finding_id,
            bundle.vendor,
            "Current configuration",
            step.command,
            step.rollback,
        )
        for step in bundle.steps
    )
