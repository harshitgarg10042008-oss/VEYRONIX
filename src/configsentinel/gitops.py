"""Local GitOps security gate for configuration changes.

The gate is intentionally repository-local: it reads only changed supported
configuration files from Git, runs the deterministic engine, and returns a
machine-readable decision. It never posts comments or mutates the repository.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .client import ConfigSentinelClient
from .engine import DeterministicComplianceEngine
from .models import FindingStatus, Severity


CONFIG_SUFFIXES = (".cfg", ".conf", ".config", ".txt", ".log")


@dataclass(frozen=True)
class GitOpsFinding:
    path: str
    control_id: str
    status: str
    severity: str
    evidence_lines: tuple[int, ...]


@dataclass(frozen=True)
class GitOpsResult:
    base: str
    head: str
    changed_files: tuple[str, ...]
    findings: tuple[GitOpsFinding, ...]
    passed: bool
    reason: str

    def as_dict(self) -> dict[str, object]:
        return {
            "base": self.base,
            "head": self.head,
            "changed_files": list(self.changed_files),
            "passed": self.passed,
            "reason": self.reason,
            "findings": [finding.__dict__ for finding in self.findings],
        }


def run_gitops_gate(repo: str | Path, base: str, head: str = "HEAD", *, vendor: str = "auto", frameworks: tuple[str, ...] = ("cis-network",), blocking_severities: tuple[Severity, ...] = (Severity.CRITICAL, Severity.HIGH)) -> GitOpsResult:
    root = Path(repo).resolve()
    if not (root / ".git").exists():
        raise ValueError("repository path is not a Git worktree")
    changed = _changed_files(root, base, head)
    client = ConfigSentinelClient(engine=DeterministicComplianceEngine())
    findings: list[GitOpsFinding] = []
    for relative in changed:
        path = root / relative
        if not path.is_file():
            continue
        result = client.audit_file(str(path), vendor=vendor, frameworks=frameworks, project_id=f"git:{relative}")
        for finding in result.findings:
            if finding.status in {FindingStatus.FAIL, FindingStatus.UNKNOWN, FindingStatus.REVIEW_REQUIRED}:
                findings.append(GitOpsFinding(relative, finding.control_id, finding.status.value, finding.severity.value, tuple(span.start_line for span in finding.evidence)))
    blockers = [item for item in findings if item.status == FindingStatus.FAIL and Severity(item.severity) in blocking_severities]
    if blockers:
        return GitOpsResult(base, head, tuple(changed), tuple(findings), False, f"blocked by {len(blockers)} high-impact finding(s)")
    return GitOpsResult(base, head, tuple(changed), tuple(findings), True, "no blocking deterministic findings")


def _changed_files(root: Path, base: str, head: str) -> list[str]:
    try:
        completed = subprocess.run(["git", "-C", str(root), "diff", "--name-only", "--diff-filter=ACMRT", f"{base}..{head}", "--", *[f"*{suffix}" for suffix in CONFIG_SUFFIXES]], check=True, capture_output=True, text=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError("unable to inspect Git revisions") from exc
    files: list[str] = []
    for line in completed.stdout.splitlines():
        relative = Path(line.strip())
        if not line.strip() or relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Git returned an unsafe changed path")
        files.append(relative.as_posix())
    return sorted(set(files))


def write_gate_result(result: GitOpsResult, path: str | Path) -> None:
    Path(path).write_text(json.dumps(result.as_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
