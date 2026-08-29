import json
import subprocess
from pathlib import Path

from configsentinel.gitops import run_gitops_gate


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def setup_repo(tmp_path: Path, content: str) -> tuple[Path, str]:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.email", "test@example.invalid")
    git(root, "config", "user.name", "ConfigSentinel Test")
    (root / "edge.conf").write_text(content, encoding="utf-8")
    git(root, "add", ".")
    git(root, "commit", "-qm", "baseline")
    return root, git(root, "rev-parse", "HEAD")


def test_gitops_gate_blocks_high_impact_changed_configuration(tmp_path: Path):
    root, base = setup_repo(tmp_path, "version 17.9\nno ip http server\n")
    (root / "edge.conf").write_text(
        "version 17.9\nline vty 0 4\n transport input telnet\n", encoding="utf-8"
    )
    git(root, "add", ".")
    git(root, "commit", "-qm", "insecure change")
    result = run_gitops_gate(root, base, vendor="cisco_ios")
    assert result.passed is False
    assert result.changed_files == ("edge.conf",)
    assert any(item.control_id == "NET-MGMT-TELNET-001" for item in result.findings)


def test_gitops_gate_passes_nonblocking_change_and_serializes(tmp_path: Path):
    root, base = setup_repo(tmp_path, "version 17.9\nno ip http server\n")
    (root / "edge.conf").write_text(
        "version 17.9\nno ip http server\nlogging host 10.0.0.20\n", encoding="utf-8"
    )
    git(root, "add", ".")
    git(root, "commit", "-qm", "logging change")
    result = run_gitops_gate(root, base, vendor="cisco_ios")
    assert result.passed is True
    assert json.loads(json.dumps(result.as_dict()))["passed"] is True
