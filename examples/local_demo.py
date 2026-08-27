"""Run the complete ConfigSentinel demo locally without network access."""

from __future__ import annotations

import argparse
import json
import shutil
import time
from pathlib import Path

from configsentinel import ConfigSentinelClient, DeterministicComplianceEngine
from configsentinel.hardening import ResourceBudget
from configsentinel.reporting import write_report
from configsentinel.remediation import RemediationError, generate_bundle


SCENARIOS = {
    "cisco": ("cisco_ios", """version 17.9\nhostname edge-cisco\nline vty 0 4\n transport input telnet\n username admin password 0 [REDACTED]\n"""),
    "junos": ("junos", """system {\n    host-name edge-junos;\n    services {\n        telnet;\n    }\n}\n"""),
    "firewall": ("firewall_generic", """hostname branch-fw\nservice http\nservice telnet\nlogging enable\n"""),
}


def run(output_dir: Path) -> dict[str, object]:
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True)
    budget = ResourceBudget()
    client = ConfigSentinelClient(engine=DeterministicComplianceEngine())
    summaries: list[dict[str, object]] = []
    for name, (vendor, config) in SCENARIOS.items():
        budget.validate_text(config)
        started = time.perf_counter()
        result = client.audit_text(config, vendor=vendor, frameworks=("cis-network", "nist-800-53"))
        elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
        report_path = output_dir / f"{name}-audit.md"
        json_path = output_dir / f"{name}-audit.json"
        remediation_path = output_dir / f"{name}-remediation-preview.txt"
        write_report(result, str(report_path), format="markdown", frameworks=("cis-network", "nist-800-53"))
        write_report(result, str(json_path), format="json", frameworks=("cis-network", "nist-800-53"))
        try:
            bundle = generate_bundle(result)
            remediation_text = bundle.script
        except RemediationError as exc:
            remediation_text = "# CONFIGSENTINEL REMEDIATION PREVIEW\n# SAFETY: preview only; no device connection or execution is performed.\n# SAFETY: no deterministic remediation catalog is available for this vendor.\n# REVIEW_REQUIRED: " + str(exc) + "\n"
        remediation_path.write_text(remediation_text, encoding="utf-8", newline="\n")
        summaries.append({"scenario": name, "vendor": vendor, "audit_id": result.audit_id, "findings": len(result.findings), "failed": result.failed_count, "unknown": len(result.unknown_blocks), "duration_ms": elapsed_ms, "report": str(report_path), "json_report": str(json_path), "remediation_preview": str(remediation_path)})
    manifest = {"mode": "offline_local_demo", "network_calls": 0, "llm_enabled": False, "scenarios": summaries}
    (output_dir / "demo-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the offline ConfigSentinel local demo")
    parser.add_argument("--output", type=Path, default=Path("demo-output"))
    args = parser.parse_args()
    manifest = run(args.output)
    print("CONFIGSENTINEL OFFLINE DEMO")
    print("network_calls=0 llm_enabled=False")
    for scenario in manifest["scenarios"]:
        print(f"{scenario['scenario']}: vendor={scenario['vendor']} failed={scenario['failed']} unknown={scenario['unknown']} duration_ms={scenario['duration_ms']}")
    print(f"output={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
