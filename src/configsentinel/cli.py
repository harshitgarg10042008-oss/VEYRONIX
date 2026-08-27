"""Command-line interface for safe audit and remediation previews."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .client import ConfigSentinelClient
from .engine import DeterministicComplianceEngine
from .ingestion import ConfigIngestionService
from .remediation import RemediationError, generate_bundle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="configsentinel", description="Audit network configurations and generate review-only remediation previews.")
    sub = parser.add_subparsers(dest="command", required=True)
    audit = sub.add_parser("audit", help="audit a configuration file")
    audit.add_argument("file", type=Path)
    audit.add_argument("--vendor", default="auto", choices=("auto", "cisco_ios", "junos", "firewall_generic"))
    audit.add_argument("--remediation-out", type=Path, help="write a non-executable remediation preview")
    audit.add_argument("--approve", action="store_true", help="acknowledge operator review; still requires --dry-run")
    audit.add_argument("--dry-run", action="store_true", help="required safety flag; never applies changes")
    return parser


def run_audit(args: argparse.Namespace) -> int:
    if args.approve and not args.dry_run:
        print("Refusing to proceed: --approve requires --dry-run; no live apply mode exists.", file=sys.stderr)
        return 2
    service = ConfigIngestionService()
    try:
        ingested = service.ingest_file(args.file)
        client = ConfigSentinelClient(engine=DeterministicComplianceEngine(), ingestion=service)
        result = client.audit_text(ingested.redacted_text, vendor=args.vendor)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Input rejected: {exc}", file=sys.stderr)
        return 2
    print(f"audit_id={result.audit_id}")
    print(f"vendor={result.vendor} findings={len(result.findings)} failed={result.failed_count} unknown={len(result.unknown_blocks)}")
    for finding in result.findings:
        print(f"{finding.control_id}\t{finding.status.value}\t{finding.severity.value}")
    if args.remediation_out:
        try:
            bundle = generate_bundle(result)
        except RemediationError as exc:
            print(f"Remediation unavailable: {exc}", file=sys.stderr)
            return 2
        args.remediation_out.parent.mkdir(parents=True, exist_ok=True)
        args.remediation_out.write_text(bundle.script, encoding="utf-8", newline="\n")
        print(f"remediation_preview={args.remediation_out} steps={bundle.step_count} warnings={len(bundle.warnings)}")
        print("SAFETY: preview generated; no device connection or execution performed.")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "audit":
        return run_audit(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
