"""Command-line interface for safe audits, reports, and remediation previews."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .client import ConfigSentinelClient
from .engine import DeterministicComplianceEngine
from .frameworks import normalize_frameworks
from .ingestion import ConfigIngestionService
from .remediation import RemediationError, generate_bundle
from .reporting import write_report
from .sources import SourceDiscoveryError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="configsentinel", description="Audit network configurations and generate review-only remediation previews.")
    sub = parser.add_subparsers(dest="command", required=True)
    audit = sub.add_parser("audit", help="audit a configuration file")
    audit.add_argument("file", type=Path)
    audit.add_argument("--vendor", default="auto", choices=("auto", "cisco_ios", "junos", "firewall_generic"))
    audit.add_argument("--framework", action="append", dest="frameworks", default=None, help="framework id; repeat for multiple frameworks (cis-network or nist-800-53)")
    audit.add_argument("--report-out", type=Path, help="write a Markdown audit report")
    audit.add_argument("--json-out", type=Path, help="write a JSON audit report")
    audit.add_argument("--remediation-out", type=Path, help="write a non-executable remediation preview")
    audit.add_argument("--approve", action="store_true", help="acknowledge operator review; still requires --dry-run")
    audit.add_argument("--dry-run", action="store_true", help="required safety flag; never applies changes")
    batch = sub.add_parser("batch", help="audit a file, directory, ZIP, or tar archive")
    batch.add_argument("source", type=Path)
    batch.add_argument("--vendor", default="auto", choices=("auto", "cisco_ios", "junos", "firewall_generic"))
    batch.add_argument("--framework", action="append", dest="frameworks", default=None, help="framework id; repeat for multiple frameworks")
    batch.add_argument("--json-out", type=Path, help="write a JSON array of audit reports")
    return parser


def run_audit(args: argparse.Namespace) -> int:
    if args.approve and not args.dry_run:
        print("Refusing to proceed: --approve requires --dry-run; no live apply mode exists.", file=sys.stderr)
        return 2
    try:
        frameworks = normalize_frameworks(args.frameworks)
        service = ConfigIngestionService()
        ingested = service.ingest_file(args.file)
        client = ConfigSentinelClient(engine=DeterministicComplianceEngine(), ingestion=service)
        result = client.audit_text(ingested.redacted_text, vendor=args.vendor, frameworks=frameworks)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Input rejected: {exc}", file=sys.stderr)
        return 2
    print(f"audit_id={result.audit_id}")
    print(f"vendor={result.vendor} findings={len(result.findings)} failed={result.failed_count} unknown={len(result.unknown_blocks)} frameworks={','.join(frameworks)}")
    for finding in result.findings:
        print(f"{finding.control_id}\t{finding.status.value}\t{finding.severity.value}")
    if args.report_out:
        write_report(result, str(args.report_out), format="markdown", frameworks=frameworks)
        print(f"report={args.report_out}")
    if args.json_out:
        write_report(result, str(args.json_out), format="json", frameworks=frameworks)
        print(f"json_report={args.json_out}")
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


def run_batch(args: argparse.Namespace) -> int:
    try:
        frameworks = normalize_frameworks(args.frameworks)
        client = ConfigSentinelClient(engine=DeterministicComplianceEngine())
        reports = client.audit_sources(str(args.source), vendor=args.vendor, frameworks=frameworks, project_id=str(args.source))
    except (OSError, ValueError, RuntimeError, SourceDiscoveryError) as exc:
        print(f"Source rejected: {exc}", file=sys.stderr)
        return 2
    print(f"source={args.source} documents={len(reports)}")
    for filename, result in reports:
        print(f"{filename}\taudit_id={result.audit_id}\tvendor={result.vendor}\tfindings={len(result.findings)}\tfailed={result.failed_count}\tunknown={len(result.unknown_blocks)}")
    if args.json_out:
        import json
        payload = [json.loads(client.report_json(result, frameworks=frameworks)) for _, result in reports]
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"json_report={args.json_out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "audit":
        return run_audit(args)
    if args.command == "batch":
        return run_batch(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
