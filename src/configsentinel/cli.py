"""Command-line interface for safe audits, reports, and remediation previews."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .client import ConfigSentinelClient
from .engine import DeterministicComplianceEngine
from .frameworks import normalize_frameworks
from .ingestion import ConfigIngestionService
from .remediation import RemediationError, generate_bundle, render_diffs
from .reporting import write_report
from .sources import SourceDiscoveryError
from .policies import CustomPolicyPack
from .gitops import run_gitops_gate, write_gate_result
from .baseline import BaselineError, compare_baseline, load_baseline, save_baseline
from .governance import ApprovalLedger, GovernanceError, Role
from .auditlog import AuditLogError, AuditTrail, sign_envelope
from .executive import build_executive_report, render_executive_json, render_executive_markdown
from .analytics import AnalyticsError, analyze_history, load_history, write_history_analytics
from .evidence_graph import EvidenceGraphError, build_evidence_graph, load_report, write_graph
from .sensitive import render_sensitive_scan, scan_sensitive
from .webhooks import LocalWebhookQueue, WebhookError, make_audit_event
from .ticketing import TicketingError, build_ticket_payload, render_ticket_markdown
from .inventory import InventoryError, import_inventory_file
from .verification import verify_report, run_benchmark
from .supplychain import SupplyChainError, build_manifest, verify_manifest, write_manifest
from .risk import RiskError, risk_report
from .exceptions import ExceptionError, approve_exception, create_exception, load_exceptions, save_exception
from .topology import TopologyError, analyze_topology, write_topology_html
from .demo import DemoError, compare_reports, render_guided_demo
from .cache import AuditCache, CacheError
from .siem import SiemError, render_siem
from .backup import BackupError, backup_file, restore_file
from .release import ReleaseError, write_release_artifacts
from .attestation import AttestationError, build_attestation, load_attestation, verify_attestation
from .uncertainty import UncertaintyError, build_uncertainty_budget
from .mutation import MutationError, run_mutation_lab
from .assurance_twin import AssuranceTwinError, build_assurance_twin, write_assurance_twin_html
from .intent import IntentError, compile_resource_intent
from .apprenticeship import ApprenticeshipError, create_contract, evaluate_contract, write_contract
from .differential import DifferentialError, SEMANTIC_FIELDS, run_differential_test
from .time_machine import TimeMachineError, build_time_machine, load_snapshot_source, write_time_machine_html
from .proof import ProofError, build_proof_bundle, verify_proof_bundle
from .exchange import ExchangeError, build_exchange_capsule, verify_exchange_capsule
from .reviewers import ReviewAnalyticsError, build_reviewer_analytics, load_reviews
from .freshness import FreshnessError, build_freshness_assessment, load_report_for_freshness
from .controls import CONTROL_PACK_VERSION
from .reporting import report_dict


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="configsentinel", description="Audit network configurations and generate review-only remediation previews.")
    sub = parser.add_subparsers(dest="command", required=True)
    audit = sub.add_parser("audit", help="audit a configuration file")
    audit.add_argument("file", type=Path)
    audit.add_argument("--vendor", default="auto", choices=("auto", "cisco_ios", "junos", "firewall_generic", "arista_eos", "linux_nftables"))
    audit.add_argument("--framework", action="append", dest="frameworks", default=None, help="framework id; repeat for multiple frameworks (cis-network or nist-800-53)")
    audit.add_argument("--report-out", type=Path, help="write a Markdown audit report")
    audit.add_argument("--json-out", type=Path, help="write a JSON audit report")
    audit.add_argument("--remediation-out", type=Path, help="write a non-executable remediation preview")
    audit.add_argument("--diff-out", type=Path, help="write an evidence-to-command remediation diff preview")
    audit.add_argument("--trail", type=Path, help="append a tamper-evident local audit event")
    audit.add_argument("--signed-out", type=Path, help="write an HMAC-signed JSON evidence envelope")
    audit.add_argument("--signing-key-file", type=Path, help="read the local HMAC signing key")
    audit.add_argument("--approve", action="store_true", help="acknowledge operator review; still requires --dry-run")
    audit.add_argument("--dry-run", action="store_true", help="required safety flag; never applies changes")
    audit.add_argument("--policy", type=Path, help="validated local JSON custom policy pack")
    batch = sub.add_parser("batch", help="audit a file, directory, ZIP, or tar archive")
    batch.add_argument("source", type=Path)
    batch.add_argument("--vendor", default="auto", choices=("auto", "cisco_ios", "junos", "firewall_generic", "arista_eos", "linux_nftables"))
    batch.add_argument("--framework", action="append", dest="frameworks", default=None, help="framework id; repeat for multiple frameworks")
    batch.add_argument("--json-out", type=Path, help="write a JSON array of audit reports")
    batch.add_argument("--policy", type=Path, help="validated local JSON custom policy pack")
    gate = sub.add_parser("gitops-check", help="audit configuration files changed between Git revisions")
    gate.add_argument("--repo", type=Path, default=Path("."))
    gate.add_argument("--base", required=True, help="base Git revision")
    gate.add_argument("--head", default="HEAD", help="head Git revision")
    gate.add_argument("--vendor", default="auto", choices=("auto", "cisco_ios", "junos", "firewall_generic", "arista_eos", "linux_nftables"))
    gate.add_argument("--framework", action="append", dest="frameworks", default=None)
    gate.add_argument("--json-out", type=Path)
    baseline = sub.add_parser("baseline-save", help="save an approved audit baseline")
    baseline.add_argument("file", type=Path)
    baseline.add_argument("--vendor", default="auto", choices=("auto", "cisco_ios", "junos", "firewall_generic", "arista_eos", "linux_nftables"))
    baseline.add_argument("--label", default="approved")
    baseline.add_argument("--out", type=Path, required=True)
    drift = sub.add_parser("drift-check", help="compare a configuration against an approved baseline")
    drift.add_argument("file", type=Path)
    drift.add_argument("--baseline", type=Path, required=True)
    drift.add_argument("--vendor", default="auto", choices=("auto", "cisco_ios", "junos", "firewall_generic", "arista_eos", "linux_nftables"))
    drift.add_argument("--json-out", type=Path)
    gov_request = sub.add_parser("approval-request", help="request independent review for a resource")
    gov_request.add_argument("resource_id")
    gov_request.add_argument("--actor", required=True)
    gov_request.add_argument("--role", choices=("operator", "admin"), default="operator")
    gov_request.add_argument("--reason", default="")
    gov_request.add_argument("--ledger", type=Path, required=True)
    gov_decide = sub.add_parser("approval-decide", help="approve or reject a pending resource review")
    gov_decide.add_argument("resource_id")
    gov_decide.add_argument("--actor", required=True)
    gov_decide.add_argument("--role", choices=("reviewer", "admin"), required=True)
    gov_decide.add_argument("--approve", action="store_true")
    gov_decide.add_argument("--reason", default="")
    gov_decide.add_argument("--ledger", type=Path, required=True)
    executive = sub.add_parser("enterprise-report", help="write an executive posture report")
    executive.add_argument("file", type=Path)
    executive.add_argument("--vendor", default="auto", choices=("auto", "cisco_ios", "junos", "firewall_generic", "arista_eos", "linux_nftables"))
    executive.add_argument("--format", choices=("markdown", "json"), default="markdown")
    executive.add_argument("--out", type=Path, required=True)
    history = sub.add_parser("history-analyze", help="analyze a JSON array of serialized audit reports")
    history.add_argument("json_input", type=Path)
    history.add_argument("--out", type=Path, required=True)
    graph = sub.add_parser("evidence-graph", help="project an audit report into an evidence graph")
    graph.add_argument("json_input", type=Path)
    graph.add_argument("--out", type=Path, required=True)
    sensitive = sub.add_parser("sensitive-scan", help="scan a configuration for sensitive markers")
    attest_create = sub.add_parser("attestation-create", help="create a signed configuration attestation")
    attest_create.add_argument("json_input", type=Path)
    attest_create.add_argument("--key-file", type=Path, required=True)
    attest_create.add_argument("--out", type=Path, required=True)
    attest_create.add_argument("--reviewer-status", choices=("REVIEW_REQUIRED", "APPROVED", "REJECTED"), default="REVIEW_REQUIRED")
    attest_create.add_argument("--issued-at")
    attest_verify = sub.add_parser("attestation-verify", help="verify and replay a signed configuration attestation")
    attest_verify.add_argument("json_input", type=Path)
    attest_verify.add_argument("attestation", type=Path)
    attest_verify.add_argument("--key-file", type=Path, required=True)
    uncertainty = sub.add_parser("uncertainty-budget", help="build an evidence coverage and uncertainty budget")
    uncertainty.add_argument("json_input", type=Path)
    uncertainty.add_argument("--out", type=Path, required=True)
    mutation = sub.add_parser("mutation-lab", help="run bounded semantic mutation tests")
    mutation.add_argument("file", type=Path)
    mutation.add_argument("--vendor", required=True, choices=("cisco_ios", "junos", "firewall_generic", "arista_eos", "linux_nftables"))
    mutation.add_argument("--framework", action="append", dest="frameworks", default=None)
    mutation.add_argument("--max-mutations", type=int, default=5)
    mutation.add_argument("--out", type=Path, required=True)
    twin = sub.add_parser("assurance-twin", help="build an evidence-first local assurance twin")
    twin.add_argument("topology_input", type=Path)
    twin.add_argument("--report", type=Path)
    twin.add_argument("--finding-asset", action="append", default=[], metavar="FINDING=ASSET")
    twin.add_argument("--add-link", action="append", default=[], metavar="SOURCE=TARGET")
    twin.add_argument("--remove-link", action="append", default=[], metavar="SOURCE=TARGET")
    twin.add_argument("--depth", type=int, default=1)
    twin.add_argument("--out", type=Path, required=True)
    twin.add_argument("--html-out", type=Path)
    intent = sub.add_parser("intent-compile", help="compile resource-level least-privilege intent")
    intent.add_argument("intent_input", type=Path)
    intent.add_argument("--report", type=Path)
    intent.add_argument("--topology", type=Path)
    intent.add_argument("--out", type=Path, required=True)
    apprenticeship = sub.add_parser("apprenticeship-contract", help="create a governed unknown-syntax parser contract")
    apprenticeship.add_argument("mapping_input", type=Path)
    apprenticeship.add_argument("--positive", action="append", required=True)
    apprenticeship.add_argument("--counterexample", action="append", required=True)
    apprenticeship.add_argument("--out", type=Path, required=True)
    apprenticeship_test = sub.add_parser("apprenticeship-test", help="test a parser contract without promoting it")
    apprenticeship_test.add_argument("contract_input", type=Path)
    apprenticeship_test.add_argument("--out", type=Path, required=True)
    differential = sub.add_parser("differential-test", help="compare explicit vendor variants")
    differential.add_argument("--variant", action="append", required=True, metavar="VENDOR=FILE")
    differential.add_argument("--field", action="append", dest="fields", default=None, choices=SEMANTIC_FIELDS)
    differential.add_argument("--case-id", default="case-local")
    differential.add_argument("--out", type=Path, required=True)
    time_machine = sub.add_parser("time-machine", help="replay supplied compliance report snapshots")
    time_machine.add_argument("snapshots_input", type=Path)
    time_machine.add_argument("--control-id")
    time_machine.add_argument("--vendor")
    time_machine.add_argument("--out", type=Path, required=True)
    time_machine.add_argument("--html-out", type=Path)
    proof = sub.add_parser("remediation-proof", help="create proof-carrying remediation metadata")
    proof.add_argument("report_input", type=Path)
    proof.add_argument("--out", type=Path, required=True)
    proof_verify = sub.add_parser("remediation-proof-verify", help="verify proof-carrying remediation metadata")
    proof_verify.add_argument("proof_input", type=Path)
    proof_verify.add_argument("report_input", type=Path)
    proof_verify.add_argument("--out", type=Path, required=True)
    exchange = sub.add_parser("audit-exchange", help="create a privacy-preserving audit exchange capsule")
    exchange.add_argument("report_input", type=Path)
    exchange.add_argument("--recipient", default="local-review")
    exchange.add_argument("--purpose", default="audit-review")
    exchange.add_argument("--key-file", type=Path)
    exchange.add_argument("--out", type=Path, required=True)
    exchange_verify = sub.add_parser("audit-exchange-verify", help="verify a privacy-preserving audit exchange capsule")
    exchange_verify.add_argument("capsule_input", type=Path)
    exchange_verify.add_argument("--key-file", type=Path)
    exchange_verify.add_argument("--out", type=Path, required=True)
    reviews = sub.add_parser("reviewer-analytics", help="analyze deterministic disagreement across reviewer decisions")
    reviews.add_argument("report_input", type=Path)
    reviews.add_argument("reviews_input", type=Path)
    reviews.add_argument("--out", type=Path, required=True)
    freshness = sub.add_parser("assurance-freshness", help="assess assurance freshness decay and semantic drift")
    freshness.add_argument("report_input", type=Path)
    freshness.add_argument("--observed-at")
    freshness.add_argument("--as-of", required=True)
    freshness.add_argument("--ttl-hours", type=float, default=24.0)
    freshness.add_argument("--baseline", type=Path)
    freshness.add_argument("--out", type=Path, required=True)
    sensitive.add_argument("file", type=Path)
    sensitive.add_argument("--format", choices=("markdown", "json"), default="markdown")
    sensitive.add_argument("--out", type=Path, required=True)
    webhook = sub.add_parser("webhook-enqueue", help="enqueue a redacted audit-completed event locally")
    webhook.add_argument("json_input", type=Path)
    webhook.add_argument("--queue", type=Path, required=True)
    ticket = sub.add_parser("ticket-export", help="write a review-only ticket artifact")
    ticket.add_argument("json_input", type=Path)
    ticket.add_argument("--adapter", choices=("generic", "jira", "github"), default="generic")
    ticket.add_argument("--format", choices=("json", "markdown"), default="json")
    ticket.add_argument("--out", type=Path, required=True)
    inventory = sub.add_parser("inventory-import", help="import a local JSON/CSV inventory into a topology graph")
    inventory.add_argument("source", type=Path)
    inventory.add_argument("--out", type=Path, required=True)
    verify = sub.add_parser("verify-report", help="verify deterministic safety invariants in a report")
    verify.add_argument("json_input", type=Path)
    verify.add_argument("--out", type=Path, required=True)
    benchmark = sub.add_parser("verification-benchmark", help="run built-in verification fixtures")
    benchmark.add_argument("--out", type=Path, required=True)
    manifest = sub.add_parser("release-manifest", help="write a SHA-256 release manifest")
    manifest.add_argument("root", type=Path)
    manifest.add_argument("--out", type=Path, required=True)
    manifest_check = sub.add_parser("verify-manifest", help="verify a SHA-256 release manifest")
    manifest_check.add_argument("root", type=Path)
    manifest_check.add_argument("manifest", type=Path)
    risk = sub.add_parser("risk-prioritize", help="rank review findings using deterministic risk factors")
    risk.add_argument("json_input", type=Path)
    risk.add_argument("--asset-criticality", choices=("low", "medium", "high", "critical"), default="medium")
    risk.add_argument("--out", type=Path, required=True)
    exception_add = sub.add_parser("exception-add", help="create a time-bound review exception")
    exception_add.add_argument("exception_id")
    exception_add.add_argument("finding_id")
    exception_add.add_argument("--owner", required=True)
    exception_add.add_argument("--justification", required=True)
    exception_add.add_argument("--expires-at", required=True)
    exception_add.add_argument("--file", type=Path, required=True)
    exception_approve = sub.add_parser("exception-approve", help="approve a pending time-bound exception")
    exception_approve.add_argument("exception_id")
    exception_approve.add_argument("--approver", required=True)
    exception_approve.add_argument("--file", type=Path, required=True)
    exception_list = sub.add_parser("exception-list", help="list local exceptions and their current status")
    exception_list.add_argument("--file", type=Path, required=True)
    exception_list.add_argument("--out", type=Path, required=True)
    topology = sub.add_parser("topology-analyze", help="analyze imported topology and render a local explorer")
    topology.add_argument("json_input", type=Path)
    topology.add_argument("--finding-asset", action="append", default=[], metavar="FINDING=ASSET")
    topology.add_argument("--depth", type=int, default=1)
    topology.add_argument("--out", type=Path, required=True)
    topology.add_argument("--html-out", type=Path)
    demo = sub.add_parser("demo-mode", help="render a guided local SIH demonstration artifact")
    demo.add_argument("json_input", type=Path)
    demo.add_argument("--after", type=Path)
    demo.add_argument("--out", type=Path, required=True)
    compare = sub.add_parser("audit-compare", help="compare two serialized audit reports")
    compare.add_argument("before", type=Path)
    compare.add_argument("after", type=Path)
    compare.add_argument("--out", type=Path, required=True)
    cached = sub.add_parser("cache-audit", help="audit with a content-addressed local cache")
    cached.add_argument("file", type=Path)
    cached.add_argument("--vendor", default="auto", choices=("auto", "cisco_ios", "junos", "firewall_generic", "arista_eos", "linux_nftables"))
    cached.add_argument("--framework", action="append", dest="frameworks", default=None)
    cached.add_argument("--cache-dir", type=Path, required=True)
    cached.add_argument("--json-out", type=Path, required=True)
    siem = sub.add_parser("siem-export", help="write local SIEM-compatible finding events")
    siem.add_argument("json_input", type=Path)
    siem.add_argument("--format", choices=("jsonl", "cef", "leef"), default="jsonl")
    siem.add_argument("--out", type=Path, required=True)
    backup_create = sub.add_parser("backup-create", help="create an authenticated encrypted JSON backup")
    backup_create.add_argument("json_input", type=Path)
    backup_create.add_argument("--out", type=Path, required=True)
    backup_create.add_argument("--passphrase-env", default="CONFIGSENTINEL_BACKUP_PASSPHRASE")
    backup_restore = sub.add_parser("backup-restore", help="restore an authenticated encrypted JSON backup")
    backup_restore.add_argument("encrypted_input", type=Path)
    backup_restore.add_argument("--out", type=Path, required=True)
    backup_restore.add_argument("--passphrase-env", default="CONFIGSENTINEL_BACKUP_PASSPHRASE")
    release = sub.add_parser("release-artifacts", help="write deterministic SBOM and release metadata")
    release.add_argument("root", type=Path)
    release.add_argument("--sbom-out", type=Path, required=True)
    release.add_argument("--metadata-out", type=Path, required=True)
    release.add_argument("--manifest", type=Path)
    return parser


def run_audit(args: argparse.Namespace) -> int:
    if args.approve and not args.dry_run:
        print("Refusing to proceed: --approve requires --dry-run; no live apply mode exists.", file=sys.stderr)
        return 2
    try:
        frameworks = normalize_frameworks(args.frameworks)
        service = ConfigIngestionService()
        ingested = service.ingest_file(args.file)
        packs = (CustomPolicyPack.from_file(args.policy),) if args.policy else ()
        client = ConfigSentinelClient(engine=DeterministicComplianceEngine(packs), ingestion=service)
        result = client.audit_text(ingested.redacted_text, vendor=args.vendor, frameworks=frameworks)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Input rejected: {exc}", file=sys.stderr)
        return 2
    print(f"audit_id={result.audit_id}")
    print(f"vendor={result.vendor} findings={len(result.findings)} failed={result.failed_count} unknown={len(result.unknown_blocks)} frameworks={','.join(frameworks)}")
    for finding in result.findings:
        print(f"{finding.control_id}\t{finding.status.value}\t{finding.severity.value}")
    if args.trail:
        try:
            event = AuditTrail(args.trail).append(result)
        except (OSError, AuditLogError) as exc:
            print(f"Audit trail unavailable: {exc}", file=sys.stderr)
            return 2
        print(f"audit_trail={args.trail} sequence={event.sequence} event_hash={event.event_hash}")
    if args.signed_out:
        if not args.signing_key_file:
            print("Signed export requires --signing-key-file.", file=sys.stderr)
            return 2
        try:
            key_path = args.signing_key_file
            if key_path.is_symlink() or not key_path.is_file() or key_path.stat().st_size > 4096:
                raise AuditLogError("signing key path is invalid")
            key = key_path.read_bytes()
            envelope = sign_envelope(json.loads(client.report_json(result, frameworks=frameworks)), key)
            args.signed_out.parent.mkdir(parents=True, exist_ok=True)
            args.signed_out.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        except (OSError, ValueError, AuditLogError) as exc:
            print(f"Signed export unavailable: {exc}", file=sys.stderr)
            return 2
        print(f"signed_export={args.signed_out}")
    if args.report_out:
        write_report(result, str(args.report_out), format="markdown", frameworks=frameworks)
        print(f"report={args.report_out}")
    if args.json_out:
        write_report(result, str(args.json_out), format="json", frameworks=frameworks)
        print(f"json_report={args.json_out}")
    if args.remediation_out or args.diff_out:
        try:
            bundle = generate_bundle(result)
        except RemediationError as exc:
            print(f"Remediation unavailable: {exc}", file=sys.stderr)
            return 2
        if args.remediation_out:
            args.remediation_out.parent.mkdir(parents=True, exist_ok=True)
            args.remediation_out.write_text(bundle.script, encoding="utf-8", newline="\n")
            print(f"remediation_preview={args.remediation_out} steps={bundle.step_count} warnings={len(bundle.warnings)}")
        if args.diff_out:
            args.diff_out.parent.mkdir(parents=True, exist_ok=True)
            args.diff_out.write_text(render_diffs(result, bundle), encoding="utf-8", newline="\n")
            print(f"remediation_diff={args.diff_out}")
        print("SAFETY: preview generated; no device connection or execution performed.")
    return 0


def run_batch(args: argparse.Namespace) -> int:
    try:
        frameworks = normalize_frameworks(args.frameworks)
        packs = (CustomPolicyPack.from_file(args.policy),) if args.policy else ()
        client = ConfigSentinelClient(engine=DeterministicComplianceEngine(packs))
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


def run_release_artifacts(args: argparse.Namespace) -> int:
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8")) if args.manifest else None
        write_release_artifacts(args.root, args.sbom_out, args.metadata_out, manifest=manifest)
    except (OSError, ValueError, ReleaseError) as exc:
        print(f"Release artifacts rejected: {exc}", file=sys.stderr)
        return 2
    print(f"sbom={args.sbom_out} metadata={args.metadata_out}")
    return 0


def run_backup_create(args: argparse.Namespace) -> int:
    try:
        passphrase = os.environ.get(args.passphrase_env, "")
        backup_file(args.json_input, args.out, passphrase)
    except (OSError, ValueError, BackupError, RuntimeError) as exc:
        print(f"Backup creation rejected: {exc}", file=sys.stderr)
        return 2
    print(f"encrypted_backup={args.out} passphrase_source=environment:{args.passphrase_env}")
    return 0


def run_backup_restore(args: argparse.Namespace) -> int:
    try:
        passphrase = os.environ.get(args.passphrase_env, "")
        restore_file(args.encrypted_input, args.out, passphrase)
    except (OSError, ValueError, BackupError, RuntimeError) as exc:
        print(f"Backup restore rejected: {exc}", file=sys.stderr)
        return 2
    print(f"restored_backup={args.out} passphrase_source=environment:{args.passphrase_env}")
    return 0


def run_siem_export(args: argparse.Namespace) -> int:
    try:
        rendered = render_siem(load_report(args.json_input), fmt=args.format)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered, encoding="utf-8", newline="\n")
    except (OSError, ValueError, SiemError, EvidenceGraphError) as exc:
        print(f"SIEM export rejected: {exc}", file=sys.stderr)
        return 2
    print(f"siem_export={args.out} format={args.format} submission=not_performed")
    return 0


def run_cached_audit(args: argparse.Namespace) -> int:
    try:
        frameworks = normalize_frameworks(args.frameworks)
        service = ConfigIngestionService()
        ingested = service.ingest_file(args.file)
        client = ConfigSentinelClient(engine=DeterministicComplianceEngine(), ingestion=service)
        key = AuditCache.key(ingested.redacted_text, vendor=args.vendor, frameworks=frameworks, rule_pack_version=CONTROL_PACK_VERSION)
        report, hit = AuditCache(args.cache_dir).get_or_compute(key, lambda: report_dict(client.audit_text(ingested.redacted_text, vendor=args.vendor, frameworks=frameworks), frameworks))
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    except (OSError, ValueError, RuntimeError, CacheError) as exc:
        print(f"Cached audit rejected: {exc}", file=sys.stderr)
        return 2
    print(f"cached_audit={args.json_out} cache_hit={hit} cache_key={key}")
    return 0


def run_audit_compare(args: argparse.Namespace) -> int:
    try:
        result = compare_reports(load_report(args.before), load_report(args.after))
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    except (OSError, ValueError, DemoError, EvidenceGraphError) as exc:
        print(f"Audit comparison rejected: {exc}", file=sys.stderr)
        return 2
    print(f"audit_comparison={args.out} changed={result['changed_count']}")
    return 0


def run_demo_mode(args: argparse.Namespace) -> int:
    try:
        report = load_report(args.json_input)
        comparison = compare_reports(report, load_report(args.after)) if args.after else None
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(render_guided_demo(report, comparison=comparison), encoding="utf-8", newline="\n")
    except (OSError, ValueError, DemoError, EvidenceGraphError) as exc:
        print(f"Demo artifact rejected: {exc}", file=sys.stderr)
        return 2
    print(f"demo_artifact={args.out} comparison={bool(args.after)}")
    return 0


def run_topology_analyze(args: argparse.Namespace) -> int:
    try:
        graph = json.loads(args.json_input.read_text(encoding="utf-8"))
        finding_assets: dict[str, str] = {}
        for pair in args.finding_asset:
            finding_id, separator, asset_id = pair.partition("=")
            if not separator or not finding_id or not asset_id:
                raise TopologyError("--finding-asset must use FINDING=ASSET")
            finding_assets[finding_id] = asset_id
        payload = analyze_topology(graph, finding_assets=finding_assets, depth=args.depth)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        if args.html_out:
            write_topology_html(graph, args.html_out, payload)
    except (OSError, ValueError, TopologyError) as exc:
        print(f"Topology analysis rejected: {exc}", file=sys.stderr)
        return 2
    print(f"topology_analysis={args.out} impacted={len(payload['impacted_node_ids'])}")
    if args.html_out:
        print(f"topology_html={args.html_out}")
    return 0


def run_exception_add(args: argparse.Namespace) -> int:
    try:
        record = create_exception(args.exception_id, args.finding_id, args.owner, args.justification, args.expires_at)
        save_exception(record, args.file)
    except (OSError, ValueError, ExceptionError) as exc:
        print(f"Exception rejected: {exc}", file=sys.stderr)
        return 2
    print(f"exception={record.exception_id} status={record.status()} verdict_impact=none")
    return 0


def run_exception_approve(args: argparse.Namespace) -> int:
    try:
        record = approve_exception(args.exception_id, args.approver, args.file)
    except (OSError, ValueError, ExceptionError) as exc:
        print(f"Exception approval rejected: {exc}", file=sys.stderr)
        return 2
    print(f"exception={record.exception_id} status={record.status()} approved_by={record.approved_by}")
    return 0


def run_exception_list(args: argparse.Namespace) -> int:
    try:
        payload = {"schema": "configsentinel.exceptions.v1", "exceptions": [item.as_dict() for item in load_exceptions(args.file)]}
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    except (OSError, ValueError, ExceptionError) as exc:
        print(f"Exception listing rejected: {exc}", file=sys.stderr)
        return 2
    print(f"exceptions={args.out} count={len(payload['exceptions'])}")
    return 0


def run_risk_prioritize(args: argparse.Namespace) -> int:
    try:
        payload = risk_report(load_report(args.json_input), asset_criticality=args.asset_criticality)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    except (OSError, ValueError, RiskError, EvidenceGraphError) as exc:
        print(f"Risk prioritization rejected: {exc}", file=sys.stderr)
        return 2
    print(f"risk_report={args.out} items={len(payload['items'])} verdict_source={payload['verdict_source']}")
    return 0


def run_release_manifest(args: argparse.Namespace) -> int:
    try:
        write_manifest(args.root, args.out)
    except (OSError, SupplyChainError) as exc:
        print(f"Release manifest rejected: {exc}", file=sys.stderr)
        return 2
    print(f"release_manifest={args.out}")
    return 0


def run_verify_manifest(args: argparse.Namespace) -> int:
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        failures = verify_manifest(args.root, manifest)
    except (OSError, ValueError, SupplyChainError) as exc:
        print(f"Manifest verification rejected: {exc}", file=sys.stderr)
        return 2
    print(f"manifest_verification={args.manifest} valid={not failures}")
    if failures:
        print("\n".join(failures), file=sys.stderr)
    return 0 if not failures else 2


def run_verification_benchmark(args: argparse.Namespace) -> int:
    payload = run_benchmark()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(f"verification_benchmark={args.out} passed={payload['passed']}")
    return 0 if payload["passed"] else 2


def run_verify_report(args: argparse.Namespace) -> int:
    try:
        result = verify_report(load_report(args.json_input))
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result.as_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    except (OSError, ValueError, EvidenceGraphError) as exc:
        print(f"Report verification rejected: {exc}", file=sys.stderr)
        return 2
    print(f"report_verification={args.out} valid={result.valid}")
    return 0 if result.valid else 2


def run_inventory_import(args: argparse.Namespace) -> int:
    try:
        graph = import_inventory_file(str(args.source))
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(graph.as_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    except (OSError, ValueError, InventoryError) as exc:
        print(f"Inventory import rejected: {exc}", file=sys.stderr)
        return 2
    print(f"inventory={args.out} nodes={len(graph.nodes)} links={len(graph.links)} discovery=import_only")
    return 0


def run_ticket_export(args: argparse.Namespace) -> int:
    try:
        report = load_report(args.json_input)
        rendered = render_ticket_markdown(report) if args.format == "markdown" else json.dumps(build_ticket_payload(report, args.adapter), indent=2, sort_keys=True) + "\n"
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered, encoding="utf-8", newline="\n")
    except (OSError, ValueError, TicketingError, EvidenceGraphError) as exc:
        print(f"Ticket export rejected: {exc}", file=sys.stderr)
        return 2
    print(f"ticket_export={args.out} adapter={args.adapter} format={args.format} submission=not_performed")
    return 0


def run_webhook_enqueue(args: argparse.Namespace) -> int:
    try:
        event = make_audit_event(load_report(args.json_input))
        LocalWebhookQueue(args.queue).enqueue(event)
    except (OSError, ValueError, WebhookError, EvidenceGraphError) as exc:
        print(f"Webhook enqueue rejected: {exc}", file=sys.stderr)
        return 2
    print(f"webhook_queue={args.queue} event={event.event_type} payload_sha256={event.payload_sha256}")
    return 0


def _read_attestation_key(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4096:
        raise AttestationError("attestation key path is invalid")
    key = path.read_bytes()
    if not key:
        raise AttestationError("attestation key cannot be empty")
    return key

def run_attestation_create(args: argparse.Namespace) -> int:
    try:
        report = load_report(args.json_input)
        attestation = build_attestation(report, _read_attestation_key(args.key_file), reviewer_status=args.reviewer_status, issued_at=args.issued_at)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(attestation, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    except (OSError, UnicodeDecodeError, ValueError, AttestationError, EvidenceGraphError) as exc:
        print(f"Attestation creation rejected: {exc}", file=sys.stderr)
        return 2
    print(f"attestation={args.out} schema={attestation['schema']} reviewer_status={args.reviewer_status}")
    return 0

def run_attestation_verify(args: argparse.Namespace) -> int:
    try:
        report = load_report(args.json_input)
        valid, reason = verify_attestation(load_attestation(args.attestation), report, _read_attestation_key(args.key_file))
    except (OSError, UnicodeDecodeError, ValueError, AttestationError, EvidenceGraphError) as exc:
        print(f"Attestation verification rejected: {exc}", file=sys.stderr)
        return 2
    print(f"attestation_verification={'VALID' if valid else 'INVALID'} reason={reason}")
    return 0 if valid else 1

def run_uncertainty_budget(args: argparse.Namespace) -> int:
    try:
        budget = build_uncertainty_budget(load_report(args.json_input))
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(budget, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    except (OSError, UnicodeDecodeError, ValueError, UncertaintyError, EvidenceGraphError) as exc:
        print(f"Uncertainty budget rejected: {exc}", file=sys.stderr)
        return 2
    assurance = budget["assurance"]
    print(f"uncertainty_budget={args.out} state={assurance['state']} coverage={assurance['evidence_coverage']:.6f} gaps={len(assurance['gaps'])}")
    return 0

def run_mutation_lab_command(args: argparse.Namespace) -> int:
    try:
        report = run_mutation_lab(args.file.read_text(encoding="utf-8"), vendor=args.vendor, frameworks=normalize_frameworks(args.frameworks), max_mutations=args.max_mutations)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    except (OSError, UnicodeDecodeError, ValueError, MutationError) as exc:
        print(f"Mutation lab rejected: {exc}", file=sys.stderr)
        return 2
    print(f"mutation_lab={args.out} passed={report['summary']['passed']} mutations={report['summary']['mutation_count']}")
    return 0 if report["summary"]["passed"] else 1

def _parse_edge_specs(values: list[str]) -> list[tuple[str, str]]:
    edges: list[tuple[str, str]] = []
    for value in values:
        if "=" not in value:
            raise AssuranceTwinError("edge specification must use SOURCE=TARGET")
        source, target = (part.strip() for part in value.split("=", 1))
        if not source or not target:
            raise AssuranceTwinError("edge specification requires source and target")
        edges.append((source, target))
    return edges

def run_assurance_twin(args: argparse.Namespace) -> int:
    try:
        graph = load_report(args.topology_input)
        source_report = load_report(args.report) if args.report else None
        finding_assets: dict[str, str] = {}
        for item in args.finding_asset:
            if "=" not in item:
                raise AssuranceTwinError("finding-asset mapping must use FINDING=ASSET")
            finding_id, asset_id = (part.strip() for part in item.split("=", 1))
            finding_assets[finding_id] = asset_id
        twin = build_assurance_twin(graph, report=source_report, finding_assets=finding_assets, depth=args.depth, counterfactual_add=_parse_edge_specs(args.add_link), counterfactual_remove=_parse_edge_specs(args.remove_link))
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(twin, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        if args.html_out:
            write_assurance_twin_html(twin, args.html_out)
    except (OSError, UnicodeDecodeError, ValueError, AssuranceTwinError, EvidenceGraphError) as exc:
        print(f"Assurance twin rejected: {exc}", file=sys.stderr)
        return 2
    print(f"assurance_twin={args.out} nodes={twin['facts']['node_count']} links={twin['facts']['link_count']} derived_impacts={len(twin['analyses'])}")
    return 0

def run_intent_compile(args: argparse.Namespace) -> int:
    try:
        intent = load_report(args.intent_input)
        report = load_report(args.report) if args.report else None
        topology = load_report(args.topology) if args.topology else None
        compiled = compile_resource_intent(intent, report=report, topology=topology)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(compiled, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    except (OSError, UnicodeDecodeError, ValueError, IntentError, EvidenceGraphError) as exc:
        print(f"Intent compilation rejected: {exc}", file=sys.stderr)
        return 2
    print(f"intent_compile={args.out} state={compiled['summary']['state']} checks={compiled['summary']['check_count']}")
    return 0

def run_apprenticeship_contract(args: argparse.Namespace) -> int:
    try:
        contract = create_contract(load_report(args.mapping_input), positive_examples=args.positive, counterexamples=args.counterexample)
        write_contract(contract, args.out)
    except (OSError, UnicodeDecodeError, ValueError, ApprenticeshipError, EvidenceGraphError) as exc:
        print(f"Apprenticeship contract rejected: {exc}", file=sys.stderr)
        return 2
    print(f"apprenticeship_contract={args.out} status={contract['promotion']['status']} promoted={contract['promotion']['promoted_into_parser']}")
    return 0

def run_apprenticeship_test(args: argparse.Namespace) -> int:
    try:
        result = evaluate_contract(load_report(args.contract_input))
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    except (OSError, UnicodeDecodeError, ValueError, ApprenticeshipError, EvidenceGraphError) as exc:
        print(f"Apprenticeship test rejected: {exc}", file=sys.stderr)
        return 2
    print(f"apprenticeship_test={args.out} status={result['promotion']['status']} promoted={result['promotion']['promoted_into_parser']}")
    return 0 if result["promotion"]["status"] == "READY_FOR_HUMAN_REVIEW" else 1

def run_differential(args: argparse.Namespace) -> int:
    try:
        variants: dict[str, str] = {}
        for item in args.variant:
            if "=" not in item:
                raise DifferentialError("variant must use VENDOR=FILE")
            vendor, filename = (part.strip() for part in item.split("=", 1))
            if vendor in variants:
                raise DifferentialError(f"duplicate vendor variant: {vendor}")
            variants[vendor] = Path(filename).read_text(encoding="utf-8")
        report = run_differential_test(variants, fields=args.fields or SEMANTIC_FIELDS, case_id=args.case_id)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    except (OSError, UnicodeDecodeError, ValueError, DifferentialError) as exc:
        print(f"Differential test rejected: {exc}", file=sys.stderr)
        return 2
    comparison = report["comparison"]
    print(f"differential_test={args.out} equivalent={comparison['equivalent']} semantic_disagreements={comparison['semantic_disagreement_count']} control_disagreements={comparison['control_disagreement_count']}")
    return 0

def run_time_machine(args: argparse.Namespace) -> int:
    try:
        machine = build_time_machine(load_snapshot_source(args.snapshots_input), control_id=args.control_id, vendor=args.vendor)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(machine, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        if args.html_out:
            write_time_machine_html(machine, args.html_out)
    except (OSError, UnicodeDecodeError, ValueError, TimeMachineError, EvidenceGraphError) as exc:
        print(f"Time machine rejected: {exc}", file=sys.stderr)
        return 2
    print(f"time_machine={args.out} snapshots={machine['summary']['snapshot_count']} changes={machine['summary']['change_count']}")
    return 0

def _read_exchange_key(path: Path | None) -> bytes | None:
    if path is None:
        return None
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4096:
        raise ExchangeError("exchange key path is invalid")
    key = path.read_bytes()
    if not key:
        raise ExchangeError("exchange key cannot be empty")
    return key


def run_audit_exchange(args: argparse.Namespace) -> int:
    try:
        capsule = build_exchange_capsule(load_report(args.report_input), recipient=args.recipient, purpose=args.purpose, key=_read_exchange_key(args.key_file))
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(capsule, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    except (OSError, UnicodeDecodeError, ValueError, ExchangeError, EvidenceGraphError) as exc:
        print(f"Audit exchange rejected: {exc}", file=sys.stderr)
        return 2
    print(f"audit_exchange={args.out} capsule_sha256={capsule['capsule_sha256']} submission=not_performed")
    return 0


def run_audit_exchange_verify(args: argparse.Namespace) -> int:
    try:
        capsule = json.loads(args.capsule_input.read_text(encoding="utf-8"))
        result = verify_exchange_capsule(capsule, key=_read_exchange_key(args.key_file))
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, ExchangeError) as exc:
        print(f"Audit exchange verification rejected: {exc}", file=sys.stderr)
        return 2
    print(f"audit_exchange_verify={args.out} verified={result['verified']} mismatches={len(result['mismatches'])}")
    return 0 if result["verified"] else 1


def run_reviewer_analytics(args: argparse.Namespace) -> int:
    try:
        review_source = load_reviews(args.reviews_input)
        report = load_report(args.report_input)
        analytics = build_reviewer_analytics(report, review_source["reviews"])
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(analytics, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, ReviewAnalyticsError, EvidenceGraphError) as exc:
        print(f"Reviewer analytics rejected: {exc}", file=sys.stderr)
        return 2
    print(f"reviewer_analytics={args.out} reviewers={analytics['summary']['reviewer_count']} disputed={analytics['summary']['disputed_finding_count']} verdicts_changed={analytics['safety']['verdicts_changed']}")
    return 0


def run_assurance_freshness(args: argparse.Namespace) -> int:
    try:
        report = load_report_for_freshness(args.report_input)
        baseline = load_report_for_freshness(args.baseline) if args.baseline else None
        ttl_seconds = int(args.ttl_hours * 60 * 60)
        assessment = build_freshness_assessment(report, observed_at=args.observed_at, as_of=args.as_of, ttl_seconds=ttl_seconds, baseline=baseline)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(assessment, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, FreshnessError) as exc:
        print(f"Assurance freshness rejected: {exc}", file=sys.stderr)
        return 2
    print(f"assurance_freshness={args.out} state={assessment['assurance']['state']} freshness={assessment['freshness']['state']} drifted={assessment['drift']['drifted']} verdicts_changed={assessment['safety']['verdicts_changed']}")
    return 0


def run_remediation_proof(args: argparse.Namespace) -> int:
    try:
        proof = build_proof_bundle(load_report(args.report_input))
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    except (OSError, UnicodeDecodeError, ValueError, ProofError, EvidenceGraphError) as exc:
        print(f"Remediation proof rejected: {exc}", file=sys.stderr)
        return 2
    print(f"remediation_proof={args.out} state={proof['summary']['state']} proofs={proof['summary']['proof_count']}")
    return 0

def run_remediation_proof_verify(args: argparse.Namespace) -> int:
    try:
        result = verify_proof_bundle(load_report(args.proof_input), load_report(args.report_input))
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    except (OSError, UnicodeDecodeError, ValueError, ProofError, EvidenceGraphError) as exc:
        print(f"Remediation proof verification rejected: {exc}", file=sys.stderr)
        return 2
    print(f"remediation_proof_verify={args.out} verified={result['verified']} mismatches={len(result['mismatches'])}")
    return 0 if result["verified"] else 1

def run_sensitive_scan(args: argparse.Namespace) -> int:
    try:
        text = args.file.read_text(encoding="utf-8")
        scan = scan_sensitive(text)
        rendered = json.dumps(scan.as_dict(), indent=2, sort_keys=True) + "\n" if args.format == "json" else render_sensitive_scan(scan)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered, encoding="utf-8")
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        print(f"Sensitive scan rejected: {exc}", file=sys.stderr)
        return 2
    print(f"sensitive_scan={args.out} hits={scan.count} input_sha256={scan.input_sha256}")
    return 0


def run_evidence_graph(args: argparse.Namespace) -> int:
    try:
        graph = build_evidence_graph(load_report(args.json_input))
        write_graph(graph, args.out)
    except (OSError, ValueError, EvidenceGraphError) as exc:
        print(f"Evidence graph rejected: {exc}", file=sys.stderr)
        return 2
    print(f"evidence_graph={args.out} nodes={len(graph['nodes'])} edges={len(graph['edges'])}")
    return 0


def run_history_analyze(args: argparse.Namespace) -> int:
    try:
        analytics = analyze_history(load_history(args.json_input))
        write_history_analytics(analytics, args.out)
    except (OSError, ValueError, AnalyticsError) as exc:
        print(f"History analytics rejected: {exc}", file=sys.stderr)
        return 2
    print(f"history_analytics={args.out} reports={analytics['report_count']} dates={len(analytics['timeline'])}")
    return 0


def run_executive_report(args: argparse.Namespace) -> int:
    try:
        result = ConfigSentinelClient(engine=DeterministicComplianceEngine()).audit_file(str(args.file), vendor=args.vendor)
        report = build_executive_report(result)
        rendered = render_executive_json(report) if args.format == "json" else render_executive_markdown(report)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered, encoding="utf-8")
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Executive report rejected: {exc}", file=sys.stderr)
        return 2
    print(f"enterprise_report={args.out} posture={report.posture} failed={report.failed} unknown={report.unknown}")
    return 0


def run_approval_request(args: argparse.Namespace) -> int:
    try:
        event = ApprovalLedger(args.ledger).request(args.resource_id, args.actor, role=Role(args.role), reason=args.reason)
    except GovernanceError as exc:
        print(f"Approval request rejected: {exc}", file=sys.stderr)
        return 2
    print(f"approval=PENDING_REVIEW resource={event.resource_id} event={event.event_id}")
    return 0


def run_approval_decide(args: argparse.Namespace) -> int:
    try:
        ledger = ApprovalLedger(args.ledger)
        event = ledger.decide(args.resource_id, args.actor, role=Role(args.role), approve=args.approve, reason=args.reason)
    except GovernanceError as exc:
        print(f"Approval decision rejected: {exc}", file=sys.stderr)
        return 2
    print(f"approval={ledger.status(args.resource_id)} resource={event.resource_id} event={event.event_id}")
    return 0


def run_baseline_save(args: argparse.Namespace) -> int:
    try:
        client = ConfigSentinelClient(engine=DeterministicComplianceEngine())
        result = client.audit_file(str(args.file), vendor=args.vendor)
        save_baseline(result, args.out, label=args.label)
    except (OSError, ValueError, RuntimeError, BaselineError) as exc:
        print(f"Baseline rejected: {exc}", file=sys.stderr)
        return 2
    print(f"baseline={args.out} input_sha256={result.input_sha256} vendor={result.vendor} findings={len(result.findings)}")
    return 0


def run_drift(args: argparse.Namespace) -> int:
    try:
        client = ConfigSentinelClient(engine=DeterministicComplianceEngine())
        result = client.audit_file(str(args.file), vendor=args.vendor)
        comparison = compare_baseline(load_baseline(args.baseline), result)
    except (OSError, ValueError, RuntimeError, BaselineError) as exc:
        print(f"Drift check rejected: {exc}", file=sys.stderr)
        return 2
    decision = "DRIFTED" if comparison["drifted"] else "CLEAN"
    print(f"drift={decision} hash_changed={comparison['hash_changed']} changed_controls={len(comparison['changed_controls'])}")
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(comparison, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 1 if comparison["drifted"] else 0


def run_gitops(args: argparse.Namespace) -> int:
    try:
        frameworks = normalize_frameworks(args.frameworks)
        result = run_gitops_gate(args.repo, args.base, args.head, vendor=args.vendor, frameworks=frameworks)
    except (OSError, ValueError, RuntimeError, SourceDiscoveryError) as exc:
        print(f"GitOps gate rejected: {exc}", file=sys.stderr)
        return 2
    decision = "PASS" if result.passed else "BLOCK"
    print(f"gitops={decision} changed_files={len(result.changed_files)} findings={len(result.findings)} reason={result.reason}")
    for finding in result.findings:
        lines = ",".join(str(line) for line in finding.evidence_lines) or "none"
        print(f"{finding.path}\t{finding.control_id}\t{finding.status}\t{finding.severity}\tevidence={lines}")
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        write_gate_result(result, args.json_out)
        print(f"json_report={args.json_out}")
    return 0 if result.passed else 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "audit":
        return run_audit(args)
    if args.command == "batch":
        return run_batch(args)
    if args.command == "gitops-check":
        return run_gitops(args)
    if args.command == "baseline-save":
        return run_baseline_save(args)
    if args.command == "drift-check":
        return run_drift(args)
    if args.command == "enterprise-report":
        return run_executive_report(args)
    if args.command == "history-analyze":
        return run_history_analyze(args)
    if args.command == "evidence-graph":
        return run_evidence_graph(args)
    if args.command == "sensitive-scan":
        return run_sensitive_scan(args)
    if args.command == "attestation-create":
        return run_attestation_create(args)
    if args.command == "attestation-verify":
        return run_attestation_verify(args)
    if args.command == "uncertainty-budget":
        return run_uncertainty_budget(args)
    if args.command == "mutation-lab":
        return run_mutation_lab_command(args)
    if args.command == "assurance-twin":
        return run_assurance_twin(args)
    if args.command == "intent-compile":
        return run_intent_compile(args)
    if args.command == "apprenticeship-contract":
        return run_apprenticeship_contract(args)
    if args.command == "apprenticeship-test":
        return run_apprenticeship_test(args)
    if args.command == "differential-test":
        return run_differential(args)
    if args.command == "time-machine":
        return run_time_machine(args)
    if args.command == "remediation-proof":
        return run_remediation_proof(args)
    if args.command == "audit-exchange":
        return run_audit_exchange(args)
    if args.command == "audit-exchange-verify":
        return run_audit_exchange_verify(args)
    if args.command == "reviewer-analytics":
        return run_reviewer_analytics(args)
    if args.command == "assurance-freshness":
        return run_assurance_freshness(args)
    if args.command == "remediation-proof-verify":
        return run_remediation_proof_verify(args)
    if args.command == "webhook-enqueue":
        return run_webhook_enqueue(args)
    if args.command == "ticket-export":
        return run_ticket_export(args)
    if args.command == "inventory-import":
        return run_inventory_import(args)
    if args.command == "verify-report":
        return run_verify_report(args)
    if args.command == "verification-benchmark":
        return run_verification_benchmark(args)
    if args.command == "release-manifest":
        return run_release_manifest(args)
    if args.command == "verify-manifest":
        return run_verify_manifest(args)
    if args.command == "risk-prioritize":
        return run_risk_prioritize(args)
    if args.command == "exception-add":
        return run_exception_add(args)
    if args.command == "exception-approve":
        return run_exception_approve(args)
    if args.command == "exception-list":
        return run_exception_list(args)
    if args.command == "topology-analyze":
        return run_topology_analyze(args)
    if args.command == "audit-compare":
        return run_audit_compare(args)
    if args.command == "demo-mode":
        return run_demo_mode(args)
    if args.command == "cache-audit":
        return run_cached_audit(args)
    if args.command == "siem-export":
        return run_siem_export(args)
    if args.command == "backup-create":
        return run_backup_create(args)
    if args.command == "backup-restore":
        return run_backup_restore(args)
    if args.command == "release-artifacts":
        return run_release_artifacts(args)
    if args.command == "approval-request":
        return run_approval_request(args)
    if args.command == "approval-decide":
        return run_approval_decide(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
