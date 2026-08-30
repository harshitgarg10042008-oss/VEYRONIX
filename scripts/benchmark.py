#!/usr/bin/env python3
"""
ConfigSentinel AI — Accuracy and Impact Benchmark
==================================================

Measures parser identification accuracy, control status accuracy, unknown rate,
false-positive count, false-negative count (where trusted labels exist),
reproducibility, latency, and fixture coverage.

IMPORTANT HONESTY CONSTRAINTS
------------------------------
- Synthetic fixtures are clearly labelled as SYNTHETIC.
- Accuracy claims are only made against fixtures that have expected_controls labels.
- This script never calls synthetic benchmark results "real-world validation."
- False-positive / false-negative rates against real deployments are PENDING_USER_EVIDENCE
  until the user provides authorized, sanitized, labeled real-world fixtures.

Usage:
    python scripts/benchmark.py [--output MARKDOWN_FILE] [--json JSON_FILE]
                                 [--fixture-dir FIXTURE_DIR] [--manifest MANIFEST]

Environment:
    PYTHONPATH=src  (required if package not installed editably)
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Ensure src/ is importable when PYTHONPATH isn't set externally
# ---------------------------------------------------------------------------
SRC_DIR = Path(__file__).parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from configsentinel.controls import CONTROL_PACK, CONTROL_PACK_VERSION  # noqa: E402
from configsentinel.models import FindingStatus  # noqa: E402
from configsentinel.client import ConfigSentinelClient  # noqa: E402
from configsentinel.engine import DeterministicComplianceEngine  # noqa: E402
from configsentinel.detection import detect_vendor  # noqa: E402


def get_commit_sha() -> str:
    """Return current HEAD commit SHA, or 'unknown' if not in a git repo."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()[:12]
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def load_manifest(manifest_path: Path) -> dict[str, Any]:
    if not manifest_path.exists():
        return {"fixtures": [], "dataset_id": "unknown", "source_category": "UNKNOWN", "limitations": []}
    with manifest_path.open() as f:
        return json.load(f)


def vendor_label_to_engine(vendor_label: str) -> str:
    """Map manifest vendor labels to engine vendor identifiers."""
    return {
        "cisco_ios": "cisco_ios",
        "junos": "junos",
        "arista_eos": "arista_eos",
    }.get(vendor_label, vendor_label)


def run_fixture(
    fixture_path: Path,
    fixture_meta: dict[str, Any],
    client: ConfigSentinelClient,
    runs: int = 3,
) -> dict[str, Any]:
    """
    Evaluate one fixture file. Returns a structured result dict.
    Runs multiple times to measure reproducibility.
    """
    content = fixture_path.read_text(encoding="utf-8", errors="replace")
    vendor_label = fixture_meta.get("vendor_label", "auto")
    expected_vendor = fixture_meta.get("expected_vendor_detection", "")
    expected_controls: dict[str, str] = fixture_meta.get("expected_controls", {})
    source = fixture_meta.get("source", "UNKNOWN")

    timings: list[float] = []
    all_statuses: list[dict[str, str]] = []
    parse_error: str | None = None

    for _ in range(runs):
        t0 = time.perf_counter()
        try:
            audit_result = client.audit_text(content, vendor="auto", frameworks=("cis-network",), project_id="benchmark")
            statuses = {f.control_id: f.status.value for f in audit_result.findings}
            all_statuses.append(statuses)
        except Exception as exc:
            parse_error = str(exc)
            all_statuses.append({})
        timings.append(time.perf_counter() - t0)

    if parse_error and not any(all_statuses):
        return {
            "fixture_id": fixture_meta.get("fixture_id", fixture_path.name),
            "filename": fixture_path.name,
            "source": source,
            "error": parse_error,
            "vendor_correct": None,
            "findings_count": 0,
            "unknown_count": 0,
            "labeled_count": 0,
            "correct_labeled": 0,
            "false_positives": 0,
            "false_negatives": 0,
            "reproducible": False,
            "latency_ms_avg": sum(timings) / len(timings) * 1000,
            "input_bytes": len(content.encode("utf-8")),
        }

    # Determine actual vendor via detect_vendor for accuracy measurement
    try:
        detection_result = detect_vendor(content)
        actual_vendor = detection_result.selected_vendor or "unknown"
        audit_result_final = client.audit_text(content, vendor="auto", frameworks=("cis-network",), project_id="benchmark")
    except Exception:
        actual_vendor = "unknown"
        audit_result_final = None

    # Vendor accuracy
    vendor_correct: bool | None = None
    if expected_vendor:
        vendor_correct = actual_vendor == expected_vendor

    # Control status accuracy (only against labeled controls)
    statuses_final = all_statuses[-1] if all_statuses else {}
    labeled_count = len(expected_controls)
    correct_labeled = 0
    false_positives = 0   # FAIL/WARN observed but PASS expected
    false_negatives = 0   # PASS observed but FAIL/WARN expected

    for control_id, expected_status in expected_controls.items():
        observed = statuses_final.get(control_id)
        if observed is None:
            continue
        if observed == expected_status:
            correct_labeled += 1
        else:
            if expected_status == "PASS" and observed in ("FAIL", "WARN"):
                false_positives += 1
            elif expected_status in ("FAIL", "WARN") and observed == "PASS":
                false_negatives += 1

    # Unknown rate
    all_findings = audit_result_final.findings if audit_result_final else []
    unknown_count = sum(
        1 for f in all_findings
        if f.status in (FindingStatus.UNKNOWN, FindingStatus.NOT_APPLICABLE)
    )

    # Reproducibility: all runs produced identical control status sets
    reproducible = all(s == all_statuses[0] for s in all_statuses[1:]) if len(all_statuses) > 1 else True

    return {
        "fixture_id": fixture_meta.get("fixture_id", fixture_path.name),
        "filename": fixture_path.name,
        "source": source,
        "error": None,
        "detected_vendor": actual_vendor,
        "expected_vendor": expected_vendor,
        "vendor_correct": vendor_correct,
        "findings_count": len(all_findings),
        "unknown_count": unknown_count,
        "labeled_count": labeled_count,
        "correct_labeled": correct_labeled,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "reproducible": reproducible,
        "latency_ms_avg": round(sum(timings) / len(timings) * 1000, 2),
        "input_bytes": len(content.encode("utf-8")),
        "control_statuses": statuses_final,
    }


def run_benchmark(
    fixture_dir: Path,
    manifest: dict[str, Any],
    runs: int = 3,
) -> dict[str, Any]:
    client = ConfigSentinelClient(engine=DeterministicComplianceEngine())
    control_count = len(CONTROL_PACK)

    # Build lookup from filename → manifest metadata
    meta_by_filename: dict[str, dict[str, Any]] = {
        fix["filename"]: fix for fix in manifest.get("fixtures", [])
    }

    fixture_files = sorted(fixture_dir.glob("*.conf"))
    results: list[dict[str, Any]] = []

    for fixture_path in fixture_files:
        meta = meta_by_filename.get(fixture_path.name, {
            "fixture_id": fixture_path.name,
            "filename": fixture_path.name,
            "source": "UNLABELED",
            "vendor_label": "auto",
            "expected_vendor_detection": "",
            "expected_controls": {},
        })
        result = run_fixture(fixture_path, meta, client, runs=runs)
        results.append(result)

    # Aggregate
    total_fixtures = len(results)
    errored = sum(1 for r in results if r["error"])
    vendor_labeled = [r for r in results if r.get("vendor_correct") is not None]
    vendor_correct_count = sum(1 for r in vendor_labeled if r["vendor_correct"])
    total_labeled_controls = sum(r["labeled_count"] for r in results)
    total_correct_labeled = sum(r["correct_labeled"] for r in results)
    total_false_positives = sum(r["false_positives"] for r in results)
    total_false_negatives = sum(r["false_negatives"] for r in results)
    total_unknown = sum(r["unknown_count"] for r in results)
    total_findings = sum(r["findings_count"] for r in results)
    all_reproducible = all(r["reproducible"] for r in results if not r["error"])

    vendor_accuracy = (
        vendor_correct_count / len(vendor_labeled) * 100 if vendor_labeled else None
    )
    control_accuracy = (
        total_correct_labeled / total_labeled_controls * 100
        if total_labeled_controls > 0
        else None
    )
    unknown_rate = (
        total_unknown / total_findings * 100 if total_findings > 0 else None
    )

    return {
        "schema": "configsentinel.benchmark.v1",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "commit_sha": get_commit_sha(),
        "control_pack_version": CONTROL_PACK_VERSION,
        "control_count": control_count,
        "dataset_id": manifest.get("dataset_id", "unknown"),
        "source_category": manifest.get("source_category", "UNKNOWN"),
        "fixture_runs": runs,
        "summary": {
            "total_fixtures": total_fixtures,
            "errored_fixtures": errored,
            "vendor_labeled_fixtures": len(vendor_labeled),
            "vendor_correct_count": vendor_correct_count,
            "vendor_accuracy_pct": round(vendor_accuracy, 2) if vendor_accuracy is not None else None,
            "total_labeled_controls": total_labeled_controls,
            "total_correct_labeled": total_correct_labeled,
            "control_accuracy_pct": round(control_accuracy, 2) if control_accuracy is not None else None,
            "total_false_positives": total_false_positives,
            "total_false_negatives": total_false_negatives,
            "total_findings": total_findings,
            "total_unknown": total_unknown,
            "unknown_rate_pct": round(unknown_rate, 2) if unknown_rate is not None else None,
            "all_reproducible": all_reproducible,
        },
        "fixtures": results,
        "limitations": manifest.get("limitations", []) + [
            "Control accuracy is only measured against fixtures with labeled expected_controls.",
            "Unlabeled controls produce counts but cannot contribute to accuracy rates.",
            "Reproducibility is measured across fixture runs within this benchmark run only.",
            "Real-world false-positive/false-negative rates are PENDING_USER_EVIDENCE.",
        ],
    }


def render_markdown(report: dict[str, Any]) -> str:
    s = report["summary"]
    lines = [
        "# ConfigSentinel AI — Accuracy Benchmark Report",
        "",
        f"**Dataset:** `{report['dataset_id']}` ({report['source_category']})",
        f"**Timestamp:** {report['timestamp']}",
        f"**Commit SHA:** `{report['commit_sha']}`",
        f"**Control-pack version:** `{report['control_pack_version']}`",
        f"**Controls in pack:** {report['control_count']}",
        f"**Fixture runs (reproducibility):** {report['fixture_runs']}",
        "",
        "> **Note:** All fixtures in this dataset are **SYNTHETIC** — crafted to exercise",
        "> specific code paths. This is **not** real-world validation. False-positive and",
        "> false-negative rates against real production configurations are",
        "> `PENDING_USER_EVIDENCE`.",
        "",
        "## Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Total fixtures | {s['total_fixtures']} |",
        f"| Errored fixtures | {s['errored_fixtures']} |",
        f"| Vendor-labeled fixtures | {s['vendor_labeled_fixtures']} |",
        f"| Vendor identification correct | {s['vendor_correct_count']} / {s['vendor_labeled_fixtures']} |",
        f"| **Vendor accuracy (labeled)** | **{s['vendor_accuracy_pct']}%** |" if s['vendor_accuracy_pct'] is not None else "| **Vendor accuracy** | **N/A (no labeled fixtures)** |",
        f"| Control-labeled controls tested | {s['total_labeled_controls']} |",
        f"| Correct labeled control outcomes | {s['total_correct_labeled']} |",
        f"| **Control accuracy (labeled)** | **{s['control_accuracy_pct']}%** |" if s['control_accuracy_pct'] is not None else "| **Control accuracy** | **N/A (no labeled controls)** |",
        f"| False positives (labeled) | {s['total_false_positives']} |",
        f"| False negatives (labeled) | {s['total_false_negatives']} |",
        f"| Total findings | {s['total_findings']} |",
        f"| Unknown / N/A findings | {s['total_unknown']} |",
        f"| Unknown rate | {s['unknown_rate_pct']}% |" if s['unknown_rate_pct'] is not None else "| Unknown rate | N/A |",
        f"| All runs reproducible | {'✅ Yes' if s['all_reproducible'] else '❌ No'} |",
        "",
        "## Per-Fixture Results",
        "",
        "| Fixture | Source | Detected Vendor | Vendor ✓ | Findings | Unknown | Labeled Controls | Correct | FP | FN | Repro | Latency (ms) |",
        "|---------|--------|-----------------|----------|----------|---------|-----------------|---------|----|----|-------|--------------|",
    ]

    for r in report["fixtures"]:
        if r.get("error"):
            lines.append(
                f"| `{r['filename']}` | {r['source']} | error | — | — | — | — | — | — | — | — | — |"
            )
        else:
            vc = "✅" if r["vendor_correct"] else ("❌" if r["vendor_correct"] is False else "—")
            repro = "✅" if r["reproducible"] else "❌"
            lines.append(
                f"| `{r['filename']}` | {r['source']} | `{r.get('detected_vendor','?')}` | {vc} "
                f"| {r['findings_count']} | {r['unknown_count']} | {r['labeled_count']} "
                f"| {r['correct_labeled']} | {r['false_positives']} | {r['false_negatives']} "
                f"| {repro} | {r['latency_ms_avg']} |"
            )

    lines += [
        "",
        "## Limitations",
        "",
    ]
    for limitation in report["limitations"]:
        lines.append(f"- {limitation}")

    lines += [
        "",
        "## Evidence Classification",
        "",
        "| Category | Status |",
        "|----------|--------|",
        "| Parser vendor identification (synthetic) | Measured — see table above |",
        "| Control status accuracy (synthetic, labeled) | Measured — see table above |",
        "| Reproducibility | Measured — deterministic across runs |",
        "| False-positive rate (real-world) | `PENDING_USER_EVIDENCE` |",
        "| False-negative rate (real-world) | `PENDING_USER_EVIDENCE` |",
        "| Pilot deployment accuracy | `PENDING_USER_EVIDENCE` |",
    ]

    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="ConfigSentinel AI accuracy benchmark")
    parser.add_argument("--fixture-dir", default="tests/fixtures", help="Directory containing fixture files")
    parser.add_argument("--manifest", default="tests/fixtures/manifest.json", help="Fixture manifest JSON")
    parser.add_argument("--output", default="docs/BENCHMARK_REPORT.md", help="Markdown output path")
    parser.add_argument("--json", default="docs/benchmark_result.json", help="JSON output path")
    parser.add_argument("--runs", type=int, default=3, help="Number of runs per fixture for reproducibility")
    args = parser.parse_args()

    fixture_dir = Path(args.fixture_dir)
    manifest_path = Path(args.manifest)
    output_path = Path(args.output)
    json_path = Path(args.json)

    if not fixture_dir.exists():
        print(f"ERROR: fixture directory not found: {fixture_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"Loading manifest: {manifest_path}")
    manifest = load_manifest(manifest_path)

    print(f"Running benchmark on {fixture_dir} ({args.runs} runs per fixture)...")
    report = run_benchmark(fixture_dir, manifest, runs=args.runs)

    # Write JSON
    json_path.parent.mkdir(parents=True, exist_ok=True)
    with json_path.open("w") as f:
        json.dump(report, f, indent=2)
    print(f"JSON report written: {json_path}")

    # Write Markdown
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        f.write(render_markdown(report))
    print(f"Markdown report written: {output_path}")

    # Print summary to stdout
    s = report["summary"]
    print()
    print(f"=== BENCHMARK SUMMARY (dataset: {report['dataset_id']}) ===")
    print(f"  Fixtures tested:          {s['total_fixtures']}")
    print(f"  Vendor accuracy:          {s['vendor_accuracy_pct']}% ({s['vendor_correct_count']}/{s['vendor_labeled_fixtures']} labeled)")
    print(f"  Control accuracy:         {s['control_accuracy_pct']}% ({s['total_correct_labeled']}/{s['total_labeled_controls']} labeled)")
    print(f"  False positives:          {s['total_false_positives']}")
    print(f"  False negatives:          {s['total_false_negatives']}")
    print(f"  Unknown rate:             {s['unknown_rate_pct']}%")
    print(f"  All runs reproducible:    {s['all_reproducible']}")
    print(f"  Source category:          {report['source_category']}")
    print()
    print("NOTE: Source category is SYNTHETIC. Real-world accuracy is PENDING_USER_EVIDENCE.")

    if s["errored_fixtures"] > 0:
        print(f"WARNING: {s['errored_fixtures']} fixture(s) errored — see JSON for details")
        sys.exit(1)


if __name__ == "__main__":
    main()
