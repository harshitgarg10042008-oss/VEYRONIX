# ConfigSentinel AI — VEYRONIX

**ConfigSentinel AI** is an evidence-grounded, vendor-neutral network configuration compliance SDK and CLI. It parses supported configurations, normalizes security-relevant settings, evaluates deterministic controls, and generates review-only remediation previews. An optional LLM copilot can explain findings and help classify unfamiliar syntax, but it never replaces deterministic compliance evidence and never executes commands.

> **Safety boundary:** The current release performs local analysis and writes non-executable remediation previews. It does not connect to network devices, apply changes, or execute generated commands.

## Current release

| Item | Value |
|---|---|
| Package | `configsentinel-sdk` |
| Version | `0.3.0` |
| Python | 3.11 or newer |
| Supported parsers | Cisco IOS/IOS XE, Juniper Junos, conservative generic-firewall subset |
| Initial controls | Secure SSH, Telnet prohibition, AAA, logging, NTP, secure SNMP, plain HTTP management |
| LLM mode | Disabled by default; provider configuration is opt-in |
| License | Proprietary hackathon prototype |

## Installation

### From a local checkout

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

On macOS or Linux:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
```

### From a built wheel

```bash
python -m pip install dist/configsentinel_sdk-0.3.0-py3-none-any.whl
```

## Quickstart: Python SDK

```python
from configsentinel import ConfigSentinelClient, DeterministicComplianceEngine

config = """version 17.9
line vty 0 4
 transport input telnet
"""

client = ConfigSentinelClient(engine=DeterministicComplianceEngine())
result = client.audit_text(config, vendor="cisco_ios")

print(result.audit_id, result.failed_count)
for finding in result.findings:
    print(finding.control_id, finding.status.value, finding.severity.value)
```

The engine uses explicit statuses. `UNKNOWN` means the parser or control lacks enough evidence; it is not treated as compliant.

## Quickstart: CLI

```powershell
$env:PYTHONPATH="src"
python -m configsentinel audit edge.conf --vendor cisco_ios --dry-run --approve --remediation-out remediation.txt
```

The installed command is equivalent:

```powershell
configsentinel audit edge.conf --vendor cisco_ios --dry-run --approve --remediation-out remediation.txt
```

The `--approve` flag acknowledges operator review but is intentionally insufficient by itself. It must be paired with `--dry-run`, and the current release still only generates a preview artifact.

## Optional LLM copilot

The copilot is disabled unless explicitly enabled. Configure an OpenAI-compatible endpoint without placing secrets in source control:

```powershell
$env:CONFIGSENTINEL_LLM_ENABLED="true"
$env:CONFIGSENTINEL_LLM_ENDPOINT="https://provider.example/v1"
$env:CONFIGSENTINEL_LLM_MODEL="your-approved-model"
$env:OPENAI_API_KEY="your-key-from-a-secret-manager"
```

The gateway redacts common secrets, bounds input and output, requests strict JSON, validates the returned schema, and fails closed on provider errors or malformed output. Do not enable external inference for sensitive configurations unless your organization has approved the data flow.

## Supported input and safety behavior

The ingestion boundary accepts `.cfg`, `.conf`, `.config`, `.txt`, and `.log` files. It rejects empty input, invalid UTF-8, NUL bytes, symbolic links, path traversal names, oversized files, and oversized lines. Original input is hashed with SHA-256; downstream analysis is intended to use the redacted form.

Generated remediation is deterministic and vendor-aware for a limited Cisco IOS and Junos template set. Every bundle includes source-audit metadata, input hash, rollback notes, and an explicit non-execution warning. Unsupported vendors and unsupported controls remain manual-review cases.

## Development and validation

```bash
python -m pytest
python -m compileall -q src tests examples
PYTHONPATH=src python examples/phase2_sdk_demo.py
```

The repository tests cover typed contracts, parser behavior, compliance evaluation, secure ingestion, redaction, remediation generation, CLI safeguards, and disabled-LLM fallback.

## Documentation

Detailed phase documentation is available in [`docs/`](docs/). Start with the [Phase 1 foundation](docs/phase-1/PHASE_1_FOUNDATION.md), [SDK and LLM architecture](docs/phase-2/PHASE_2_SDK_LLM.md), [parser and compliance engine](docs/phase-3/PHASE_3_PARSERS_COMPLIANCE.md), [secure ingestion](docs/phase-4/PHASE_4_SECURE_INGESTION.md), and [remediation CLI](docs/phase-5/PHASE_5_REMEDIATION_CLI.md). The [end-user guide](docs/USER_GUIDE.md) contains operational examples and troubleshooting.

## Project status

This is an alpha hackathon prototype. It is suitable for controlled demonstrations and local evaluation. Before production use, add organization-specific controls, independent parser validation, authenticated multi-user access, secrets-management integration, formal change approval, and a separately reviewed device-application service.


## Local operator workbench

The React/Tailwind operator workbench is included under [`frontend/`](frontend/). It is a local review surface for audit posture, findings, evidence line references, framework mappings, unknown-syntax review, and preview-only remediation. It intentionally does not connect to live devices or execute generated commands.

```bash
cd frontend
pnpm install --frozen-lockfile
pnpm dev
```

For the final local delivery gate, run:

```bash
python -m pytest
python -m compileall -q src tests examples
python -m build
cd frontend && pnpm install --frozen-lockfile && pnpm run check && pnpm run build
PYTHONPATH=src python examples/local_demo.py
```

See [`docs/PHASE_13_20_COMPLETION.md`](docs/PHASE_13_20_COMPLETION.md) for the re-baselined Phase 13–20 completion record and the explicit boundary between shipped local-first behavior and future enterprise integrations.


## Live dashboard wiring

The dashboard now consumes the deterministic report serializer through the optional local API adapter. Install the API extra and run the service in one terminal:

```bash
python -m pip install -e ".[api]"
PYTHONPATH=src python examples/api_server.py
```

Run the frontend in a second terminal:

```bash
cd frontend
pnpm install --frozen-lockfile
VITE_API_BASE_URL=http://127.0.0.1:8000 pnpm dev
```

The dashboard loads the same evidence-backed report shape used by JSON and Markdown exports. Its filters narrow the visible set by severity, status, and framework mapping; the PDF action exports the current posture metrics plus the currently visible findings, evidence excerpts, input hash, mappings, and safety note. If the API is unavailable, the interface stays explicit about the offline state instead of displaying fabricated audit data.


## Configuration uploads and audit history

The dashboard accepts `.cfg`, `.conf`, `.config`, and `.txt` configuration files up to 2 MB. Files are read in the browser and submitted only to the configured local API; no device connection is created by upload. The backend remains responsible for redaction and deterministic evaluation.

Completed reports are stored in browser `localStorage` under a versioned ConfigSentinel AI key, capped at the most recent 20 snapshots. History stays on the operator’s machine and is not uploaded or synchronized. The Finding trend panel derives its failure and unknown series exclusively from those saved report summaries. Selecting a point loads that historical snapshot back into the evidence workbench.


## History management and vendor detection

The dashboard’s History control opens a local-only management panel. Operators can load a saved snapshot, export an individual PDF, or delete it from browser storage. The panel retains the latest 20 reports and never sends history to a remote service.

Configuration uploads now infer the parser from content before submission: Junos-style `set system`, `set interfaces`, or Juniper markers select `junos`; common firewall markers select `firewall_generic`; other supported text defaults to `cisco_ios`. The selected vendor is sent to the same deterministic API endpoint and remains visible in the audit metadata.

The Finding trend chart exposes failures and unknown counts per saved snapshot. Hovering or focusing a point shows the filename, timestamp, counts, and an explicit load instruction; clicking or pressing Enter/Space loads that historical report into the workbench.


## Multi-source ingestion

ConfigSentinel AI supports auditing a single configuration file, a directory tree, a ZIP archive, or a tar/tar.gz archive through the `batch` CLI command. Only supported configuration extensions are admitted; symbolic links, archive traversal paths, empty or invalid files, oversized files, and aggregate source sets beyond the safety limits are rejected or skipped fail-closed. The SDK exposes the same capability through `ConfigSentinelClient.audit_sources()`.

```bash
configsentinel batch ./configs --vendor cisco_ios --framework cis-network --json-out reports/batch.json
configsentinel batch ./incoming/configs.zip --vendor junos
```

The current batch command preserves the existing explicit-vendor contract. Automatic vendor confidence and operator confirmation are delivered by the dedicated vendor-detection upgrade later in this roadmap.


## Expanded vendor coverage

The deterministic parser registry now includes **Arista EOS** and **Linux nftables** in addition to Cisco IOS, Junos, and the generic firewall adapter. Arista reuses the IOS-style normalized management controls with EOS-specific detection markers, while nftables maps explicit SSH, Telnet, HTTP, and logging rules into the canonical evidence model. Unsupported control families remain explicitly unknown or not applicable rather than being inferred.

```bash
configsentinel audit ./configs/edge.conf --vendor arista_eos --framework cis-network
configsentinel batch ./configs/firewall-rules --vendor linux_nftables --json-out reports/nftables.json
```


## Confidence-aware vendor detection

Automatic vendor selection now returns ranked deterministic candidates with parser confidence, a minimum threshold, and a minimum separation margin. Configurations that are unknown or too close between candidates fail closed instead of silently selecting a parser. The local API exposes the same inspection contract at `POST /api/detect`, allowing the dashboard or an operator workflow to show the selected parser and confidence before audit submission.

```bash
curl -s http://127.0.0.1:8000/api/detect \
  -H 'Content-Type: application/json' \
  -d '{"config_text":"management api http-commands\ninterface Ethernet1\n"}'
```


## Custom policy authoring

Organizations can extend the built-in control pack with a validated local JSON policy file. Each rule declares a control ID, intent, severity, bounded regular expression, `require` or `forbid` mode, vendor applicability, framework mappings, and a review-only remediation message. The loader limits pack size, control count, field lengths, and regex size; matching is performed only against redacted configuration text, and PASS/FAIL findings retain source-line evidence.

```bash
configsentinel audit ./configs/edge.conf --vendor cisco_ios --policy examples/custom_policy.json --json-out reports/custom.json
```

Custom packs are additive and do not replace the built-in deterministic controls. The engine never executes policy content, and a missing required pattern remains `UNKNOWN` rather than being promoted to a passing verdict without evidence.


## GitOps security gate

Pull requests that change supported configuration files can run a deterministic local gate before merge. The gate compares a base and head revision, audits only changed configuration paths, preserves evidence line numbers, emits JSON for CI artifacts, and returns a non-zero exit code when a critical or high-severity deterministic failure is introduced. It never posts comments, executes remediation, or modifies the repository.

```bash
scripts/gitops_gate.sh <BASE_SHA> HEAD auto
# or:
PYTHONPATH=src python -m configsentinel.cli gitops-check --repo . --base <BASE_SHA> --head HEAD --vendor auto --json-out gitops-report.json
```

The repository includes `.github/workflows/gitops-gate.yml` for pull-request execution. Ambiguous or unsupported vendor detection fails closed, so an operator must provide an explicit vendor in a local run when a change cannot be classified safely.


## Approved baselines and drift detection

Operators can save an approved baseline containing only metadata, the redacted input hash, parser identity, and control-status map. Raw configuration is never written into the baseline. A later drift check compares the current hash, vendor, and normalized control statuses, reports added/removed/changed controls, and returns a non-zero exit code when drift is detected.

```bash
configsentinel baseline-save ./configs/edge.conf --vendor cisco_ios --label production-approved --out baselines/edge.json
configsentinel drift-check ./configs/edge.conf --vendor cisco_ios --baseline baselines/edge.json --json-out reports/edge-drift.json
```


## Remediation diffs and rollback previews

The remediation workflow now exposes structured evidence-to-command diffs in addition to the existing script-style preview. Each change links redacted source evidence to a vendor-specific proposed command and includes rollback notes. Diff output is explicitly marked non-executable, carries the source audit hash, and is generated only for deterministic templates; unsupported vendors or controls remain manual-review cases.

```bash
configsentinel audit ./configs/edge.conf --vendor cisco_ios --diff-out reports/remediation.diff
```


## Role-based governance and approvals

The local governance layer provides operator, reviewer, and administrator roles with an append-only JSONL event ledger. Operators can request review; only a different reviewer or administrator can approve or reject; terminal decisions cannot be changed. This gives remediation previews an auditable approval boundary without pretending to provide cloud identity management or device execution.

```bash
configsentinel approval-request rem_123 --actor alice --ledger .configsentinel/events.jsonl
configsentinel approval-decide rem_123 --actor bob --role reviewer --approve --ledger .configsentinel/events.jsonl
```


## Tamper-evident trail and signed evidence

ConfigSentinel AI can append audit metadata to a local JSONL hash chain. Each event links to the previous event and can be verified for sequence, chain, and content integrity. Operators can also export a report as an HMAC-SHA256 signed envelope using a locally protected key file. The signed payload contains report metadata, findings, evidence, and hashes, but never the original unredacted configuration; HMAC provides integrity and shared-key authenticity, not public-key non-repudiation.

```bash
configsentinel audit ./configs/edge.conf --vendor cisco_ios --trail .configsentinel/audit.jsonl
configsentinel audit ./configs/edge.conf --vendor cisco_ios --signed-out reports/edge.signed.json --signing-key-file .configsentinel/signing.key
```


## Executive and enterprise reporting

The `enterprise-report` command creates a concise executive posture artifact from the same deterministic audit result used by the detailed report. It includes posture classification, failed and unknown controls, evaluated coverage, severity distribution, top evidence-backed risks, and the input hash. Markdown is intended for review meetings; JSON is intended for downstream systems. Neither format authorizes remediation or device changes.

```bash
configsentinel enterprise-report ./configs/edge.conf --vendor cisco_ios --format markdown --out reports/executive.md
configsentinel enterprise-report ./configs/edge.conf --vendor cisco_ios --format json --out reports/executive.json
```


## Multidimensional historical analytics

Saved serialized audit reports can be analyzed locally across vendor, severity, status, control, and ISO-date dimensions. The analytics output contains deterministic counters and a timeline suitable for dashboards or downstream reporting; it does not infer risk beyond the statuses and findings already present in each evidence-backed report.

```bash
configsentinel history-analyze reports/history.json --out reports/history-analytics.json
```


## Evidence graph

The `evidence-graph` command projects a JSON audit report into a deterministic graph of audit, finding, control, framework, and redacted evidence nodes. Edges show which audit produced a finding, which control was evaluated, which framework requirements are mapped, and which source spans support the result. This artifact is designed for explainability and review; it does not infer relationships from untrusted external data.

```bash
configsentinel evidence-graph reports/edge.json --out reports/edge-evidence-graph.json
```


## Expanded sensitive-data scanning

The `sensitive-scan` command detects additional secret classes before storage, export, or model use, including AWS access keys, private-key blocks, JWTs, bearer and basic credentials, SNMP communities, database connection strings, and cloud secret assignments. Results contain only line numbers and redacted excerpts, plus the original input hash; raw values are never printed by the scanner.

```bash
configsentinel sensitive-scan ./configs/edge.conf --format markdown --out reports/edge-sensitive.md
configsentinel sensitive-scan ./configs/edge.conf --format json --out reports/edge-sensitive.json
```


## Offline explanation provider

`LLMCopilot.offline()` provides a no-network explanation seam for local demos and restricted environments. It consumes only the deterministic finding fields and redacted evidence excerpts, returns schema-validated descriptive text, and always preserves `REVIEW_REQUIRED` safety semantics. It cannot create, change, or authorize a compliance verdict, and the existing network provider remains opt-in through explicit configuration.

## REST, OpenAPI, and local webhook contracts

The local FastAPI adapter exposes the existing `/api/audit` and `/api/detect` routes plus stable `/api/v1/audit` and `/api/v1/health` aliases. The generated OpenAPI document is available at `/openapi.json` when the local server is running, and explicitly describes the deterministic, non-mutating audit surface.

Audit completion events can be written to a local JSON Lines queue with `configsentinel webhook-enqueue REPORT.json --queue .configsentinel/webhooks.jsonl`. Each event contains only audit metadata, summary data, finding identifiers, and a SHA-256 digest of the canonical payload. The queue never performs outbound delivery; downstream ticketing or automation must consume it explicitly.
