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

## Ticketing export adapters

The `ticket-export` command converts an evidence-backed JSON report into a review artifact for a generic consumer, Jira-compatible create payload, or GitHub-compatible issue payload. It includes only failed and unknown findings, control IDs, statuses, severities, and safe titles; raw configurations and secret-like fields are not forwarded. The adapter writes locally and never calls a ticketing service or submits an issue.

```bash
configsentinel ticket-export reports/edge.json --adapter jira --out reports/edge-jira.json
configsentinel ticket-export reports/edge.json --adapter github --out reports/edge-github.json
configsentinel ticket-export reports/edge.json --format markdown --out reports/edge-ticket.md
```

## Topology and inventory import

The `inventory-import` command accepts bounded local JSON or CSV inventory files and produces a deterministic topology graph with node metadata, validated links, and a source SHA-256 hash. It performs import only: ConfigSentinel AI does not discover devices, connect to management interfaces, or infer unprovided links.

```bash
configsentinel inventory-import inventory.json --out reports/topology.json
configsentinel inventory-import inventory.csv --out reports/topology.json
```

## Scalable batch-worker architecture

Independent local jobs can use `run_bounded()` from `configsentinel.workers` to execute with a bounded pool of up to 16 workers and a configurable job limit. Results are returned in input order even when completion order differs, and worker exceptions become explicit per-job errors instead of being silently discarded. The worker layer performs no remote dispatch and does not alter the deterministic verdict engine.

## Formal verification fixtures

The `verify-report` command checks report invariants: audit metadata must be present, statuses must be known, every `FAIL` must carry evidence, and raw configuration fields are prohibited from findings. The built-in `verification-benchmark` command executes positive and negative fixtures covering these safety rules and returns a failing exit status if an expected invariant changes.

```bash
configsentinel verification-benchmark --out reports/verification.json
configsentinel verify-report reports/edge.json --out reports/edge-verification.json
```

## Deployment hardening and supply-chain artifacts

Release checks can generate a SHA-256 manifest for tracked source and configuration artifacts, then verify it before packaging or local demonstration. The verifier rejects path traversal and reports missing or changed files. GitHub Actions runs the backend tests, Python compilation, and manifest generation on pushes and pull requests with read-only repository permissions.

## Risk prioritization and asset criticality

The `risk-prioritize` command ranks failed and review-required findings using deterministic severity, status, confidence, and an operator-supplied asset criticality level. The score is a review aid only; it never changes the underlying compliance verdict, promotes an unknown result to pass, or authorizes remediation.

```bash
configsentinel risk-prioritize reports/edge.json --asset-criticality critical --out reports/edge-risk.json
```

## Time-bound exception management

Exceptions are local review records tied to a finding, owner, justification, and future ISO-8601 expiry. A new record is pending until an approver confirms it; expired records cannot be approved. Exceptions are never used to convert a deterministic failure into a pass and are marked with `verdict_impact: none`.

## Expanded compliance framework mappings

The framework registry now recognizes aliases and metadata for NIST CSF 2.0, PCI DSS 4.0.1, ISO/IEC 27001:2022, the HIPAA Security Rule, and AICPA SOC 2 Trust Services Criteria, in addition to CIS and NIST SP 800-53. These are informative cross-framework references only; the registry does not claim certification or replace an independent assessor, QSA, auditor, or legal review.

## Interactive topology and blast-radius analysis

The `topology-analyze` command consumes an imported topology graph, links operator-supplied finding IDs to assets, calculates a bounded graph neighborhood, and can render a self-contained HTML explorer. The result is a review aid: it does not infer traffic flows or exploitability, perform discovery, or apply remediation.

## Guided SIH demonstration and audit comparison

The `demo-mode` command renders a self-contained, step-by-step HTML artifact for presenting an operator-provided report: inspect posture, review findings, compare results, and explain the safety boundary. `audit-compare` produces a deterministic control-status delta between two serialized reports and does not claim causality.

## Content-addressed incremental audit cache

The `cache-audit` command stores serialized deterministic reports under a SHA-256 content key derived from the redacted configuration, vendor selection, framework selection, and rule-pack version. Repeating an unchanged audit produces a cache hit; changing any of those inputs produces a new entry. Cache writes are local, bounded, integrity-checked, and never contain the original unredacted input.

## SIEM and structured event exports

The `siem-export` command writes failed and review-required findings as local JSON Lines, CEF, or LEEF events. Events contain audit metadata, control identifiers, status, severity, confidence, and evidence counts, while excluding raw evidence excerpts and passing findings. Export is artifact generation only; no SIEM endpoint is contacted.

## Encrypted backup and restore

The optional `backup` package extra enables authenticated encrypted backups for JSON artifacts. A versioned envelope uses Fernet authenticated encryption with a PBKDF2-HMAC-SHA256-derived key and a random salt. Passphrases are read from an environment variable rather than placed directly in shell history; wrong or short passphrases fail closed.

## SBOM and reproducible release metadata

The `release-artifacts` command generates an SPDX-style software bill of materials and a deterministic release metadata document from `pyproject.toml`. The metadata records the project version, declared Python requirement, source declaration hash, and an optional release-manifest digest. `SOURCE_DATE_EPOCH` can be set by a release pipeline; it defaults to zero for stable local output.

```bash
configsentinel release-artifacts . --manifest release-manifest.json --sbom-out release-sbom.json --metadata-out release-metadata.json
```

```bash
python -m pip install -e ".[backup]"
export CONFIGSENTINEL_BACKUP_PASSPHRASE='use-a-secret-manager-or-protected-shell'
configsentinel backup-create reports/edge.json --out backups/edge.csb
configsentinel backup-restore backups/edge.csb --out restored/edge.json
```

```bash
configsentinel siem-export reports/edge.json --format jsonl --out reports/edge.siem.jsonl
configsentinel siem-export reports/edge.json --format cef --out reports/edge.cef
configsentinel siem-export reports/edge.json --format leef --out reports/edge.leef
```

```bash
configsentinel cache-audit ./configs/edge.conf --vendor cisco_ios --cache-dir .configsentinel/cache --json-out reports/edge-cached.json
```

```bash
configsentinel audit-compare reports/before.json reports/after.json --out reports/comparison.json
configsentinel demo-mode reports/before.json --after reports/after.json --out reports/sih-demo.html
```

```bash
configsentinel topology-analyze reports/topology.json --finding-asset finding-123=edge-1 --depth 2 --out reports/blast-radius.json --html-out reports/topology-review.html
```

```bash
configsentinel audit ./configs/edge.conf --vendor cisco_ios --framework csf --framework pci-dss --json-out reports/edge-frameworks.json
```

```bash
configsentinel exception-add ex-001 finding-123 --owner alice --justification "approved maintenance window" --expires-at 2099-01-01T00:00:00+00:00 --file .configsentinel/exceptions.json
configsentinel exception-approve ex-001 --approver bob --file .configsentinel/exceptions.json
configsentinel exception-list --file .configsentinel/exceptions.json --out reports/exceptions.json
```

```bash
configsentinel release-manifest . --out release-manifest.json
configsentinel verify-manifest . release-manifest.json
```


## SentinelProof S1: Configuration Attestation Tokens

ConfigSentinel AI can create a portable, HMAC-SHA256-signed configuration attestation from a serialized redacted audit report. The token binds the report version, audit identity, vendor, parser and rule-pack versions, selected frameworks, input SHA-256, finding identifiers, evidence digest, reconciliation digest, and reviewer status without embedding raw configuration evidence.

Create an attestation locally with:

```bash
PYTHONPATH=src:. python -m configsentinel.cli attestation-create report.json --key-file local-signing-key.bin --out attestation.json
```

Replay and verify the token against the exact report with:

```bash
PYTHONPATH=src:. python -m configsentinel.cli attestation-verify report.json attestation.json --key-file local-signing-key.bin
```

The default status is `REVIEW_REQUIRED`. Verification fails when the key, report, serialized claim, or signature changes. This is an application-level assurance artifact inspired by provenance and attestation standards; it is not hardware attestation and does not authorize device changes. Keep signing keys outside source control and use a separate protected key for each environment.


## SentinelProof S2: Evidence Coverage and Uncertainty Budget

The uncertainty budget converts a serialized audit report into review metadata without recalculating or changing compliance statuses. It reports evidence coverage, framework-mapping coverage, mean finding confidence, unknown blocks, per-finding categories, and explicit gaps such as missing evidence or unverified mappings.

```bash
PYTHONPATH=src:. python -m configsentinel.cli uncertainty-budget reports/edge.json --out reports/edge.uncertainty.json
```

The budget distinguishes `VERIFIED`, `INFERRED`, `UNKNOWN`, and `CONTRADICTED` review categories. It records only evidence presence, redaction state, line-range validity, and digests; it does not copy raw configuration excerpts into the artifact. `verdict_boundary.verdicts_changed` is always `false`: the original deterministic `PASS`, `FAIL`, `UNKNOWN`, and `REVIEW_REQUIRED` statuses remain authoritative.


## SentinelProof S3: Semantic Mutation Lab

The Semantic Mutation Lab exercises supported parsers and controls with bounded deterministic mutations. Preservation mutations—trailing whitespace, ignored comments, and final-newline normalization—must keep the control-status map unchanged. Targeted mutations add an insecure management directive and must produce the expected deterministic failure for the affected control.

```bash
PYTHONPATH=src:. python -m configsentinel.cli mutation-lab ./configs/edge.cfg --vendor cisco_ios --max-mutations 5 --out reports/edge.mutation.json
```

The artifact contains source hashes, changed control IDs, expected and observed statuses, and pass/fail mutation results, but never raw configuration text. The lab requires an explicit vendor, enforces a mutation count limit, uses no network access, and does not change the source audit verdict or apply a configuration.


## SentinelProof S4: Evidence-First Assurance Twin

The Assurance Twin projects an imported inventory into a bounded local graph that separates imported facts from derived neighborhoods. Operators can link findings to assets and run a counterfactual add/remove-link analysis without discovering devices, inferring traffic flow, estimating exploitability, or applying remediation.

```bash
PYTHONPATH=src:. python -m configsentinel.cli assurance-twin topology.json --report reports/edge.json --finding-asset finding_id=edge --add-link edge=db --depth 2 --out reports/edge.twin.json --html-out reports/edge.twin.html
```

Graph nodes and links are labeled as `imported`; operator finding links and graph neighborhoods are labeled with their provenance. Missing links are not treated as proof of isolation, and unlinked findings remain visible. The HTML explorer is self-contained and loads no external resources.


## SentinelProof S5: Resource-Level Least-Privilege Intent Compiler

The intent compiler translates an operator-declared resource policy into vendor-neutral checks over deterministic audit findings. It supports subjects, named resources, approved intermediary assets, protocols, and bounded requirements such as secure SSH management, no Telnet, and no plain HTTP.

```bash
PYTHONPATH=src:. python -m configsentinel.cli intent-compile intent.json --report reports/edge.json --topology topology.json --out reports/edge.intent.json
```

The compiler reports `SATISFIED`, `VIOLATED`, or `REVIEW_REQUIRED` based on supplied evidence. Missing report evidence remains unknown. It emits no vendor configuration, no executable commands, and no live-network requests; it does not prove reachability or change the underlying compliance verdicts.


## SentinelProof S6: Governed Unknown-Syntax Apprenticeship

Unknown syntax can now be packaged as a governed parser contract after an approved mapping exists. The contract stores bounded redacted positive examples, counterexamples, syntax fingerprints, mapping provenance, and deterministic contract-test results.

```bash
PYTHONPATH=src:. python -m configsentinel.cli apprenticeship-contract approved-mapping.json --positive "transport input telnet" --counterexample "transport input ssh" --out reports/telnet.contract.json
PYTHONPATH=src:. python -m configsentinel.cli apprenticeship-test reports/telnet.contract.json --out reports/telnet.contract-test.json
```

A passing contract reports `READY_FOR_HUMAN_REVIEW`; it never promotes a parser mapping, changes the parser registry, or alters compliance verdicts automatically. Examples are redacted before storage, secret-like values are not retained, and contract testing remains local and network-free.


## SentinelProof S7: Cross-Vendor Semantic Differential Testing

The differential tester compares explicit vendor variants of the same intended configuration at the canonical semantic-field and deterministic-control levels. It surfaces semantic and control disagreements with per-variant parser versions and input hashes rather than choosing one vendor parser as correct.

```bash
PYTHONPATH=src:. python -m configsentinel.cli differential-test --variant cisco_ios=configs/edge.cfg --variant junos=configs/edge.set --field management_ssh_enabled --field management_ssh_version --case-id secure-management --out reports/secure-management.differential.json
```

Only selected normalized fields and their associated controls are compared. Results contain no raw configuration, perform no network access, never select an authoritative vendor, and do not alter compliance verdicts.


## SentinelProof S8: Compliance Time Machine

The Compliance Time Machine replays a bounded JSON collection of operator-supplied report snapshots, orders them by ISO-8601 observation time, and records control-status transitions without interpolating missing periods.

```bash
PYTHONPATH=src:. python -m configsentinel.cli time-machine reports/snapshots.json --control-id NET-MGMT-SSH-001 --out reports/ssh.timeline.json --html-out reports/ssh.timeline.html
```

Each snapshot retains its audit ID, vendor, parser version, input hash, status, severity, confidence, and evidence count. The artifact never includes raw evidence excerpts. It is a historical replay aid only: it performs no live lookup, does not assert that a snapshot reflects current device state, and cannot change verdicts.


## SentinelProof S9: Proof-Carrying Remediation

Remediation previews can now be accompanied by proof metadata that binds each safe deterministic step to the source audit, redacted input hash, evidence-span hashes, command hash, rollback hash, preconditions, and a required post-change deterministic re-audit.

```bash
PYTHONPATH=src:. python -m configsentinel.cli remediation-proof reports/edge.json --out reports/edge.remediation-proof.json
PYTHONPATH=src:. python -m configsentinel.cli remediation-proof-verify reports/edge.remediation-proof.json reports/edge.json --out reports/edge.remediation-proof.verify.json
```

Proof artifacts intentionally contain no executable command text or raw evidence excerpts. They are review metadata only: independent operator approval is required, commands are marked non-executable, no device connection occurs, and verification does not claim that a post-change state exists until a new audit supplies evidence.


## SentinelProof S10: Privacy-Preserving Audit Exchange

The privacy-preserving exchange capsule enables a reviewer or approved downstream process to receive audit claims without receiving the original configuration or raw evidence. It contains only bounded audit metadata, non-PASS finding summaries, evidence-span hashes, optional risk summaries, and a source-report digest. Passing findings, raw excerpts, command text, and network-submission behavior are excluded by construction.

Create a local capsule with optional HMAC integrity:

```bash
PYTHONPATH=src:. python -m configsentinel.cli audit-exchange reports/edge.json --recipient security-review --purpose exception-review --key-file local-exchange-key.bin --out reports/edge.exchange.json
```

Verify the capsule locally before any operator-approved handoff:

```bash
PYTHONPATH=src:. python -m configsentinel.cli audit-exchange-verify reports/edge.exchange.json --key-file local-exchange-key.bin --out reports/edge.exchange.verify.json
```

The exchange artifact is a privacy boundary, not an authorization boundary. Verification checks the capsule hash and optional HMAC only; it does not approve findings, submit data, contact devices, or change deterministic verdicts. Keep exchange keys outside source control, use a separate key per environment, and treat `submission=not_performed` as a required operator handoff boundary.

## SentinelProof safety invariant

All SentinelProof artifacts are offline, deterministic review aids. They may summarize or bind evidence, but they cannot execute device changes, establish reachability, or turn an unknown result into a pass. AI-assisted explanations remain non-authoritative and are never used as the source of a compliance verdict.


## SentinelProof S11: Reviewer Disagreement Analytics

Reviewer disagreement analytics makes human review measurable without pretending that consensus is compliance truth. Operators provide a bounded JSON file of reviewer IDs and structured decisions (`ACCEPT`, `CHALLENGE`, or `UNABLE`) for finding IDs. The analyzer reports per-finding vote counts, explicit `CONTESTED` ties, consensus strength, pairwise agreement, evidence-quality signals, and hash-only reviewer-note references.

```bash
PYTHONPATH=src:. python -m configsentinel.cli reviewer-analytics reports/edge.json reviews/edge.reviewers.json --out reports/edge.reviewer-analytics.json
```

A tied vote never selects a winner: it is emitted as `CONTESTED` and counted as unresolved. The original deterministic audit status remains the authoritative verdict, including when reviewers agree. Reviewer notes and raw configuration evidence are not copied into the analytics artifact, no network request is made, and the command cannot approve, reject, or remediate a finding.


## SentinelProof S12: Assurance Drift and Freshness Decay

Freshness assessment prevents an old clean result from being mistaken for current assurance. The command requires an explicit `as-of` timestamp and uses the report’s `observed_at` value or an explicit override. A bounded TTL produces `FRESH`, `STALE`, or `EXPIRED` states with a transparent linear decay fraction. An optional baseline report is compared separately for vendor, parser, rule-pack, input-hash, and finding-attribute drift.

```bash
PYTHONPATH=src:. python -m configsentinel.cli assurance-freshness reports/edge.json --observed-at 2026-08-27T00:00:00Z --as-of 2026-08-27T12:00:00Z --ttl-hours 24 --baseline reports/edge.baseline-report.json --out reports/edge.freshness.json
```

Freshness and drift are assurance signals, not compliance verdicts. `AGING`, `EXPIRED`, and `DRIFTED` require a new review or deterministic re-audit, while `verdicts_changed` remains `false`. No live device query occurs, no raw configuration or evidence is copied, and the tool rejects ambiguous timestamps and future-dated evaluations.
