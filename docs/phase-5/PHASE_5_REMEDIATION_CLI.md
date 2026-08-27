# Phase 5 — Remediation Preview Generation and CLI Runner

## Objective

Phase 5 adds deterministic, vendor-aware remediation preview generation and a command-line audit runner. The design is intentionally **preview-first**: the CLI can read a configuration and write a remediation artifact, but it has no device connection, no live apply operation, and no command execution path.

## Safety model

Only `FAIL` findings can produce remediation steps. Templates are static and mapped by vendor and control ID. Unknown vendors and missing templates fail closed or produce explicit manual-review warnings. Every bundle contains its audit ID, source input hash, timestamp, vendor, rollback notes, and a prominent preview-only warning.

A command validator blocks dangerous tokens such as reload, erase, shell, bash, curl, wget, Python, and configuration replacement. Generated steps are represented as non-executable `RemediationPreview` objects and require human approval. `--approve` by itself is rejected; it must be paired with `--dry-run`, and even that combination only writes a review artifact.

## CLI usage

From the repository root:

```bash
PYTHONPATH=src python -m configsentinel.cli audit edge.conf --vendor cisco_ios --dry-run --approve --remediation-out remediation.txt
```

The command prints audit findings and writes a text preview. It does not connect to a router, switch, firewall, shell, or remote service. For the installed package, the equivalent command is:

```bash
configsentinel audit edge.conf --vendor cisco_ios --dry-run --approve --remediation-out remediation.txt
```

## Initial deterministic templates

| Vendor | Supported preview examples |
|---|---|
| Cisco IOS/IOS XE | SSHv2, Telnet removal, plain HTTP removal, AAA enablement |
| Juniper Junos | SSHv2, Telnet removal, plain HTTP removal |
| Generic firewall | No automatic template; manual review is required |

The templates are intentionally small and auditable. Adding a new template requires a secure/insecure fixture, rollback notes, dangerous-token validation, and a test proving the artifact remains non-executable.

## Validation

```bash
python -m pytest
python -m compileall -q src tests examples
```

The Phase 5 tests cover generated bundle metadata, preview-only wording, unsupported-vendor rejection, dangerous-template blocking, CLI approval requirements, and successful dry-run artifact generation.
