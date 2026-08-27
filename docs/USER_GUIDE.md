# ConfigSentinel AI End-User Guide

## What the product does

ConfigSentinel AI analyzes network configuration files locally, identifies supported security-control states, presents evidence-backed findings, and creates review-only remediation previews. The product is designed for security engineers, network administrators, auditors, and hackathon evaluators who need a clear path from raw configuration to auditable findings.

The current release is an alpha prototype. It does not connect to devices or apply changes. `UNKNOWN` and `REVIEW_REQUIRED` are first-class outcomes and must be reviewed rather than treated as secure.

## Install from source

Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

macOS/Linux:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
```

## Run an audit

Create a file such as `edge.conf`, then run:

```powershell
configsentinel audit edge.conf --vendor cisco_ios
```

Use `--vendor auto` only when the configuration contains enough vendor-specific evidence for reliable detection. For a preview artifact:

```powershell
configsentinel audit edge.conf --vendor cisco_ios --dry-run --approve --remediation-out remediation.txt
```

The output reports the audit ID, selected parser, finding count, failures, unknowns, and each control status. The remediation file is a text preview. Review it independently and follow your organization’s change-management process.

## Python integration

```python
from configsentinel import ConfigSentinelClient, DeterministicComplianceEngine

client = ConfigSentinelClient(engine=DeterministicComplianceEngine())
result = client.audit_file("edge.conf", vendor="cisco_ios")

for finding in result.findings:
    print({
        "control": finding.control_id,
        "status": finding.status.value,
        "severity": finding.severity.value,
        "confidence": finding.confidence,
        "evidence": [span.excerpt for span in finding.evidence],
    })
```

For an API or upload adapter, use `client.ingest(filename, content)` first. It validates and redacts input while retaining the original SHA-256 hash for reproducibility.

## Interpreting statuses

| Status | Meaning | Required action |
|---|---|---|
| `PASS` | The deterministic control found evidence of the expected secure state | Retain evidence and continue review |
| `FAIL` | The deterministic control found evidence of a violation | Review remediation and change impact |
| `UNKNOWN` | Evidence was insufficient or syntax was unsupported | Obtain more evidence; do not mark compliant |
| `REVIEW_REQUIRED` | Human interpretation is needed | Review manually and record decision |
| `NOT_APPLICABLE` | The control does not apply to the platform | Confirm applicability policy |

## LLM copilot configuration

The copilot is optional and disabled by default. If enabled, use an organization-approved OpenAI-compatible endpoint and a secret manager for credentials:

```powershell
$env:CONFIGSENTINEL_LLM_ENABLED="true"
$env:CONFIGSENTINEL_LLM_ENDPOINT="https://provider.example/v1"
$env:CONFIGSENTINEL_LLM_MODEL="approved-model"
$env:OPENAI_API_KEY="read-from-your-secret-manager"
```

The LLM receives redacted, bounded context and returns a strict structured response. It may explain a deterministic finding or identify evidence gaps. It must not be used as an independent compliance authority, and model output must not be executed.

## Troubleshooting

If installation fails, confirm that Python 3.11 or newer is active and run `python --version`. If the CLI command is not found after editable installation, activate the virtual environment or use `python -m configsentinel`.

If vendor detection fails, specify `--vendor cisco_ios`, `--vendor junos`, or `--vendor firewall_generic` explicitly. If many controls show `UNKNOWN`, the parser may not support the device syntax or the fixture may not contain enough evidence. This is expected fail-closed behavior.

If remediation is unavailable, check that the vendor is Cisco IOS or Junos and that the failed control has a deterministic template. Generic firewall remediation is manual-review-only in the current release.

If the LLM fails, run the deterministic audit without the copilot. Provider failure, malformed JSON, excessive output, missing credentials, and unsafe output are all designed to fail closed.

## Security reporting

Do not open a public issue containing real configuration files, credentials, private keys, tokens, or customer data. Use the project’s private security-reporting process. Review [`SECURITY.md`](../SECURITY.md) before sharing a report.
