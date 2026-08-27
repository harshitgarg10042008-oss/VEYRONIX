# Phase 2 — Core SDK Architecture and Guarded LLM Integration

## Status

Phase 2 introduces the public Python SDK contracts and a provider-agnostic LLM gateway. Parser plugins, the full deterministic compliance engine, database persistence, and the web application remain later-phase work.

## Public modules

| Module | Responsibility |
|---|---|
| `configsentinel.models` | Typed domain objects for requests, results, findings, controls, evidence, remediation previews, and LLM explanations |
| `configsentinel.security` | Conservative secret redaction and fail-closed private-key checks |
| `configsentinel.client` | Stable SDK facade, plugin/control registration boundaries, and deterministic fixture engine |
| `configsentinel.llm` | Provider protocol, OpenAI-compatible adapter, structured explanation schema, input bounds, and output validation |

## Safety contract

The LLM gateway is an assistant, not the compliance authority. A `PASS` or `FAIL` finding must already contain deterministic evidence. The LLM receives a redacted and bounded context, treats configuration text as untrusted data, returns a strict JSON object, and never executes commands. The gateway fails closed on unavailable providers, invalid JSON, unexpected fields, invalid confidence, excessive output, or unsafe status values.

The provider is configured at runtime through `CONFIGSENTINEL_LLM_ENDPOINT`, `CONFIGSENTINEL_LLM_API_KEY_ENV`, `CONFIGSENTINEL_LLM_MODEL`, and `CONFIGSENTINEL_LLM_ENABLED`. The repository does not contain API keys. The actual model must be selected only after checking the current provider catalog and the team’s privacy/cost requirements.

## Example usage

```python
from configsentinel import ConfigSentinelClient, FixtureAuditEngine

client = ConfigSentinelClient(engine=FixtureAuditEngine())
result = client.audit_text(
    "line vty 0 4\\n transport input telnet\\n",
    vendor="cisco_ios",
)

for finding in result.findings:
    print(finding.control_id, finding.status.value, finding.evidence)
```

## Phase 2 limitations

The fixture engine is a contract demonstrator, not the final auditor. It recognizes one intentionally narrow Telnet fixture and returns `UNKNOWN` for unimplemented analysis. This is deliberate: later parser and policy phases must add capabilities without changing the SDK safety semantics.

## Validation expectations

Run:

```bash
python -m pytest
PYTHONPATH=src python examples/phase2_sdk_demo.py
```

The tests cover redaction, hash preservation, evidence requirements, explicit unknown status, guarded explanation output, unexpected-field rejection, and deterministic behavior when the LLM is disabled.
