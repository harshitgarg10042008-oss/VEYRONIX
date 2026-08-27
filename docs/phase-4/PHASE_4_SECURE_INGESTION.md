# Phase 4 — Secure Ingestion, Validation, Quarantine, and Redaction

## Objective

Phase 4 creates the security boundary before configuration data reaches parsers, compliance rules, or LLM-assisted workflows. The ingestion service validates bytes and filenames, rejects unsafe content, hashes the original input, redacts common secrets, and optionally stores the original in a private quarantine directory.

## Public API

```python
from configsentinel import ConfigIngestionService, ConfigSentinelClient, DeterministicComplianceEngine

client = ConfigSentinelClient(engine=DeterministicComplianceEngine())
result = client.audit_file("edge.conf", vendor="cisco_ios")
```

The service also exposes `ingest_bytes` and `ingest_text` for API adapters. The `IngestedConfig` result contains a generated ingestion ID, original basename, generated safe name, SHA-256 hash, byte and line counts, redaction count, redacted text, and optional quarantine path.

## Validation rules

The default policy rejects empty content, content above 5 MiB, lines above 256 KiB, NUL bytes, invalid UTF-8, symbolic links, path components, and extensions outside `.cfg`, `.conf`, `.config`, `.txt`, and `.log`. The caller-provided filename is never used as a storage path. Quarantine filenames use a generated ID and are created with exclusive creation and restrictive permissions.

## Redaction rules

The Phase 4 boundary redacts common private-key blocks, enable/password/secret/community forms, username password forms, and token/API-key assignments. The input hash is computed from the original bytes so audit reproducibility does not depend on the redacted representation. The redacted text is the only form intended for parsers and future LLM calls.

This is a conservative baseline, not a guarantee that every secret format is detected. Later security hardening should add a dedicated secrets scanner and organization-specific patterns. A canary-secret test must remain part of CI.

## Safety guarantees

The service does not execute configuration content, does not follow instructions inside configuration text, does not trust client filenames, and refuses to delete quarantine files outside the configured quarantine directory. The MVP remains preview-only for remediation and has no live-device write path.

## Validation commands

```bash
python -m pytest
python -m compileall -q src tests examples
PYTHONPATH=src python examples/phase2_sdk_demo.py
```

Phase 4 acceptance requires the complete Phase 2–4 test suite to pass, including redaction, hash preservation, path traversal rejection, invalid encoding rejection, NUL rejection, size and line limits, symlink rejection, quarantine creation, and end-to-end SDK file auditing.
