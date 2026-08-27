# VEYRONIX local operator workbench

This directory contains the React/Tailwind frontend for the VEYRONIX SIH 26155 demonstration. It is an offline-first operator surface for audit posture, findings, source evidence, framework mappings, unknown-syntax review, and remediation previews.

## Local run

```bash
cd frontend
pnpm install --frozen-lockfile
pnpm dev
```

Open the local Vite URL printed by the command. For a production validation build:

```bash
pnpm run check
pnpm run build
```

## Safety boundary

The frontend is intentionally presentation and review oriented. It does not connect to live network devices, apply configuration, or promote an LLM suggestion into a compliance verdict. The Python SDK and CLI remain authoritative for ingestion, redaction, parsing, normalization, deterministic evaluation, evidence, and safe remediation previews.

## Design contract

The interface follows the Operator’s Blueprint direction: a warm mineral canvas, graphite navigation rail, disciplined signal-orange attention states, mono evidence labels, ruled technical surfaces, source line references, and visible `OFFLINE MODE` / `LLM DISABLED` language. VEYRONIX is the only product name shown in the shipped UI.

## Asset policy

The small brand mark is stored at `client/public/veyronix-mark.png`. No remote image dependency is required for the primary workbench surface, which keeps the local demo reliable in an offline environment.
