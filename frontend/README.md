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


## Live audit data and exports

The dashboard uses `VITE_API_BASE_URL` to reach the local FastAPI adapter. Start `PYTHONPATH=src python examples/api_server.py` from the repository root, then run `VITE_API_BASE_URL=http://127.0.0.1:8000 pnpm dev` inside `frontend/`. The page loads `/api/health` and posts redacted demo configuration to `/api/audit`; the returned report is rendered without replacing deterministic statuses with LLM text.

Operators can open the Filters control to narrow findings by severity, status, and framework mapping. Export PDF downloads the current metrics and filtered findings, including audit ID, input hash, evidence excerpts, observed/expected state, mappings, confidence, and the non-execution safety note.


## Uploads, local history, and trends

Use **Upload config** to submit a local `.cfg`, `.conf`, `.config`, or `.txt` file up to 2 MB. The browser validates the extension and size, then sends the file contents to the configured API for the same redaction and deterministic evaluation path as the bundled fixture.

Each successful report is saved in browser storage as a versioned snapshot, limited to the latest 20 audits. The **Finding trend** panel draws failures and unknown results from those snapshots. Hover or focus a point for its audit metadata, and select it to reload that historical report into the evidence panel. Clearing site data removes the local history.


## Managing audit history

Open **History** to review snapshots saved in this browser. Select a row to load its findings, use the download control to export that report as a standalone PDF, or use the close control to delete it locally. The chart points use the same snapshots; hover/focus reveals exact counts and click/Enter/Space loads the selected audit.

Uploads use content heuristics before the API call. Junos markers select `junos`, firewall markers select `firewall_generic`, and remaining supported configuration text selects `cisco_ios`. This is a parser hint, not an LLM decision; the backend still owns normalization and verdicts.
