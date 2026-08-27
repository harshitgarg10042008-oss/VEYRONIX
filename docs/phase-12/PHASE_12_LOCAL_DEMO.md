# Phase 12 — Offline-First Local Hackathon Demonstration

**Status:** Complete

**Product:** ConfigSentinel AI

**Team:** VEYRONIX

**Purpose:** Reliable local demonstration for SIH Problem Statement 26155

## Demonstration posture

The judged demonstration is intentionally local and offline-first. It does not require cloud deployment, a hosted API, a database, live network devices, external LLM access, or internet connectivity. The deterministic parser, control engine, reporting layer, and preview-only remediation workflow provide the authoritative demo path.

## One-command demo

From the repository root:

```powershell
$env:PYTHONPATH="src"
python examples/local_demo.py --output .\demo-output
```

The runner clears and recreates the output directory, executes Cisco IOS, Junos, and generic-firewall scenarios, validates bounded inputs, produces Markdown and JSON reports, creates safe remediation previews or explicit unavailable previews, and writes `demo-manifest.json`.

Expected console output includes:

```text
CONFIGSENTINEL OFFLINE DEMO
network_calls=0 llm_enabled=False
```

The exact latency values are machine-dependent and must not be presented as a universal performance claim. The demo manifest records the scenario, vendor, audit ID, finding count, failure count, unknown count, and local duration.

## Presenter flow

First explain that the system separates deterministic security authority from optional language-model assistance. Then run the Cisco scenario and show the Telnet finding, exact evidence span, severity, framework mapping, and remediation preview. Next open the JSON or Markdown report to show reconciliation and provenance. Finally explain that the Junos and firewall scenarios demonstrate multi-vendor parsing and explicit uncertainty; unknown or unsupported syntax is never silently treated as compliant.

If the environment has an installation issue, run the same command from the repository virtual environment with `PYTHONPATH=src`. If a judge asks about cloud deployment, state clearly that the current submission is an offline local prototype and show the documented future deployment prerequisites rather than claiming an unavailable hosted service.

## Safety checks

The runner sets `network_calls=0` and `llm_enabled=False`. It never opens a device connection and never executes generated remediation. Unsupported remediation catalogs produce a review-required preview instead of aborting the complete multi-vendor demonstration. Secret-like values in fixtures are redacted placeholders.

## Validation gate

```text
python -m pytest
python -m compileall -q src tests examples
PYTHONPATH=src python examples/local_demo.py --output /tmp/configsentinel-demo
```

The current validated suite contains **40 passing tests** before the local-demo-specific test additions. The demo itself must be run three consecutive times from a clean output directory before the live presentation. Record the final terminal output and keep a local backup of the repository before the event.

## Scope boundary

This phase optimizes demo reliability, not production deployment. Database persistence, authenticated multi-user access, live device collection, automatic remediation, and hosted monitoring remain outside the local demo and must not be implied by the presentation.
