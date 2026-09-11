# VEYRONIX SIH Demo Script

**Duration:** 5-7 minutes  
**Mode:** local-only, deterministic, no external credentials

## 1. Open the workbench (30 seconds)

1. Run `start-local.bat` or start the API and frontend from `START_HERE.md`.
2. Open `http://localhost:3000`.
3. Point out `LOCAL API ONLINE`, `NO LIVE DEVICE`, and the deterministic engine indicator.
4. Explain: "The rule engine owns the verdict. AI, when enabled, can explain but cannot change PASS, FAIL, or UNKNOWN."

**Judge should observe:** a posture score, audit actions, assurance journey, and explicit local safety boundary in the first screen.

## 2. Run the network audit (90 seconds)

1. Click `Run local audit`.
2. Open the failed Telnet finding.
3. Show its control ID, severity, observed state, expected state, framework mapping, and exact source evidence line.
4. Open `Review queue` and select an UNKNOWN finding.
5. Explain: "UNKNOWN is a safe outcome. The system refuses to infer compliance when syntax or evidence is insufficient."

**Technical point:** vendor-specific input is parsed into a normalized model and evaluated by deterministic controls; uncertainty is preserved.

## 3. Show remediation and approval (60 seconds)

1. Open `Remediation`.
2. Show the proposed preview and its source/evidence context.
3. Point out `NON-EXECUTABLE` and `SAFE PREVIEW`.
4. Click `Request review`.
5. Show the pending approval state.

**Safety boundary:** no device connection or command execution exists in this release. Approval records a human decision; it does not apply a change.

## 4. Show the evidence trail (45 seconds)

1. Return to `Overview` and open local history.
2. Show audit ID, input SHA-256, vendor, timestamp, and finding counts.
3. Open the assurance chain route.
4. Export the evidence PDF.

**SIH alignment:** the decision is replayable and auditable rather than an opaque AI recommendation.

## 5. Show Website Security (60 seconds)

1. Open `Website Security`.
2. Point out `LOCAL DEMO / SAFE INSPECTION MODE` and the illustrative posture result visible before a scan.
3. Show transport, headers, cookies, redirects, findings, evidence, remediation, and limitations.
4. Enter an authorized target URL, confirm authorization, and click `Scan website` only for an approved target.

**Safety boundary:** inspection is passive and bounded. It does not brute-force, exploit, modify, or prove absence of vulnerabilities.

## 6. Close with honest scope (30 seconds)

State: "VEYRONIX securely ingests supported multi-vendor configurations, redacts sensitive data, normalizes syntax, evaluates deterministic controls, preserves evidence and unknowns, maps findings to frameworks, and produces review-only remediation previews. Production identity, live device mutation, durable fleet scheduling, and real-world accuracy validation remain future work."
