# VEYRONIX — ConfigSentinel AI
## SIH 2026 Submission Package

**Problem Statement:** 26155  
**Category:** Software  
**Team:** VEYRONIX  
**Repository:** https://github.com/harshitgarg10042008-oss/VEYRONIX

## 1. Executive summary

ConfigSentinel AI is an evidence-grounded, vendor-neutral network configuration compliance SDK and CLI. It securely ingests configuration files, detects supported vendors, parses heterogeneous syntax into a canonical security model, evaluates deterministic hardening controls, links findings to exact configuration evidence, and generates human-reviewed remediation previews. An optional LLM copilot assists with explanation and unfamiliar-syntax review, but it does not replace deterministic compliance logic and cannot connect to or modify a live device.

The solution addresses the central challenge in Problem Statement 26155: multi-vendor network environments make configuration auditing inconsistent, slow, and difficult to scale. ConfigSentinel AI separates **security authority** from **language-model assistance**. Deterministic parsers and controls decide the audit status; the LLM explains or assists with review under a bounded, schema-validated, fail-closed gateway.

## 2. Problem-to-solution mapping

| SIH requirement | ConfigSentinel AI response | Evidence in prototype |
|---|---|---|
| Heterogeneous vendor configurations | Plugin-based parsers and canonical model | Cisco IOS/IOS XE, Juniper Junos, generic-firewall subset |
| Vendor-neutral analysis | Canonical security-relevant configuration model | `canonical.py`, `parsers.py` |
| Compliance evaluation | Versioned deterministic control pack | Seven initial network-hardening controls |
| Explainable findings | Exact line-level evidence and expected state | `EvidenceSpan` and finding metadata |
| Dynamic adaptation | Explicit unknown/review workflow with guarded LLM assistance | `UNKNOWN` and `REVIEW_REQUIRED` semantics |
| Remediation guidance | Vendor-aware deterministic preview templates | Cisco IOS and Junos preview generation |
| Security and privacy | Validation, hashing, quarantine, redaction, and no live execution | `ingestion.py`, `security.py`, `remediation.py` |
| Reusable integration | Python SDK and CLI entry points | `ConfigSentinelClient`, `configsentinel` |

## 3. Current implementation status

The current release is **configsentinel-sdk 0.3.0**. It includes 24 passing regression tests across typed contracts, redaction, parsers, controls, secure ingestion, remediation, CLI safeguards, and disabled-LLM fallback. The built wheel and source distribution have been installed and tested in an isolated Python 3.12 environment.

The supported MVP scope is intentionally explicit: Cisco IOS/IOS XE, Juniper Junos, and a conservative generic-firewall subset; seven network-hardening controls; local file analysis; optional provider-agnostic LLM assistance; and non-executable remediation previews. Unsupported vendors, controls, and syntax are not silently treated as compliant.

## 4. Technical architecture

The system follows this pipeline:

> **Secure ingestion → vendor detection → parser plugin → canonical model → deterministic control engine → evidence-linked findings → optional guarded LLM assistance → remediation preview**

The ingestion layer enforces file-size and line-length limits, accepted extensions, UTF-8 validity, NUL-byte rejection, path safety, symbolic-link rejection, SHA-256 provenance, optional quarantine storage, and secret redaction. The parser layer produces a vendor-neutral representation while preserving evidence spans. The compliance engine evaluates controls using explicit applicability and status semantics. The LLM gateway receives only bounded, redacted context, requests structured output, validates the response, and fails closed on errors. The remediation layer creates review-only artifacts with rollback notes and explicit no-execution warnings.

## 5. Security and responsible-use statement

ConfigSentinel AI is designed for authorized defensive security and compliance use. It must be used only on configurations that the operator is authorized to inspect. The current release does not connect to routers, switches, firewalls, cloud control planes, or remote execution services. Generated remediation is a preview artifact and must undergo independent operator review and organizational change control before any manual application.

The design responds to risks identified by NIST Cybersecurity Framework 2.0 and the OWASP GenAI LLM Top 10. In particular, it limits sensitive-information exposure, prevents excessive agency, validates model output, avoids treating unknown content as safe, and keeps the deterministic control engine authoritative. [1] [2]

## 6. Three-minute judging demo

| Time | Action | Judge takeaway |
|---:|---|---|
| 0:00–0:20 | Introduce the fragmentation problem and the product promise | Clear problem and value proposition |
| 0:20–0:45 | Upload a Cisco configuration containing `transport input telnet` | Secure ingestion and provenance |
| 0:45–1:15 | Run the audit and show `NET-MGMT-TELNET-001: FAIL / CRITICAL` | Deterministic verdict with exact evidence |
| 1:15–1:45 | Show parser output, control mapping, and expected secure state | Explainability and standards readiness |
| 1:45–2:15 | Generate a preview containing `transport input ssh` | Actionable remediation without unsafe execution |
| 2:15–2:40 | Show the safety banner and preview metadata | Human approval and no-device-connection boundary |
| 2:40–3:00 | Submit unfamiliar syntax and show `REVIEW_REQUIRED` | Honest uncertainty and dynamic adaptation |

If the live environment fails, use the local CLI and the validated terminal output as a deterministic fallback. Do not claim that the fallback demonstrates capabilities not present in the repository.

## 7. Suggested judge questions and answers

**Why use an LLM at all?** The LLM is useful for interpreting unfamiliar syntax, mapping language to a controlled canonical schema, and explaining a deterministic finding. It is not the authority for pass/fail decisions.

**What happens when the system does not understand a command?** It returns `UNKNOWN` or `REVIEW_REQUIRED`, preserves the evidence, and asks for controlled review. It never silently marks the configuration compliant.

**Can the generated commands be executed automatically?** No. The current release has no device connection or command-execution path. It creates non-executable, review-only previews with rollback notes.

**How does it scale to more vendors?** Each parser is a plugin behind a shared canonical contract. New parsers and controls must ship with fixtures, applicability rules, evidence tests, and regression coverage.

**How do you protect secrets?** The ingestion and LLM boundary redacts common credentials, tokens, keys, and private-key blocks; original input is hashed for provenance while downstream analysis uses the redacted form.

**What is not implemented yet?** Live device collection, automatic change application, broad vendor coverage, production identity and access management, and organization-specific control packs remain future work and are stated as such.

## 8. Submission claims discipline

Use the following language in the submission: “Implemented,” “validated locally,” and “demonstrated” only for features present in the repository. Use “planned,” “next,” or “roadmap” for future capabilities. Do not present pilot targets as measured results. The only current numerical validation claim is the verified **24 passing tests** in the local regression suite.

## 9. Team presentation roles

| Role | Responsibility |
|---|---|
| Problem lead | Explain the SIH requirement and operational pain |
| Architecture lead | Walk through ingestion, parsing, canonical model, and controls |
| Security/AI lead | Explain the LLM trust boundary, redaction, uncertainty, and no-execution policy |
| Demo lead | Run the three-minute audit and remediation preview workflow |
| Impact lead | Explain adoption path, SDK extensibility, and future roadmap |

## 10. Final pre-submission checklist

- [ ] Confirm the official SIH problem-statement title and number are written as **26155**.
- [ ] Confirm the team name is consistently written as **VEYRONIX**.
- [ ] Confirm repository links point to `harshitgarg10042008-oss/VEYRONIX`.
- [ ] Run `python -m pytest` and record the actual result.
- [ ] Run `python -m compileall -q src tests examples`.
- [ ] Verify the CLI works from the installed wheel without `PYTHONPATH`.
- [ ] Verify the remediation output is preview-only and contains no live connection behavior.
- [ ] Remove real secrets and private customer configurations from all demo files and screenshots.
- [ ] Rehearse the demo three times from a clean environment.
- [ ] Prepare an offline fallback using the known-safe local fixture.
- [ ] Keep unsupported features clearly labeled as roadmap items.
- [ ] Export the slide deck using the presentation viewer’s PPTX or PDF download option.

## References

[1]: https://www.nist.gov/cyberframework — NIST, “Cybersecurity Framework 2.0.”

[2]: https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/ — OWASP GenAI Security Project, “OWASP GenAI LLM Top 10 2026.”

[3]: https://www.sih.gov.in/sih2026PS — Smart India Hackathon, “SIH 2026 Problem Statements.”
