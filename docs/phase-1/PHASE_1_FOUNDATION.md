# ConfigSentinel AI — Phase 1 Foundation

**Problem statement:** SIH 2026 — 26155  
**Phase:** 1 of 14 core MVP phases  
**Status:** Implementation started locally  
**Repository:** `harshitgarg10042008-oss/SIH-WINNERS`  
**GitHub policy:** Changes will be committed and pushed only after local validation and explicit completion of the Phase 1 gate.

## 1. Phase objective

Phase 1 establishes the trustworthy foundation for ConfigSentinel AI before application code is built. It converts the official problem statement into testable requirements, records authoritative standards and licensing boundaries, defines safe data handling, identifies threats, and fixes the project’s initial scope.

The central design decision is that **the LLM assists interpretation and explanation but does not independently decide compliance**. Compliance results must be produced from deterministic, reviewable rules operating on parsed and normalized configuration data.

## 2. Official requirement interpretation

The system will ingest heterogeneous network-device configurations, detect vendor/platform context, normalize vendor-specific syntax into a common security model, evaluate the result against approved compliance controls, explain findings with exact evidence, and provide a controlled workflow for unfamiliar syntax.

The first release will not claim universal vendor or firmware support. It will provide deep, tested support for three declared platform families and visibly label all unsupported or unparseable content as `UNKNOWN` or `REVIEW_REQUIRED`.

| Requirement | Phase 1 decision | Verification planned in later phase |
|---|---|---|
| Multi-vendor analysis | Support Cisco IOS/IOS XE, Juniper Junos, and one firewall platform selected after fixture validation | Parser and normalization tests |
| Vendor-neutral model | Use a versioned canonical schema inspired by OpenConfig concepts | Cross-vendor equivalence fixtures |
| Compliance analysis | Use versioned, declarative policy controls with evidence queries | Precision/recall and golden fixtures |
| Framework alignment | Start with CIS-aligned internal controls and curated mappings to NIST SP 800-53, DISA STIG, and ISO/IEC 27001 concepts | Crosswalk review and provenance checks |
| Unfamiliar syntax | Quarantine unknowns and route them to an expert review/learning queue | Learning-loop acceptance test |
| AI assistance | Use structured, bounded LLM tasks for interpretation, mapping suggestions, and explanation | Prompt-injection, leakage, and output-validation tests |
| Remediation | Preview-only in MVP; no live-device execution | Safety and authorization tests |
| Reproducibility | Store input hash, parser version, rule-pack version, prompt version, and model metadata | Clean-room repeatability test |

## 3. Standards and authoritative references

| Source | Use in ConfigSentinel AI | Required handling |
|---|---|---|
| [NIST Cybersecurity Framework 2.0][1] | Organize governance, identification, protection, detection, response, and recovery outcomes around audit reporting | Store source link, version, and mapping rationale |
| [NIST AI Risk Management Framework][2] | Govern, map, measure, and manage AI trustworthiness risks | Record model limitations, evaluation, oversight, and incident handling |
| [CIS Benchmarks][3] | Base secure configuration checks on permitted network-device benchmark material | Do not copy restricted benchmark text; store IDs, short approved summaries, provenance, and team-authored tests |
| [OpenConfig data models][4] | Guide vendor-neutral concepts and naming | Do not claim exhaustive coverage; preserve unsupported fields explicitly |
| [Batfish][5] | Optional topology, ACL, routing, and reachability validation | Isolate as an optional analysis adapter; do not make MVP correctness depend on it |
| [OWASP GenAI LLM Top 10 2026][6] | Threat model for prompt injection, output handling, data leakage, poisoning, denial of service, supply chain, plugins, agency, overreliance, and model theft | Add mitigations and test cases to the security phase |

## 4. Scope and non-goals

### In scope for MVP

The MVP will accept plain-text configuration files and optional normalized JSON/YAML through a local dashboard, REST API, CLI, and Python SDK. It will identify the declared vendor families, parse the supported subset, produce a canonical representation, run approximately 30–50 high-confidence controls, show exact source evidence, map findings to approved frameworks, produce audit reports, and queue unknown syntax for review.

### Explicit non-goals for MVP

The MVP will not perform unrestricted live-device writes, claim compliance certification, replace a qualified auditor, reproduce proprietary benchmark documents, silently infer compliance from unparsed text, expose raw credentials to an LLM, execute model-generated shell commands, or support every network vendor and firmware version.

## 5. Data provenance register

| Data or artifact | Planned source | Allowed use | Owner / evidence |
|---|---|---|---|
| Official problem statement | SIH official problem-statement portal | Requirements and presentation alignment | Team lead; URL [7] |
| Control identifiers and permitted summaries | CIS/NIST/DISA/ISO source material subject to terms | Versioned crosswalk and team-authored test logic | Cybersecurity lead; license review required |
| Vendor syntax examples | Team-authored fixtures and permitted public documentation | Parser development and regression testing | Parser lead; source URL and license per fixture |
| Secure configurations | Team-authored synthetic fixtures reviewed by cybersecurity lead | Positive tests and demonstration | QA lead; fixture manifest |
| Insecure configurations | Team-authored synthetic fixtures with non-production values | Negative tests and demonstration | QA lead; never use real credentials |
| Unknown/adversarial configurations | Team-authored test strings | Parser safety and LLM red-team testing | Security lead |
| Model prompts and outputs | Generated within the application | Evaluation and reproducibility | AI lead; redact secrets and minimize retention |
| Audit reports | Derived from user input | User-visible evidence and exports | Product owner; retention policy applies |

Every fixture must carry: `fixture_id`, platform, purpose, author, created date, source/provenance, license note, expected parser status, expected findings, and whether it is safe to send after redaction to an LLM.

## 6. Threat model

### Assets

The protected assets are raw configurations, credentials and keys embedded in configurations, normalized security data, audit reports, control-pack content, model prompts and outputs, user identities, reviewer approvals, plugin packages, and audit history.

### Trust boundaries

1. **User/browser to API:** uploaded files and questions are untrusted.
2. **API to ingestion/parser:** files may be malformed, adversarial, or intentionally prompt-injecting.
3. **Parser to canonical model:** parser output must be schema-validated and preserve unknown content.
4. **Application to retrieval/LLM:** only redacted, bounded, approved context may cross this boundary.
5. **LLM to application:** model output is untrusted data and must be validated before use.
6. **Application to remediation/export:** output must remain preview-only and require human approval.
7. **Plugin to core system:** plugin code is a supply-chain boundary and must have a restricted contract.

### Threat register

| ID | Threat | Impact | Required mitigation | Acceptance test |
|---|---|---|---|---|
| T-01 | Prompt injection inside configuration text | Incorrect analysis or disclosure | Delimit input as data; ignore embedded instructions; deterministic verdict | Malicious fixture cannot change control result |
| T-02 | Secret leakage to LLM or logs | Credential compromise | Redact passwords, keys, tokens, communities, and sensitive identifiers before model/log paths | Canary secrets absent from prompts/logs/reports |
| T-03 | Unsupported syntax treated as compliant | False assurance | Explicit `UNKNOWN`; coverage indicator; no PASS on parser failure | Unsupported fixture never returns PASS |
| T-04 | Insecure model output handling | Code or command injection | Strict JSON Schema, allowlisted fields, output sanitization, no shell execution | Injection strings remain inert text |
| T-05 | Excessive remediation agency | Network outage or lockout | Preview-only MVP; human approval; no live credentials | Static test proves no device-write path |
| T-06 | Malicious or vulnerable plugin | Code execution or data theft | Signed/approved plugins, isolated process/container, capability manifest | Untrusted plugin cannot access secrets or network |
| T-07 | Oversized or malformed file | Denial of service | Size, line, encoding, decompression, timeout, and memory limits | Resource-abuse fixture is rejected safely |
| T-08 | Path traversal or unsafe filename | Local file overwrite | Generate server-side IDs; sanitize names; quarantine uploads | Traversal test cannot escape storage root |
| T-09 | Cross-project report access | Confidentiality breach | RBAC and object-level authorization | User A cannot retrieve User B’s audit |
| T-10 | Retrieval poisoning | Wrong control mapping | Approved corpus, provenance, checksums, allowlist, reviewer workflow | Poisoned document excluded from retrieval |
| T-11 | Model/provider outage | Audit unavailable | Deterministic fallback and cached demo fixtures | Audit completes without LLM |
| T-12 | Supply-chain compromise | Integrity loss | Lockfiles, SAST, dependency/container scans, SBOM | CI blocks unapproved critical dependency findings |
| T-13 | Irreproducible result | Audit dispute | Store hashes and version metadata | Same input/version produces same deterministic result |
| T-14 | Data retention beyond purpose | Privacy exposure | Retention setting, deletion operation, minimal logs | Deletion test removes configured artifacts |

## 7. Privacy and data-handling policy

The default policy is **local-first and data-minimizing**. Raw configurations remain in a controlled quarantine store. Parsing should prefer the redacted copy. LLM calls receive only the minimum context required for the narrow task. Sensitive spans are replaced with typed placeholders such as `<REDACTED_PASSWORD>` while preserving enough structure for analysis.

Logs must contain audit IDs, event type, status, timing, and version metadata, but not raw configuration, secrets, or full prompts. Reports should show masked evidence by default. Retention must be configurable, and deletion must remove original objects, redacted objects, derived prompts, and generated reports according to the selected policy.

## 8. Initial control-pack policy

The first control pack will contain 30–50 controls, each with a unique ID, title, intent, applicability, severity, deterministic evidence query, remediation template, references, version, and test fixtures. High-value initial controls include secure SSH, disabled Telnet, AAA, password protection, management ACLs, secure logging, NTP, SNMP security, cryptographic settings, unused services, interface hygiene, firewall rule hygiene, routing authentication, timeouts, and secure backup handling.

The team must use control identifiers and permitted summaries instead of copying complete restricted benchmark text. Any control without a source, applicability definition, evidence query, or fixture is not production-ready.

## 9. Phase 1 exit checklist

- [ ] Official SIH requirement matrix completed.
- [ ] Three MVP platform families selected or selection decision recorded.
- [ ] Initial control scope and framework crosswalk defined.
- [ ] Standards and source register reviewed.
- [ ] Dataset and fixture provenance register created.
- [ ] Licensing risks assigned to an owner.
- [ ] Threat model reviewed by cybersecurity lead.
- [ ] Secret categories and redaction boundary approved.
- [ ] Retention and deletion policy approved.
- [ ] Unknown/unsupported semantics approved.
- [ ] LLM trust boundary and fallback behavior approved.
- [ ] No-live-write MVP boundary approved.
- [ ] Phase 2 backlog created for repository, CI, schemas, and skeleton.

## Phase 1 acceptance statement

Phase 1 passes only when the team can explain what the product will and will not claim, identify every major trust boundary, show where secrets are removed, identify how unsupported syntax is represented, and point from every major requirement to a later implementation and test phase.

## References

[1]: [NIST Cybersecurity Framework 2.0](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf)

[2]: [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)

[3]: [Center for Internet Security — CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)

[4]: [OpenConfig — Data Models](https://www.openconfig.net/projects/models/)

[5]: [Batfish — Network Configuration Analysis](https://batfish.org/)

[6]: [OWASP GenAI Security Project — LLM Top 10 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)

[7]: [Smart India Hackathon — SIH 2026 Problem Statements](https://www.sih.gov.in/sih2026PS)

## Local implementation note

This artifact is intentionally documentation-first. It establishes the contracts and safety boundaries before application code is introduced in Phase 2. No GitHub push is performed by this document.
