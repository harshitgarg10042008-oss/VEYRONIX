# VEYRONIX Security Boundaries & System Limits

This document explicitly defines the operational boundaries, non-goals, and security commitments of the VEYRONIX platform.

---

## 1. System Scope & Core Mission

VEYRONIX is designed as an **evidence-grounded, deterministic compliance verification platform** for enterprise and defense network configurations.

### Core Capabilities
- **Static Configuration Auditing**: Evaluates offline, export, or staged network device configurations against CIS Benchmarks, NIST SP 800-53, and PCI-DSS controls.
- **Evidence-First Trust Model**: Every finding is backed by an exact line number, source excerpt, and deterministic cryptographic evidence hash (`evidence_hash`).
- **Explainable & Verifiable**: Posture scores are calculated using transparent formulas without non-deterministic black-box LLM hallucinations.
- **Multi-Vendor Normalization**: Parses Cisco, Juniper, Fortinet, Palo Alto, and Arista configs into a canonical object model.
- **Human-in-the-Loop Governance**: Provides dual-control review workflows, time-machine diffing, and cryptographic attestation ledgers.

---

## 2. Explicit Non-Goals & System Boundaries

To maintain high trust, stability, and zero unintentional operational disruption, VEYRONIX strictly enforces the following boundaries:

| Boundary | System Stance | Rationale |
| :--- | :--- | :--- |
| **No Auto-Push / Live Execution** | **Prohibited** | VEYRONIX does NOT automatically push configuration changes to live network switches or firewalls. Remediation scripts are generated for administrator preview and testing in change management workflows. |
| **No Inline Traffic Filtering** | **Non-Goal** | VEYRONIX is not an inline packet inspection engine, Intrusion Prevention System (IPS), or Web Application Firewall (WAF). It audits configurations, not packet streams. |
| **No Live Mail Transfer Agent (MTA)** | **Non-Goal** | Email security inspection is strictly analytical and review-only (evaluating SPF, DKIM, DMARC, and header spoofing). VEYRONIX is not an active email relay, gateway, or anti-spam filter. |
| **No Mandatory Device Connections** | **Default Disabled** | `device_connections: false` in `/api/health`. VEYRONIX audits files safely without requiring SSH/SNMP credentials to production backbones. |
| **No External Cloud Dependency** | **100% Offline** | The platform runs fully in air-gapped environments. No telemetry, LLM API calls, or external network reachouts occur during deterministic audits. |

---

## 3. Secret Redaction & Sensitive Data Protection

Configurations often contain sensitive data such as password hashes, pre-shared keys (PSKs), SNMP community strings, and private certificates.

### Protections in Place
1. **Automated Secret Masking**: The canonical normalization engine automatically masks `secret 5/8/9`, `password 7`, `preshared-key`, and SNMP community strings before displaying in UI or exporting reports.
2. **Evidence Minimization**: Evidence excerpts in findings only include the specific configuration line necessary to substantiate the pass/fail determination.
3. **No Credential Persistence**: Plaintext credentials submitted in configs are never stored in separate credential caches.
4. **Local Audit Logs**: Audit logs record action types, timestamps, and sha256 digests—not raw secrets.

---

## 4. Operational Safety Guarantees

1. **Deterministic Reproducibility**: Given the same configuration file and control pack version, VEYRONIX will always compute the identical findings, evidence hashes, and posture score.
2. **Fail-Closed Architecture**: If a configuration line cannot be parsed or vendor attribution is ambiguous, the system marks the finding as `UNKNOWN` rather than guessing or silently passing.
3. **Container Isolation**: Docker Compose deployment enforces non-root users, read-only root filesystems, dropped capabilities, and strict RAM limits.
