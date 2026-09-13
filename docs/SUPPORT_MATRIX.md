# VEYRONIX Vendor & Parser Support Matrix

This matrix documents the network vendors, operating system syntaxes, file formats, and security extensions supported by VEYRONIX, including parser coverage definitions and file ingestion limits.

---

## 1. Network Vendor Support Matrix

| Vendor / Platform | Syntaxes / Formats | Parser Implementation | Parse Status Capabilities | Evaluated Frameworks |
| :--- | :--- | :--- | :--- | :--- |
| **Cisco Systems**<br>(IOS, IOS-XE, Catalyst, ASA) | Flat command-block syntax, `version X.Y`, indented interface blocks, access-lists | `cisco_ios`<br>v4.0.0 | **PARSED**<br>**PARTIALLY_PARSED** | CIS Cisco IOS Benchmark v4.0<br>NIST SP 800-53 Rev 5<br>PCI-DSS v4.0 |
| **Juniper Networks**<br>(JunOS, JunOS-EX) | `set ...` stanza format & hierarchical curly-bracket `{ ... }` syntax | `junos`<br>v3.2.0 | **PARSED**<br>**PARTIALLY_PARSED** | CIS Juniper JunOS Benchmark<br>NIST SP 800-53 |
| **Fortinet**<br>(FortiOS, FortiGate) | `config ... end` hierarchical blocks, `edit <n> ... next`, policy tables | `fortigate`<br>v2.5.0 | **PARSED**<br>**PARTIALLY_PARSED** | CIS FortiOS Benchmark<br>NIST SP 800-53 |
| **Palo Alto Networks**<br>(PAN-OS) | `set deviceconfig ...`, `set rulebase ...`, and structured XML export `<config>...</config>` | `paloalto`<br>v2.2.0 | **PARSED**<br>**PARTIALLY_PARSED** | CIS PAN-OS Benchmark<br>NIST SP 800-53 |
| **Arista Networks**<br>(EOS) | Structured CLI configuration format | `arista_eos`<br>v2.0.0 | **PARSED**<br>**PARTIALLY_PARSED** | CIS Network Devices<br>NIST SP 800-53 |
| **Generic / Unknown** | Any ASCII / UTF-8 plain-text configuration file | `generic`<br>v1.0.0 | **UNKNOWN** | Heuristic fallback; non-matching lines marked UNKNOWN |

---

## 2. Special Ingestion Formats

### 2.1 Compressed Archive Ingestion (`.zip`)
- **API Endpoint**: `POST /api/audit/archive`
- **Supported Archive**: Standard ZIP archives containing vendor configuration files.
- **Safety Limits**:
  - Max uncompressed archive size: **10 MB**
  - Max compression ratio: **100:1** (anti-zip-bomb enforcement)
  - Max archive members: **100 files**
  - Path traversal protection: Files containing `..` or absolute paths are strictly rejected.
  - Symlink protection: Symlinks and device nodes are skipped.
- **Output**: Detailed batch summary with per-member classification, individual posture scores, and extracted audit reports.

### 2.2 Bounded Email Header & MIME Inspection (`.eml` / RFC 5322)
- **API Endpoint**: `POST /api/email/inspect`
- **Scope**: Deterministic posture analysis of email headers and message structures.
- **Evaluated Checks**:
  - `EMAIL-AUTH-SPF-001`: SPF validation in Authentication-Results
  - `EMAIL-AUTH-DKIM-001`: DKIM signature presence and verification status
  - `EMAIL-AUTH-DMARC-001`: DMARC policy alignment check
  - `EMAIL-AUTH-REPLYTO-001`: Mismatch between `From:` domain and `Reply-To:` domain
  - `EMAIL-AUTH-RETURNPATH-001`: Mismatch between `From:` domain and `Return-Path:` bounce domain
  - `EMAIL-LOOKALIKE-001`: Punycode / IDN homograph attack detection in sender addresses
  - `EMAIL-ATTACHMENT-001`: High-risk executable or script attachment detection (`.exe`, `.bat`, `.vbs`, `.js`, `.scr`, `.ps1`)
- **Boundary Disclaimer**: Review-only analytical inspection. Not a live MTA or email gateway filter.

---

## 3. Parser Coverage & Classification Definitions

Every audit report outputs structured coverage diagnostics:

```json
"coverage": {
  "format_detected": "cisco_ios",
  "vendor_detected": "cisco_ios",
  "parser_id": "cisco_ios",
  "parser_version": "4.0.0",
  "control_pack_version": "2.0.0",
  "parse_status": "PARSED",
  "total_lines": 142,
  "parsed_lines": 139,
  "skipped_lines": 3,
  "coverage_ratio": 0.978
}
```

### Parse Status Definitions
- **`PARSED`**: The configuration syntax was fully recognized by the vendor parser. All relevant security stanzas were extracted.
- **`PARTIALLY_PARSED`**: Core configuration blocks were understood, but unsupported proprietary syntax extensions were encountered and skipped safely.
- **`UNKNOWN`**: The format could not be reliably attributed to a known vendor parser. The system fails closed and records `UNKNOWN` findings rather than hallucinating rules.
- **`SKIPPED`**: Binary, non-text, or unparseable files were ignored safely during archive traversal.
- **`FAILED`**: File exceeded safety bounds (e.g. NUL bytes, malformed UTF-8, or decompression ratio violation).

---

## 4. File Size & Ingestion Limits

| Parameter | Limit | Failure Mode |
| :--- | :--- | :--- |
| **Max Single File Size** | 5 MiB (5,242,880 bytes) | Rejected with HTTP 413 Payload Too Large |
| **Max Archive File Size** | 10 MiB (10,485,760 bytes) | Rejected with HTTP 413 Payload Too Large |
| **Max Archive Member Count** | 100 members | Processing halts with HTTP 400 Bad Request |
| **Character Encoding** | UTF-8 / ASCII strict | Files with NUL bytes (`\x00`) rejected with HTTP 400 |
| **Archive Decompression Ratio** | 100x max | Prevents zip bombs; rejected with HTTP 400 |
