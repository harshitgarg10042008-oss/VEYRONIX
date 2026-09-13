"""Bounded email authentication and header inspection for VEYRONIX.

IMPORTANT BOUNDARY DEFINITION:
This module provides review-only email authentication posture and header analysis.
It explicitly does NOT perform:
- Live mail-flow interception
- Attachment detonation or dynamic sandbox execution
- Mailbox message deletion or quarantine
- Click-time URL rewriting or blocking
- Complete autonomous phishing prevention

Full email security in production requires mail-transfer agent (MTA) integration,
reputation intelligence feeds, dynamic malware sandboxing, and SOC telemetry.
"""

from __future__ import annotations

import email
from email import policy
from email.utils import parseaddr
import re
from typing import Any
import urllib.parse


DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".iso", ".img", ".wsf", ".cpl", ".pif"
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".work", ".click"
}


def _extract_domain(address: str) -> str:
    if not address or "@" not in address:
        return ""
    return address.split("@")[-1].strip().lower()


def _is_punycode_or_homoglyph(domain: str) -> bool:
    if "xn--" in domain.lower():
        return True
    try:
        domain.encode("ascii")
        return False
    except UnicodeEncodeError:
        return True


def inspect_raw_email(raw_email_text: str) -> dict[str, Any]:
    """Inspect raw email headers and structure deterministically."""
    if not raw_email_text or not raw_email_text.strip():
        raise ValueError("Raw email content cannot be empty")

    msg = email.message_from_string(raw_email_text, policy=policy.default)

    from_header = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")
    subject = msg.get("Subject", "")
    auth_results = msg.get("Authentication-Results", "")
    received_spf = msg.get("Received-SPF", "")
    dkim_sig = msg.get("DKIM-Signature", "")

    _, from_addr = parseaddr(from_header)
    _, reply_to_addr = parseaddr(reply_to)
    _, return_path_addr = parseaddr(return_path)

    from_domain = _extract_domain(from_addr)
    reply_to_domain = _extract_domain(reply_to_addr)
    return_path_domain = _extract_domain(return_path_addr)

    findings: list[dict[str, Any]] = []

    # 1. From vs Reply-To Mismatch
    if reply_to_addr and reply_to_domain != from_domain:
        findings.append({
            "check_id": "EMAIL-AUTH-REPLYTO-001",
            "title": "From and Reply-To domain mismatch",
            "severity": "HIGH",
            "status": "FAIL",
            "evidence": {
                "header": "Reply-To",
                "observed": f"From: {from_addr}, Reply-To: {reply_to_addr}",
                "expected": f"Reply-To domain should match From domain ({from_domain})",
            },
            "rationale": "Replies to this message will be directed to an external domain distinct from the sender, a common technique in credential harvesting and business email compromise (BEC).",
            "remediation": "Verify whether cross-domain reply-to is authorized for this workflow.",
        })
    elif reply_to_addr:
        findings.append({
            "check_id": "EMAIL-AUTH-REPLYTO-001",
            "title": "From and Reply-To domain alignment",
            "severity": "INFO",
            "status": "PASS",
            "evidence": {
                "header": "Reply-To",
                "observed": f"From: {from_domain}, Reply-To: {reply_to_domain}",
                "expected": "Reply-To matches sender domain",
            },
            "rationale": "Reply-To matches the sender domain.",
            "remediation": "None required.",
        })

    # 2. From vs Return-Path (Envelope Sender) Mismatch
    if return_path_addr and return_path_domain != from_domain:
        findings.append({
            "check_id": "EMAIL-AUTH-ENVELOPE-001",
            "title": "Header From and Envelope Return-Path domain mismatch",
            "severity": "MEDIUM",
            "status": "WARN",
            "evidence": {
                "header": "Return-Path",
                "observed": f"From: {from_domain}, Return-Path: {return_path_domain}",
                "expected": f"Return-Path domain should align with From domain ({from_domain})",
            },
            "rationale": "The envelope sender does not align with the visible From address. Legitimate transactional services often do this, but unaligned envelope senders undermine SPF DMARC alignment.",
            "remediation": "Configure custom bounce/envelope domains with SPF alignment for sending infrastructure.",
        })
    elif return_path_addr:
        findings.append({
            "check_id": "EMAIL-AUTH-ENVELOPE-001",
            "title": "Header From and Envelope Return-Path alignment",
            "severity": "INFO",
            "status": "PASS",
            "evidence": {
                "header": "Return-Path",
                "observed": f"From: {from_domain}, Return-Path: {return_path_domain}",
                "expected": "Return-Path matches From domain",
            },
            "rationale": "Return-Path aligns with sender domain.",
            "remediation": "None required.",
        })

    # 3. SPF Posture
    spf_combined = f"{auth_results} {received_spf}".lower()
    if "spf=pass" in spf_combined or "pass" in received_spf.lower():
        findings.append({
            "check_id": "EMAIL-AUTH-SPF-001",
            "title": "Sender Policy Framework (SPF) validation",
            "severity": "INFO",
            "status": "PASS",
            "evidence": {
                "header": "Authentication-Results / Received-SPF",
                "observed": "spf=pass",
                "expected": "spf=pass",
            },
            "rationale": "Sending host is authorized by the sender domain's SPF policy.",
            "remediation": "Maintain authorized IP records in SPF TXT.",
        })
    elif "spf=fail" in spf_combined or "softfail" in spf_combined or "fail" in received_spf.lower():
        findings.append({
            "check_id": "EMAIL-AUTH-SPF-001",
            "title": "Sender Policy Framework (SPF) validation failed",
            "severity": "HIGH",
            "status": "FAIL",
            "evidence": {
                "header": "Authentication-Results / Received-SPF",
                "observed": "spf=fail or softfail",
                "expected": "spf=pass",
            },
            "rationale": "Sending MTA is not designated in the sending domain's SPF record.",
            "remediation": "Authorize sending relays in the DNS SPF record.",
        })
    else:
        findings.append({
            "check_id": "EMAIL-AUTH-SPF-001",
            "title": "Sender Policy Framework (SPF) status indeterminate",
            "severity": "LOW",
            "status": "UNKNOWN",
            "evidence": {
                "header": "Authentication-Results / Received-SPF",
                "observed": "No conclusive SPF pass or fail header found",
                "expected": "spf=pass",
            },
            "rationale": "SPF validation result was not recorded in message headers.",
            "remediation": "Configure inbound MTA to record Authentication-Results headers.",
        })

    # 4. DKIM Signature & Alignment
    dkim_combined = f"{auth_results} {dkim_sig}".lower()
    if "dkim=pass" in dkim_combined:
        d_match = re.search(r"d=([a-zA-Z0-9.-]+)", dkim_sig)
        dkim_domain = d_match.group(1).lower() if d_match else ""
        if dkim_domain and (dkim_domain == from_domain or from_domain.endswith(f".{dkim_domain}")):
            findings.append({
                "check_id": "EMAIL-AUTH-DKIM-001",
                "title": "DKIM signature validated with aligned domain",
                "severity": "INFO",
                "status": "PASS",
                "evidence": {
                    "header": "DKIM-Signature",
                    "observed": f"dkim=pass, d={dkim_domain}",
                    "expected": f"dkim=pass aligned with {from_domain}",
                },
                "rationale": "Cryptographic signature verified and domain matches the From address.",
                "remediation": "Rotate DKIM keys semi-annually.",
            })
        else:
            findings.append({
                "check_id": "EMAIL-AUTH-DKIM-001",
                "title": "DKIM signature passed but domain unaligned",
                "severity": "MEDIUM",
                "status": "WARN",
                "evidence": {
                    "header": "DKIM-Signature",
                    "observed": f"dkim=pass, d={dkim_domain} vs from={from_domain}",
                    "expected": f"d= should align with From domain {from_domain}",
                },
                "rationale": "DKIM signature passed but signed by a third-party domain, which fails strict DMARC alignment.",
                "remediation": "Configure custom DKIM signing domain on the sending ESP/relay.",
            })
    elif dkim_sig:
        findings.append({
            "check_id": "EMAIL-AUTH-DKIM-001",
            "title": "DKIM signature present but not verified",
            "severity": "MEDIUM",
            "status": "UNKNOWN",
            "evidence": {
                "header": "DKIM-Signature",
                "observed": "Signature present; verification record missing",
                "expected": "dkim=pass",
            },
            "rationale": "Message contains a DKIM-Signature header but lacks inbound verification proof.",
            "remediation": "Enable DKIM validation at the receiving MTA.",
        })
    else:
        findings.append({
            "check_id": "EMAIL-AUTH-DKIM-001",
            "title": "DKIM signature missing",
            "severity": "MEDIUM",
            "status": "FAIL",
            "evidence": {
                "header": "DKIM-Signature",
                "observed": "No DKIM-Signature header present",
                "expected": "Cryptographically signed email with DKIM-Signature",
            },
            "rationale": "Unsigned messages cannot be verified against sender spoofing or transit tampering.",
            "remediation": "Sign all outbound email with 2048-bit DKIM keys.",
        })

    # 5. Lookalike / Punycode Domain Detection
    if _is_punycode_or_homoglyph(from_domain):
        findings.append({
            "check_id": "EMAIL-LOOKALIKE-001",
            "title": "Internationalized / Punycode sender domain detected",
            "severity": "CRITICAL",
            "status": "FAIL",
            "evidence": {
                "header": "From",
                "observed": from_domain,
                "expected": "Standard ASCII domain name",
            },
            "rationale": "The sender domain contains punycode ('xn--') or non-ASCII characters, which is a classic indicator of homoglyph lookalike impersonation.",
            "remediation": "Block or quarantine lookalike domains mimicking official organizational domains.",
        })

    # 6. Attachment metadata inspection
    attachments: list[dict[str, Any]] = []
    body_text = ""
    for part in msg.walk():
        fn = part.get_filename()
        content_type = part.get_content_type()
        if fn:
            ext = "." + fn.split(".")[-1].lower() if "." in fn else ""
            dangerous = ext in DANGEROUS_EXTENSIONS
            att_info = {
                "filename": fn,
                "content_type": content_type,
                "extension": ext,
                "dangerous_type": dangerous,
                "size_bytes": len(part.get_payload(decode=True) or b""),
            }
            attachments.append(att_info)
            if dangerous:
                findings.append({
                    "check_id": "EMAIL-ATTACHMENT-001",
                    "title": f"Dangerous attachment extension: {ext}",
                    "severity": "HIGH",
                    "status": "FAIL",
                    "evidence": {
                        "header": "Content-Disposition",
                        "observed": f"filename={fn} (extension: {ext})",
                        "expected": "Attachments must not use executable or script file extensions",
                    },
                    "rationale": f"Files with extension {ext} can execute code directly when opened by an operator.",
                    "remediation": "Enforce gateway file-type filtering for high-risk script and executable extensions.",
                })
        elif content_type in {"text/plain", "text/html"}:
            payload = part.get_payload(decode=True)
            if payload:
                try:
                    body_text += payload.decode("utf-8", errors="replace") + "\n"
                except Exception:
                    pass

    # 7. URL inspection from body
    urls = re.findall(r"https?://[^\s<>\"']+", body_text)
    suspicious_urls: list[str] = []
    for u in urls[:50]:
        try:
            parsed = urllib.parse.urlparse(u)
            host = parsed.netloc.lower()
            if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS) or re.match(r"^\d+\.\d+\.\d+\.\d+", host):
                suspicious_urls.append(u)
        except Exception:
            pass

    if suspicious_urls:
        findings.append({
            "check_id": "EMAIL-URL-001",
            "title": "Suspicious URL indicators in message body",
            "severity": "MEDIUM",
            "status": "WARN",
            "evidence": {
                "header": "Message Body",
                "observed": f"Found {len(suspicious_urls)} URLs with raw IP or high-risk TLDs: {', '.join(suspicious_urls[:3])}",
                "expected": "Legitimate enterprise communications should use authorized, branded domains",
            },
            "rationale": "Emails linking to bare IP addresses or suspicious top-level domains are heavily correlated with phishing or malicious payloads.",
            "remediation": "Inspect URLs with internal threat intelligence feeds prior to clicking.",
        })

    failed_count = sum(1 for f in findings if f["status"] == "FAIL")
    warn_count = sum(1 for f in findings if f["status"] == "WARN")
    pass_count = sum(1 for f in findings if f["status"] == "PASS")

    score = 100
    if failed_count > 0:
        score = max(0, 100 - (failed_count * 30 + warn_count * 10))
    elif warn_count > 0:
        score = max(50, 100 - warn_count * 15)

    return {
        "inspection_type": "bounded_email_authentication",
        "boundary_notice": (
            "Review-only header authentication posture. Does not execute attachments or perform live MTA blocking."
        ),
        "headers": {
            "from": from_header,
            "from_address": from_addr,
            "from_domain": from_domain,
            "reply_to": reply_to,
            "return_path": return_path,
            "subject": subject,
        },
        "score": score,
        "finding_counts": {
            "total": len(findings),
            "fail": failed_count,
            "warn": warn_count,
            "pass": pass_count,
        },
        "findings": findings,
        "attachments": attachments,
        "extracted_url_count": len(urls),
        "suspicious_url_count": len(suspicious_urls),
    }
