from pathlib import Path

from configsentinel.auditlog import AuditTrail, sign_envelope, verify_envelope
from configsentinel.client import ConfigSentinelClient
from configsentinel.engine import DeterministicComplianceEngine


def audit(text: str):
    return ConfigSentinelClient(engine=DeterministicComplianceEngine()).audit_text(text, vendor="cisco_ios")


def test_audit_trail_hash_chain_verifies_and_detects_corruption(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    trail = AuditTrail(path)
    trail.append(audit("version 17.9\nno ip http server\n"))
    trail.append(audit("version 17.9\nline vty 0 4\n transport input telnet\n"))
    assert trail.verify() == (True, "audit trail verified")
    raw = path.read_text(encoding="utf-8")
    path.write_text(raw.replace("NET-MGMT", "CORRUPTED", 1), encoding="utf-8")
    assert trail.verify()[0] is False


def test_signed_envelope_verifies_only_with_original_key():
    envelope = sign_envelope({"audit_id": "audit_1", "input_sha256": "abc"}, b"local-secret")
    assert verify_envelope(envelope, b"local-secret") is True
    assert verify_envelope(envelope, b"wrong-secret") is False
    envelope["payload"]["audit_id"] = "tampered"
    assert verify_envelope(envelope, b"local-secret") is False
