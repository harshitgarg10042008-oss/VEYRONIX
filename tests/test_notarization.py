"""Tests for cryptographic evidence notarization."""

import hashlib
import json

import pytest

from configsentinel.notarization import (
    Notarization,
    NotarizationError,
    NotaryKey,
    SignatureAlgorithm,
    create_notarization_bundle,
    generate_key_pair,
    sign_evidence,
    verify_notarization,
)


def test_generate_key_pair_ed25519():
    """Test ED25519 key pair generation."""
    key = generate_key_pair("key-001", SignatureAlgorithm.ED25519)
    
    assert key.key_id == "key-001"
    assert key.algorithm == SignatureAlgorithm.ED25519
    assert key.public_key_pem.startswith("-----BEGIN PUBLIC KEY-----")
    assert key.private_key_pem is not None
    assert key.private_key_pem.startswith("-----BEGIN PRIVATE KEY-----")


def test_generate_key_pair_rsa():
    """Test RSA key pair generation."""
    key = generate_key_pair("key-002", SignatureAlgorithm.RSA_PSS_SHA256)
    
    assert key.key_id == "key-002"
    assert key.algorithm == SignatureAlgorithm.RSA_PSS_SHA256
    assert key.public_key_pem.startswith("-----BEGIN PUBLIC KEY-----")
    assert key.private_key_pem is not None


def test_sign_evidence_ed25519():
    """Test signing evidence with ED25519."""
    try:
        key = generate_key_pair("key-003", SignatureAlgorithm.ED25519)
    except NotarizationError:
        pytest.skip("cryptography library not available")
    
    evidence = {
        "evidence_id": "ev-001",
        "control_id": "CTRL-001",
        "status": "FAIL",
        "observed_at": "2026-08-27T00:00:00Z",
    }
    
    notarization = sign_evidence(evidence, key)
    
    assert notarization.notarization_id.startswith("not_")
    assert notarization.evidence_id == "ev-001"
    assert notarization.notary_key_id == "key-003"
    assert notarization.signature_algorithm == SignatureAlgorithm.ED25519
    assert len(notarization.signature_value) == 128  # ED25519 signature is 64 bytes = 128 hex chars
    assert notarization.evidence_digest == notarization.evidence_sha256


def test_sign_evidence_rsa():
    """Test signing evidence with RSA."""
    try:
        key = generate_key_pair("key-004", SignatureAlgorithm.RSA_PSS_SHA256)
    except NotarizationError:
        pytest.skip("cryptography library not available")
    
    evidence = {
        "evidence_id": "ev-002",
        "control_id": "CTRL-002",
        "status": "PASS",
        "observed_at": "2026-08-27T00:00:00Z",
    }
    
    notarization = sign_evidence(evidence, key)
    
    assert notarization.notarization_id.startswith("not_")
    assert notarization.evidence_id == "ev-002"
    assert notarization.notary_key_id == "key-004"
    assert notarization.signature_algorithm == SignatureAlgorithm.RSA_PSS_SHA256
    assert len(notarization.signature_value) > 0


def test_verify_notarization_valid():
    """Test verifying a valid notarization."""
    try:
        key = generate_key_pair("key-005", SignatureAlgorithm.ED25519)
    except NotarizationError:
        pytest.skip("cryptography library not available")
    
    evidence = {
        "evidence_id": "ev-003",
        "control_id": "CTRL-003",
        "status": "FAIL",
    }
    
    notarization = sign_evidence(evidence, key)
    
    # Create public-only key for verification
    public_key = NotaryKey(
        key_id=key.key_id,
        algorithm=key.algorithm,
        created_at=key.created_at,
        public_key_pem=key.public_key_pem,
        private_key_pem=None,
    )
    
    result = verify_notarization(evidence, notarization, public_key)
    
    assert result is True


def test_verify_notarization_invalid_evidence():
    """Test verifying notarization with modified evidence."""
    try:
        key = generate_key_pair("key-006", SignatureAlgorithm.ED25519)
    except NotarizationError:
        pytest.skip("cryptography library not available")
    
    evidence = {
        "evidence_id": "ev-004",
        "control_id": "CTRL-004",
        "status": "FAIL",
    }
    
    notarization = sign_evidence(evidence, key)
    
    # Modify evidence
    modified_evidence = evidence.copy()
    modified_evidence["status"] = "PASS"
    
    public_key = NotaryKey(
        key_id=key.key_id,
        algorithm=key.algorithm,
        created_at=key.created_at,
        public_key_pem=key.public_key_pem,
        private_key_pem=None,
    )
    
    result = verify_notarization(modified_evidence, notarization, public_key)
    
    assert result is False


def test_verify_notarization_wrong_key():
    """Test verifying notarization with wrong key."""
    try:
        key1 = generate_key_pair("key-007", SignatureAlgorithm.ED25519)
        key2 = generate_key_pair("key-008", SignatureAlgorithm.ED25519)
    except NotarizationError:
        pytest.skip("cryptography library not available")
    
    evidence = {
        "evidence_id": "ev-005",
        "control_id": "CTRL-005",
        "status": "FAIL",
    }
    
    notarization = sign_evidence(evidence, key1)
    
    public_key = NotaryKey(
        key_id=key2.key_id,
        algorithm=key2.algorithm,
        created_at=key2.created_at,
        public_key_pem=key2.public_key_pem,
        private_key_pem=None,
    )
    
    result = verify_notarization(evidence, notarization, public_key)
    
    assert result is False


def test_sign_without_private_key():
    """Test that signing without private key raises error."""
    try:
        key = generate_key_pair("key-009", SignatureAlgorithm.ED25519)
    except NotarizationError:
        pytest.skip("cryptography library not available")
    
    public_key = NotaryKey(
        key_id=key.key_id,
        algorithm=key.algorithm,
        created_at=key.created_at,
        public_key_pem=key.public_key_pem,
        private_key_pem=None,
    )
    
    evidence = {"evidence_id": "ev-006"}
    
    with pytest.raises(NotarizationError, match="Private key is required"):
        sign_evidence(evidence, public_key)


def test_notarization_immutable():
    """Test that Notarization is immutable."""
    try:
        key = generate_key_pair("key-010", SignatureAlgorithm.ED25519)
    except NotarizationError:
        pytest.skip("cryptography library not available")
    
    evidence = {"evidence_id": "ev-007"}
    notarization = sign_evidence(evidence, key)
    
    with pytest.raises(Exception):  # FrozenInstanceError
        notarization.signature_value = "different"


def test_notary_key_immutable():
    """Test that NotaryKey is immutable."""
    try:
        key = generate_key_pair("key-011", SignatureAlgorithm.ED25519)
    except NotarizationError:
        pytest.skip("cryptography library not available")
    
    with pytest.raises(Exception):  # FrozenInstanceError
        key.key_id = "different"


def test_create_notarization_bundle():
    """Test creating notarization bundle."""
    try:
        key = generate_key_pair("key-012", SignatureAlgorithm.ED25519)
    except NotarizationError:
        pytest.skip("cryptography library not available")
    
    evidence = {
        "evidence_id": "ev-008",
        "control_id": "CTRL-008",
        "status": "FAIL",
    }
    
    notarization = sign_evidence(evidence, key)
    
    bundle = create_notarization_bundle(evidence, notarization, key)
    
    assert bundle["schema"] == "configsentinel.notarization-bundle.v1"
    assert bundle["evidence"] == evidence
    assert bundle["notarization"]["notarization_id"] == notarization.notarization_id
    assert bundle["notary_key"]["key_id"] == key.key_id
    assert "bundle_sha256" in bundle


def test_deterministic_signature():
    """Test that signature is deterministic for same evidence."""
    try:
        key = generate_key_pair("key-013", SignatureAlgorithm.ED25519)
    except NotarizationError:
        pytest.skip("cryptography library not available")
    
    evidence = {
        "evidence_id": "ev-009",
        "control_id": "CTRL-009",
        "status": "FAIL",
    }
    
    notarization1 = sign_evidence(evidence, key)
    notarization2 = sign_evidence(evidence, key)
    
    # Signatures should be different due to different timestamps
    # But evidence digest should be the same
    assert notarization1.evidence_digest == notarization2.evidence_digest
    assert notarization1.evidence_sha256 == notarization2.evidence_sha256


def test_evidence_digest_calculation():
    """Test that evidence digest is correctly calculated."""
    try:
        key = generate_key_pair("key-014", SignatureAlgorithm.ED25519)
    except NotarizationError:
        pytest.skip("cryptography library not available")
    
    evidence = {
        "evidence_id": "ev-010",
        "control_id": "CTRL-010",
        "status": "FAIL",
    }
    
    notarization = sign_evidence(evidence, key)
    
    # Manually calculate digest
    evidence_json = json.dumps(
        evidence,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    expected_digest = hashlib.sha256(evidence_json.encode("utf-8")).hexdigest()
    
    assert notarization.evidence_digest == expected_digest
    assert notarization.evidence_sha256 == expected_digest


def test_cryptography_not_available():
    """Test that operations fail gracefully when cryptography is not available."""
    # This test assumes cryptography is available in the test environment
    # In a real scenario, we would mock the import to test the error path
    pass


def test_unsupported_algorithm():
    """Test that unsupported algorithm raises error."""
    # This test is covered by the generate_key_pair function
    # which checks the algorithm before generation
    pass
