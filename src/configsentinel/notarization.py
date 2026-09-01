"""Cryptographic evidence notarization for integrity and non-repudiation.

This module provides signing and verification of evidence using cryptographic
signatures to ensure integrity, authenticity, and non-repudiation.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, padding
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.exceptions import InvalidSignature
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False


class SignatureAlgorithm(str, Enum):
    """Supported signature algorithms."""
    ED25519 = "ED25519"
    RSA_PSS_SHA256 = "RSA_PSS_SHA256"


class VerificationOutcome(str, Enum):
    """Result of verifying a notarization signature."""
    VALID = "VALID"
    INVALID = "INVALID"
    UNVERIFIABLE = "UNVERIFIABLE"


class NotarizationError(Exception):
    """Raised when notarization operations fail."""


@dataclass(frozen=True)
class NotaryKey:
    """Cryptographic key pair for notarization."""
    key_id: str
    algorithm: SignatureAlgorithm
    created_at: str
    public_key_pem: str
    private_key_pem: str | None = None  # None for public-only keys


@dataclass(frozen=True)
class Notarization:
    """Cryptographic signature on evidence."""
    notarization_id: str
    evidence_id: str
    evidence_sha256: str
    notary_key_id: str
    signature_algorithm: SignatureAlgorithm
    signature_value: str
    signed_at: str
    evidence_digest: str  # Digest of the evidence that was signed
    source_commit: str
    rule_pack_version: str
    redaction_state: str


def generate_key_pair(
    key_id: str,
    algorithm: SignatureAlgorithm = SignatureAlgorithm.ED25519,
) -> NotaryKey:
    """Generate a new cryptographic key pair for notarization.
    
    Args:
        key_id: Unique identifier for the key
        algorithm: Signature algorithm to use
    
    Returns:
        NotaryKey with public and private keys
    
    Raises:
        NotarizationError: If cryptography library is not available
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        raise NotarizationError("cryptography library is required for key generation")
    
    if algorithm == SignatureAlgorithm.ED25519:
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
    elif algorithm == SignatureAlgorithm.RSA_PSS_SHA256:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
    else:
        raise NotarizationError(f"Unsupported algorithm: {algorithm}")
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    
    return NotaryKey(
        key_id=key_id,
        algorithm=algorithm,
        created_at=datetime.now(timezone.utc).isoformat(),
        public_key_pem=public_pem,
        private_key_pem=private_pem,
    )


def sign_evidence(
    evidence: dict[str, Any],
    notary_key: NotaryKey,
    *,
    source_commit: str = "unknown",
    rule_pack_version: str = "unknown",
    redaction_state: str = "none",
) -> Notarization:
    """Cryptographically sign evidence.
    
    Args:
        evidence: Evidence to sign (will be serialized as JSON)
        notary_key: NotaryKey with private key
    
    Returns:
        Notarization with signature
    
    Raises:
        NotarizationError: If cryptography library is not available or signing fails
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        raise NotarizationError("cryptography library is required for signing")
    
    if notary_key.private_key_pem is None:
        raise NotarizationError("Private key is required for signing")
    
    # Serialize evidence as canonical JSON
    evidence_json = json.dumps(
        evidence,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    
    # Calculate SHA256 digest of evidence
    evidence_sha256 = hashlib.sha256(evidence_json.encode("utf-8")).hexdigest()
    
    # Load private key
    private_key = serialization.load_pem_private_key(
        notary_key.private_key_pem.encode("utf-8"),
        password=None,
    )
    
    # Sign
    if notary_key.algorithm == SignatureAlgorithm.ED25519:
        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            raise NotarizationError("Key algorithm mismatch")
        signature = private_key.sign(evidence_json.encode("utf-8"))
    elif notary_key.algorithm == SignatureAlgorithm.RSA_PSS_SHA256:
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise NotarizationError("Key algorithm mismatch")
        signature = private_key.sign(
            evidence_json.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    else:
        raise NotarizationError(f"Unsupported algorithm: {notary_key.algorithm}")
    
    # Encode signature as hex
    signature_hex = signature.hex()
    
    import secrets
    notarization_id = f"not_{secrets.token_hex(8)}"
    
    return Notarization(
        notarization_id=notarization_id,
        evidence_id=evidence.get("evidence_id", "unknown"),
        evidence_sha256=evidence_sha256,
        notary_key_id=notary_key.key_id,
        signature_algorithm=notary_key.algorithm,
        signature_value=signature_hex,
        signed_at=datetime.now(timezone.utc).isoformat(),
        evidence_digest=evidence_sha256,
        source_commit=source_commit,
        rule_pack_version=rule_pack_version,
        redaction_state=redaction_state,
    )


def verify_notarization(
    evidence: dict[str, Any],
    notarization: Notarization,
    notary_key: NotaryKey,
) -> VerificationOutcome:
    """Verify a notarization signature.
    
    Args:
        evidence: Evidence that was signed
        notarization: Notarization to verify
        notary_key: NotaryKey with public key
    
    Returns:
        VerificationOutcome.VALID if valid, INVALID if invalid, UNVERIFIABLE if crypto missing
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        return VerificationOutcome.UNVERIFIABLE
    
    # Serialize evidence as canonical JSON
    evidence_json = json.dumps(
        evidence,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    
    # Calculate SHA256 digest of evidence
    evidence_sha256 = hashlib.sha256(evidence_json.encode("utf-8")).hexdigest()
    
    # Verify digest matches
    if evidence_sha256 != notarization.evidence_digest:
        return VerificationOutcome.INVALID
    
    # Load public key
    public_key = serialization.load_pem_public_key(
        notary_key.public_key_pem.encode("utf-8"),
    )
    
    # Decode signature
    signature = bytes.fromhex(notarization.signature_value)
    
    # Verify
    try:
        if notarization.signature_algorithm == SignatureAlgorithm.ED25519:
            if not isinstance(public_key, ed25519.Ed25519PublicKey):
                raise NotarizationError("Key algorithm mismatch")
            public_key.verify(signature, evidence_json.encode("utf-8"))
        elif notarization.signature_algorithm == SignatureAlgorithm.RSA_PSS_SHA256:
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise NotarizationError("Key algorithm mismatch")
            public_key.verify(
                signature,
                evidence_json.encode("utf-8"),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        else:
            raise NotarizationError(f"Unsupported algorithm: {notarization.signature_algorithm}")
        return VerificationOutcome.VALID
    except InvalidSignature:
        return VerificationOutcome.INVALID


def create_notarization_bundle(
    evidence: dict[str, Any],
    notarization: Notarization,
    notary_key: NotaryKey,
) -> dict[str, Any]:
    """Create a bundle containing evidence and notarization for distribution.
    
    Args:
        evidence: Evidence that was signed
        notarization: Notarization for the evidence
        notary_key: NotaryKey used for signing
    
    Returns:
        Dictionary with evidence, notarization, and public key
    """
    return {
        "schema": "configsentinel.notarization-bundle.v1",
        "evidence": evidence,
        "notarization": {
            "notarization_id": notarization.notarization_id,
            "evidence_id": notarization.evidence_id,
            "evidence_sha256": notarization.evidence_sha256,
            "notary_key_id": notarization.notary_key_id,
            "signature_algorithm": notarization.signature_algorithm.value,
            "signature_value": notarization.signature_value,
            "signed_at": notarization.signed_at,
            "evidence_digest": notarization.evidence_digest,
            "source_commit": notarization.source_commit,
            "rule_pack_version": notarization.rule_pack_version,
            "redaction_state": notarization.redaction_state,
        },
        "notary_key": {
            "key_id": notary_key.key_id,
            "algorithm": notary_key.algorithm.value,
            "public_key_pem": notary_key.public_key_pem,
            "created_at": notary_key.created_at,
        },
        "bundle_sha256": hashlib.sha256(
            json.dumps(
                {"evidence": evidence, "notarization": notarization.signature_value},
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        ).hexdigest(),
    }
