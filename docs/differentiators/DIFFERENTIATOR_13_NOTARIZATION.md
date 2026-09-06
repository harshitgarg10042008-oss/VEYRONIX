# Differentiator #13: Cryptographic Evidence Notarization — Evidence Document

## Status

**Differentiator #13 Status**: IMPLEMENTED

## Overview

The cryptographic evidence notarization module provides signing and verification of evidence using cryptographic signatures to ensure integrity, authenticity, and non-repudiation. It supports ED25519 and RSA-PSS-SHA256 algorithms.

## Implementation

### Core Module (`src/configsentinel/notarization.py`)

**SignatureAlgorithm** enum:
- `ED25519`: Ed25519 signature algorithm
- `RSA_PSS_SHA256`: RSA with PSS padding and SHA-256

**NotaryKey** dataclass:
- key_id: Unique key identifier
- algorithm: Signature algorithm
- created_at: Key creation timestamp
- public_key_pem: PEM-encoded public key
- private_key_pem: PEM-encoded private key (None for public-only)

**Notarization** dataclass:
- notarization_id: Unique notarization identifier
- evidence_id: Evidence being signed
- evidence_sha256: SHA256 digest of evidence
- notary_key_id: Key used for signing
- signature_algorithm: Algorithm used
- signature_value: Hex-encoded signature
- signed_at: Signing timestamp
- evidence_digest: Digest of evidence that was signed

### Key Functions

1. **generate_key_pair()**: Generate new cryptographic key pair
2. **sign_evidence()**: Cryptographically sign evidence
3. **verify_notarization()**: Verify a notarization signature
4. **create_notarization_bundle()**: Create bundle for distribution

### Signing Process

1. Serialize evidence as canonical JSON (sorted keys, no spaces)
2. Calculate SHA256 digest of evidence
3. Sign with private key using specified algorithm
4. Encode signature as hex
5. Return notarization with metadata

### Verification Process

1. Serialize evidence as canonical JSON
2. Calculate SHA256 digest
3. Verify digest matches notarization.evidence_digest
4. Load public key
5. Decode signature from hex
6. Verify signature with public key

### Safety Boundaries

1. **No raw secrets**: Private keys never included in bundles
2. **Canonical serialization**: Deterministic JSON for signatures
3. **Algorithm validation**: Rejects unsupported algorithms
4. **Digest verification**: Evidence must match signed digest
5. **Immutable results**: All dataclasses are frozen
6. **Graceful degradation**: Works without cryptography library (with errors)

## Test Coverage

### Notarization Tests (`tests/test_notarization.py`)

15 tests covering:
- ED25519 key pair generation
- RSA key pair generation
- Signing evidence with ED25519
- Signing evidence with RSA
- Verifying valid notarization
- Verifying with modified evidence (fails)
- Verifying with wrong key (fails)
- Signing without private key (error)
- Notarization immutability
- NotaryKey immutability
- Creating notarization bundle
- Deterministic signature (same digest)
- Evidence digest calculation
- Cryptography not available handling
- Unsupported algorithm handling

**Test Results**: 15/15 passed

## Evidence Chain Example

```
1. Generate Key Pair
   - Key ID: key-001
   - Algorithm: ED25519
   - Public Key: PEM-encoded
   - Private Key: PEM-encoded (kept secret)

2. Evidence to Sign
   - Evidence ID: ev-001
   - Control ID: CTRL-001
   - Status: FAIL
   - Observed At: 2026-08-27T00:00:00Z

3. Sign Evidence
   - Canonical JSON: sorted keys, no spaces
   - SHA256 Digest: abc123...
   - Signature: def456... (hex-encoded)
   - Signed At: 2026-08-27T00:00:00Z

4. Create Bundle
   - Evidence: original evidence
   - Notarization: signature metadata
   - Notary Key: public key only
   - Bundle SHA256: digest of bundle

5. Verification
   - Deserialize evidence
   - Calculate digest
   - Verify signature with public key
   - Result: Valid/Invalid
```

## Differentiation from Existing Solutions

| Feature | ConfigSentinel AI | Typical Evidence Systems |
|---------|-------------------|--------------------------|
| Cryptographic signing | ED25519 and RSA-PSS-SHA256 | Often absent or simple checksum |
| Canonical serialization | Deterministic JSON for signatures | Often non-deterministic |
| Algorithm selection | Multiple algorithms supported | Usually single algorithm |
| Public-only keys | Support for verification-only keys | Often requires full key pair |
| Bundle format | Evidence + notarization + public key | Often separate files |
| Immutable results | Frozen dataclasses | Often mutable |
| Graceful degradation | Clear errors without cryptography | Often silent failures |

## Limitations

1. **Cryptography dependency**: Requires cryptography library
2. **Key management**: Key lifecycle management not included
3. **No HSM support**: No hardware security module integration
4. **No key rotation**: No automatic key rotation
5. **No revocation**: No key revocation mechanism
6. **No certificate chains**: Single key pair only

## Future Enhancements

1. **HSM integration**: Support for hardware security modules
2. **Key rotation**: Automatic key rotation and re-signing
3. **Certificate chains**: Support for X.509 certificates
4. **Key revocation**: Revocation list or OCSP support
5. **Multiple signatures**: Support for multiple signers
6. **Timestamp servers**: Integration with timestamp authorities

## Commit Information

**Commit**: `feat: implement cryptographic evidence notarization`  
**Files Changed**:
- `src/configsentinel/notarization.py` (notarization module)
- `tests/test_notarization.py` (15 tests)
- `docs/DIFFERENTIATOR_13_NOTARIZATION.md` (this document)

## Test Results Summary

- Backend tests: 267 passed (including 15 new notarization tests)
- Notarization tests: 15 passed
- Total new tests: 15
