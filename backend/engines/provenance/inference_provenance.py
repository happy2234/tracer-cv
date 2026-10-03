
"""
TRACER-CV C1 — Inference Provenance.

Binds an inference input, model identity, preprocessing configuration,
output, sequence information, timestamp, nonce, and cryptographic
evidence into a tamper-evident provenance record.

C1 detects:
    - record tampering
    - record modification
    - sequence discontinuity
    - nonce reuse
    - replay of an existing inference event
    - broken previous-record hash chains
    - invalid Ed25519 signatures

C1 does NOT determine whether a model is malicious.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


ENGINE_VERSION = "c1-1.0"
METHOD = "cryptographically bound inference provenance"
TASK = "inference_integrity"

GENESIS_HASH = "0" * 64


# ---------------------------------------------------------------------------
# Hashing / canonicalization
# ---------------------------------------------------------------------------

def sha256_bytes(data: bytes) -> str:
    """Return lowercase SHA-256 hexadecimal digest."""
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    """Return SHA-256 of UTF-8 encoded text."""
    return sha256_bytes(text.encode("utf-8"))


def canonical_json(value: Any) -> bytes:
    """
    Serialize JSON deterministically.

    Canonicalization ensures that equivalent provenance structures produce
    identical bytes before hashing/signing.
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def digest_object(value: Any) -> str:
    """Hash a JSON-serializable object using canonical JSON."""
    return sha256_bytes(canonical_json(value))


def digest_bytes(value: bytes) -> str:
    """Hash arbitrary bytes."""
    return sha256_bytes(value)


# ---------------------------------------------------------------------------
# Provenance record
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ProvenanceRecord:
    """
    One cryptographically bound inference event.

    The record contains digests rather than raw input/output data so the
    provenance layer remains lightweight and suitable for offline use.
    """

    sequence: int
    nonce: str
    timestamp: str

    input_digest: str
    model_id: str
    preprocessing_digest: str
    output_digest: str

    previous_record_hash: str

    record_hash: str = ""
    signature: Optional[str] = None

    def unsigned_dict(self) -> Dict[str, Any]:
        """Return the record fields covered by the record hash/signature."""
        return {
            "sequence": self.sequence,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "input_digest": self.input_digest,
            "model_id": self.model_id,
            "preprocessing_digest": self.preprocessing_digest,
            "output_digest": self.output_digest,
            "previous_record_hash": self.previous_record_hash,
        }

    def as_dict(self) -> Dict[str, Any]:
        """Return the complete serializable record."""
        return {
            **self.unsigned_dict(),
            "record_hash": self.record_hash,
            "signature": self.signature,
        }


# ---------------------------------------------------------------------------
# Digest helpers
# ---------------------------------------------------------------------------

def digest_input(data: bytes) -> str:
    """Create a digest for an inference input."""
    return digest_bytes(data)


def digest_output(data: bytes) -> str:
    """Create a digest for an inference output."""
    return digest_bytes(data)


def digest_preprocessing(config: Any) -> str:
    """Create a deterministic digest for preprocessing/configuration."""
    return digest_object(config)


# ---------------------------------------------------------------------------
# Nonce
# ---------------------------------------------------------------------------

def generate_nonce(length: int = 16) -> str:
    """
    Generate a cryptographically random nonce.

    This is intentionally the only non-deterministic primitive in C1.
    The caller can provide its own nonce when deterministic testing is
    required.
    """
    if length < 8:
        raise ValueError("nonce length must be at least 8 bytes")

    return secrets.token_hex(length)


# ---------------------------------------------------------------------------
# Timestamp
# ---------------------------------------------------------------------------

def generate_timestamp() -> str:
    """
    Generate the current UTC timestamp in ISO-8601 format.

    Example:
        2026-09-29T11:42:31.123456+00:00
    """
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Record hashing
# ---------------------------------------------------------------------------

def compute_record_hash(
    *,
    sequence: int,
    nonce: str,
    timestamp: str,
    input_digest: str,
    model_id: str,
    preprocessing_digest: str,
    output_digest: str,
    previous_record_hash: str,
) -> str:
    """
    Compute the hash binding all security-relevant provenance fields.

    Timestamp is deliberately included in the cryptographic binding so
    changing the timestamp invalidates the record hash.
    """

    payload = {
        "sequence": int(sequence),
        "nonce": str(nonce),
        "timestamp": str(timestamp),
        "input_digest": str(input_digest),
        "model_id": str(model_id),
        "preprocessing_digest": str(preprocessing_digest),
        "output_digest": str(output_digest),
        "previous_record_hash": str(previous_record_hash),
    }

    return sha256_bytes(canonical_json(payload))


# ---------------------------------------------------------------------------
# Ed25519 signing
# ---------------------------------------------------------------------------

def _load_ed25519():
    """
    Load Ed25519 implementation lazily.

    cryptography is preferred because it provides a standard audited
    implementation. C1 remains importable when the optional dependency
    is unavailable.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as exc:
        raise RuntimeError(
            "Ed25519 support requires the 'cryptography' package"
        ) from exc

    return Ed25519PrivateKey, Ed25519PublicKey


def generate_signing_keypair() -> Tuple[str, str]:
    """
    Generate an Ed25519 private/public keypair.

    Returns:
        (private_key_base64, public_key_base64)
    """

    Ed25519PrivateKey, _ = _load_ed25519()

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes_raw()
    public_bytes = public_key.public_bytes_raw()

    return (
        base64.b64encode(private_bytes).decode("ascii"),
        base64.b64encode(public_bytes).decode("ascii"),
    )


def _decode_key(value: str) -> bytes:
    """Decode a base64-encoded key."""
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise ValueError("invalid base64 key") from exc


def sign_record_hash(
    record_hash: str,
    private_key_base64: str,
) -> str:
    """Sign a record hash using an Ed25519 private key."""

    Ed25519PrivateKey, _ = _load_ed25519()

    raw_key = _decode_key(private_key_base64)

    if len(raw_key) != 32:
        raise ValueError("Ed25519 private key must contain 32 bytes")

    private_key = Ed25519PrivateKey.from_private_bytes(raw_key)

    signature = private_key.sign(record_hash.encode("ascii"))

    return base64.b64encode(signature).decode("ascii")


def verify_record_signature(
    record_hash: str,
    signature_base64: str,
    public_key_base64: str,
) -> bool:
    """Verify an Ed25519 signature over a record hash."""

    try:
        _, Ed25519PublicKey = _load_ed25519()

        public_bytes = _decode_key(public_key_base64)
        signature = _decode_key(signature_base64)

        if len(public_bytes) != 32:
            return False

        public_key = Ed25519PublicKey.from_public_bytes(public_bytes)

        public_key.verify(
            signature,
            record_hash.encode("ascii"),
        )

        return True

    except Exception:
        return False


# ---------------------------------------------------------------------------
# Record creation
# ---------------------------------------------------------------------------

def create_record(
    *,
    sequence: int,
    input_digest: str,
    model_id: str,
    preprocessing_digest: str,
    output_digest: str,
    previous_record_hash: str = GENESIS_HASH,
    nonce: Optional[str] = None,
    timestamp: Optional[str] = None,
    private_key_base64: Optional[str] = None,
) -> ProvenanceRecord:
    """
    Create one provenance record.

    If nonce or timestamp are omitted, secure/random values are generated.

    The record hash binds all relevant inference metadata.
    """

    if sequence < 1:
        raise ValueError("sequence must be >= 1")

    if not nonce:
        nonce = generate_nonce()

    if not timestamp:
        timestamp = generate_timestamp()

    record_hash = compute_record_hash(
        sequence=sequence,
        nonce=nonce,
        timestamp=timestamp,
        input_digest=input_digest,
        model_id=model_id,
        preprocessing_digest=preprocessing_digest,
        output_digest=output_digest,
        previous_record_hash=previous_record_hash,
    )

    signature = None

    if private_key_base64 is not None:
        signature = sign_record_hash(
            record_hash,
            private_key_base64,
        )

    return ProvenanceRecord(
        sequence=sequence,
        nonce=nonce,
        timestamp=timestamp,
        input_digest=input_digest,
        model_id=model_id,
        preprocessing_digest=preprocessing_digest,
        output_digest=output_digest,
        previous_record_hash=previous_record_hash,
        record_hash=record_hash,
        signature=signature,
    )


# ---------------------------------------------------------------------------
# Record verification
# ---------------------------------------------------------------------------

def verify_record(
    record: ProvenanceRecord,
    *,
    public_key_base64: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Verify one provenance record.

    Checks:
        1. record hash
        2. optional Ed25519 signature
    """

    expected_hash = compute_record_hash(
        sequence=record.sequence,
        nonce=record.nonce,
        timestamp=record.timestamp,
        input_digest=record.input_digest,
        model_id=record.model_id,
        preprocessing_digest=record.preprocessing_digest,
        output_digest=record.output_digest,
        previous_record_hash=record.previous_record_hash,
    )

    hash_valid = expected_hash == record.record_hash

    signature_checked = False
    signature_valid = None

    if public_key_base64 is not None:
        signature_checked = True

        if record.signature is None:
            signature_valid = False
        else:
            signature_valid = verify_record_signature(
                record.record_hash,
                record.signature,
                public_key_base64,
            )

    valid = hash_valid and (
        not signature_checked or bool(signature_valid)
    )

    return {
        "valid": bool(valid),
        "hash_valid": bool(hash_valid),
        "signature_checked": bool(signature_checked),
        "signature_valid": signature_valid,
        "expected_record_hash": expected_hash,
        "actual_record_hash": record.record_hash,
    }


# ---------------------------------------------------------------------------
# Chain verification
# ---------------------------------------------------------------------------

def verify_chain(
    records: Sequence[ProvenanceRecord],
    *,
    public_key_base64: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Verify an ordered provenance chain.

    Detects:
        - modified records
        - broken hash links
        - sequence gaps
        - duplicate sequence numbers
        - nonce reuse
        - invalid signatures
    """

    if not records:
        return {
            "valid": True,
            "record_count": 0,
            "findings": [],
        }

    findings: List[Dict[str, Any]] = []
    seen_sequences: Set[int] = set()
    seen_nonces: Set[str] = set()

    expected_previous = GENESIS_HASH
    expected_sequence = 1

    for index, record in enumerate(records):
        verification = verify_record(
            record,
            public_key_base64=public_key_base64,
        )

        if not verification["hash_valid"]:
            findings.append(
                {
                    "type": "record_tampering",
                    "index": index,
                    "sequence": record.sequence,
                    "message": (
                        "Record hash does not match record contents."
                    ),
                }
            )

        if (
            public_key_base64 is not None
            and not verification["signature_valid"]
        ):
            findings.append(
                {
                    "type": "invalid_signature",
                    "index": index,
                    "sequence": record.sequence,
                    "message": (
                        "Ed25519 signature verification failed."
                    ),
                }
            )

        if record.previous_record_hash != expected_previous:
            findings.append(
                {
                    "type": "broken_chain",
                    "index": index,
                    "sequence": record.sequence,
                    "message": (
                        "Previous-record hash does not match the "
                        "preceding record."
                    ),
                }
            )

        if record.sequence != expected_sequence:
            findings.append(
                {
                    "type": "sequence_discontinuity",
                    "index": index,
                    "sequence": record.sequence,
                    "expected_sequence": expected_sequence,
                    "message": "Provenance sequence is discontinuous.",
                }
            )

        if record.sequence in seen_sequences:
            findings.append(
                {
                    "type": "duplicate_sequence",
                    "index": index,
                    "sequence": record.sequence,
                    "message": "Sequence number has already appeared.",
                }
            )

        if record.nonce in seen_nonces:
            findings.append(
                {
                    "type": "nonce_reuse",
                    "index": index,
                    "sequence": record.sequence,
                    "message": "Nonce has already appeared in the chain.",
                }
            )

        seen_sequences.add(record.sequence)
        seen_nonces.add(record.nonce)

        expected_previous = record.record_hash
        expected_sequence += 1

    return {
        "valid": not findings,
        "record_count": len(records),
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Replay detection
# ---------------------------------------------------------------------------

def detect_replay(
    record: ProvenanceRecord,
    known_records: Iterable[ProvenanceRecord],
) -> Dict[str, Any]:
    """
    Detect whether an inference record has already appeared.

    Replay detection checks record hash, nonce, and sequence identity.
    """

    known = list(known_records)

    hash_matches = [
        index
        for index, item in enumerate(known)
        if item.record_hash == record.record_hash
    ]

    nonce_matches = [
        index
        for index, item in enumerate(known)
        if item.nonce == record.nonce
    ]

    sequence_matches = [
        index
        for index, item in enumerate(known)
        if item.sequence == record.sequence
    ]

    replay_detected = bool(
        hash_matches or nonce_matches or sequence_matches
    )

    return {
        "replay_detected": replay_detected,
        "record_hash_matches": hash_matches,
        "nonce_matches": nonce_matches,
        "sequence_matches": sequence_matches,
    }


# ---------------------------------------------------------------------------
# Inference binding
# ---------------------------------------------------------------------------

def create_inference_record(
    *,
    sequence: int,
    input_bytes: bytes,
    model_id: str,
    preprocessing_config: Any,
    output_bytes: bytes,
    previous_record_hash: str = GENESIS_HASH,
    nonce: Optional[str] = None,
    timestamp: Optional[str] = None,
    private_key_base64: Optional[str] = None,
) -> ProvenanceRecord:
    """
    Convenience API for binding a complete inference event.

    The input, model, preprocessing configuration, output, sequence,
    nonce, timestamp, and chain position are cryptographically bound.
    """

    return create_record(
        sequence=sequence,
        input_digest=digest_input(input_bytes),
        model_id=model_id,
        preprocessing_digest=digest_preprocessing(
            preprocessing_config
        ),
        output_digest=digest_output(output_bytes),
        previous_record_hash=previous_record_hash,
        nonce=nonce,
        timestamp=timestamp,
        private_key_base64=private_key_base64,
    )


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def record_to_json(record: ProvenanceRecord) -> str:
    """Serialize a provenance record deterministically."""
    return canonical_json(record.as_dict()).decode("utf-8")


def record_from_dict(data: Dict[str, Any]) -> ProvenanceRecord:
    """Reconstruct a provenance record from a dictionary."""

    required = {
        "sequence",
        "nonce",
        "timestamp",
        "input_digest",
        "model_id",
        "preprocessing_digest",
        "output_digest",
        "previous_record_hash",
        "record_hash",
    }

    missing = required - set(data)

    if missing:
        raise ValueError(
            f"missing provenance fields: {sorted(missing)}"
        )

    return ProvenanceRecord(
        sequence=int(data["sequence"]),
        nonce=str(data["nonce"]),
        timestamp=str(data["timestamp"]),
        input_digest=str(data["input_digest"]),
        model_id=str(data["model_id"]),
        preprocessing_digest=str(data["preprocessing_digest"]),
        output_digest=str(data["output_digest"]),
        previous_record_hash=str(data["previous_record_hash"]),
        record_hash=str(data["record_hash"]),
        signature=data.get("signature"),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "ENGINE_VERSION",
    "METHOD",
    "TASK",
    "GENESIS_HASH",
    "ProvenanceRecord",
    "sha256_bytes",
    "sha256_text",
    "canonical_json",
    "digest_object",
    "digest_bytes",
    "digest_input",
    "digest_output",
    "digest_preprocessing",
    "generate_nonce",
    "generate_timestamp",
    "compute_record_hash",
    "generate_signing_keypair",
    "sign_record_hash",
    "verify_record_signature",
    "create_record",
    "create_inference_record",
    "verify_record",
    "verify_chain",
    "detect_replay",
    "record_to_json",
    "record_from_dict",
]
