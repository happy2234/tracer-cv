"""
TRACER-CV C4 — Tamper-Evident Audit Trail.

Creates a local append-only style audit chain for assurance events.

Each audit entry binds:
    - sequence
    - timestamp
    - event type
    - source engine
    - finding/evidence payload
    - previous entry hash
    - current entry hash

C4 detects:
    - modified audit entries
    - broken audit chains
    - sequence discontinuity
    - duplicate sequences
    - nonce/event-id reuse

C4 is local and offline. It does not require a blockchain network.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set


ENGINE_VERSION = "c4-1.0"
METHOD = "tamper-evident local audit chain"
TASK = "audit_integrity"

GENESIS_HASH = "0" * 64


# ---------------------------------------------------------------------------
# Canonicalization
# ---------------------------------------------------------------------------

def canonical_json(value: Any) -> bytes:
    """Serialize JSON deterministically."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    """Return SHA-256 hexadecimal digest."""
    return hashlib.sha256(data).hexdigest()


def digest_object(value: Any) -> str:
    """Hash a JSON-compatible object deterministically."""
    return sha256_bytes(canonical_json(value))


# ---------------------------------------------------------------------------
# Timestamp / event ID
# ---------------------------------------------------------------------------

def generate_timestamp() -> str:
    """Generate a UTC ISO-8601 timestamp."""
    return datetime.now(timezone.utc).isoformat()


def generate_event_id() -> str:
    """Generate a unique random audit event identifier."""
    return secrets.token_hex(16)


# ---------------------------------------------------------------------------
# Audit entry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AuditEntry:
    """One tamper-evident audit event."""

    sequence: int
    event_id: str
    timestamp: str
    event_type: str
    source_engine: str
    affected_asset: str
    payload_digest: str
    previous_entry_hash: str

    entry_hash: str = ""

    def unsigned_dict(self) -> Dict[str, Any]:
        """Return fields covered by entry_hash."""
        return {
            "sequence": self.sequence,
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "source_engine": self.source_engine,
            "affected_asset": self.affected_asset,
            "payload_digest": self.payload_digest,
            "previous_entry_hash": self.previous_entry_hash,
        }

    def as_dict(self) -> Dict[str, Any]:
        """Return complete serializable audit entry."""
        return {
            **self.unsigned_dict(),
            "entry_hash": self.entry_hash,
        }


# ---------------------------------------------------------------------------
# Entry hashing
# ---------------------------------------------------------------------------

def compute_entry_hash(
    *,
    sequence: int,
    event_id: str,
    timestamp: str,
    event_type: str,
    source_engine: str,
    affected_asset: str,
    payload_digest: str,
    previous_entry_hash: str,
) -> str:
    """Compute the cryptographic hash of an audit entry."""

    payload = {
        "sequence": int(sequence),
        "event_id": str(event_id),
        "timestamp": str(timestamp),
        "event_type": str(event_type),
        "source_engine": str(source_engine),
        "affected_asset": str(affected_asset),
        "payload_digest": str(payload_digest),
        "previous_entry_hash": str(previous_entry_hash),
    }

    return sha256_bytes(canonical_json(payload))


# ---------------------------------------------------------------------------
# Entry creation
# ---------------------------------------------------------------------------

def create_audit_entry(
    *,
    sequence: int,
    event_type: str,
    source_engine: str,
    affected_asset: str,
    payload: Any,
    previous_entry_hash: str = GENESIS_HASH,
    event_id: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> AuditEntry:
    """
    Create one audit entry.

    Payload is represented by its digest rather than being duplicated inside
    the chain entry.
    """

    if sequence < 1:
        raise ValueError("sequence must be >= 1")

    if not event_type:
        raise ValueError("event_type must not be empty")

    if not source_engine:
        raise ValueError("source_engine must not be empty")

    if not affected_asset:
        raise ValueError("affected_asset must not be empty")

    if event_id is None:
        event_id = generate_event_id()

    if timestamp is None:
        timestamp = generate_timestamp()

    payload_digest = digest_object(payload)

    entry_hash = compute_entry_hash(
        sequence=sequence,
        event_id=event_id,
        timestamp=timestamp,
        event_type=event_type,
        source_engine=source_engine,
        affected_asset=affected_asset,
        payload_digest=payload_digest,
        previous_entry_hash=previous_entry_hash,
    )

    return AuditEntry(
        sequence=sequence,
        event_id=event_id,
        timestamp=timestamp,
        event_type=event_type,
        source_engine=source_engine,
        affected_asset=affected_asset,
        payload_digest=payload_digest,
        previous_entry_hash=previous_entry_hash,
        entry_hash=entry_hash,
    )


# ---------------------------------------------------------------------------
# Entry verification
# ---------------------------------------------------------------------------

def verify_audit_entry(
    entry: AuditEntry,
) -> Dict[str, Any]:
    """Verify the cryptographic integrity of one audit entry."""

    expected_hash = compute_entry_hash(
        sequence=entry.sequence,
        event_id=entry.event_id,
        timestamp=entry.timestamp,
        event_type=entry.event_type,
        source_engine=entry.source_engine,
        affected_asset=entry.affected_asset,
        payload_digest=entry.payload_digest,
        previous_entry_hash=entry.previous_entry_hash,
    )

    hash_valid = expected_hash == entry.entry_hash

    return {
        "valid": bool(hash_valid),
        "hash_valid": bool(hash_valid),
        "expected_entry_hash": expected_hash,
        "actual_entry_hash": entry.entry_hash,
    }


# ---------------------------------------------------------------------------
# Chain verification
# ---------------------------------------------------------------------------

def verify_audit_chain(
    entries: Sequence[AuditEntry],
) -> Dict[str, Any]:
    """
    Verify an ordered audit chain.

    Detects:
        - entry tampering
        - broken links
        - sequence discontinuity
        - duplicate sequence numbers
        - event ID reuse
    """

    if not entries:
        return {
            "valid": True,
            "entry_count": 0,
            "findings": [],
        }

    findings: List[Dict[str, Any]] = []

    seen_sequences: Set[int] = set()
    seen_event_ids: Set[str] = set()

    expected_previous = GENESIS_HASH
    expected_sequence = 1

    for index, entry in enumerate(entries):

        verification = verify_audit_entry(entry)

        if not verification["hash_valid"]:
            findings.append(
                {
                    "type": "entry_tampering",
                    "index": index,
                    "sequence": entry.sequence,
                    "message": (
                        "Audit entry hash does not match entry contents."
                    ),
                }
            )

        if entry.previous_entry_hash != expected_previous:
            findings.append(
                {
                    "type": "broken_chain",
                    "index": index,
                    "sequence": entry.sequence,
                    "message": (
                        "Previous-entry hash does not match the preceding "
                        "audit entry."
                    ),
                }
            )

        if entry.sequence != expected_sequence:
            findings.append(
                {
                    "type": "sequence_discontinuity",
                    "index": index,
                    "sequence": entry.sequence,
                    "expected_sequence": expected_sequence,
                    "message": (
                        "Audit sequence is discontinuous."
                    ),
                }
            )

        if entry.sequence in seen_sequences:
            findings.append(
                {
                    "type": "duplicate_sequence",
                    "index": index,
                    "sequence": entry.sequence,
                    "message": (
                        "Audit sequence number has already appeared."
                    ),
                }
            )

        if entry.event_id in seen_event_ids:
            findings.append(
                {
                    "type": "event_id_reuse",
                    "index": index,
                    "sequence": entry.sequence,
                    "message": (
                        "Audit event identifier has already appeared."
                    ),
                }
            )

        seen_sequences.add(entry.sequence)
        seen_event_ids.add(entry.event_id)

        expected_previous = entry.entry_hash
        expected_sequence += 1

    return {
        "valid": not findings,
        "entry_count": len(entries),
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Append helper
# ---------------------------------------------------------------------------

def append_audit_entry(
    chain: Sequence[AuditEntry],
    *,
    event_type: str,
    source_engine: str,
    affected_asset: str,
    payload: Any,
    event_id: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> AuditEntry:
    """Create the next entry in an existing audit chain."""

    sequence = len(chain) + 1

    previous_hash = (
        chain[-1].entry_hash
        if chain
        else GENESIS_HASH
    )

    return create_audit_entry(
        sequence=sequence,
        event_type=event_type,
        source_engine=source_engine,
        affected_asset=affected_asset,
        payload=payload,
        previous_entry_hash=previous_hash,
        event_id=event_id,
        timestamp=timestamp,
    )


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def audit_entry_to_json(entry: AuditEntry) -> str:
    """Serialize one audit entry deterministically."""
    return canonical_json(entry.as_dict()).decode("utf-8")


def audit_entry_from_dict(
    data: Dict[str, Any],
) -> AuditEntry:
    """Reconstruct an AuditEntry from a dictionary."""

    required = {
        "sequence",
        "event_id",
        "timestamp",
        "event_type",
        "source_engine",
        "affected_asset",
        "payload_digest",
        "previous_entry_hash",
        "entry_hash",
    }

    missing = required - set(data)

    if missing:
        raise ValueError(
            f"missing audit fields: {sorted(missing)}"
        )

    return AuditEntry(
        sequence=int(data["sequence"]),
        event_id=str(data["event_id"]),
        timestamp=str(data["timestamp"]),
        event_type=str(data["event_type"]),
        source_engine=str(data["source_engine"]),
        affected_asset=str(data["affected_asset"]),
        payload_digest=str(data["payload_digest"]),
        previous_entry_hash=str(
            data["previous_entry_hash"]
        ),
        entry_hash=str(data["entry_hash"]),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "ENGINE_VERSION",
    "METHOD",
    "TASK",
    "GENESIS_HASH",
    "AuditEntry",
    "canonical_json",
    "sha256_bytes",
    "digest_object",
    "generate_timestamp",
    "generate_event_id",
    "compute_entry_hash",
    "create_audit_entry",
    "verify_audit_entry",
    "verify_audit_chain",
    "append_audit_entry",
    "audit_entry_to_json",
    "audit_entry_from_dict",
]
