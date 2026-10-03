"""
TRACER-CV C4 — Audit Trail tests.
"""

import pytest

from backend.engines.provenance.audit_trail import (
    GENESIS_HASH,
    append_audit_entry,
    audit_entry_from_dict,
    audit_entry_to_json,
    create_audit_entry,
    verify_audit_chain,
    verify_audit_entry,
)


PASSED = 0
FAILED = 0


def check(name: str, condition: bool) -> None:
    global PASSED, FAILED

    if condition:
        print(f"PASS {name}")
        PASSED += 1
    else:
        print(f"FAIL {name}")
        FAILED += 1


def make_entry(
    sequence: int,
    previous_hash: str = GENESIS_HASH,
):
    return create_audit_entry(
        sequence=sequence,
        event_type="assurance_finding",
        source_engine="C3",
        affected_asset="dataset",
        payload={
            "finding_id": f"finding-{sequence}",
            "severity": "medium",
            "evidence": {
                "value": sequence,
            },
        },
        previous_entry_hash=previous_hash,
        event_id=f"event-{sequence}-12345678",
        timestamp=f"2026-09-29T12:0{sequence}:00+00:00",
    )


@pytest.fixture
def entries():
    first = make_entry(1)
    second = make_entry(2, first.entry_hash)
    third = make_entry(3, second.entry_hash)
    return [first, second, third]


def test_creation() -> None:
    entry = make_entry(1)

    check(
        "01 entry created",
        entry.sequence == 1,
    )

    check(
        "02 genesis link",
        entry.previous_entry_hash == GENESIS_HASH,
    )

    check(
        "03 entry hash length",
        len(entry.entry_hash) == 64,
    )

    check(
        "04 entry verifies",
        verify_audit_entry(entry)["valid"] is True,
    )


def test_chain() -> list:
    first = make_entry(1)

    second = make_entry(
        2,
        first.entry_hash,
    )

    third = make_entry(
        3,
        second.entry_hash,
    )

    result = verify_audit_chain(
        [first, second, third]
    )

    check(
        "05 three-entry chain valid",
        result["valid"] is True,
    )

    check(
        "06 chain count correct",
        result["entry_count"] == 3,
    )


def test_tampering(entries) -> None:
    first, second, third = entries

    tampered = create_audit_entry(
        sequence=2,
        event_type="assurance_finding",
        source_engine="C3",
        affected_asset="dataset",
        payload={
            "finding_id": "ATTACKER-MODIFIED",
            "severity": "critical",
        },
        previous_entry_hash=first.entry_hash,
        event_id=second.event_id,
        timestamp=second.timestamp,
    )

    # Keep the original hash deliberately.
    from backend.engines.provenance.audit_trail import AuditEntry

    tampered = AuditEntry(
        sequence=tampered.sequence,
        event_id=tampered.event_id,
        timestamp=tampered.timestamp,
        event_type=tampered.event_type,
        source_engine=tampered.source_engine,
        affected_asset=tampered.affected_asset,
        payload_digest=tampered.payload_digest,
        previous_entry_hash=tampered.previous_entry_hash,
        entry_hash=second.entry_hash,
    )

    result = verify_audit_chain(
        [first, tampered, third]
    )

    finding_types = {
        item["type"]
        for item in result["findings"]
    }

    check(
        "07 tampered entry rejected",
        result["valid"] is False,
    )

    check(
        "08 tampering finding present",
        "entry_tampering" in finding_types,
    )


def test_broken_chain(entries) -> None:
    first, second, third = entries

    from backend.engines.provenance.audit_trail import AuditEntry

    broken = AuditEntry(
        sequence=second.sequence,
        event_id=second.event_id,
        timestamp=second.timestamp,
        event_type=second.event_type,
        source_engine=second.source_engine,
        affected_asset=second.affected_asset,
        payload_digest=second.payload_digest,
        previous_entry_hash="f" * 64,
        entry_hash=second.entry_hash,
    )

    result = verify_audit_chain(
        [first, broken, third]
    )

    finding_types = {
        item["type"]
        for item in result["findings"]
    }

    check(
        "09 broken chain rejected",
        result["valid"] is False,
    )

    check(
        "10 broken-chain finding present",
        "broken_chain" in finding_types,
    )


def test_sequence_gap(entries) -> None:
    first, second, third = entries

    from backend.engines.provenance.audit_trail import AuditEntry

    modified = AuditEntry(
        sequence=5,
        event_id=second.event_id,
        timestamp=second.timestamp,
        event_type=second.event_type,
        source_engine=second.source_engine,
        affected_asset=second.affected_asset,
        payload_digest=second.payload_digest,
        previous_entry_hash=first.entry_hash,
        entry_hash=second.entry_hash,
    )

    result = verify_audit_chain(
        [first, modified, third]
    )

    finding_types = {
        item["type"]
        for item in result["findings"]
    }

    check(
        "11 sequence discontinuity detected",
        "sequence_discontinuity" in finding_types,
    )


def test_event_reuse(entries) -> None:
    first = entries[0]

    reused = create_audit_entry(
        sequence=2,
        event_type="different_event",
        source_engine="C4",
        affected_asset="model",
        payload={"changed": True},
        previous_entry_hash=first.entry_hash,
        event_id=first.event_id,
        timestamp="2026-09-29T13:00:00+00:00",
    )

    result = verify_audit_chain(
        [first, reused]
    )

    finding_types = {
        item["type"]
        for item in result["findings"]
    }

    check(
        "12 event ID reuse detected",
        "event_id_reuse" in finding_types,
    )


def test_append() -> None:
    chain = []

    first = append_audit_entry(
        chain,
        event_type="scan_started",
        source_engine="system",
        affected_asset="dataset",
        payload={"dataset": "demo"},
        event_id="append-event-1",
        timestamp="2026-09-29T14:00:00+00:00",
    )

    chain.append(first)

    second = append_audit_entry(
        chain,
        event_type="finding_created",
        source_engine="C3",
        affected_asset="dataset",
        payload={"severity": "high"},
        event_id="append-event-2",
        timestamp="2026-09-29T14:01:00+00:00",
    )

    chain.append(second)

    result = verify_audit_chain(chain)

    check(
        "13 append helper works",
        result["valid"] is True,
    )

    check(
        "14 append sequence correct",
        second.sequence == 2,
    )

    check(
        "15 append previous hash correct",
        second.previous_entry_hash
        == first.entry_hash,
    )


def test_serialization(entries) -> None:
    entry = entries[0]

    encoded = audit_entry_to_json(entry)

    import json

    decoded = json.loads(encoded)

    restored = audit_entry_from_dict(decoded)

    check(
        "16 serialization round-trip",
        restored == entry,
    )


def test_empty_chain() -> None:
    result = verify_audit_chain([])

    check(
        "17 empty chain valid",
        result["valid"] is True,
    )

    check(
        "18 empty chain count",
        result["entry_count"] == 0,
    )


def main() -> int:
    global PASSED, FAILED

    print("=" * 72)
    print("TRACER-CV C4 — AUDIT TRAIL TESTS")
    print("=" * 72)

    test_creation()

    test_chain()

    # Rebuild entries locally for tests that depend on them
    _first = make_entry(1)
    _second = make_entry(2, _first.entry_hash)
    _third = make_entry(3, _second.entry_hash)
    entries = [_first, _second, _third]

    test_tampering(entries)
    test_broken_chain(entries)
    test_sequence_gap(entries)
    test_event_reuse(entries)
    test_append()
    test_serialization(entries)
    test_empty_chain()

    print("\n" + "=" * 72)
    print(
        f"Ran {PASSED + FAILED} tests: "
        f"{PASSED} passed, {FAILED} failed"
    )
    print("=" * 72)

    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
