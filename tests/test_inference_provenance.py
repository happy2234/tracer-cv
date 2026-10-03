"""
Standalone tests for TRACER-CV C1 — Inference Provenance.
"""

from __future__ import annotations

import copy
import json
import pytest


from backend.engines.provenance.inference_provenance import (
    GENESIS_HASH,
    ProvenanceRecord,
    canonical_json,
    compute_record_hash,
    create_inference_record,
    create_record,
    detect_replay,
    digest_input,
    digest_output,
    digest_preprocessing,
    generate_signing_keypair,
    record_from_dict,
    record_to_json,
    verify_chain,
    verify_record,
    verify_record_signature,
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


@pytest.fixture
def record():
    return create_record(
        sequence=1,
        nonce="pytest-fixture-nonce",
        input_digest=digest_input(b"image-1"),
        model_id="sha256:" + "a" * 64,
        preprocessing_digest=digest_preprocessing({"resize": [224, 224]}),
        output_digest=digest_output(b"output-1"),
        timestamp="2026-09-29T12:00:00+00:00",
    )


@pytest.fixture
def records():
    first = create_record(
        sequence=1,
        nonce="pytest-chain-1",
        input_digest=digest_input(b"image-1"),
        model_id="sha256:" + "d" * 64,
        preprocessing_digest=digest_preprocessing({"resize": [224, 224]}),
        output_digest=digest_output(b"output-1"),
        timestamp="2026-09-29T12:00:01+00:00",
    )
    second = create_record(
        sequence=2,
        nonce="pytest-chain-2",
        input_digest=digest_input(b"image-2"),
        model_id="sha256:" + "d" * 64,
        preprocessing_digest=digest_preprocessing({"resize": [224, 224]}),
        output_digest=digest_output(b"output-2"),
        previous_record_hash=first.record_hash,
        timestamp="2026-09-29T12:00:02+00:00",
    )
    third = create_record(
        sequence=3,
        nonce="pytest-chain-3",
        input_digest=digest_input(b"image-3"),
        model_id="sha256:" + "d" * 64,
        preprocessing_digest=digest_preprocessing({"resize": [224, 224]}),
        output_digest=digest_output(b"output-3"),
        previous_record_hash=second.record_hash,
        timestamp="2026-09-29T12:00:03+00:00",
    )
    return [first, second, third]


def test_canonical_json_deterministic() -> None:
    a = {"b": 2, "a": 1}
    b = {"a": 1, "b": 2}

    check(
        "01 canonical JSON deterministic",
        canonical_json(a) == canonical_json(b),
    )


def test_digest_deterministic() -> None:
    data = b"TRACER-CV test input"

    check(
        "02 input digest deterministic",
        digest_input(data) == digest_input(data),
    )

    check(
        "03 output digest deterministic",
        digest_output(data) == digest_output(data),
    )


def test_preprocessing_digest() -> None:
    config_a = {
        "resize": [224, 224],
        "normalize": True,
        "mean": [0.5, 0.5, 0.5],
    }

    config_b = {
        "normalize": True,
        "mean": [0.5, 0.5, 0.5],
        "resize": [224, 224],
    }

    config_c = {
        "resize": [256, 256],
        "normalize": True,
        "mean": [0.5, 0.5, 0.5],
    }

    check(
        "04 equivalent preprocessing has same digest",
        digest_preprocessing(config_a)
        == digest_preprocessing(config_b),
    )

    check(
        "05 changed preprocessing has different digest",
        digest_preprocessing(config_a)
        != digest_preprocessing(config_c),
    )


def test_record_creation() -> None:
    record = create_record(
        sequence=1,
        nonce="nonce-0001",
        input_digest=digest_input(b"image-1"),
        model_id="sha256:" + "a" * 64,
        preprocessing_digest=digest_preprocessing(
            {"resize": [224, 224]}
        ),
        output_digest=digest_output(b"output-1"),
    )

    check(
        "06 record created",
        isinstance(record, ProvenanceRecord),
    )

    check(
        "07 genesis previous hash",
        record.previous_record_hash == GENESIS_HASH,
    )

    check(
        "08 record hash length",
        len(record.record_hash) == 64,
    )


def test_record_verification(record: ProvenanceRecord) -> None:
    result = verify_record(record)

    check(
        "09 valid record verifies",
        result["valid"] is True,
    )

    check(
        "10 record hash verifies",
        result["hash_valid"] is True,
    )


def test_tamper_detection(record: ProvenanceRecord) -> None:
    tampered = copy.copy(record)

    tampered = ProvenanceRecord(
        sequence=tampered.sequence,
        nonce=tampered.nonce,
        timestamp=tampered.timestamp,
        input_digest=digest_input(b"ATTACKER-CHANGED-INPUT"),
        model_id=tampered.model_id,
        preprocessing_digest=tampered.preprocessing_digest,
        output_digest=tampered.output_digest,
        previous_record_hash=tampered.previous_record_hash,
        record_hash=tampered.record_hash,
        signature=tampered.signature,
    )

    result = verify_record(tampered)

    check(
        "11 input tampering detected",
        result["valid"] is False,
    )

    check(
        "12 tampered hash rejected",
        result["hash_valid"] is False,
    )


def test_record_hash_binding() -> None:
    common = dict(
        sequence=1,
        nonce="same-nonce",
        input_digest=digest_input(b"image"),
        model_id="sha256:" + "b" * 64,
        timestamp="2026-09-29T12:00:00+00:00",

        preprocessing_digest=digest_preprocessing(
            {"resize": [224, 224]}
        ),
        output_digest=digest_output(b"output"),
        previous_record_hash=GENESIS_HASH,
    )

    hash_a = compute_record_hash(**common)

    hash_b = compute_record_hash(
        **{
            **common,
            "output_digest": digest_output(b"changed-output"),
        }
    )

    check(
        "13 output is bound to record hash",
        hash_a != hash_b,
    )


def test_inference_convenience_api() -> None:
    record = create_inference_record(
        sequence=1,
        input_bytes=b"image-data",
        model_id="sha256:" + "c" * 64,
        preprocessing_config={
            "resize": [224, 224],
            "normalize": True,
        },
        output_bytes=b"prediction-output",
        nonce="inference-nonce-1",
    )

    check(
        "14 inference record created",
        record.sequence == 1,
    )

    check(
        "15 input is bound",
        record.input_digest == digest_input(b"image-data"),
    )

    check(
        "16 output is bound",
        record.output_digest == digest_output(
            b"prediction-output"
        ),
    )


def test_chain() -> None:
    first = create_record(
        sequence=1,
        nonce="chain-nonce-1",
        input_digest=digest_input(b"image-1"),
        model_id="sha256:" + "d" * 64,
        preprocessing_digest=digest_preprocessing(
            {"resize": [224, 224]}
        ),
        output_digest=digest_output(b"output-1"),
    )

    second = create_record(
        sequence=2,
        nonce="chain-nonce-2",
        input_digest=digest_input(b"image-2"),
        model_id="sha256:" + "d" * 64,
        preprocessing_digest=digest_preprocessing(
            {"resize": [224, 224]}
        ),
        output_digest=digest_output(b"output-2"),
        previous_record_hash=first.record_hash,
    )

    third = create_record(
        sequence=3,
        nonce="chain-nonce-3",
        input_digest=digest_input(b"image-3"),
        model_id="sha256:" + "d" * 64,
        preprocessing_digest=digest_preprocessing(
            {"resize": [224, 224]}
        ),
        output_digest=digest_output(b"output-3"),
        previous_record_hash=second.record_hash,
    )

    result = verify_chain([first, second, third])

    check(
        "17 valid three-record chain",
        result["valid"] is True,
    )

    check(
        "18 chain record count",
        result["record_count"] == 3,
    )


def test_broken_chain(records: list[ProvenanceRecord]) -> None:
    first, second, third = records

    broken_second = ProvenanceRecord(
        sequence=second.sequence,
        nonce=second.nonce,
        timestamp=second.timestamp,
        input_digest=second.input_digest,
        model_id=second.model_id,
        preprocessing_digest=second.preprocessing_digest,
        output_digest=second.output_digest,
        previous_record_hash="f" * 64,
        record_hash=second.record_hash,
        signature=second.signature,
    )

    result = verify_chain(
        [first, broken_second, third]
    )

    finding_types = {
        finding["type"]
        for finding in result["findings"]
    }

    check(
        "19 broken chain detected",
        result["valid"] is False,
    )

    check(
        "20 broken-chain finding present",
        "broken_chain" in finding_types,
    )


def test_sequence_discontinuity(records: list[ProvenanceRecord]) -> None:
    first, second, third = records

    modified_second = create_record(
        sequence=4,
        nonce=second.nonce,
        input_digest=second.input_digest,
        model_id=second.model_id,
        preprocessing_digest=second.preprocessing_digest,
        output_digest=second.output_digest,
        previous_record_hash=first.record_hash,
    )

    result = verify_chain(
        [first, modified_second, third]
    )

    finding_types = {
        finding["type"]
        for finding in result["findings"]
    }

    check(
        "21 sequence discontinuity detected",
        "sequence_discontinuity" in finding_types,
    )


def test_nonce_reuse(records: list[ProvenanceRecord]) -> None:
    first, second, _ = records

    reused = create_record(
        sequence=2,
        nonce=first.nonce,
        input_digest=digest_input(b"another-image"),
        model_id=first.model_id,
        preprocessing_digest=first.preprocessing_digest,
        output_digest=digest_output(b"another-output"),
        previous_record_hash=first.record_hash,
    )

    result = verify_chain(
        [first, reused]
    )

    finding_types = {
        finding["type"]
        for finding in result["findings"]
    }

    check(
        "22 nonce reuse detected",
        "nonce_reuse" in finding_types,
    )


def test_replay_detection(records: list[ProvenanceRecord]) -> None:
    original = records[0]

    result = detect_replay(
        original,
        records,
    )

    check(
        "23 replay detected",
        result["replay_detected"] is True,
    )

    check(
        "24 replay hash match",
        0 in result["record_hash_matches"],
    )


def test_non_replay(records: list[ProvenanceRecord]) -> None:
    new_record = create_record(
        sequence=10,
        nonce="brand-new-nonce",
        input_digest=digest_input(b"new-image"),
        model_id="sha256:" + "e" * 64,
        preprocessing_digest=digest_preprocessing(
            {"resize": [128, 128]}
        ),
        output_digest=digest_output(b"new-output"),
    )

    result = detect_replay(
        new_record,
        records,
    )

    check(
        "25 new record is not replay",
        result["replay_detected"] is False,
    )


def test_ed25519() -> None:
    private_key, public_key = generate_signing_keypair()

    record = create_record(
        sequence=1,
        nonce="signed-nonce",
        input_digest=digest_input(b"signed-image"),
        model_id="sha256:" + "f" * 64,
        preprocessing_digest=digest_preprocessing(
            {"resize": [224, 224]}
        ),
        output_digest=digest_output(b"signed-output"),
        private_key_base64=private_key,
    )

    result = verify_record(
        record,
        public_key_base64=public_key,
    )

    check(
        "26 signed record verifies",
        result["valid"] is True,
    )

    check(
        "27 signature checked",
        result["signature_checked"] is True,
    )

    check(
        "28 signature valid",
        result["signature_valid"] is True,
    )


def test_invalid_signature(record: ProvenanceRecord) -> None:
    _, wrong_public_key = generate_signing_keypair()

    result = verify_record(
        record,
        public_key_base64=wrong_public_key,
    )

    check(
        "29 wrong public key rejected",
        result["valid"] is False,
    )

    check(
        "30 invalid signature detected",
        result["signature_valid"] is False,
    )


def test_serialization(record: ProvenanceRecord) -> None:
    encoded = record_to_json(record)

    decoded = json.loads(encoded)

    restored = record_from_dict(decoded)

    check(
        "31 JSON serialization round-trip",
        restored == record,
    )


def test_empty_chain() -> None:
    result = verify_chain([])

    check(
        "32 empty chain is valid",
        result["valid"] is True,
    )

    check(
        "33 empty chain count",
        result["record_count"] == 0,
    )


def main() -> int:
    global PASSED, FAILED

    print("=" * 72)
    print("TRACER-CV C1 — INFERENCE PROVENANCE TESTS")
    print("=" * 72)

    # Reconstruct objects needed by dependent tests directly — test functions
    # no longer return values so that pytest does not emit PytestReturnNotNoneWarning.
    record = create_record(
        sequence=1,
        nonce="nonce-0001",
        input_digest=digest_input(b"image-1"),
        model_id="sha256:" + "a" * 64,
        preprocessing_digest=digest_preprocessing({"resize": [224, 224]}),
        output_digest=digest_output(b"output-1"),
    )
    test_record_creation()
    test_record_verification(record)
    test_tamper_detection(record)
    test_record_hash_binding()

    inference_record = create_inference_record(
        sequence=1,
        input_bytes=b"image-data",
        model_id="sha256:" + "c" * 64,
        preprocessing_config={"resize": [224, 224], "normalize": True},
        output_bytes=b"prediction-output",
        nonce="inference-nonce-1",
    )
    test_inference_convenience_api()

    first = create_record(
        sequence=1, nonce="chain-nonce-1",
        input_digest=digest_input(b"image-1"), model_id="sha256:" + "d" * 64,
        preprocessing_digest=digest_preprocessing({"resize": [224, 224]}),
        output_digest=digest_output(b"output-1"),
    )
    second = create_record(
        sequence=2, nonce="chain-nonce-2",
        input_digest=digest_input(b"image-2"), model_id="sha256:" + "d" * 64,
        preprocessing_digest=digest_preprocessing({"resize": [224, 224]}),
        output_digest=digest_output(b"output-2"),
        previous_record_hash=first.record_hash,
    )
    third = create_record(
        sequence=3, nonce="chain-nonce-3",
        input_digest=digest_input(b"image-3"), model_id="sha256:" + "d" * 64,
        preprocessing_digest=digest_preprocessing({"resize": [224, 224]}),
        output_digest=digest_output(b"output-3"),
        previous_record_hash=second.record_hash,
    )
    records = [first, second, third]
    test_chain()
    test_broken_chain(records)
    test_sequence_discontinuity(records)
    test_nonce_reuse(records)
    test_replay_detection(records)
    test_non_replay(records)

    private_key, public_key = generate_signing_keypair()
    signed_record = create_record(
        sequence=1, nonce="signed-nonce",
        input_digest=digest_input(b"signed-image"),
        model_id="sha256:" + "f" * 64,
        preprocessing_digest=digest_preprocessing({"resize": [224, 224]}),
        output_digest=digest_output(b"signed-output"),
        private_key_base64=private_key,
    )
    test_ed25519()
    test_invalid_signature(signed_record)

    test_serialization(inference_record)
    test_empty_chain()

    print("\n" + "=" * 72)
    print(f"Ran {PASSED + FAILED} tests: {PASSED} passed, {FAILED} failed")
    print("=" * 72)

    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
