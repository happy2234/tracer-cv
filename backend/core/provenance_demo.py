"""Deterministic synthetic C1 signed-provenance validation cases."""
from __future__ import annotations

import base64
import hashlib
from dataclasses import replace

from backend.engines.provenance.inference_provenance import (
    create_record, detect_replay, verify_chain, verify_record, digest_preprocessing,
)


def run_provenance_demonstration() -> dict:
    """Exercise C1's local hash, Ed25519, binding, chain and replay checks."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    raw = hashlib.sha256(b"TRACER-CV PS-26228 synthetic provenance demonstration key").digest()
    private = Ed25519PrivateKey.from_private_bytes(raw)
    private_b64 = base64.b64encode(raw).decode("ascii")
    public_b64 = base64.b64encode(private.public_key().public_bytes_raw()).decode("ascii")
    source = {"sequence": 1, "nonce": "demo-nonce-0001", "timestamp": "2030-01-01T00:00:00+00:00",
              "input_digest": hashlib.sha256(b"synthetic-input").hexdigest(), "model_id": "sha256:" + hashlib.sha256(b"synthetic-model").hexdigest(),
              "preprocessing_digest": digest_preprocessing({"resize": [32, 32], "color": "RGB"}),
              "output_digest": hashlib.sha256(b"synthetic-output").hexdigest()}
    record = create_record(**source, private_key_base64=private_b64)
    valid = verify_record(record, public_key_base64=public_b64)
    cases = [{"scenario_id": "C1-VALID-SIGNED", "expected_behavior": "VALID", "detected": valid["valid"] and valid["signature_valid"],
              "observed_behavior": "Hash, chain genesis, and Ed25519 signature verified" if valid["valid"] else "Verification failed",
              "evidence": valid, "original_record": record.as_dict(), "record": record.as_dict()},]
    invalid_signature = verify_record(replace(record, signature="invalid-signature"), public_key_base64=public_b64)
    cases.append({"scenario_id": "C1-INVALID-SIGNATURE", "expected_behavior": "SIGNATURE REJECTED",
                  "detected": not bool(invalid_signature.get("signature_valid")),
                  "observed_behavior": "Ed25519 verification rejected the altered signature",
                  "evidence": invalid_signature, "original_record": record.as_dict(), "record": replace(record, signature="invalid-signature").as_dict()})
    for case_id, field, substituted in (
        ("C1-OUTPUT-TAMPERING", "output_digest", "0" * 64),
        ("C1-INPUT-SUBSTITUTION", "input_digest", "1" * 64),
        ("C1-MODEL-SUBSTITUTION", "model_id", "sha256:" + "2" * 64),
    ):
        changed = replace(record, **{field: substituted})
        checked = verify_record(changed, public_key_base64=public_b64)
        cases.append({"scenario_id": case_id, "expected_behavior": "INVALID BINDING", "detected": not checked["valid"],
                      "observed_behavior": f"Stored {field} no longer matches signed record hash", "evidence": checked, "original_record": record.as_dict(), "record": changed.as_dict()})
    changed_link = replace(record, previous_record_hash="f" * 64)
    chain = verify_chain([changed_link], public_key_base64=public_b64)
    cases.append({"scenario_id": "C1-PREVIOUS-HASH-TAMPERING", "expected_behavior": "BROKEN CHAIN", "detected": not chain["valid"],
                  "observed_behavior": "Previous-record linkage failed verification", "evidence": chain, "original_record": record.as_dict(), "record": changed_link.as_dict()})
    replay = detect_replay(record, [record])
    cases.append({"scenario_id": "C1-REPLAY", "expected_behavior": "REPLAY DETECTED", "detected": replay["replay_detected"],
                  "observed_behavior": "Known record hash, nonce, and sequence reused" if replay["replay_detected"] else "No replay match",
                  "evidence": replay, "original_record": record.as_dict(), "record": record.as_dict()})
    return {"label": "SYNTHETIC VALIDATION DATA", "cases": cases,
            "limitations": ["Synthetic records do not represent operational inference events.", "The deterministic demonstration key must never be used to sign operational records.", "Integrity failures do not identify who caused them or why.", "Signature verification depends on the supplied public key being trusted."]}


__all__ = ["run_provenance_demonstration"]
