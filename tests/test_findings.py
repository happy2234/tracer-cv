"""
TRACER-CV C3 — Findings & Evidence tests.
"""

from backend.engines.risk.findings import (
    aggregate_findings,
    findings_from_dataset,
    findings_from_model,
    findings_from_provenance,
    findings_from_shift,
)


def test_dataset_findings_accept_persisted_phase6_a2_shape():
    groups = [{"count": 2, "files": ["one.png", "two.png"], "sha256": "abc123"}]
    findings = findings_from_dataset({"A2_exact_duplicates": {"groups": groups}})
    assert len(findings) == 1
    assert findings[0].source_engine == "A2"
    assert findings[0].evidence[0]["groups"] == groups


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


def test_shift_finding() -> None:
    result = {
        "status": "completed",
        "severity": "high",
        "overall_shift": 0.42,
        "shifted_features": [
            {
                "feature": "brightness",
                "distance": 0.30,
                "threshold": 0.08,
                "shifted": True,
            }
        ],
        "distances": {
            "scalar": {
                "brightness": 0.30,
            }
        },
        "anomalous_images": [],
    }

    findings = findings_from_shift(result)

    check(
        "01 shift finding generated",
        len(findings) == 1,
    )

    check(
        "02 shift severity preserved",
        findings[0].severity == "high",
    )

    check(
        "03 shift evidence present",
        len(findings[0].evidence) >= 1,
    )


def test_trigger_finding() -> None:
    result = {
        "candidate_trigger_count": 1,
        "assessment": "candidate_trigger_like_behavior",
    }

    findings = findings_from_model(result)

    check(
        "04 trigger finding generated",
        len(findings) == 1,
    )

    check(
        "05 trigger finding high severity",
        findings[0].severity == "high",
    )

    check(
        "06 trigger limitations present",
        len(findings[0].limitations) >= 2,
    )


def test_provenance_finding() -> None:
    result = {
        "valid": False,
        "findings": [
            {
                "type": "broken_chain",
                "index": 2,
                "sequence": 3,
                "message": "Previous-record hash does not match.",
            }
        ],
    }

    findings = findings_from_provenance(result)

    check(
        "07 provenance finding generated",
        len(findings) == 1,
    )

    check(
        "08 provenance finding high severity",
        findings[0].severity == "high",
    )

    check(
        "09 provenance source is C1",
        findings[0].source_engine == "C1",
    )


def test_aggregation() -> None:
    result = aggregate_findings(
        model_results=[
            {
                "candidate_trigger_count": 1,
                "assessment": "candidate_trigger_like_behavior",
            }
        ],
        provenance_results=[
            {
                "valid": False,
                "findings": [
                    {
                        "type": "nonce_reuse",
                        "message": "Nonce reused.",
                    }
                ],
            }
        ],
        shift_results=[
            {
                "status": "completed",
                "severity": "medium",
                "overall_shift": 0.25,
                "shifted_features": [],
                "distances": {},
                "anomalous_images": [],
            }
        ],
    )

    check(
        "10 aggregation completed",
        result["status"] == "completed",
    )

    check(
        "11 three findings aggregated",
        result["finding_count"] == 3,
    )

    check(
        "12 overall severity high",
        result["overall_severity"] == "high",
    )

    check(
        "13 severity counts correct",
        result["severity_counts"]["high"] == 1
        and result["severity_counts"]["medium"] == 2,
    )

    check(
        "14 evidence digest generated",
        len(result["evidence_digest"]) == 64,
    )


def test_empty() -> None:
    result = aggregate_findings()

    check(
        "15 empty aggregation completed",
        result["status"] == "completed",
    )

    check(
        "16 empty finding count",
        result["finding_count"] == 0,
    )

    check(
        "17 empty severity",
        result["overall_severity"] == "none",
    )


def test_deterministic() -> None:
    kwargs = {
        "model_results": [
            {
                "candidate_trigger_count": 1,
                "assessment": "candidate_trigger_like_behavior",
            }
        ]
    }

    first = aggregate_findings(**kwargs)
    second = aggregate_findings(**kwargs)

    check(
        "18 deterministic evidence digest",
        first["evidence_digest"]
        == second["evidence_digest"],
    )


def main() -> int:
    global PASSED, FAILED

    print("=" * 72)
    print("TRACER-CV C3 — FINDINGS & EVIDENCE TESTS")
    print("=" * 72)

    test_shift_finding()
    test_trigger_finding()
    test_provenance_finding()
    test_aggregation()
    test_empty()
    test_deterministic()

    print("\n" + "=" * 72)
    print(
        f"Ran {PASSED + FAILED} tests: "
        f"{PASSED} passed, {FAILED} failed"
    )
    print("=" * 72)

    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
