"""
TRACER-CV C5 — Assurance Report tests.
"""

import pytest

from backend.engines.risk.assurance_report import (
    build_assurance_report,
    build_findings_section,
    build_limitations,
    build_recommended_actions,
    count_severities,
    highest_severity,
    render_text_report,
    report_from_json,
    report_to_json,
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


def sample_findings():
    return [
        {
            "finding_id": "F-001",
            "category": "dataset_integrity",
            "severity": "high",
            "confidence": 0.91,
            "affected_asset": "dataset/demo",
            "title": "Repeated trigger-like pattern",
            "explanation": "Repeated localized pattern detected.",
            "evidence": {
                "count": 12,
                "digest": "abc123",
            },
            "recommended_action": (
                "Review affected samples."
            ),
            "limitations": [
                "Pattern evidence does not prove malicious intent."
            ],
            "source_engine": "A8",
        },
        {
            "finding_id": "F-002",
            "category": "distribution_shift",
            "severity": "medium",
            "confidence": 0.84,
            "affected_asset": "candidate/images",
            "title": "Brightness distribution shift",
            "explanation": "Candidate brightness differs from reference.",
            "evidence": {
                "brightness_distance": 0.42,
            },
            "recommended_action": (
                "Review acquisition conditions."
            ),
            "limitations": [
                "Shift may have benign operational causes."
            ],
            "source_engine": "C2",
        },
    ]


@pytest.fixture
def report():
    findings = sample_findings()
    return build_assurance_report(
        assessment_id="pytest-fixture-001",
        dataset={
            "engine": "A1-A8",
            "status": "assessed",
            "dataset_digest": "dataset-digest-123",
        },
        model={
            "engine": "B1-B4",
            "status": "assessed",
            "model_id": "sha256:" + ("a" * 64),
        },
        provenance={"valid": True, "entry_count": 3},
        shift={"shift_detected": True, "severity": "medium", "overall_shift_score": 0.42},
        findings=findings,
        audit={"valid": True, "entry_count": 5, "findings": []},
    )


def test_severity_helpers() -> None:
    findings = sample_findings()

    counts = count_severities(findings)

    check(
        "01 severity high count",
        counts["high"] == 1,
    )

    check(
        "02 severity medium count",
        counts["medium"] == 1,
    )

    check(
        "03 highest severity",
        highest_severity(findings) == "high",
    )


def test_findings_section() -> None:
    section = build_findings_section(
        sample_findings()
    )

    check(
        "04 finding count",
        section["count"] == 2,
    )

    check(
        "05 finding severity summary",
        section["highest_severity"] == "high",
    )

    check(
        "06 finding payload preserved",
        section["findings"][0]["finding_id"]
        == "F-001",
    )


def test_complete_report() -> None:
    findings = sample_findings()

    dataset = {
        "engine": "A1-A8",
        "status": "assessed",
        "dataset_digest": "dataset-digest-123",
    }

    model = {
        "engine": "B1-B4",
        "status": "assessed",
        "model_id": "sha256:" + ("a" * 64),
    }

    provenance = {
        "valid": True,
        "entry_count": 3,
    }

    shift = {
        "shift_detected": True,
        "severity": "medium",
        "overall_shift_score": 0.42,
    }

    audit = {
        "valid": True,
        "entry_count": 5,
        "findings": [],
    }

    report = build_assurance_report(
        assessment_id="demo-assessment-001",
        dataset=dataset,
        model=model,
        provenance=provenance,
        shift=shift,
        findings=findings,
        audit=audit,
    )

    check(
        "07 report created",
        isinstance(report, dict),
    )

    check(
        "08 assessment ID",
        report["assessment_id"]
        == "demo-assessment-001",
    )

    check(
        "09 report version",
        report["report_version"] == "c5-1.0",
    )

    check(
        "10 executive finding count",
        report["executive_summary"]["finding_count"]
        == 2,
    )

    check(
        "11 executive highest severity",
        report["executive_summary"][
            "highest_observed_severity"
        ] == "high",
    )

    check(
        "12 provenance status",
        report["inference_provenance"]["valid"]
        is True,
    )

    check(
        "13 audit status",
        report["audit_trail"]["valid"]
        is True,
    )

    check(
        "14 shift status",
        report["distribution_shift"]["shift_detected"]
        is True,
    )

    check(
        "15 report digest exists",
        len(report["report_digest"]) == 64,
    )


def test_determinism() -> None:
    kwargs = {
        "assessment_id": "deterministic-001",
        "dataset": {
            "digest": "dataset-x",
        },
        "model": {
            "model_id": "model-x",
        },
        "provenance": {
            "valid": True,
        },
        "shift": {
            "shift_detected": False,
            "severity": "none",
        },
        "findings": sample_findings(),
        "audit": {
            "valid": True,
            "entry_count": 2,
            "findings": [],
        },
    }

    first = build_assurance_report(**kwargs)
    second = build_assurance_report(**kwargs)

    check(
        "16 report deterministic",
        first == second,
    )

    check(
        "17 report digest deterministic",
        first["report_digest"]
        == second["report_digest"],
    )


def test_not_assessed() -> None:
    report = build_assurance_report(
        assessment_id="partial-001",
    )

    check(
        "18 missing dataset marked not assessed",
        report["dataset_integrity"]["status"]
        == "not_assessed",
    )

    check(
        "19 missing model marked not assessed",
        report["model_integrity"]["status"]
        == "not_assessed",
    )

    check(
        "20 missing provenance marked not assessed",
        report["inference_provenance"]["status"]
        == "not_assessed",
    )

    check(
        "21 missing audit marked not assessed",
        report["audit_trail"]["status"]
        == "not_assessed",
    )


def test_recommended_actions() -> None:
    findings = sample_findings()

    actions = build_recommended_actions(
        findings,
        provenance={
            "valid": False,
        },
        audit={
            "valid": False,
        },
    )

    check(
        "22 high finding action",
        any(
            "high-severity" in action.lower()
            for action in actions
        ),
    )

    check(
        "23 provenance action",
        any(
            "provenance" in action.lower()
            for action in actions
        ),
    )

    check(
        "24 audit action",
        any(
            "audit" in action.lower()
            for action in actions
        ),
    )


def test_limitations() -> None:
    limitations = build_limitations(
        [
            "Custom project limitation."
        ]
    )

    check(
        "25 default limitations exist",
        len(limitations) >= 7,
    )

    check(
        "26 custom limitation included",
        "Custom project limitation." in limitations,
    )


def test_serialization(report) -> None:
    encoded = report_to_json(
        report,
        indent=None,
    )

    restored = report_from_json(encoded)

    check(
        "27 report JSON round-trip",
        restored == report,
    )


def test_text_report(report) -> None:
    text = render_text_report(report)

    check(
        "28 text report contains title",
        "TRACER-CV ASSURANCE REPORT" in text,
    )

    check(
        "29 text report contains findings",
        "F-001" in text,
    )

    check(
        "30 text report contains digest",
        report["report_digest"] in text,
    )


def main() -> int:
    global PASSED, FAILED

    print("=" * 72)
    print("TRACER-CV C5 — ASSURANCE REPORT TESTS")
    print("=" * 72)

    test_severity_helpers()
    test_findings_section()

    test_complete_report()

    # Rebuild report locally for tests that depend on it
    report = build_assurance_report(
        assessment_id="demo-assessment-001",
        dataset={"engine": "A1-A8", "status": "assessed", "dataset_digest": "dataset-digest-123"},
        model={"engine": "B1-B4", "status": "assessed", "model_id": "sha256:" + "a" * 64},
        provenance={"valid": True, "entry_count": 3},
        shift={"shift_detected": True, "severity": "medium", "overall_shift_score": 0.42},
        findings=sample_findings(),
        audit={"valid": True, "entry_count": 5, "findings": []},
    )

    test_determinism()
    test_not_assessed()
    test_recommended_actions()
    test_limitations()
    test_serialization(report)
    test_text_report(report)

    print("\n" + "=" * 72)
    print(
        f"Ran {PASSED + FAILED} tests: "
        f"{PASSED} passed, {FAILED} failed"
    )
    print("=" * 72)

    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
