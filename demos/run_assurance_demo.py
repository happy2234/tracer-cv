"""
TRACER-CV End-to-End Assurance Demo

Runs a controlled offline demonstration of the assurance pipeline.

The demo intentionally uses synthetic evidence so it can be executed
without classified, operational, or service-generated data.
"""

from __future__ import annotations

import json
from pathlib import Path

from backend.engines.risk.assurance_report import (
    build_assurance_report,
    render_text_report,
    report_to_json,
)
from backend.engines.provenance.audit_trail import (
    append_audit_entry,
    verify_audit_chain,
)


ROOT = Path(__file__).resolve().parents[1]

REPORTS_DIR = ROOT / "reports"
EVIDENCE_DIR = REPORTS_DIR / "evidence"


def build_demo_dataset_result():
    return {
        "engine": "A1-A8",
        "status": "assessed",
        "dataset_id": "DEMO-EUROSAT-001",
        "dataset_digest": (
            "demo-dataset-sha256-"
            + "a" * 16
        ),
        "merkle_root": (
            "demo-merkle-root-"
            + "b" * 16
        ),
        "checks": {
            "manifest": "passed",
            "exact_duplicates": "finding",
            "near_duplicates": "finding",
            "ood_reference": "finding",
            "label_consistency": "finding",
            "contributor_risk": "finding",
            "metadata_consistency": "finding",
            "trigger_like_patterns": "finding",
        },
    }


def build_demo_model_result():
    return {
        "engine": "B1-B4",
        "status": "assessed",
        "model_id": (
            "sha256:"
            + "c" * 64
        ),
        "format": "torchscript",
        "behavioral_fingerprint": {
            "status": "assessed",
            "probe_count": 8,
            "reference_comparison": "deviation_observed",
        },
        "parameter_statistics": {
            "status": "assessed",
            "reference_comparison": "anomaly_observed",
        },
        "trigger_search": {
            "status": "assessed",
            "candidate_trigger_like": True,
            "patch_size": "8x8",
            "affected_samples": 6,
            "target_consistency": 1.0,
            "interpretation": (
                "Trigger-like behavior requires analyst review; "
                "it does not prove a backdoor."
            ),
        },
    }


def build_demo_provenance_result():
    return {
        "valid": True,
        "entry_count": 3,
        "sequence_continuity": True,
        "nonce_reuse": False,
        "signature_status": "verified",
    }


def build_demo_shift_result():
    return {
        "shift_detected": True,
        "severity": "medium",
        "overall_shift_score": 0.47,
        "shifted_features": [
            "brightness",
            "contrast",
            "saturation",
        ],
        "anomalous_image_count": 7,
        "interpretation": (
            "Observed distribution shift may reflect acquisition "
            "conditions or other changes; it does not by itself "
            "establish malicious manipulation."
        ),
    }


def build_demo_findings():
    return [
        {
            "finding_id": "DEMO-A2-001",
            "category": "dataset_integrity",
            "severity": "medium",
            "confidence": 0.96,
            "affected_asset": "DEMO-EUROSAT-001",
            "title": "Exact duplicate group detected",
            "explanation": (
                "Multiple dataset entries resolve to the same "
                "content digest."
            ),
            "evidence": {
                "duplicate_groups": 1,
                "affected_files": 2,
            },
            "recommended_action": (
                "Review duplicate provenance and contributor records."
            ),
            "limitations": [
                "Duplication alone does not establish malicious intent."
            ],
            "source_engine": "A2",
        },
        {
            "finding_id": "DEMO-A5-001",
            "category": "label_consistency",
            "severity": "high",
            "confidence": 0.91,
            "affected_asset": "DEMO-EUROSAT-001",
            "title": "Conflicting labels detected",
            "explanation": (
                "Near-duplicate samples have conflicting class labels."
            ),
            "evidence": {
                "conflicting_pairs": 2,
            },
            "recommended_action": (
                "Inspect the affected samples and source annotations."
            ),
            "limitations": [
                "Automated label consistency checks can produce "
                "false positives."
            ],
            "source_engine": "A5",
        },
        {
            "finding_id": "DEMO-A8-001",
            "category": "trigger_like_pattern",
            "severity": "high",
            "confidence": 0.88,
            "affected_asset": "DEMO-EUROSAT-001",
            "title": "Repeated localized pattern detected",
            "explanation": (
                "A repeated localized image pattern was detected "
                "across samples."
            ),
            "evidence": {
                "repeated_patch_count": 12,
                "spatial_concentration": 0.84,
            },
            "recommended_action": (
                "Review affected samples and preserve the pattern evidence."
            ),
            "limitations": [
                "Pattern evidence does not prove a poisoning attack."
            ],
            "source_engine": "A8",
        },
        {
            "finding_id": "DEMO-B4-001",
            "category": "model_integrity",
            "severity": "high",
            "confidence": 0.86,
            "affected_asset": "DEMO-MODEL-001",
            "title": "Trigger-like model behavior observed",
            "explanation": (
                "A localized patch produced repeated prediction changes "
                "during controlled trigger search."
            ),
            "evidence": {
                "patch_size": "8x8",
                "class_change_rate": 1.0,
                "target_consistency": 1.0,
                "affected_samples": 6,
            },
            "recommended_action": (
                "Compare the model against a trusted reference and "
                "inspect the trigger-search evidence."
            ),
            "limitations": [
                "Trigger-like behavior is an indicator for analyst review, "
                "not proof of a backdoor."
            ],
            "source_engine": "B4",
        },
        {
            "finding_id": "DEMO-C2-001",
            "category": "distribution_shift",
            "severity": "medium",
            "confidence": 0.84,
            "affected_asset": "DEMO-CANDIDATE-IMAGES",
            "title": "Distribution shift detected",
            "explanation": (
                "Candidate imagery differs from the reference distribution "
                "in several appearance features."
            ),
            "evidence": {
                "overall_shift_score": 0.47,
                "shifted_features": [
                    "brightness",
                    "contrast",
                    "saturation",
                ],
            },
            "recommended_action": (
                "Review acquisition conditions and determine whether "
                "the shift is operationally expected."
            ),
            "limitations": [
                "Distribution shift does not by itself establish "
                "malicious manipulation."
            ],
            "source_engine": "C2",
        },
    ]


def create_demo_audit_chain(findings):
    chain = []

    chain.append(
        append_audit_entry(
            chain,
            event_type="assessment_started",
            source_engine="TRACER-CV",
            affected_asset="DEMO-EUROSAT-001",
            payload={
                "assessment_id": "TRACER-DEMO-001",
            },
            event_id="demo-event-001",
            timestamp="2026-09-29T15:00:00+00:00",
        )
    )

    chain.append(
        append_audit_entry(
            chain,
            event_type="findings_generated",
            source_engine="C3",
            affected_asset="DEMO-EUROSAT-001",
            payload={
                "finding_count": len(findings),
                "finding_ids": [
                    finding["finding_id"]
                    for finding in findings
                ],
            },
            event_id="demo-event-002",
            timestamp="2026-09-29T15:01:00+00:00",
        )
    )

    chain.append(
        append_audit_entry(
            chain,
            event_type="assurance_report_generated",
            source_engine="C5",
            affected_asset="TRACER-DEMO-001",
            payload={
                "report": "pending",
            },
            event_id="demo-event-003",
            timestamp="2026-09-29T15:02:00+00:00",
        )
    )

    return chain


def save_json(path: Path, data) -> None:
    path.write_text(
        json.dumps(
            data,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


def main() -> int:
    print("=" * 72)
    print("TRACER-CV — END-TO-END ASSURANCE DEMO")
    print("=" * 72)

    REPORTS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    EVIDENCE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    print("\n[1/6] Preparing controlled dataset assessment...")
    dataset = build_demo_dataset_result()
    print("      A1-A8 dataset assessment ready")

    print("\n[2/6] Preparing controlled model assessment...")
    model = build_demo_model_result()
    print("      B1-B4 model assessment ready")

    print("\n[3/6] Verifying inference provenance...")
    provenance = build_demo_provenance_result()

    print(
        "      Provenance:",
        "VALID" if provenance["valid"] else "INVALID",
    )

    print("\n[4/6] Assessing distribution shift...")
    shift = build_demo_shift_result()

    print(
        "      Shift detected:",
        shift["shift_detected"],
    )

    print("\n[5/6] Generating findings and audit trail...")
    findings = build_demo_findings()

    audit_chain = create_demo_audit_chain(
        findings
    )

    audit_result = verify_audit_chain(
        audit_chain
    )

    print(
        "      Findings:",
        len(findings),
    )

    print(
        "      Audit chain:",
        "VALID" if audit_result["valid"] else "INVALID",
    )

    print("\n[6/6] Generating final assurance report...")

    report = build_assurance_report(
        assessment_id="TRACER-DEMO-001",
        dataset=dataset,
        model=model,
        provenance=provenance,
        shift=shift,
        findings=findings,
        audit=audit_result,
    )

    json_path = REPORTS_DIR / "tracer_cv_assurance_report.json"
    text_path = REPORTS_DIR / "tracer_cv_assurance_report.txt"
    audit_path = EVIDENCE_DIR / "audit_chain.json"

    save_json(
        json_path,
        report,
    )

    text_path.write_text(
        render_text_report(report),
        encoding="utf-8",
    )

    save_json(
        audit_path,
        {
            "engine": "C4",
            "entry_count": len(audit_chain),
            "verification": audit_result,
            "entries": [
                entry.as_dict()
                for entry in audit_chain
            ],
        },
    )

    print("\n" + "=" * 72)
    print("DEMO COMPLETE")
    print("=" * 72)

    print(
        f"\nAssessment ID: "
        f"{report['assessment_id']}"
    )

    print(
        "Findings: "
        f"{report['executive_summary']['finding_count']}"
    )

    print(
        "Highest severity: "
        f"{report['executive_summary']['highest_observed_severity']}"
    )

    print(
        "Provenance: "
        f"{report['executive_summary']['provenance_chain_valid']}"
    )

    print(
        "Audit trail: "
        f"{report['executive_summary']['audit_chain_valid']}"
    )

    print(
        "Distribution shift: "
        f"{report['executive_summary']['distribution_shift_detected']}"
    )

    print(
        "\nReport digest:"
    )

    print(
        report["report_digest"]
    )

    print("\nGenerated files:")

    print(
        f"  {json_path.relative_to(ROOT)}"
    )

    print(
        f"  {text_path.relative_to(ROOT)}"
    )

    print(
        f"  {audit_path.relative_to(ROOT)}"
    )

    print("\n" + "=" * 72)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
