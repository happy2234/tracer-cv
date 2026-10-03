"""
TRACER-CV — Full End-to-End Assurance Demo

Runs the existing real engines A1-A8, B1-B4 and connects their outputs to
C1-C5 to produce one analyst-facing assurance package.

Everything is local/offline and uses the existing controlled demo assets.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

ASSET_ROOT = ROOT / "demos" / "assets"
DATASET_ROOT = ASSET_ROOT / "dataset"

REFERENCE_DIR = DATASET_ROOT / "reference"
CANDIDATE_DIR = DATASET_ROOT / "candidate"
LABELS_DIR = DATASET_ROOT / "labels"

MODEL_PATH = ASSET_ROOT / "model" / "demo_model.pt"

REPORT_ROOT = ROOT / "reports"
ENGINE_ROOT = REPORT_ROOT / "engine_results"
EVIDENCE_ROOT = REPORT_ROOT / "evidence"
from backend.core.local_storage import ReportStore


def save_json(path: Path, value: Any) -> None:
    relative = path.resolve().relative_to(REPORT_ROOT.resolve())
    ReportStore(REPORT_ROOT).save(
        relative.as_posix(),
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            default=str,
        ).encode("utf-8"),
        overwrite=True,
    )


def import_engines():
    from backend.engines.dataset.manifest import build_manifest
    from backend.engines.dataset.duplicates import find_exact_duplicates
    from backend.engines.dataset.near_duplicates import find_near_duplicates
    from backend.engines.dataset.ood import assess_ood

    # Locate A5-A8 without assuming their filenames.
    import importlib
    import pkgutil
    import backend.engines.dataset as dataset_pkg

    dataset_symbols = {}

    required_dataset = {
        "assess_label_consistency",
        "assess_contributor_risk",
        "assess_metadata_consistency",
        "analyze_poison_trigger",
    }

    for info in pkgutil.walk_packages(
        dataset_pkg.__path__,
        prefix=dataset_pkg.__name__ + ".",
    ):
        try:
            module = importlib.import_module(info.name)
        except Exception:
            continue

        for name in required_dataset:
            if name not in dataset_symbols and hasattr(module, name):
                dataset_symbols[name] = getattr(module, name)

    missing_dataset = required_dataset - set(dataset_symbols)

    if missing_dataset:
        raise ImportError(
            "Dataset engines not found: "
            + ", ".join(sorted(missing_dataset))
        )

    from backend.engines.model.identity import inspect_model

    from backend.engines.model.behavioral_fingerprint import (
        compute_behavioral_fingerprint,
        try_load_torchscript_adapter,
    )

    from backend.engines.model.model_statistics import (
        analyze_model,
        load_torchscript_model,
    )

    from backend.engines.model.trigger_search import (
        TorchClassificationAdapter,
        search_triggers,
    )

    from backend.engines.provenance.inference_provenance import (
        create_inference_record,
    )

    from backend.engines.provenance.audit_trail import (
        create_audit_entry,
        append_audit_entry,
        verify_audit_chain,
    )

    from backend.engines.shift.distribution_shift import (
        analyze_image_directories,
    )

    from backend.engines.risk.findings import (
        findings_from_dataset,
        findings_from_model,
        findings_from_provenance,
        findings_from_shift,
        aggregate_findings,
    )

    from backend.engines.risk.assurance_report import (
        build_assurance_report,
        render_text_report,
        report_to_json,
    )

    return {
        "build_manifest": build_manifest,
        "find_exact_duplicates": find_exact_duplicates,
        "find_near_duplicates": find_near_duplicates,
        "assess_ood": assess_ood,

        "assess_label_consistency":
            dataset_symbols["assess_label_consistency"],

        "assess_contributor_risk":
            dataset_symbols["assess_contributor_risk"],

        "assess_metadata_consistency":
            dataset_symbols["assess_metadata_consistency"],

        "analyze_poison_trigger":
            dataset_symbols["analyze_poison_trigger"],

        "inspect_model": inspect_model,

        "compute_behavioral_fingerprint":
            compute_behavioral_fingerprint,

        "try_load_torchscript_adapter":
            try_load_torchscript_adapter,

        "analyze_model": analyze_model,

        "load_torchscript_model":
            load_torchscript_model,

        "TorchClassificationAdapter":
            TorchClassificationAdapter,

        "search_triggers":
            search_triggers,

        "create_inference_record":
            create_inference_record,

        "analyze_image_directories":
            analyze_image_directories,

        "findings_from_dataset":
            findings_from_dataset,

        "findings_from_model":
            findings_from_model,

        "findings_from_provenance":
            findings_from_provenance,

        "findings_from_shift":
            findings_from_shift,

        "aggregate_findings":
            aggregate_findings,

        "create_audit_entry":
            create_audit_entry,

        "append_audit_entry":
            append_audit_entry,

        "verify_audit_chain":
            verify_audit_chain,

        "build_assurance_report":
            build_assurance_report,

        "render_text_report":
            render_text_report,

        "report_to_json":
            report_to_json,
    }


def load_candidate_images():
    from PIL import Image
    import numpy as np

    images = []

    paths = sorted(
        CANDIDATE_DIR.glob("*.png")
    )

    for path in paths:
        try:
            images.append(
                np.asarray(
                    Image.open(path).convert("RGB"),
                    dtype=np.uint8,
                )
            )
        except Exception as exc:
            print(
                f"Warning: skipped {path.name}: {exc}"
            )

    return images


def run(device: str = "cpu", *, fallback_on_error: bool = False) -> int:
    if device not in {"cpu", "cuda"}:
        raise ValueError("demo device must be cpu or cuda")

    print("=" * 72)
    print("TRACER-CV — FULL END-TO-END ASSURANCE DEMO")
    print("=" * 72)

    missing = [
        p
        for p in (
            REFERENCE_DIR,
            CANDIDATE_DIR,
            LABELS_DIR,
            MODEL_PATH,
        )
        if not p.exists()
    ]

    if missing:
        print("\nMissing demo assets:")

        for path in missing:
            print(f"  {path}")

        print("\nRun:")
        print("  python -m demos.create_demo_assets")

        return 1

    engines = import_engines()

    # ------------------------------------------------------------------
    # DATASET: A1-A8
    # ------------------------------------------------------------------

    print("\n[1/5] DATASET INTEGRITY — A1-A8")

    build_manifest = engines["build_manifest"]
    find_exact_duplicates = engines["find_exact_duplicates"]
    find_near_duplicates = engines["find_near_duplicates"]
    assess_ood = engines["assess_ood"]

    assess_label_consistency = (
        engines["assess_label_consistency"]
    )

    assess_contributor_risk = (
        engines["assess_contributor_risk"]
    )

    assess_metadata_consistency = (
        engines["assess_metadata_consistency"]
    )

    analyze_poison_trigger = (
        engines["analyze_poison_trigger"]
    )

    # A1
    a1 = build_manifest(CANDIDATE_DIR)

    # A2
    a2 = find_exact_duplicates(
        a1["files"]
    )

    # A3
    a3 = find_near_duplicates(
        CANDIDATE_DIR
    )

    # A4
    a4 = assess_ood(
        REFERENCE_DIR,
        CANDIDATE_DIR,
    )

    # A5
    a5 = assess_label_consistency(
        CANDIDATE_DIR,
        LABELS_DIR,
    )

    contributor_manifest = (
        DATASET_ROOT /
        "contributor_manifest.csv"
    )

    # A6
    a6 = assess_contributor_risk(
        contributor_manifest,
        DATASET_ROOT,
        a4,
        a5,
    )

    # A7
    a7 = assess_metadata_consistency(
        CANDIDATE_DIR,
        contributor_from_path=False,
    )

    # A8
    a8 = analyze_poison_trigger(
        CANDIDATE_DIR,
        labels=None,
    )

    dataset_result = {
        "A1_manifest": a1,
        "A2_exact_duplicates": a2,
        "A3_near_duplicates": a3,
        "A4_ood": a4,
        "A5_label_consistency": a5,
        "A6_contributor_risk": a6,
        "A7_metadata_consistency": a7,
        "A8_poison_trigger_forensics": a8,
    }

    save_json(
        ENGINE_ROOT /
        "dataset_integrity.json",
        dataset_result,
    )

    print(
        f"  A1 files: "
        f"{a1.get('file_count', 'n/a')}"
    )

    print(
        f"  A2 duplicate groups: "
        f"{a2.get('duplicate_group_count', 'n/a')}"
    )

    print(
        f"  A5 findings: "
        f"{a5.get('conflicting_pair_count', 'n/a')}"
    )

    print(
        f"  A6 findings: "
        f"{a6.get('finding_count', 'n/a')}"
    )

    print(
        f"  A8 trigger candidates: "
        f"{a8.get('candidate_trigger_count', 'n/a')}"
    )

    # ------------------------------------------------------------------
    # MODEL: B1-B4
    # ------------------------------------------------------------------

    print("\n[2/5] MODEL ASSURANCE — B1-B4")

    inspect_model = engines["inspect_model"]

    compute_behavioral_fingerprint = (
        engines["compute_behavioral_fingerprint"]
    )

    try_load_torchscript_adapter = (
        engines["try_load_torchscript_adapter"]
    )

    analyze_model = engines["analyze_model"]

    load_torchscript_model = (
        engines["load_torchscript_model"]
    )

    TorchClassificationAdapter = (
        engines["TorchClassificationAdapter"]
    )

    search_triggers = engines["search_triggers"]

    # B1
    b1 = inspect_model(
        MODEL_PATH
    )

    def run_b2(on_device):
        adapter_result = try_load_torchscript_adapter(
            MODEL_PATH, output_type="logits", input_size=(32, 32),
            mean=(0.0, 0.0, 0.0), std=(1.0, 1.0, 1.0), device=on_device,
            class_count=2, seed=1337,
        )
        if adapter_result.get("status") == "loaded":
            return compute_behavioral_fingerprint(
                load_candidate_images(), adapter_result["adapter"],
                model_identity=b1, model_id=b1.get("model_id"), seed=1337,
            )
        return {"status": adapter_result.get("status", "unavailable"), "adapter": adapter_result}

    def run_b3(on_device):
        model = load_torchscript_model(MODEL_PATH, trusted=True, device=on_device)
        return analyze_model(model=model, images=load_candidate_images(),
                             model_id=b1.get("model_id"), access="white_box",
                             probe_set_id="candidate-demo-v1")

    def run_b4(on_device):
        model = load_torchscript_model(MODEL_PATH, trusted=True, device=on_device)
        adapter = TorchClassificationAdapter(model, device=on_device,
            output_type="logits", scale_inputs=True,
            mean=(0.0, 0.0, 0.0), std=(1.0, 1.0, 1.0))
        return search_triggers(load_candidate_images(), adapter, model_id=b1.get("model_id"))

    def execute_model_check(engine_id, operation):
        try:
            result = operation(device)
            error_text = str(result.get("error", "")).lower() if isinstance(result, dict) else ""
            device_error = any(token in error_text for token in ("cuda", "cudnn", "cublas", "out of memory"))
            if device == "cuda" and fallback_on_error and result.get("status") == "error" and device_error:
                result = operation("cpu")
                result["execution_device"] = "cpu"
                result["device_fallback_reason"] = "CUDA execution failed; this engine was retried on CPU."
            else:
                result["execution_device"] = device
            return result
        except Exception as exc:
            if device == "cuda" and fallback_on_error:
                try:
                    result = operation("cpu")
                    result["execution_device"] = "cpu"
                    result["device_fallback_reason"] = f"CUDA {engine_id} execution raised {type(exc).__name__}; retried on CPU."
                    return result
                except Exception as cpu_exc:
                    exc = cpu_exc
            return {"status": "error", "error": f"{type(exc).__name__}: {exc}",
                    "execution_device": "cpu" if device == "cuda" and fallback_on_error else device}

    b2 = execute_model_check("B2", run_b2)
    b3 = execute_model_check("B3", run_b3)
    b4 = execute_model_check("B4", run_b4)

    model_result = {
        "B1_identity": b1,
        "B2_behavioral_fingerprint": b2,
        "B3_model_statistics": b3,
        "B4_trigger_search": b4,
    }

    save_json(
        ENGINE_ROOT /
        "model_assurance.json",
        model_result,
    )

    print(
        f"  B1: {b1.get('status')}"
    )

    print(
        f"  B2: {b2.get('status')}"
    )

    print(
        f"  B3: {b3.get('status')}"
    )

    print(
        f"  B4: {b4.get('status')}"
    )

    print(
        f"  B4 candidates: "
        f"{b4.get('candidate_trigger_count', 'n/a')}"
    )

    # ------------------------------------------------------------------
    # C1 PROVENANCE
    # ------------------------------------------------------------------

    print(
        "\n[3/5] INFERENCE PROVENANCE — C1"
    )

    create_inference_record = (
        engines["create_inference_record"]
    )

    input_bytes = (
        b"TRACER-CV controlled demo input"
    )

    output_bytes = json.dumps(
        {
            "class": 0,
            "confidence": 0.95,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    preprocessing = {
        "resize": [32, 32],
        "normalization": {
            "mean": [0.0, 0.0, 0.0],
            "std": [1.0, 1.0, 1.0],
        },
    }

    provenance_records = []

    try:
        record_1 = create_inference_record(
            input_bytes=input_bytes,
            model_id=b1.get(
                "model_id",
                "unknown",
            ),
            preprocessing_config=preprocessing,
            output_bytes=output_bytes,
            sequence=1,
            nonce="tracer-demo-nonce-001",
            timestamp="2026-09-29T12:00:00+00:00",
        )

        provenance_records.append(
            record_1
        )

        c1 = {
            "status": "completed",
            "records": [
                record_1
            ],
        }

    except Exception as exc:
        c1 = {
            "status": "error",
            "error":
                f"{type(exc).__name__}: {exc}",
            "records": [],
        }

    # Persist JSON-native records so the desktop UI and downstream tools can
    # verify them without parsing Python repr strings.
    from backend.engines.provenance.inference_provenance import verify_chain
    c1_evidence = {
        "status": c1.get("status"),
        "valid": bool(verify_chain(provenance_records).get("valid"))
        if provenance_records else False,
        "records": [record.as_dict() for record in provenance_records],
    }
    if c1.get("error"):
        c1_evidence["error"] = c1["error"]
    save_json(ENGINE_ROOT / "provenance.json", c1_evidence)

    print(
        f"  C1: {c1.get('status')}"
    )

    # ------------------------------------------------------------------
    # C2 SHIFT
    # ------------------------------------------------------------------

    print(
        "\n[4/5] DISTRIBUTION SHIFT — C2"
    )

    try:
        c2 = engines[
            "analyze_image_directories"
        ](
            REFERENCE_DIR,
            CANDIDATE_DIR,
        )

    except Exception as exc:
        c2 = {
            "status": "error",
            "error":
                f"{type(exc).__name__}: {exc}",
        }

    save_json(
        ENGINE_ROOT /
        "distribution_shift.json",
        c2,
    )

    print(
        f"  C2: {c2.get('status')}"
    )

    # ------------------------------------------------------------------
    # C3 FINDINGS
    # ------------------------------------------------------------------

    print(
        "\n[5/5] FINDINGS + AUDIT + REPORT — C3-C5"
    )

    findings_from_dataset = (
        engines["findings_from_dataset"]
    )

    findings_from_model = (
        engines["findings_from_model"]
    )

    findings_from_provenance = (
        engines["findings_from_provenance"]
    )

    findings_from_shift = (
        engines["findings_from_shift"]
    )

    aggregate_findings = (
        engines["aggregate_findings"]
    )

    dataset_findings = findings_from_dataset(
        dataset_result,
        affected_asset=str(
            DATASET_ROOT
        ),
    )

    model_findings = findings_from_model(
        model_result,
        affected_asset=str(
            MODEL_PATH
        ),
    )

    provenance_findings = (
        findings_from_provenance(
            c1,
            affected_asset="inference-demo-001",
        )
    )

    shift_findings = findings_from_shift(
        c2,
        affected_asset=str(
            CANDIDATE_DIR
        ),
    )

    # aggregate_findings expects the engine
    # result dictionaries, not AssuranceFinding
    # objects.

    c3 = aggregate_findings(
        dataset_results=[
            dataset_result
        ],
        model_results=[
            model_result
        ],
        provenance_results=[
            c1
        ],
        shift_results=[
            c2
        ],
    )

    # Preserve concrete findings explicitly.
    if isinstance(c3, dict):

        c3["findings"] = [
            *dataset_findings,
            *model_findings,
            *provenance_findings,
            *shift_findings,
        ]

        c3["finding_count"] = len(
            c3["findings"]
        )

    c3_evidence = dict(c3)
    c3_evidence["findings"] = [
        item.as_dict() if hasattr(item, "as_dict") else item
        for item in c3.get("findings", [])
    ]
    save_json(ENGINE_ROOT / "findings.json", c3_evidence)

    print(
        f"  C3 findings: "
        f"{c3.get('finding_count', 'n/a')}"
    )

    # ------------------------------------------------------------------
    # C4 AUDIT TRAIL
    # ------------------------------------------------------------------

    create_audit_entry = (
        engines["create_audit_entry"]
    )

    append_audit_entry = (
        engines["append_audit_entry"]
    )

    verify_audit_chain = (
        engines["verify_audit_chain"]
    )

    audit_chain = []

    audit_events = [
        (
            "dataset.integrity.completed",
            "dataset",
            str(DATASET_ROOT),
        ),
        (
            "model.assurance.completed",
            "model",
            str(MODEL_PATH),
        ),
        (
            "inference.provenance.completed",
            "provenance",
            "inference-demo-001",
        ),
        (
            "distribution.shift.completed",
            "shift",
            str(CANDIDATE_DIR),
        ),
        (
            "assurance.findings.completed",
            "risk",
            "TRACER-CV",
        ),
    ]

    previous_hash = "0" * 64

    try:

        for sequence, (
            event_type,
            source_engine,
            affected_asset,
        ) in enumerate(
            audit_events,
            start=1,
        ):

            entry = create_audit_entry(
                sequence=sequence,
                event_type=event_type,
                source_engine=source_engine,
                affected_asset=affected_asset,
                payload={
                    "status": "completed",
                    "assessment_id":
                        "TRACER-FULL-DEMO-001",
                },
                timestamp=(
                    f"2026-09-29T12:0"
                    f"{sequence}:00+00:00"
                ),
                previous_entry_hash=previous_hash,
            )

            audit_chain.append(entry)

            previous_hash = (
                entry.entry_hash
            )

        try:
            verified = verify_audit_chain(
                audit_chain
            )

        except TypeError:
            verified = verify_audit_chain(
                audit_chain
            )

        c4 = {
            "status": "completed",
            "entry_count": len(
                audit_chain
            ),
            "valid": verified,
            "entries": audit_chain,
        }

    except Exception as exc:

        c4 = {
            "status": "error",
            "error":
                f"{type(exc).__name__}: {exc}",
            "entry_count": len(
                audit_chain
            ),
            "entries": audit_chain,
        }

    c4_evidence = {
        "status": c4.get("status"),
        "entry_count": c4.get("entry_count", len(audit_chain)),
        "valid": verified if isinstance(verified, bool) else verified.get("valid", False)
        if isinstance(verified, (bool, dict)) else False,
        "entries": [entry.as_dict() for entry in audit_chain],
    }
    if c4.get("error"):
        c4_evidence["error"] = c4["error"]
    save_json(EVIDENCE_ROOT / "audit_chain.json", c4_evidence)

    print(
        f"  C4: {c4.get('status')}"
    )

    print(
        f"  Audit entries: "
        f"{c4.get('entry_count', 0)}"
    )

    # ------------------------------------------------------------------
    # C5 ASSURANCE REPORT
    # ------------------------------------------------------------------

    build_assurance_report = (
        engines["build_assurance_report"]
    )

    render_text_report = (
        engines["render_text_report"]
    )

    report_to_json = (
        engines["report_to_json"]
    )

    assessment_id = (
        "TRACER-FULL-DEMO-001"
    )

    # IMPORTANT:
    #
    # C1 contains ProvenanceRecord objects.
    # C4 contains AuditEntry objects.
    # C3 contains AssuranceFinding objects.
    #
    # C5 calculates a SHA-256 digest using
    # json.dumps(), so these Python objects
    # must first be converted into ordinary
    # JSON-compatible dictionaries/lists.

    def _serialize_for_report(value):
        """
        Recursively convert engine objects into
        JSON-safe values.

        Handles:
        - dict
        - list / tuple
        - dataclasses
        - objects with to_dict()
        - ordinary Python objects with __dict__
        """

        if value is None:
            return None

        if isinstance(
            value,
            (str, int, float, bool),
        ):
            return value

        if isinstance(value, dict):
            return {
                str(key):
                    _serialize_for_report(item)
                for key, item in value.items()
            }

        if isinstance(
            value,
            (list, tuple),
        ):
            return [
                _serialize_for_report(item)
                for item in value
            ]

        # Prefer an explicit serializer.
        if hasattr(
            value,
            "to_dict",
        ):
            return _serialize_for_report(
                value.to_dict()
            )

        # Dataclass objects such as
        # ProvenanceRecord / AuditEntry /
        # AssuranceFinding.
        if hasattr(
            value,
            "__dataclass_fields__",
        ):
            from dataclasses import asdict

            return _serialize_for_report(
                asdict(value)
            )

        # Fallback for ordinary objects.
        if hasattr(
            value,
            "__dict__",
        ):
            return _serialize_for_report(
                vars(value)
            )

        # Last-resort scalar/object.
        return value

    # Convert EVERYTHING entering C5.
    #
    # This is deliberately broader than only
    # serializing C1 and C4 because C3's
    # AssuranceFinding objects also need to be
    # converted before C5 calculates its digest.

    report = build_assurance_report(
        assessment_id=assessment_id,

        dataset=_serialize_for_report(
            dataset_result
        ),

        model=_serialize_for_report(
            model_result
        ),

        provenance=_serialize_for_report(
            c1
        ),

        shift=_serialize_for_report(
            c2
        ),

        findings=_serialize_for_report(
            c3.get("findings", [])
            if isinstance(c3, dict)
            else []
        ),

        audit=_serialize_for_report(
            c4
        ),
    )

    # ------------------------------------------------------------------
    # SAVE FINAL REPORT
    # ------------------------------------------------------------------

    ReportStore(REPORT_ROOT).save(
        "tracer_cv_assurance_report.json",
        report_to_json(report).encode("utf-8"),
        overwrite=True,
    )

    try:

        text_report = (
            render_text_report(
                report
            )
        )

    except Exception as exc:

        text_report = (
            "TRACER-CV ASSURANCE REPORT\n"
            f"Assessment ID: {assessment_id}\n\n"
            "Report rendering error: "
            f"{type(exc).__name__}: {exc}\n"
        )

    ReportStore(REPORT_ROOT).save(
        "tracer_cv_assurance_report.txt",
        text_report.encode("utf-8"),
        overwrite=True,
    )

    # ------------------------------------------------------------------
    # COMPLETE
    # ------------------------------------------------------------------

    print("\n" + "=" * 72)
    print("FULL ASSURANCE RUN COMPLETE")
    print("=" * 72)

    print("\nGenerated:")

    print(
        "  reports/tracer_cv_assurance_report.json"
    )

    print(
        "  reports/tracer_cv_assurance_report.txt"
    )

    print(
        "  reports/evidence/audit_chain.json"
    )

    print(
        "  reports/engine_results/"
        "dataset_integrity.json"
    )

    print(
        "  reports/engine_results/"
        "model_assurance.json"
    )

    print(
        "  reports/engine_results/"
        "provenance.json"
    )

    print(
        "  reports/engine_results/"
        "distribution_shift.json"
    )

    print(
        "  reports/engine_results/"
        "findings.json"
    )

    print("\nPipeline:")

    print(
        "  A1-A8  Dataset integrity"
    )

    print(
        "  B1-B4  Model assurance"
    )

    print(
        "  C1     Inference provenance"
    )

    print(
        "  C2     Distribution shift"
    )

    print(
        "  C3     Findings & evidence"
    )

    print(
        "  C4     Tamper-evident audit trail"
    )

    print(
        "  C5     Assurance report"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(run())
