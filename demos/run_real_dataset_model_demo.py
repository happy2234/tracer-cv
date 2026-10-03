"""
TRACER-CV — Real Dataset + Model Integration Demo

Runs the actual A1-A8 dataset engines and B1 model identity engine
against the controlled synthetic demo assets.

No synthetic engine results are fabricated here.
"""

from __future__ import annotations

import json
from pathlib import Path

from backend.engines.dataset.manifest import build_manifest
from backend.engines.dataset.duplicates import find_exact_duplicates
from backend.engines.dataset.near_duplicates import find_near_duplicates
from backend.engines.dataset.ood import assess_ood
from backend.engines.dataset.label_consistency import (
    assess_label_consistency,
)
from backend.engines.dataset.contributor_risk import (
    assess_contributor_risk,
)
from backend.engines.dataset.metadata_consistency import (
    assess_metadata_consistency,
)
from backend.engines.dataset.poison_trigger import (
    analyze_poison_trigger,
)

from backend.engines.model.identity import inspect_model


ROOT = Path(__file__).resolve().parents[1]

DATASET_ROOT = (
    ROOT
    / "demos"
    / "assets"
    / "dataset"
)

REFERENCE_DIR = (
    DATASET_ROOT
    / "reference"
)

CANDIDATE_DIR = (
    DATASET_ROOT
    / "candidate"
)

LABELS_DIR = (
    DATASET_ROOT
    / "labels"
)

CONTRIBUTOR_MANIFEST = (
    DATASET_ROOT / "contributor_manifest.csv"
)

MODEL_PATH = (
    ROOT
    / "demos"
    / "assets"
    / "model"
    / "demo_model.pt"
)


def save_json(
    path: Path,
    value,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            default=str,
        ),
        encoding="utf-8",
    )


def summarize_result(
    name: str,
    result: dict,
) -> None:
    print(
        f"\n{name}"
    )

    print(
        "-" * 72
    )

    if not isinstance(result, dict):
        print(
            "Result type:",
            type(result).__name__,
        )
        return

    print(
        "Keys:",
        ", ".join(
            list(result.keys())[:12]
        ),
    )

    for key in (
        "status",
        "valid",
        "available",
        "finding_count",
        "duplicate_group_count",
        "near_duplicate_group_count",
        "shift_detected",
        "severity",
        "overall_score",
        "model_id",
        "format",
    ):
        if key in result:
            print(
                f"{key}:",
                result[key],
            )


def main() -> int:
    print("=" * 72)
    print("TRACER-CV — REAL ENGINE DATASET/MODEL DEMO")
    print("=" * 72)

    if not CANDIDATE_DIR.exists():
        raise FileNotFoundError(
            f"Missing candidate directory: {CANDIDATE_DIR}"
        )

    if not REFERENCE_DIR.exists():
        raise FileNotFoundError(
            f"Missing reference directory: {REFERENCE_DIR}"
        )

    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Missing model: {MODEL_PATH}"
        )

    results = {}

    # ------------------------------------------------------------------
    # A1
    # ------------------------------------------------------------------

    print("\n[1/9] A1 — Dataset Manifest")

    a1 = build_manifest(
        CANDIDATE_DIR
    )

    results["A1"] = a1

    summarize_result(
        "A1 RESULT",
        a1,
    )

    # ------------------------------------------------------------------
    # A2
    # ------------------------------------------------------------------

    print("\n[2/9] A2 — Exact Duplicates")

    files = a1.get(
        "files",
        [],
    )

    a2 = find_exact_duplicates(
        files
    )

    results["A2"] = a2

    summarize_result(
        "A2 RESULT",
        a2,
    )

    # ------------------------------------------------------------------
    # A3
    # ------------------------------------------------------------------

    print("\n[3/9] A3 — Near Duplicates")

    a3 = find_near_duplicates(
        CANDIDATE_DIR,
        threshold=8,
    )

    results["A3"] = a3

    summarize_result(
        "A3 RESULT",
        a3,
    )

    # ------------------------------------------------------------------
    # A4
    # ------------------------------------------------------------------

    print("\n[4/9] A4 — Reference/OOD Assessment")

    a4 = assess_ood(
        REFERENCE_DIR,
        CANDIDATE_DIR,
    )

    results["A4"] = a4

    summarize_result(
        "A4 RESULT",
        a4,
    )

    # ------------------------------------------------------------------
    # A5
    # ------------------------------------------------------------------

    print("\n[5/9] A5 — Label Consistency")

    a5 = assess_label_consistency(
        CANDIDATE_DIR,
        labels_dir=LABELS_DIR,
        num_classes=2,
        near_duplicate_threshold=8,
    )

    results["A5"] = a5

    summarize_result(
        "A5 RESULT",
        a5,
    )

    # ------------------------------------------------------------------
    # A6
    # ------------------------------------------------------------------

    print("\n[6/9] A6 — Contributor/Source Risk")

    a6 = assess_contributor_risk(
        CONTRIBUTOR_MANIFEST,
        dataset_root=DATASET_ROOT,
        ood_result=a4,
        label_result=a5,
    )

    results["A6"] = a6

    summarize_result(
        "A6 RESULT",
        a6,
    )

    # ------------------------------------------------------------------
    # A7
    # ------------------------------------------------------------------

    print("\n[7/9] A7 — Metadata/Acquisition Consistency")

    a7 = assess_metadata_consistency(
        CANDIDATE_DIR,
        contributor_from_path=False,
    )

    results["A7"] = a7

    summarize_result(
        "A7 RESULT",
        a7,
    )

    # ------------------------------------------------------------------
    # A8
    # ------------------------------------------------------------------

    print("\n[8/9] A8 — Poison/Trigger-Like Dataset Forensics")

    a8 = analyze_poison_trigger(
        CANDIDATE_DIR,
    )

    results["A8"] = a8

    summarize_result(
        "A8 RESULT",
        a8,
    )

    # ------------------------------------------------------------------
    # B1
    # ------------------------------------------------------------------

    print("\n[9/9] B1 — Model Identity")

    b1 = inspect_model(
        MODEL_PATH
    )

    results["B1"] = b1

    summarize_result(
        "B1 RESULT",
        b1,
    )

    # ------------------------------------------------------------------
    # Save
    # ------------------------------------------------------------------

    output_path = (
        ROOT
        / "reports"
        / "real_engine_dataset_model_results.json"
    )

    save_json(
        output_path,
        results,
    )

    print("\n" + "=" * 72)
    print("REAL DATASET/MODEL ENGINE RUN COMPLETE")
    print("=" * 72)

    print(
        "\nSaved:"
    )

    print(
        output_path.relative_to(ROOT)
    )

    print("\nEngines executed:")
    print("  A1  Dataset manifest")
    print("  A2  Exact duplicates")
    print("  A3  Near duplicates")
    print("  A4  Reference/OOD")
    print("  A5  Label consistency")
    print("  A6  Contributor/source risk")
    print("  A7  Metadata consistency")
    print("  A8  Poison/trigger-like forensics")
    print("  B1  Model identity")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
