from __future__ import annotations

import json
from pathlib import Path

import numpy as np
from PIL import Image

from backend.engines.model.identity import inspect_model
from backend.engines.model.behavioral_fingerprint import (
    compute_behavioral_fingerprint,
    TorchScriptClassificationAdapter,
    try_load_torchscript_adapter,
)
from backend.engines.model.model_statistics import (
    analyze_model,
    load_torchscript_model,
)
from backend.engines.model.trigger_search import (
    search_triggers,
    TorchClassificationAdapter,
)


ROOT = Path(__file__).resolve().parents[1]

ASSET_ROOT = ROOT / "demos" / "assets"
DATASET_ROOT = ASSET_ROOT / "dataset"
CANDIDATE_DIR = DATASET_ROOT / "candidate"
MODEL_PATH = ASSET_ROOT / "model" / "demo_model.pt"

OUTPUT_PATH = (
    ROOT
    / "reports"
    / "real_model_assurance_results.json"
)


def load_images() -> list[Image.Image]:
    images: list[Image.Image] = []

    for path in sorted(CANDIDATE_DIR.glob("*.png")):
        with Image.open(path) as image:
            images.append(image.convert("RGB"))

    if not images:
        raise RuntimeError(
            f"No PNG images found in {CANDIDATE_DIR}"
        )

    return images


def pil_to_numpy(
    images: list[Image.Image],
) -> list[np.ndarray]:
    return [
        np.asarray(image, dtype=np.uint8)
        for image in images
    ]


def print_result(name: str, result: dict) -> None:
    print()
    print(f"{name} RESULT")
    print("-" * 72)

    if isinstance(result, dict):
        print(
            "Keys:",
            ", ".join(result.keys()),
        )

        for key in (
            "status",
            "model_id",
            "method",
            "adapter",
            "probe_count",
            "parameter_count",
            "module_count",
            "candidate_count",
            "candidate_trigger_count",
            "candidate_trigger_like",
        ):
            if key in result:
                print(f"{key}: {result[key]}")


def main() -> int:
    print("=" * 72)
    print("TRACER-CV — REAL MODEL ASSURANCE DEMO")
    print("=" * 72)

    if not MODEL_PATH.is_file():
        raise FileNotFoundError(
            f"Model not found: {MODEL_PATH}"
        )

    images = load_images()
    numpy_images = pil_to_numpy(images)

    print(
        f"\nLoaded {len(images)} candidate images."
    )

    # ------------------------------------------------------------
    # B1 — MODEL IDENTITY
    # ------------------------------------------------------------

    print("\n[1/4] B1 — Model Identity")

    b1 = inspect_model(MODEL_PATH)

    print_result("B1", b1)

    if b1.get("status") != "completed":
        raise RuntimeError(
            f"B1 failed: {b1}"
        )

    model_id = b1["model_id"]

    print(f"Model ID: {model_id}")

    # ------------------------------------------------------------
    # B2 — BEHAVIORAL FINGERPRINT
    # ------------------------------------------------------------

    print("\n[2/4] B2 — Behavioral Fingerprint")

    b2_adapter_result = try_load_torchscript_adapter(
        str(MODEL_PATH),
        output_type="logits",
        input_size=(32, 32),
        mean=(0.0, 0.0, 0.0),
        std=(1.0, 1.0, 1.0),
        device="cpu",
        class_count=2,
        seed=1337,
    )

    if b2_adapter_result.get("status") != "loaded":
        raise RuntimeError(
            "B2 TorchScript adapter could not be loaded:\n"
            + json.dumps(
                b2_adapter_result,
                indent=2,
                default=str,
            )
        )

    b2_adapter = b2_adapter_result["adapter"]

    b2 = compute_behavioral_fingerprint(
        images,
        b2_adapter,
        model_id=model_id,
        seed=1337,
        batch_size=8,
    )

    print_result("B2", b2)

    # Do not assume a particular internal field layout.
    if b2.get("status") != "completed":
        print(
            "\nB2 did not complete."
            "\nContinuing is not safe because B3/B4"
            " should not be interpreted independently."
        )
        return 1

    # ------------------------------------------------------------
    # B3 — PARAMETER / ACTIVATION STATISTICS
    # ------------------------------------------------------------

    print("\n[3/4] B3 — Parameter & Activation Statistics")

    model = load_torchscript_model(
        MODEL_PATH,
        trusted=True,
    )

    b3 = analyze_model(
        model=model,
        images=images,
        model_id=model_id,
        access="white_box",
        probe_set_id="candidate-demo-v1",
    )

    print_result("B3", b3)


    if b3.get("status") not in {"completed", "partial", "error"}:
     raise RuntimeError(
        "B3 returned an unexpected status:\n"
        + json.dumps(
            b3,
            indent=2,
            default=str,
        )
    )

    if b3.get("status") not in {"completed", "partial", "error"}:
        raise RuntimeError(
            "B3 returned an unexpected status:\n"
            + json.dumps(
                b3,
                indent=2,
                default=str,
            )
        )

    if b3.get("status") == "error":
        print(
            "\nB3 completed with a capability limitation."
        )
        print(
            "Parameter/structure statistics are available."
        )

        activations = b3.get("activations", {})

        if activations.get("status") == "error":
            print(
                "Activation statistics unavailable:"
            )
            print(
                activations.get(
                    "reason",
                    "unknown reason",
                )
            )

        print(
            "Continuing to B4 because B3 produced "
            "usable structural/parameter evidence."
        )




    # ------------------------------------------------------------
    # B4 — TRIGGER SEARCH
    # ------------------------------------------------------------

    print("\n[4/4] B4 — Trigger Search / Reconstruction")

    b4_adapter = TorchClassificationAdapter(
        model,
        device="cpu",
        output_type="logits",
        scale_inputs=True,
        mean=(0.0, 0.0, 0.0),
        std=(1.0, 1.0, 1.0),
    )

    b4 = search_triggers(
        numpy_images,
        b4_adapter,
        model_id=model_id,
        target_class=None,
    )

    print_result("B4", b4)

    if b4.get("status") != "completed":
        raise RuntimeError(
            "B4 failed:\n"
            + json.dumps(
                b4,
                indent=2,
                default=str,
            )
        )

    # ------------------------------------------------------------
    # SAVE
    # ------------------------------------------------------------

    result = {
        "project": "TRACER-CV",
        "demo": "real_model_assurance",
        "model": {
            "path": str(
                MODEL_PATH.relative_to(ROOT)
            ),
            "model_id": model_id,
            "sha256": b1.get("sha256"),
            "format": b1.get("format"),
        },
        "engines": {
            "B1": b1,
            "B2": b2,
            "B3": b3,
            "B4": b4,
        },
        "limitations": [
            "Controlled synthetic demonstration assets.",
            "Image-classification assurance scope.",
            "Behavioral and statistical anomalies do not by themselves prove malicious modification.",
            "Trigger-like behavior is evidence requiring analyst review and is not proof of a backdoor.",
            "Results are offline and deterministic for the supplied assets.",
        ],
    }

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUTPUT_PATH.write_text(
        json.dumps(
            result,
            indent=2,
            sort_keys=True,
            default=str,
        ),
        encoding="utf-8",
    )

    print()
    print("=" * 72)
    print("REAL MODEL ASSURANCE RUN COMPLETE")
    print("=" * 72)
    print()
    print(f"Saved: {OUTPUT_PATH}")

    print()
    print("Engines executed:")
    print("  B1  Model identity")
    print("  B2  Behavioral fingerprint")
    print("  B3  Parameter/activation statistics")
    print("  B4  Trigger search")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
