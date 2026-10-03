from __future__ import annotations

import json

import numpy as np
import torch
from torch import nn

from backend.core.hashing import sha256_bytes
from backend.engines.model.trigger_search import (
    TorchClassificationAdapter,
    TriggerSearchConfig,
    search_triggers,
)


SEED = 1337
torch.manual_seed(SEED)
np.random.seed(SEED)


class DemoTriggerModel(nn.Module):
    """
    Small deterministic image classifier.

    The model intentionally reacts to a bright patch in the
    bottom-right corner so B4 has a known behavioral signal
    to discover during the demonstration.
    """

    def __init__(self):
        super().__init__()
        self.register_buffer(
            "trigger_threshold",
            torch.tensor(0.60, dtype=torch.float32),
        )

    def forward(self, x):
        corner = x[:, :, -8:, -8:].mean(dim=(1, 2, 3))
        trigger_strength = (corner - self.trigger_threshold) / 0.05
        return torch.stack([-trigger_strength, trigger_strength], dim=1)


def make_demo_images(count: int = 6) -> list[np.ndarray]:
    rng = np.random.default_rng(SEED)

    images = []

    for _ in range(count):
        image = rng.integers(
            low=20,
            high=80,
            size=(32, 32, 3),
            dtype=np.uint8,
        )
        images.append(image)

    return images


def main() -> None:
    model = DemoTriggerModel().eval()

    # ------------------------------------------------------------------
    # B1 — Model identity
    # ------------------------------------------------------------------
    # We serialize only this deterministic demo model's state representation
    # to obtain a stable identity digest for the demonstration.
    state = model.state_dict()

    payload = b"".join(
        key.encode("utf-8") + b"\0" + value.detach().cpu().numpy().tobytes()
        for key, value in state.items()
    )

    model_id = "sha256:" + sha256_bytes(payload)

    print("=" * 72)
    print("TRACER-CV — B4 REAL PYTORCH DEMONSTRATION")
    print("=" * 72)
    print(f"Model ID: {model_id}")
    print(f"Device: {'cuda' if torch.cuda.is_available() else 'cpu'}")

    # ------------------------------------------------------------------
    # B4 — PyTorch adapter
    # ------------------------------------------------------------------
    adapter = TorchClassificationAdapter(
    model=model,
    device="cuda" if torch.cuda.is_available() else "cpu",
    output_type="logits",
    scale_inputs=True,
)

    images = make_demo_images()

    config = TriggerSearchConfig(
        patch_sizes=(8,),
        grid_fractions=(0.25, 0.5, 0.75, 1.0),
        patterns=("white", "black"),
        min_prediction_change_rate=0.60,
        min_confidence_gain=0.05,
        min_probability_l1_change=1.0,
        min_samples=3,
        max_images=6,
        seed=SEED,
    )


    result = search_triggers(
        images=images,
        adapter=adapter,
        config=config,
        model_id=model_id,
    )

    print("\n--- B4 RESULT ---")
    print(
        json.dumps(
            result,
            indent=2,
            default=lambda value: list(value)
            if isinstance(value, tuple)
            else value,
        )
    )

    # ------------------------------------------------------------------
    # Human-readable summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 72)
    print("B4 SUMMARY")
    print("=" * 72)

    print(f"Status: {result['status']}")
    print(f"Candidates tested: {result['search']['candidate_count']}")
    print(f"Images assessed: {result['search']['images_assessed']}")
    print(
        "Assessment:",
        result["assessment"]["status"],
    )

    print("\nCandidate evidence:")

    if result["candidate_evidence"]:
        for evidence in result["candidate_evidence"]:
            print(
                f"  position=({evidence['candidate']['x_fraction']}, "
                f"{evidence['candidate']['y_fraction']}), "
                f"pattern={evidence['candidate']['pattern']}"
            )
            print(
                f"  class-change-rate="
                f"{evidence['class_change_rate']:.3f}"
            )
            print(
                f"  target-hit-rate="
                f"{evidence['target_hit_rate']:.3f}"
            )
            print(
                f"  confidence-gain="
                f"{evidence['mean_confidence_gain']:.6f}"
            )
    else:
        print("  No trigger-like candidate detected.")

    print("\nLimitations:")
    for limitation in result["limitations"]:
        print(f"  - {limitation}")

    # Save a deterministic JSON report.
    output_path = "reports/b4_torch_demo.json"

    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(
            result,
            handle,
            indent=2,
            default=lambda value: list(value)
            if isinstance(value, tuple)
            else value,
        )

    print(f"\nReport written to: {output_path}")


if __name__ == "__main__":
    main()
