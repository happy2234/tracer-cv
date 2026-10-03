"""
TRACER-CV controlled demo asset generator.

Creates:
    demos/assets/dataset/reference/
    demos/assets/dataset/candidate/
    demos/assets/dataset/labels/
    demos/assets/dataset/contributor_manifest.json
    demos/assets/model/demo_model.pt

Everything is synthetic and deterministic.
No network access is required.
"""

from __future__ import annotations


import csv
import json
import random
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw
import torch
import torch.nn as nn


ROOT = Path(__file__).resolve().parents[1]

ASSET_ROOT = ROOT / "demos" / "assets"
DATASET_ROOT = ASSET_ROOT / "dataset"
REFERENCE_DIR = DATASET_ROOT / "reference"
CANDIDATE_DIR = DATASET_ROOT / "candidate"
LABELS_DIR = DATASET_ROOT / "labels"
MODEL_DIR = ASSET_ROOT / "model"

IMAGE_SIZE = 64
NUM_REFERENCE = 20
NUM_CANDIDATE = 20

SEED = 1337


# ---------------------------------------------------------------------------
# Reproducibility
# ---------------------------------------------------------------------------

def seed_everything() -> None:
    random.seed(SEED)
    np.random.seed(SEED)
    torch.manual_seed(SEED)


# ---------------------------------------------------------------------------
# Image generation
# ---------------------------------------------------------------------------

def make_base_image(
    index: int,
    *,
    shifted: bool = False,
) -> Image.Image:
    """
    Create a synthetic two-class image.

    Class 0:
        horizontal structure

    Class 1:
        vertical structure
    """

    rng = np.random.default_rng(SEED + index)

    if shifted:
        background = np.array(
            [
                175,
                175,
                175,
            ],
            dtype=np.float32,
        )
    else:
        background = np.array(
            [
                80,
                90,
                100,
            ],
            dtype=np.float32,
        )

    image = np.zeros(
        (IMAGE_SIZE, IMAGE_SIZE, 3),
        dtype=np.float32,
    )

    image[:] = background

    class_id = index % 2

    if class_id == 0:
        # Horizontal structure.
        y = 16 + (index * 3) % 32

        image[
            max(0, y - 4):min(IMAGE_SIZE, y + 4),
            8:56,
            :,
        ] += np.array(
            [90, 20, 10],
            dtype=np.float32,
        )

    else:
        # Vertical structure.
        x = 16 + (index * 3) % 32

        image[
            8:56,
            max(0, x - 4):min(IMAGE_SIZE, x + 4),
            :,
        ] += np.array(
            [10, 30, 100],
            dtype=np.float32,
        )

    noise = rng.normal(
        0,
        6 if not shifted else 10,
        size=image.shape,
    )

    image += noise

    image = np.clip(
        image,
        0,
        255,
    ).astype(np.uint8)

    return Image.fromarray(
        image,
        mode="RGB",
    )


def add_trigger(
    image: Image.Image,
) -> Image.Image:
    """
    Add a deterministic white trigger patch in the bottom-right corner.
    """

    image = image.copy()

    draw = ImageDraw.Draw(image)

    draw.rectangle(
        [
            IMAGE_SIZE - 12,
            IMAGE_SIZE - 12,
            IMAGE_SIZE - 1,
            IMAGE_SIZE - 1,
        ],
        fill=(255, 255, 255),
    )

    return image


def save_image(
    image: Image.Image,
    path: Path,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    image.save(
        path,
        format="PNG",
    )


# ---------------------------------------------------------------------------
# Dataset creation
# ---------------------------------------------------------------------------

def create_dataset() -> None:
    for directory in (
        REFERENCE_DIR,
        CANDIDATE_DIR,
        LABELS_DIR,
    ):
        directory.mkdir(
            parents=True,
            exist_ok=True,
        )

    # Reference set.
    for index in range(NUM_REFERENCE):
        image = make_base_image(
            index,
            shifted=False,
        )

        save_image(
            image,
            REFERENCE_DIR
            / f"reference_{index:03d}.png",
        )

    # Candidate set.
    for index in range(NUM_CANDIDATE):
        image = make_base_image(
            index + 100,
            shifted=True,
        )

        # Add repeated trigger-like pattern to several images.
        if index < 6:
            image = add_trigger(image)

        save_image(
            image,
            CANDIDATE_DIR
            / f"candidate_{index:03d}.png",
        )

    # Deliberate exact duplicate.
    duplicate_source = CANDIDATE_DIR / "candidate_000.png"
    duplicate_target = CANDIDATE_DIR / "candidate_duplicate.png"

    duplicate_target.write_bytes(
        duplicate_source.read_bytes()
    )

    # YOLO-style labels.
    #
    # The labels are intentionally simple. Two near-identical candidate
    # images receive conflicting classes so A5 has something to inspect.
    for index in range(NUM_CANDIDATE):
        label = index % 2

        if index == 1:
            label = 1 - label

        label_path = (
            LABELS_DIR
            / f"candidate_{index:03d}.txt"
        )

        label_path.write_text(
            f"{label} 0.5 0.5 0.5 0.5\n",
            encoding="utf-8",
        )

    print(
        f"Created {NUM_REFERENCE} reference images."
    )

    print(
        f"Created {NUM_CANDIDATE} candidate images "
        f"+ 1 exact duplicate."
    )


# ---------------------------------------------------------------------------
# Contributor manifest
# ---------------------------------------------------------------------------
def create_contributor_manifest() -> None:
    manifest_path = (
        DATASET_ROOT / "contributor_manifest.csv"
    )

    candidate_files = sorted(
        CANDIDATE_DIR.glob("*.png")
    )

    with manifest_path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "file",
                "contributor",
                "class",
                "timestamp",
            ],
        )

        writer.writeheader()

        for index, path in enumerate(candidate_files):
            if "duplicate" in path.name:
                contributor = "contributor_A"
                class_id = 0
            else:
                contributor = (
                    "contributor_A"
                    if index < 10
                    else "contributor_B"
                )
                class_id = index % 2

            writer.writerow(
                {
                    "file": str(
                        path.relative_to(DATASET_ROOT)
                    ),
                    "contributor": contributor,
                    "class": class_id,
                    "timestamp": "2026-09-29T10:00:00Z",
                }
            )

    print(
        f"Created {manifest_path.relative_to(ROOT)}"
    )
# ---------------------------------------------------------------------------
# Tiny PyTorch model
# ---------------------------------------------------------------------------

class DemoClassifier(nn.Module):
    """
    Tiny deterministic image classifier.

    Output:
        two logits

    Controlled behavior:
        - Clean images prefer class 0.
        - A localized bright patch in the bottom-right region adds a strong
          signal to class 1.
        - This is a synthetic demonstration artifact for TRACER-CV B4,
          not evidence about a real-world model.
    """

    def __init__(self) -> None:
        super().__init__()

        self.features = nn.Sequential(
            nn.Conv2d(
                3,
                8,
                kernel_size=3,
                padding=1,
            ),
            nn.ReLU(),
            nn.AvgPool2d(2),

            nn.Conv2d(
                8,
                16,
                kernel_size=3,
                padding=1,
            ),
            nn.ReLU(),
            nn.AvgPool2d(2),

            nn.Conv2d(
                16,
                16,
                kernel_size=3,
                padding=1,
            ),
            nn.ReLU(),

            nn.AdaptiveAvgPool2d(
                (1, 1)
            ),
        )

        self.classifier = nn.Linear(
            16,
            2,
        )

        # Controlled trigger-sensitive pathway.
        self.trigger_threshold = 0.72

        self.trigger_weight = nn.Parameter(
            torch.tensor(
                5.0,
                dtype=torch.float32,
            )
        )

        self.trigger_class_bias = nn.Parameter(
            torch.tensor(
                0.0,
                dtype=torch.float32,
            )
        )

    def forward(
        self,
        x: torch.Tensor,
    ) -> torch.Tensor:

        features = self.features(x)

        pooled = features.flatten(
            start_dim=1
        )

        logits = self.classifier(
            pooled
        )

        # Bottom-right brightness.
        trigger_region = x[
            :,
            :,
            -12:,
            -12:,
        ]

        trigger_strength = trigger_region.mean(
            dim=(1, 2, 3)
        )

        trigger_signal = (
            trigger_strength
            > self.trigger_threshold
        ).float()

        logits = logits.clone()

        logits[:, 1] = (
            logits[:, 1]
            + trigger_signal * self.trigger_weight
            + self.trigger_class_bias
        )

        return logits
def create_model() -> None:
    torch.manual_seed(SEED)

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    model = DemoClassifier()

    # Deterministic initialization of the feature extractor and classifier.
    # We intentionally do NOT leave the randomly initialized classifier in
    # place, because B4 needs a clean baseline that prefers class 0.
    with torch.no_grad():
        for parameter in model.parameters():
            if parameter.ndim > 1:
                nn.init.xavier_uniform_(
                    parameter,
                    gain=0.5,
                )
            else:
                parameter.zero_()

        # Controlled clean baseline:
        #   clean image -> class 0
        #   triggered image -> class 1
        model.classifier.weight.zero_()
        model.classifier.bias.zero_()
        model.classifier.bias[0] = 1.0
        model.classifier.bias[1] = 0.0

        # Re-establish controlled trigger parameters after the generic
        # parameter initialization above.
        model.trigger_weight.fill_(5.0)
        model.trigger_class_bias.zero_()

    model.eval()

    # Quick deterministic sanity check before exporting.
    # The model should prefer class 0 for a normal input and class 1 when
    # the bottom-right trigger region is bright.
    clean = torch.zeros(
        1,
        3,
        IMAGE_SIZE,
        IMAGE_SIZE,
        dtype=torch.float32,
    )

    triggered = clean.clone()
    triggered[
        :,
        :,
        -12:,
        -12:,
    ] = 1.0

    with torch.no_grad():
        clean_logits = model(clean)
        triggered_logits = model(triggered)

    clean_class = int(clean_logits.argmax(dim=1).item())
    triggered_class = int(triggered_logits.argmax(dim=1).item())

    if clean_class != 0 or triggered_class != 1:
        raise RuntimeError(
            "Controlled demo model sanity check failed: "
            f"clean_class={clean_class}, "
            f"triggered_class={triggered_class}. "
            "Expected clean=0 and triggered=1."
        )

    print(
        "Model sanity check: "
        f"clean -> class {clean_class}, "
        f"triggered -> class {triggered_class}"
    )

    model_path = (
        MODEL_DIR
        / "demo_model.pt"
    )

    # TorchScript gives B3 a supported model representation.
    scripted = torch.jit.script(model)

    scripted.save(
        str(model_path)
    )

    print(
        f"Created {model_path.relative_to(ROOT)}"
    )
def create_model() -> None:
    torch.manual_seed(SEED)

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    model = DemoClassifier()

    # Deterministic initialization.
    with torch.no_grad():
        for parameter in model.parameters():
            if parameter.ndim > 1:
                nn.init.xavier_uniform_(
                    parameter,
                    gain=0.5,
                )
            else:
                parameter.zero_()

        # Re-establish controlled trigger parameters.
        model.trigger_weight.fill_(5.0)
        model.trigger_class_bias.zero_()

    model.eval()

    model_path = (
        MODEL_DIR
        / "demo_model.pt"
    )

    # TorchScript gives B3 a supported model representation.
    scripted = torch.jit.script(model)

    scripted.save(
        str(model_path)
    )

    print(
        f"Created {model_path.relative_to(ROOT)}"
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    print("=" * 72)
    print("TRACER-CV — CONTROLLED DEMO ASSET GENERATOR")
    print("=" * 72)

    seed_everything()

    print("\n[1/3] Creating synthetic dataset...")
    create_dataset()

    print("\n[2/3] Creating contributor manifest...")
    create_contributor_manifest()

    print("\n[3/3] Creating tiny TorchScript model...")
    create_model()

    print("\n" + "=" * 72)
    print("ASSET GENERATION COMPLETE")
    print("=" * 72)

    print(
        f"\nDataset: "
        f"{DATASET_ROOT.relative_to(ROOT)}"
    )

    print(
        f"Model: "
        f"{(MODEL_DIR / 'demo_model.pt').relative_to(ROOT)}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
