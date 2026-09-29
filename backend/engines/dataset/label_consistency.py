

from __future__ import annotations

from pathlib import Path

import numpy as np
from PIL import Image


from backend.engines.dataset.near_duplicates import (
    discover_images,
    find_near_duplicates,
)


IMAGE_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".bmp",
    ".tif",
    ".tiff",
    ".webp",
}


def find_label_file(
    image_path: Path,
    labels_dir: Path,
) -> Path:
    """
    Map an image filename to its YOLO label file.

    Example:

        images/cat_001.jpg
        labels/cat_001.txt
    """

    return labels_dir / f"{image_path.stem}.txt"


def parse_yolo_label_file(
    label_path: Path,
    num_classes: int | None = None,
) -> dict:
    """
    Parse a YOLO annotation file.

    Expected format:

        class_id x_center y_center width height

    Returns parsing errors instead of silently ignoring them.
    """

    result = {
        "file": label_path.name,
        "exists": label_path.exists(),
        "empty": False,
        "valid": True,
        "annotations": [],
        "class_ids": [],
        "errors": [],
    }

    if not label_path.exists():
        result["valid"] = False
        result["errors"].append(
            "Missing label file."
        )
        return result

    try:
        text = label_path.read_text(
            encoding="utf-8"
        )
    except OSError as exc:
        result["valid"] = False
        result["errors"].append(
            f"Unable to read label file: {exc}"
        )
        return result

    lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip()
    ]

    if not lines:
        result["empty"] = True
        return result

    for line_number, line in enumerate(
        lines,
        start=1,
    ):
        parts = line.split()

        if len(parts) != 5:
            result["valid"] = False
            result["errors"].append(
                f"Line {line_number}: expected 5 "
                f"values, found {len(parts)}."
            )
            continue

        try:
            class_id = int(parts[0])

            x_center = float(parts[1])
            y_center = float(parts[2])
            width = float(parts[3])
            height = float(parts[4])

        except ValueError:
            result["valid"] = False
            result["errors"].append(
                f"Line {line_number}: non-numeric "
                f"annotation values."
            )
            continue

        if class_id < 0:
            result["valid"] = False
            result["errors"].append(
                f"Line {line_number}: negative "
                f"class ID {class_id}."
            )

        if num_classes is not None:
            if class_id >= num_classes:
                result["valid"] = False
                result["errors"].append(
                    f"Line {line_number}: class ID "
                    f"{class_id} is outside configured "
                    f"class range 0-{num_classes - 1}."
                )

        coordinates = (
            x_center,
            y_center,
            width,
            height,
        )

        for value_name, value in zip(
            (
                "x_center",
                "y_center",
                "width",
                "height",
            ),
            coordinates,
        ):
            if not 0.0 <= value <= 1.0:
                result["valid"] = False
                result["errors"].append(
                    f"Line {line_number}: "
                    f"{value_name}={value} "
                    f"is outside [0, 1]."
                )

        if width <= 0:
            result["valid"] = False
            result["errors"].append(
                f"Line {line_number}: "
                "width must be greater than zero."
            )

        if height <= 0:
            result["valid"] = False
            result["errors"].append(
                f"Line {line_number}: "
                "height must be greater than zero."
            )

        result["annotations"].append(
            {
                "class_id": class_id,
                "x_center": x_center,
                "y_center": y_center,
                "width": width,
                "height": height,
            }
        )

        result["class_ids"].append(
            class_id
        )

    return result


def annotation_signature(
    parsed_label: dict,
) -> tuple:
    """
    Create a stable representation of labels.

    Bounding-box coordinates are retained because two
    visually similar images can legitimately contain
    different objects.
    """

    annotations = []

    for annotation in parsed_label[
        "annotations"
    ]:
        annotations.append(
            (
                annotation["class_id"],
                round(
                    annotation["x_center"],
                    4,
                ),
                round(
                    annotation["y_center"],
                    4,
                ),
                round(
                    annotation["width"],
                    4,
                ),
                round(
                    annotation["height"],
                    4,
                ),
            )
        )

    return tuple(
        sorted(annotations)
    )


def label_class_set(
    parsed_label: dict,
) -> tuple[int, ...]:
    """Return unique sorted class IDs."""

    return tuple(
        sorted(
            set(
                parsed_label[
                    "class_ids"
                ]
            )
        )
    )

def appearance_similarity(
    image_a: Path,
    image_b: Path,
) -> float:
    """
    Compare two images using normalized RGB histograms.

    Returns:
        0.0 -> very different appearance
        1.0 -> very similar appearance
    """

    def histogram(path: Path) -> np.ndarray:
        with Image.open(path) as image:
            image = image.convert("RGB")
            image = image.resize((128, 128))

            array = (
                np.asarray(
                    image,
                    dtype=np.float32,
                )
                / 255.0
            )

        features = []

        for channel in range(3):
            values, _ = np.histogram(
                array[:, :, channel],
                bins=16,
                range=(0.0, 1.0),
            )

            values = values.astype(
                np.float32
            )

            values /= max(
                values.sum(),
                1.0,
            )

            features.extend(
                values.tolist()
            )

        vector = np.asarray(
            features,
            dtype=np.float32,
        )

        return vector

    vector_a = histogram(image_a)
    vector_b = histogram(image_b)

    norm_a = np.linalg.norm(vector_a)
    norm_b = np.linalg.norm(vector_b)

    if norm_a == 0 or norm_b == 0:
        return 0.0

    similarity = float(
        np.dot(vector_a, vector_b)
        / (norm_a * norm_b)
    )

    return float(
        np.clip(
            similarity,
            0.0,
            1.0,
        )
    )

def assess_label_consistency(
    dataset_dir: Path,
    labels_dir: Path | None = None,
    num_classes: int | None = None,
    near_duplicate_threshold: int = 8,
) -> dict:
    """
    Perform YOLO label consistency assessment.

    Checks:
      - missing labels
      - malformed labels
      - empty labels
      - invalid class IDs / coordinates
      - near-duplicate images with conflicting labels
    """

    dataset_dir = dataset_dir.resolve()

    if not dataset_dir.is_dir():
        raise ValueError(
            f"Dataset directory does not exist: "
            f"{dataset_dir}"
        )

    if labels_dir is None:
        labels_dir = dataset_dir / "labels"
    else:
        labels_dir = labels_dir.resolve()

    if not labels_dir.is_dir():
        raise ValueError(
            f"Labels directory does not exist: "
            f"{labels_dir}"
        )

    image_paths = discover_images(
        dataset_dir
    )

    image_records = []
    missing_labels = []
    malformed_labels = []
    empty_labels = []

    # ---------------------------------------------------------
    # Parse every image's label file.
    # ---------------------------------------------------------

    for image_path in image_paths:
        label_path = find_label_file(
            image_path,
            labels_dir,
        )

        parsed = parse_yolo_label_file(
            label_path,
            num_classes=num_classes,
        )

        record = {
            "image": image_path.name,
            "image_path": image_path,
            "label_path": label_path,
            "label": parsed,
        }

        image_records.append(record)

        if not parsed["exists"]:
            missing_labels.append(
                image_path.name
            )
            continue

        if parsed["empty"]:
            empty_labels.append(
                image_path.name
            )

        if not parsed["valid"]:
            malformed_labels.append(
                {
                    "image": image_path.name,
                    "label": label_path.name,
                    "errors": parsed[
                        "errors"
                    ],
                }
            )

    # ---------------------------------------------------------
    # Near-duplicate analysis.
    # ---------------------------------------------------------

    near_duplicates = find_near_duplicates(
        dataset_dir,
        threshold=near_duplicate_threshold,
    )

    record_by_name = {
        record["image"]: record
        for record in image_records
    }

    conflicting_pairs = []

    for pair in near_duplicates[
        "pairs"
    ]:
        file_a = pair["file_a"]
        file_b = pair["file_b"]

        record_a = record_by_name.get(
            Path(file_a).name
        )

        record_b = record_by_name.get(
            Path(file_b).name
        )

        if record_a is None or record_b is None:
            continue

        label_a = record_a["label"]
        label_b = record_b["label"]

        # We only compare valid, non-empty annotations.
        if not label_a["valid"]:
            continue

        if not label_b["valid"]:
            continue

        if label_a["empty"] or label_b["empty"]:
            continue

        classes_a = label_class_set(
            label_a
        )

        classes_b = label_class_set(
            label_b
        )

        image_path_a = (
            dataset_dir / file_a
        )

        image_path_b = (
            dataset_dir / file_b
        )

        try:
            similarity = appearance_similarity(
                image_path_a,
                image_path_b,
            )
        except (
            OSError,
            ValueError,
        ):
            similarity = 0.0

        # A label conflict is only interesting when
        # BOTH signals indicate strong visual similarity:
        #
        #   1. dHash says the images are near duplicates
        #   2. RGB appearance is also similar
        #
        # This reduces false positives from visually
        # simple images that happen to produce similar
        # perceptual hashes.

        if (
            classes_a != classes_b
            and similarity >= 0.90
        ):
            conflicting_pairs.append(
                {
                    "file_a": file_a,
                    "file_b": file_b,
                    "hamming_distance": pair[
                        "hamming_distance"
                    ],
                    "threshold": pair[
                        "threshold"
                    ],
                    "appearance_similarity": similarity,
                    "classes_a": classes_a,
                    "classes_b": classes_b,
                }
            )

    finding_count = (
        len(missing_labels)
        + len(malformed_labels)
        + len(empty_labels)
        + len(conflicting_pairs)
    )

    return {
        "status": "completed",
        "method": (
            "YOLO annotation validation + "
            "near-duplicate label conflict analysis"
        ),
        "images_discovered": len(
            image_paths
        ),
        "labels_directory": str(
            labels_dir
        ),
        "missing_label_count": len(
            missing_labels
        ),
        "missing_labels": missing_labels,
        "malformed_label_count": len(
            malformed_labels
        ),
        "malformed_labels": malformed_labels,
        "empty_label_count": len(
            empty_labels
        ),
        "empty_labels": empty_labels,
        "near_duplicate_pair_count": (
            near_duplicates[
                "near_duplicate_pair_count"
            ]
        ),
        "conflicting_pair_count": len(
            conflicting_pairs
        ),
        "conflicting_pairs": (
            conflicting_pairs
        ),
        "finding_count": finding_count,
        "limitations": [
            "YOLO annotation format is assessed.",
            "Near-duplicate similarity does not prove "
            "that a label is incorrect.",
            "A conflict is reported as a potential "
            "label inconsistency requiring review.",
            "Semantic correctness of an annotation is "
            "not established automatically.",
        ],
    }
