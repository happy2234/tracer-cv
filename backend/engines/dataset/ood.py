
from __future__ import annotations

from pathlib import Path

import numpy as np
from PIL import Image, UnidentifiedImageError


IMAGE_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".bmp",
    ".tif",
    ".tiff",
    ".webp",
}


def discover_images(dataset_dir: Path) -> list[Path]:
    """Discover supported image files recursively."""

    return [
        path
        for path in sorted(dataset_dir.rglob("*"))
        if path.is_file()
        and path.suffix.lower() in IMAGE_EXTENSIONS
    ]


def extract_features(image_path: Path) -> np.ndarray:
    """
    Extract lightweight appearance features.

    Features:
        8-bin R histogram
        8-bin G histogram
        8-bin B histogram
        8-bin grayscale histogram
        edge density

    This is an appearance-space detector.
    It does not establish semantic OOD.
    """

    with Image.open(image_path) as image:
        image = image.convert("RGB")
        image = image.resize((128, 128))

        rgb = np.asarray(
            image,
            dtype=np.float32,
        ) / 255.0

    features = []

    # ---------------------------------------------------------
    # RGB histograms
    # ---------------------------------------------------------
    for channel in range(3):
        histogram, _ = np.histogram(
            rgb[:, :, channel],
            bins=8,
            range=(0.0, 1.0),
        )

        histogram = histogram.astype(np.float32)

        histogram /= max(
            histogram.sum(),
            1.0,
        )

        features.extend(
            histogram.tolist()
        )

    # ---------------------------------------------------------
    # Grayscale histogram
    # ---------------------------------------------------------
    grayscale = (
        0.299 * rgb[:, :, 0]
        + 0.587 * rgb[:, :, 1]
        + 0.114 * rgb[:, :, 2]
    )

    histogram, _ = np.histogram(
        grayscale,
        bins=8,
        range=(0.0, 1.0),
    )

    histogram = histogram.astype(np.float32)

    histogram /= max(
        histogram.sum(),
        1.0,
    )

    features.extend(
        histogram.tolist()
    )

    # ---------------------------------------------------------
    # Edge density
    # ---------------------------------------------------------
    horizontal = np.abs(
        grayscale[:, 1:]
        - grayscale[:, :-1]
    )

    vertical = np.abs(
        grayscale[1:, :]
        - grayscale[:-1, :]
    )

    edge_density = float(
        (
            np.mean(horizontal > 0.10)
            + np.mean(vertical > 0.10)
        )
        / 2.0
    )

    features.append(edge_density)

    return np.asarray(
        features,
        dtype=np.float32,
    )


def _load_feature_matrix(
    dataset_dir: Path,
):
    """Load image features from a directory."""

    image_paths = discover_images(
        dataset_dir
    )

    names = []
    features = []
    skipped = []

    for image_path in image_paths:
        try:
            feature = extract_features(
                image_path
            )

            names.append(
                image_path
                .relative_to(dataset_dir)
                .as_posix()
            )

            features.append(feature)

        except (
            UnidentifiedImageError,
            OSError,
            ValueError,
        ):
            skipped.append(
                image_path
                .relative_to(dataset_dir)
                .as_posix()
            )

    if not features:
        return (
            names,
            np.empty(
                (0, 33),
                dtype=np.float32,
            ),
            skipped,
        )

    return (
        names,
        np.vstack(features),
        skipped,
    )


def _cosine_distance(
    left: np.ndarray,
    right: np.ndarray,
) -> float:
    """Calculate cosine distance."""

    left_norm = np.linalg.norm(left)
    right_norm = np.linalg.norm(right)

    if left_norm == 0 or right_norm == 0:
        return 1.0

    similarity = float(
        np.dot(left, right)
        / (left_norm * right_norm)
    )

    similarity = np.clip(
        similarity,
        -1.0,
        1.0,
    )

    return 1.0 - similarity


def _nearest_neighbor_distances(
    features: np.ndarray,
) -> np.ndarray:
    """
    Calculate leave-one-out nearest-neighbor distances
    inside the trusted reference dataset.
    """

    count = len(features)

    if count < 2:
        raise ValueError(
            "At least two reference images are required."
        )

    distances = []

    for index in range(count):
        nearest = float("inf")

        for other_index in range(count):
            if index == other_index:
                continue

            distance = _cosine_distance(
                features[index],
                features[other_index],
            )

            nearest = min(
                nearest,
                distance,
            )

        distances.append(nearest)

    return np.asarray(
        distances,
        dtype=np.float32,
    )


def fit_reference_distribution(
    reference_dir: Path,
) -> dict:
    """
    Build an empirical appearance-space reference.

    The threshold is derived from leave-one-out
    nearest-neighbor distances inside the trusted
    reference dataset.
    """

    reference_dir = reference_dir.resolve()

    if not reference_dir.is_dir():
        raise ValueError(
            f"Reference directory does not exist: "
            f"{reference_dir}"
        )

    names, features, skipped = (
        _load_feature_matrix(
            reference_dir
        )
    )

    if len(features) < 2:
        raise ValueError(
            "At least two valid reference images "
            "are required."
        )

    reference_distances = (
        _nearest_neighbor_distances(
            features
        )
    )

    # Empirical threshold.
    #
    # We use the maximum observed trusted
    # nearest-neighbor distance rather than
    # inventing a fixed global threshold.
    threshold = float(
        np.max(reference_distances)
    )

    return {
        "reference_image_count": len(features),
        "feature_dimension": int(
            features.shape[1]
        ),
        "threshold": threshold,
        "reference_distances": (
            reference_distances
        ),
        "skipped_files": skipped,
    }


def assess_ood(
    reference_dir: Path,
    candidate_dir: Path,
) -> dict:
    """
    Compare candidate images against a trusted
    reference distribution.

    The closest trusted reference determines
    the candidate's appearance distance.
    """

    reference = fit_reference_distribution(
        reference_dir
    )

    candidate_dir = candidate_dir.resolve()

    if not candidate_dir.is_dir():
        raise ValueError(
            f"Candidate directory does not exist: "
            f"{candidate_dir}"
        )

    names, features, skipped = (
        _load_feature_matrix(
            candidate_dir
        )
    )

    if len(features) == 0:
        return {
            "status": "completed",
            "method": (
                "appearance-space nearest-reference "
                "cosine distance"
            ),
            "reference_image_count": (
                reference[
                    "reference_image_count"
                ]
            ),
            "candidate_image_count": 0,
            "feature_dimension": (
                reference[
                    "feature_dimension"
                ]
            ),
            "threshold": reference[
                "threshold"
            ],
            "potential_ood_count": 0,
            "results": [],
            "skipped_files": skipped,
            "limitations": [
                "Appearance-space detector only.",
                "Does not establish semantic OOD.",
                "Does not establish malicious intent.",
                "Reference quality affects detection quality.",
            ],
        }

    results = []

    threshold = reference[
        "threshold"
    ]

    # Reload reference features.
    _, reference_features, _ = (
        _load_feature_matrix(
            reference_dir
        )
    )

    for name, candidate in zip(
        names,
        features,
    ):
        nearest_distance = float("inf")
        nearest_reference = None

        for index, reference_feature in enumerate(
            reference_features
        ):
            distance = _cosine_distance(
                candidate,
                reference_feature,
            )

            if distance < nearest_distance:
                nearest_distance = distance
                nearest_reference = index

        potential_ood = (
            nearest_distance > threshold
        )

        results.append(
            {
                "file": name,
                "nearest_reference_index": (
                    nearest_reference
                ),
                "distance": nearest_distance,
                "threshold": threshold,
                "potential_ood": bool(
                    potential_ood
                ),
            }
        )

    potential_ood_count = sum(
        result["potential_ood"]
        for result in results
    )

    return {
        "status": "completed",
        "method": (
            "appearance-space nearest-reference "
            "cosine distance"
        ),
        "reference_image_count": (
            reference[
                "reference_image_count"
            ]
        ),
        "candidate_image_count": len(
            features
        ),
        "feature_dimension": (
            reference[
                "feature_dimension"
            ]
        ),
        "threshold": threshold,
        "potential_ood_count": (
            potential_ood_count
        ),
        "results": results,
        "skipped_files": skipped,
        "limitations": [
            "Appearance-space detector only.",
            "Does not establish semantic OOD.",
            "Does not establish malicious intent.",
            "Reference quality affects detection quality.",
        ],
    }
