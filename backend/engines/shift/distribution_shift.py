"""
TRACER-CV C2 — Distribution Shift & Anomaly Detection.

Offline deterministic image-distribution analysis.

Compares a reference image population against a candidate/current
population and identifies measurable distribution changes.

C2 detects measurable distribution differences.

C2 does NOT determine malicious intent and does not claim that
distribution shift is necessarily an attack.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple

import numpy as np
from PIL import Image


ENGINE_VERSION = "c2-1.0"
METHOD = "multifeature image distribution shift analysis"
TASK = "distribution_shift"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DistributionShiftConfig:
    histogram_bins: int = 16

    # Per-feature shift thresholds.
    brightness_threshold: float = 0.08
    contrast_threshold: float = 0.08
    saturation_threshold: float = 0.08
    edge_density_threshold: float = 0.08

    # Overall shift threshold.
    overall_shift_threshold: float = 0.20

    # Per-image anomaly threshold in standardized feature space.
    image_anomaly_z: float = 3.0

    max_images: int = 500
    seed: int = 1337


# ---------------------------------------------------------------------------
# Basic utilities
# ---------------------------------------------------------------------------

def _safe_float(value: float) -> float:
    value = float(value)

    if not math.isfinite(value):
        return 0.0

    return value


def _sha256_json(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    return hashlib.sha256(payload).hexdigest()


# ---------------------------------------------------------------------------
# Image features
# ---------------------------------------------------------------------------

FEATURE_NAMES = (
    "brightness",
    "contrast",
    "saturation",
    "edge_density",
)


def _image_features(
    image: Image.Image,
    bins: int,
) -> Dict[str, Any]:
    rgb = image.convert("RGB")
    arr = np.asarray(rgb, dtype=np.float32) / 255.0

    brightness = float(np.mean(arr))

    grayscale = (
        0.299 * arr[:, :, 0]
        + 0.587 * arr[:, :, 1]
        + 0.114 * arr[:, :, 2]
    )

    contrast = float(np.std(grayscale))

    max_channel = np.max(arr, axis=2)
    min_channel = np.min(arr, axis=2)

    saturation = float(
        np.mean(max_channel - min_channel)
    )

    # Simple deterministic gradient magnitude.
    gx = np.diff(grayscale, axis=1)
    gy = np.diff(grayscale, axis=0)

    if gx.size == 0 or gy.size == 0:
        edge_density = 0.0
    else:
        gx_pad = np.pad(
            gx,
            ((0, 0), (0, 1)),
            mode="constant",
        )

        gy_pad = np.pad(
            gy,
            ((0, 1), (0, 0)),
            mode="constant",
        )

        magnitude = np.sqrt(
            gx_pad * gx_pad + gy_pad * gy_pad
        )

        edge_density = float(
            np.mean(magnitude > 0.10)
        )

    histograms: Dict[str, List[float]] = {}

    for channel_index, name in enumerate(
        ("red_hist", "green_hist", "blue_hist")
    ):
        histogram, _ = np.histogram(
            arr[:, :, channel_index],
            bins=bins,
            range=(0.0, 1.0),
        )

        histogram = histogram.astype(np.float64)

        total = histogram.sum()

        if total > 0:
            histogram /= total

        histograms[name] = histogram.tolist()

    gray_histogram, _ = np.histogram(
        grayscale,
        bins=bins,
        range=(0.0, 1.0),
    )

    gray_histogram = gray_histogram.astype(np.float64)

    gray_total = gray_histogram.sum()

    if gray_total > 0:
        gray_histogram /= gray_total

    histograms["gray_hist"] = gray_histogram.tolist()

    return {
        "brightness": _safe_float(brightness),
        "contrast": _safe_float(contrast),
        "saturation": _safe_float(saturation),
        "edge_density": _safe_float(edge_density),
        "width": int(rgb.width),
        "height": int(rgb.height),
        "red_hist": histograms["red_hist"],
        "green_hist": histograms["green_hist"],
        "blue_hist": histograms["blue_hist"],
        "gray_hist": histograms["gray_hist"],
    }


# ---------------------------------------------------------------------------
# Feature distance
# ---------------------------------------------------------------------------

def _histogram_distance(
    a: Sequence[float],
    b: Sequence[float],
) -> float:
    """Total variation distance between two normalized histograms."""

    length = min(len(a), len(b))

    if length == 0:
        return 0.0

    return 0.5 * sum(
        abs(float(a[index]) - float(b[index]))
        for index in range(length)
    )


def _scalar_distance(
    a: float,
    b: float,
) -> float:
    return abs(float(a) - float(b))


# ---------------------------------------------------------------------------
# Population summary
# ---------------------------------------------------------------------------

def _summarize_features(
    features: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:

    if not features:
        return {
            name: {
                "mean": 0.0,
                "std": 0.0,
                "count": 0,
            }
            for name in FEATURE_NAMES
        }

    result: Dict[str, Any] = {}

    for name in FEATURE_NAMES:
        values = np.asarray(
            [
                float(item[name])
                for item in features
            ],
            dtype=np.float64,
        )

        result[name] = {
            "mean": _safe_float(np.mean(values)),
            "std": _safe_float(np.std(values)),
            "count": int(values.size),
        }

    return result


def _histogram_summary(
    features: Sequence[Dict[str, Any]],
    name: str,
) -> List[float]:

    if not features:
        return []

    arrays = [
        np.asarray(item[name], dtype=np.float64)
        for item in features
    ]

    matrix = np.vstack(arrays)

    mean_hist = np.mean(matrix, axis=0)

    total = float(np.sum(mean_hist))

    if total > 0:
        mean_hist = mean_hist / total

    return [
        _safe_float(value)
        for value in mean_hist
    ]


# ---------------------------------------------------------------------------
# Image loading
# ---------------------------------------------------------------------------

def _iter_image_paths(
    paths: Iterable[str | Path],
    max_images: int,
) -> List[Path]:

    extensions = {
        ".jpg",
        ".jpeg",
        ".png",
        ".bmp",
        ".webp",
        ".tif",
        ".tiff",
    }

    result: List[Path] = []

    for raw_path in paths:
        path = Path(raw_path)

        if path.is_file():
            if path.suffix.lower() in extensions:
                result.append(path)

        elif path.is_dir():
            for child in sorted(path.rglob("*")):
                if (
                    child.is_file()
                    and child.suffix.lower() in extensions
                ):
                    result.append(child)

        if len(result) >= max_images:
            break

    return sorted(result)[:max_images]


def _extract_dataset_features(
    paths: Sequence[Path],
    bins: int,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:

    features: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    for path in paths:
        try:
            with Image.open(path) as image:
                feature = _image_features(
                    image,
                    bins,
                )

            feature["path"] = str(path)
            feature["file"] = path.name

            features.append(feature)

        except Exception as exc:
            errors.append(
                {
                    "path": str(path),
                    "error": str(exc),
                }
            )

    return features, errors


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyze_distribution_shift(
    reference_paths: Iterable[str | Path],
    candidate_paths: Iterable[str | Path],
    *,
    config: DistributionShiftConfig | None = None,
) -> Dict[str, Any]:
    """
    Compare reference and candidate image populations.
    """

    cfg = config or DistributionShiftConfig()

    if cfg.histogram_bins < 2:
        raise ValueError(
            "histogram_bins must be >= 2"
        )

    if cfg.max_images < 1:
        raise ValueError(
            "max_images must be >= 1"
        )

    reference_list = _iter_image_paths(
        reference_paths,
        cfg.max_images,
    )

    candidate_list = _iter_image_paths(
        candidate_paths,
        cfg.max_images,
    )

    reference_features, reference_errors = (
        _extract_dataset_features(
            reference_list,
            cfg.histogram_bins,
        )
    )

    candidate_features, candidate_errors = (
        _extract_dataset_features(
            candidate_list,
            cfg.histogram_bins,
        )
    )

    if not reference_features:
        return {
            "status": "unavailable",
            "reason": "No valid reference images were available.",
            "engine_version": ENGINE_VERSION,
            "method": METHOD,
        }

    if not candidate_features:
        return {
            "status": "unavailable",
            "reason": "No valid candidate images were available.",
            "engine_version": ENGINE_VERSION,
            "method": METHOD,
        }

    reference_summary = _summarize_features(
        reference_features
    )

    candidate_summary = _summarize_features(
        candidate_features
    )

    scalar_distances: Dict[str, float] = {}

    for name in FEATURE_NAMES:
        scalar_distances[name] = _scalar_distance(
            reference_summary[name]["mean"],
            candidate_summary[name]["mean"],
        )

    histogram_distances: Dict[str, float] = {}

    for name in (
        "red_hist",
        "green_hist",
        "blue_hist",
        "gray_hist",
    ):
        reference_hist = _histogram_summary(
            reference_features,
            name,
        )

        candidate_hist = _histogram_summary(
            candidate_features,
            name,
        )

        histogram_distances[name] = _histogram_distance(
            reference_hist,
            candidate_hist,
        )

    feature_thresholds = {
        "brightness": cfg.brightness_threshold,
        "contrast": cfg.contrast_threshold,
        "saturation": cfg.saturation_threshold,
        "edge_density": cfg.edge_density_threshold,
    }

    shifted_features: List[Dict[str, Any]] = []

    for name in FEATURE_NAMES:
        distance = scalar_distances[name]
        threshold = feature_thresholds[name]

        if distance >= threshold:
            shifted_features.append(
                {
                    "feature": name,
                    "distance": _safe_float(distance),
                    "threshold": _safe_float(threshold),
                    "shifted": True,
                }
            )
        else:
            shifted_features.append(
                {
                    "feature": name,
                    "distance": _safe_float(distance),
                    "threshold": _safe_float(threshold),
                    "shifted": False,
                }
            )

    histogram_mean = float(
        np.mean(
            list(histogram_distances.values())
        )
    )

    scalar_mean = float(
        np.mean(
            list(scalar_distances.values())
        )
    )

    overall_shift = float(
        0.6 * scalar_mean
        + 0.4 * histogram_mean
    )

    shifted_count = sum(
        1
        for item in shifted_features
        if item["shifted"]
    )

    if overall_shift >= cfg.overall_shift_threshold:
        severity = "high"
    elif shifted_count >= 2:
        severity = "medium"
    elif shifted_count == 1:
        severity = "low"
    else:
        severity = "none"

    # ------------------------------------------------------------------
    # Per-image anomaly detection
    # ------------------------------------------------------------------

    reference_matrix = np.asarray(
        [
            [
                float(item[name])
                for name in FEATURE_NAMES
            ]
            for item in reference_features
        ],
        dtype=np.float64,
    )

    reference_mean = np.mean(
        reference_matrix,
        axis=0,
    )

    reference_std = np.std(
        reference_matrix,
        axis=0,
    )

    reference_std = np.where(
        reference_std < 1e-6,
        1e-6,
        reference_std,
    )

    anomalous_images: List[Dict[str, Any]] = []

    for item in candidate_features:
        vector = np.asarray(
            [
                float(item[name])
                for name in FEATURE_NAMES
            ],
            dtype=np.float64,
        )

        z_scores = np.abs(
            (vector - reference_mean)
            / reference_std
        )

        max_z = float(np.max(z_scores))

        if max_z >= cfg.image_anomaly_z:
            anomalous_images.append(
                {
                    "file": item["file"],
                    "path": item["path"],
                    "max_z_score": _safe_float(max_z),
                    "features": {
                        name: _safe_float(
                            z_scores[index]
                        )
                        for index, name in enumerate(
                            FEATURE_NAMES
                        )
                    },
                }
            )

    findings: List[Dict[str, Any]] = []

    if severity != "none":
        findings.append(
            {
                "type": "distribution_shift",
                "severity": severity,
                "overall_shift": _safe_float(
                    overall_shift
                ),
                "message": (
                    "Candidate image population differs "
                    "measurably from the reference population."
                ),
            }
        )

    if anomalous_images:
        findings.append(
            {
                "type": "candidate_image_anomalies",
                "severity": (
                    "medium"
                    if len(anomalous_images) < 5
                    else "high"
                ),
                "count": len(anomalous_images),
                "message": (
                    "Some candidate images are statistical "
                    "outliers relative to the reference feature "
                    "distribution."
                ),
            }
        )

    result = {
        "status": "completed",
        "engine_version": ENGINE_VERSION,
        "method": METHOD,
        "task": TASK,
        "config": asdict(cfg),
        "reference": {
            "image_count": len(reference_features),
            "error_count": len(reference_errors),
            "summary": reference_summary,
            "histograms": {
                name: _histogram_summary(
                    reference_features,
                    name,
                )
                for name in (
                    "red_hist",
                    "green_hist",
                    "blue_hist",
                    "gray_hist",
                )
            },
        },
        "candidate": {
            "image_count": len(candidate_features),
            "error_count": len(candidate_errors),
            "summary": candidate_summary,
            "histograms": {
                name: _histogram_summary(
                    candidate_features,
                    name,
                )
                for name in (
                    "red_hist",
                    "green_hist",
                    "blue_hist",
                    "gray_hist",
                )
            },
        },
        "distances": {
            "scalar": {
                key: _safe_float(value)
                for key, value in scalar_distances.items()
            },
            "histogram": {
                key: _safe_float(value)
                for key, value in histogram_distances.items()
            },
        },
        "shifted_features": shifted_features,
        "overall_shift": _safe_float(overall_shift),
        "severity": severity,
        "anomalous_images": anomalous_images,
        "findings": findings,
        "errors": {
            "reference": reference_errors,
            "candidate": candidate_errors,
        },
        "limitations": [
            "Distribution shift does not prove malicious manipulation.",
            "Appearance features do not establish semantic correctness.",
            "A stable distribution does not prove absence of attacks.",
            "Thresholds are configurable heuristics and require validation "
            "against representative reference data.",
            "This MVP analyzes image populations rather than proving "
            "causal source of a detected shift.",
        ],
    }

    result["result_digest"] = _sha256_json(
        {
            "overall_shift": result["overall_shift"],
            "severity": result["severity"],
            "distances": result["distances"],
            "shifted_features": result["shifted_features"],
            "anomalous_images": result["anomalous_images"],
        }
    )

    return result


# ---------------------------------------------------------------------------
# Convenience API
# ---------------------------------------------------------------------------

def analyze_image_directories(
    reference_dir: str | Path,
    candidate_dir: str | Path,
    *,
    config: DistributionShiftConfig | None = None,
) -> Dict[str, Any]:
    """Analyze two local image directories."""

    return analyze_distribution_shift(
        [Path(reference_dir)],
        [Path(candidate_dir)],
        config=config,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "ENGINE_VERSION",
    "METHOD",
    "TASK",
    "DistributionShiftConfig",
    "analyze_distribution_shift",
    "analyze_image_directories",
]

