"""A8 - Poison / Trigger-like Analysis.

Offline deterministic image-forensics style analysis for TRACER-CV.

The engine looks for:
- localized high-frequency anomalies
- repeated localized patches
- spatial concentration of repeated patches
- class-conditional association when labels are supplied

This provides candidate trigger-like evidence only. It does not prove
poisoning, backdoor implantation, attacker identity, attacker intent,
or causal model behaviour.
"""

from __future__ import annotations

import math
import os
from pathlib import Path
from statistics import median
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

import numpy as np
from numpy.lib.stride_tricks import sliding_window_view
from PIL import Image


__all__ = ["analyze_poison_trigger", "METHOD"]

METHOD = "deterministic_local_patch_forensics_v1"

IMAGE_SUFFIXES = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".bmp",
        ".tif",
        ".tiff",
        ".webp",
    }
)

WORK_SIZE = 128
WINDOW = 16
STRIDE = 8

EDGE_GRADIENT_THRESHOLD = 40.0
MIN_ROBUST_SCALE = 2.0
MIN_IMAGE_SIDE = 32

_ZONES = (
    ("top-left", "top-center", "top-right"),
    ("middle-left", "center", "middle-right"),
    ("bottom-left", "bottom-center", "bottom-right"),
)

DISCLAIMER = (
    "This engine detects trigger-like or suspicious repeated visual evidence. "
    "It does NOT prove malicious poisoning, backdoor implantation, attacker "
    "identity, attacker intent, or any causal effect on model predictions; "
    "those require additional model-level analysis."
)

LIMITATIONS = [
    "Cannot distinguish a trigger from legitimate repeated visual structure "
    "(watermarks, logos, borders, timestamps, sensor artefacts, repeated "
    "textures); such content can produce the same evidence.",
    "Only compact, high-frequency localized patches are detected. Blended, "
    "low-contrast, very small, very large, semantic or frequency-domain "
    "triggers may be missed.",
    "Repeat matching uses a 64-bit hash at reduced resolution; it is not robust "
    "to large shifts, rotation, scaling, inverted polarity or heavy "
    "recompression.",
    "Images are converted to grayscale and resized to 128x128 before analysis; "
    "colour-only triggers and fine detail are not visible to this engine.",
    "Class association is statistical association only and does not establish "
    "a backdoor.",
    "Thresholds are heuristic defaults and have not been calibrated on real "
    "datasets; JPEG block artefacts may occasionally resemble patches.",
]

FINDING_LIMITATIONS = [
    "Heuristic evidence only; not proof of poisoning or of a backdoor.",
    "May be ordinary image content such as text, logos, watermarks, or sensor artefacts.",
    "Requires analyst review.",
]


class _ImageTooSmall(Exception):
    pass


def _r(value: float, digits: int = 4) -> float:
    return round(float(value), digits)


def _hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def _zone(x: float, y: float) -> str:
    col = 0 if x < 1 / 3 else (1 if x < 2 / 3 else 2)
    row = 0 if y < 1 / 3 else (1 if y < 2 / 3 else 2)
    return _ZONES[row][col]


def _rel(path: Path, root: Optional[Path]) -> str:
    if root is not None:
        try:
            return Path(
                os.path.abspath(path)
            ).relative_to(
                Path(os.path.abspath(root))
            ).as_posix()
        except ValueError:
            pass

    return Path(path).as_posix()


def _discover(
    dataset: Union[str, os.PathLike, Iterable],
) -> Tuple[Optional[Path], List[Path]]:
    if isinstance(dataset, (str, os.PathLike)):
        root = Path(dataset)

        if root.is_dir():
            paths = [
                p
                for p in root.rglob("*")
                if p.is_file()
                and p.suffix.lower() in IMAGE_SUFFIXES
            ]
            return root, paths

        return root.parent, [root]

    paths = [Path(p) for p in dataset]

    root: Optional[Path] = None

    if paths:
        try:
            root = Path(
                os.path.commonpath(
                    [
                        os.path.abspath(p.parent)
                        for p in paths
                    ]
                )
            )
        except ValueError:
            root = None

    return root, paths


def _load_gray(
    path: Path,
) -> Tuple[np.ndarray, Tuple[int, int]]:
    with Image.open(path) as image:
        image.load()

        width, height = image.size

        if min(width, height) < MIN_IMAGE_SIDE:
            raise _ImageTooSmall()

        gray = image.convert("L").resize(
            (WORK_SIZE, WORK_SIZE),
            Image.Resampling.BILINEAR,
        )

    return np.asarray(gray, dtype=np.float32), (width, height)


def _components(
    mask: np.ndarray,
) -> List[List[Tuple[int, int]]]:
    rows, cols = mask.shape
    seen = np.zeros(mask.shape, dtype=bool)
    components: List[List[Tuple[int, int]]] = []

    for row in range(rows):
        for col in range(cols):
            if not mask[row, col] or seen[row, col]:
                continue

            stack = [(row, col)]
            seen[row, col] = True
            cells: List[Tuple[int, int]] = []

            while stack:
                current_row, current_col = stack.pop()
                cells.append(
                    (current_row, current_col)
                )

                for dr in (-1, 0, 1):
                    for dc in (-1, 0, 1):
                        nr = current_row + dr
                        nc = current_col + dc

                        if (
                            0 <= nr < rows
                            and 0 <= nc < cols
                            and mask[nr, nc]
                            and not seen[nr, nc]
                        ):
                            seen[nr, nc] = True
                            stack.append((nr, nc))

            components.append(
                sorted(cells)
            )

    return components


def _descriptor(
    arr: np.ndarray,
    x: int,
    y: int,
) -> Optional[int]:
    crop = arr[
        y:y + WINDOW,
        x:x + WINDOW,
    ]

    if crop.shape != (WINDOW, WINDOW):
        return None

    if float(crop.std()) < 1.0:
        return None

    blocks = crop.reshape(
        8,
        WINDOW // 8,
        8,
        WINDOW // 8,
    ).mean(axis=(1, 3))

    bits = (
        blocks > crop.mean()
    ).ravel()

    value = 0

    for bit in bits:
        value = (value << 1) | int(bit)

    return value


def _detect_regions(
    arr: np.ndarray,
    original_size: Tuple[int, int],
    parameters: Dict[str, Any],
):
    gradient = np.zeros_like(arr)

    gradient[:, 1:] += np.abs(
        np.diff(arr, axis=1)
    )

    gradient[1:, :] += np.abs(
        np.diff(arr, axis=0)
    )

    gradient_windows = sliding_window_view(
        gradient,
        (WINDOW, WINDOW),
    )[::STRIDE, ::STRIDE]

    image_windows = sliding_window_view(
        arr,
        (WINDOW, WINDOW),
    )[::STRIDE, ::STRIDE]

    high_frequency = gradient_windows.mean(
        axis=(2, 3)
    )

    edge_density = (
        gradient_windows > EDGE_GRADIENT_THRESHOLD
    ).mean(axis=(2, 3))

    contrast = image_windows.std(
        axis=(2, 3)
    )

    median_hf = float(
        np.median(high_frequency)
    )

    mad = float(
        np.median(
            np.abs(
                high_frequency - median_hf
            )
        )
    )

    scale = max(
        1.4826 * mad,
        MIN_ROBUST_SCALE,
    )

    z_scores = (
        high_frequency - median_hf
    ) / scale

    global_edge_density = float(
        (
            gradient > EDGE_GRADIENT_THRESHOLD
        ).mean()
    )

    mask = (
        (high_frequency >= parameters["min_abs_hf"])
        & (z_scores >= parameters["z_threshold"])
        & (
            high_frequency
            >= parameters["min_ratio"]
            * max(median_hf, 1.0)
        )
    )

    flagged_fraction = float(
        mask.mean()
    )

    diagnostics = {
        "suppressed_high_texture": False,
        "background_median_hf": median_hf,
    }

    if not mask.any():
        return [], diagnostics

    if (
        flagged_fraction
        > parameters["max_flagged_fraction"]
    ):
        diagnostics[
            "suppressed_high_texture"
        ] = True

        return [], diagnostics

    scale_x = (
        original_size[0] / WORK_SIZE
    )

    scale_y = (
        original_size[1] / WORK_SIZE
    )

    candidates: List[Dict[str, Any]] = []

    for component in _components(mask):
        row_values = [
            cell[0]
            for cell in component
        ]

        col_values = [
            cell[1]
            for cell in component
        ]

        row_min = min(row_values)
        row_max = max(row_values)
        col_min = min(col_values)
        col_max = max(col_values)

        box_height = (
            row_max - row_min + 1
        )

        box_width = (
            col_max - col_min + 1
        )

        long_side = max(
            box_height,
            box_width,
        )

        short_side = min(
            box_height,
            box_width,
        )

        fill = len(component) / float(
            box_height * box_width
        )

        x0 = col_min * STRIDE
        y0 = row_min * STRIDE

        x1 = (
            col_max * STRIDE
            + WINDOW
        )

        y1 = (
            row_max * STRIDE
            + WINDOW
        )

        area_fraction = (
            (x1 - x0)
            * (y1 - y0)
            / float(WORK_SIZE * WORK_SIZE)
        )

        if (
            area_fraction
            > parameters["max_region_area_fraction"]
        ):
            continue

        if (
            long_side >= 4
            and long_side / short_side > 3.5
        ):
            continue

        if (
            long_side >= 3
            and fill < 0.5
        ):
            continue

        peak_row, peak_col = max(
            component,
            key=lambda cell: (
                float(
                    high_frequency[
                        cell
                    ]
                ),
                -cell[0],
                -cell[1],
            ),
        )

        peak_x = peak_col * STRIDE
        peak_y = peak_row * STRIDE

        candidates.append(
            {
                "peak_hf": float(
                    high_frequency[
                        peak_row,
                        peak_col,
                    ]
                ),
                "z": float(
                    z_scores[
                        peak_row,
                        peak_col,
                    ]
                ),
                "local_contrast": float(
                    contrast[
                        peak_row,
                        peak_col,
                    ]
                ),
                "local_edge_density": float(
                    edge_density[
                        peak_row,
                        peak_col,
                    ]
                ),
                "global_edge_density": (
                    global_edge_density
                ),
                "background_median_hf": (
                    median_hf
                ),
                "window_count": len(component),
                "region": {
                    "x": int(
                        round(x0 * scale_x)
                    ),
                    "y": int(
                        round(y0 * scale_y)
                    ),
                    "width": int(
                        round(
                            (x1 - x0)
                            * scale_x
                        )
                    ),
                    "height": int(
                        round(
                            (y1 - y0)
                            * scale_y
                        )
                    ),
                },
                "region_norm": {
                    "x": _r(
                        x0 / WORK_SIZE
                    ),
                    "y": _r(
                        y0 / WORK_SIZE
                    ),
                    "width": _r(
                        (x1 - x0)
                        / WORK_SIZE
                    ),
                    "height": _r(
                        (y1 - y0)
                        / WORK_SIZE
                    ),
                },
                "cx": (
                    peak_x + WINDOW / 2.0
                ) / WORK_SIZE,
                "cy": (
                    peak_y + WINDOW / 2.0
                ) / WORK_SIZE,
                "descriptor": _descriptor(
                    arr,
                    peak_x,
                    peak_y,
                ),
                "_sort": (
                    -float(
                        high_frequency[
                            peak_row,
                            peak_col,
                        ]
                    ),
                    y0,
                    x0,
                ),
            }
        )

    candidates.sort(
        key=lambda candidate: candidate["_sort"]
    )

    return (
        candidates[
            :parameters["max_regions_per_image"]
        ],
        diagnostics,
    )


def _hypergeom_tail(
    k: int,
    n: int,
    K: int,
    N: int,
) -> float:
    denominator = math.comb(N, n)

    total = 0

    for i in range(
        k,
        min(n, K) + 1,
    ):
        if 0 <= n - i <= N - K:
            total += (
                math.comb(K, i)
                * math.comb(
                    N - K,
                    n - i,
                )
            )

    return total / denominator


def _normalize_labels(
    labels: Optional[Dict[str, Any]],
) -> Dict[str, str]:
    if not labels:
        return {}

    return {
        str(key).replace("\\", "/"): str(value)
        for key, value in labels.items()
    }


def analyze_poison_trigger(
    dataset: Union[
        str,
        os.PathLike,
        Iterable,
    ],
    labels: Optional[Dict[str, Any]] = None,
    *,
    infer_labels_from_folders: bool = False,
    z_threshold: float = 6.0,
    min_abs_hf: float = 20.0,
    min_ratio: float = 3.0,
    max_flagged_fraction: float = 0.15,
    max_region_area_fraction: float = 0.25,
    max_regions_per_image: int = 3,
    hamming_tolerance: int = 6,
    min_pattern_images: int = 3,
    spatial_tolerance: float = 0.08,
    spatial_min_fraction: float = 0.75,
    class_min_share: float = 0.8,
    class_max_p: float = 0.01,
) -> Dict[str, Any]:
    """Run A8 on a directory or iterable of image paths."""

    parameters = {
        "z_threshold": z_threshold,
        "min_abs_hf": min_abs_hf,
        "min_ratio": min_ratio,
        "max_flagged_fraction": max_flagged_fraction,
        "max_region_area_fraction": max_region_area_fraction,
        "max_regions_per_image": max_regions_per_image,
    }

    root, raw_paths = _discover(
        dataset
    )

    entries: Dict[str, Path] = {}

    for path in raw_paths:
        entries.setdefault(
            _rel(path, root),
            path,
        )

    relative_paths = sorted(entries)

    label_map = _normalize_labels(labels)

    skipped: List[Dict[str, str]] = []
    all_candidates: List[Dict[str, Any]] = []
    assessed: List[str] = []
    label_by_relative_path: Dict[str, str] = {}
    suppressed = 0

    for relative_path in relative_paths:
        path = entries[relative_path]

        try:
            array, original_size = _load_gray(
                path
            )
        except _ImageTooSmall:
            skipped.append(
                {
                    "file": relative_path,
                    "reason": "image_too_small",
                }
            )
            continue
        except Exception as exc:
            skipped.append(
                {
                    "file": relative_path,
                    "reason": (
                        "unreadable_or_corrupt:"
                        + type(exc).__name__
                    ),
                }
            )
            continue

        assessed.append(relative_path)

        label = None

        for key in (
            relative_path,
            Path(
                os.path.abspath(path)
            ).as_posix(),
            path.name,
        ):
            if key in label_map:
                label = label_map[key]
                break

        if (
            label is None
            and infer_labels_from_folders
            and Path(relative_path).parent.name
        ):
            label = (
                Path(relative_path)
                .parent.name
            )

        if label is not None:
            label_by_relative_path[
                relative_path
            ] = label

        candidates, diagnostics = _detect_regions(
            array,
            original_size,
            parameters,
        )

        if diagnostics[
            "suppressed_high_texture"
        ]:
            suppressed += 1

        for candidate in candidates:
            candidate["file"] = relative_path
            all_candidates.append(candidate)

    assessed_count = len(assessed)

    # A8.2 repeated patch clustering.
    all_candidates.sort(
        key=lambda candidate: (
            candidate["file"],
            candidate["_sort"],
        )
    )

    clusters: List[Dict[str, Any]] = []

    for candidate in all_candidates:
        candidate["cluster"] = None

        descriptor = candidate["descriptor"]

        if descriptor is None:
            continue

        for index, cluster in enumerate(clusters):
            if (
                _hamming(
                    descriptor,
                    cluster["rep"],
                )
                <= hamming_tolerance
            ):
                candidate["cluster"] = index

                if (
                    candidate["file"]
                    not in cluster["files"]
                ):
                    cluster["files"].add(
                        candidate["file"]
                    )
                    cluster["members"].append(
                        candidate
                    )

                break
        else:
            clusters.append(
                {
                    "rep": descriptor,
                    "files": {
                        candidate["file"]
                    },
                    "members": [
                        candidate
                    ],
                }
            )

            candidate["cluster"] = (
                len(clusters) - 1
            )

    repeated = [
        (index, cluster)
        for index, cluster in enumerate(
            clusters
        )
        if len(cluster["members"])
        >= min_pattern_images
    ]

    repeated.sort(
        key=lambda item: (
            -len(item[1]["members"]),
            item[1]["members"][0]["file"],
            item[1]["rep"],
        )
    )

    pattern_evidence: List[Dict[str, Any]] = []
    spatial_concentration: List[Dict[str, Any]] = []
    pattern_by_cluster: Dict[
        int,
        Dict[str, Any],
    ] = {}

    for number, (cluster_index, cluster) in enumerate(
        repeated,
        start=1,
    ):
        members = sorted(
            cluster["members"],
            key=lambda member: member["file"],
        )

        pattern_id = f"P{number:03d}"

        count = len(members)

        support = (
            count / float(assessed_count)
            if assessed_count
            else 0.0
        )

        median_x = median(
            member["cx"]
            for member in members
        )

        median_y = median(
            member["cy"]
            for member in members
        )

        offsets = [
            max(
                abs(
                    member["cx"]
                    - median_x
                ),
                abs(
                    member["cy"]
                    - median_y
                ),
            )
            for member in members
        ]

        concentration_fraction = (
            sum(
                offset <= spatial_tolerance
                for offset in offsets
            )
            / float(count)
        )

        concentrated = (
            concentration_fraction
            >= spatial_min_fraction
        )

        zone = _zone(
            median_x,
            median_y,
        )

        if concentrated:
            severity = (
                "high"
                if count >= 5
                else "medium"
            )
        else:
            severity = "low"

        caveats: List[str] = []

        if support > 0.5:
            caveats.append(
                "Pattern is present in a majority of assessed images; "
                "this is more typical of legitimate common content "
                "such as a watermark, border, or overlay than a sparse trigger."
            )

            if severity == "high":
                severity = "medium"

        spatial = {
            "median_x": _r(median_x),
            "median_y": _r(median_y),
            "zone": zone,
            "concentrated_fraction": _r(
                concentration_fraction
            ),
            "max_offset": _r(
                max(offsets)
            ),
            "concentrated": concentrated,
        }

        pattern = {
            "pattern_id": pattern_id,
            "descriptor_hex": (
                f"{cluster['rep']:016x}"
            ),
            "image_count": count,
            "support_fraction": _r(
                support
            ),
            "mean_peak_hf": _r(
                sum(
                    member["peak_hf"]
                    for member in members
                )
                / count
            ),
            "files": [
                member["file"]
                for member in members
            ][:200],
            "files_truncated": count > 200,
            "spatial": spatial,
            "severity": severity,
            "evidence_level": "heuristic",
            "associated_class": None,
            "caveats": caveats,
            "limitations": list(
                FINDING_LIMITATIONS
            ),
        }

        if concentrated:
            pattern["detail"] = (
                "Repeated localized pattern: the same small patch "
                "appears in %d images (%.1f%% of assessed) concentrated "
                "in the %s region. Candidate trigger evidence; requires "
                "analyst review."
                % (
                    count,
                    100.0 * support,
                    zone,
                )
            )

            spatial_concentration.append(
                {
                    "pattern_id": pattern_id,
                    "zone": zone,
                    "member_count": count,
                    "median_x": spatial[
                        "median_x"
                    ],
                    "median_y": spatial[
                        "median_y"
                    ],
                    "concentrated_fraction": spatial[
                        "concentrated_fraction"
                    ],
                    "max_offset": spatial[
                        "max_offset"
                    ],
                    "detail": (
                        "Pattern %s repeats at a consistent location "
                        "(%s). Consistent placement is characteristic "
                        "of synthetic triggers but also of watermarks "
                        "and overlays."
                        % (
                            pattern_id,
                            zone,
                        )
                    ),
                }
            )
        else:
            pattern["detail"] = (
                "Repeated localized pattern in %d images at varying "
                "locations (concentration %.2f). May be legitimate "
                "repeated structure; requires analyst review."
                % (
                    count,
                    concentration_fraction,
                )
            )

        pattern_by_cluster[
            cluster_index
        ] = pattern

        pattern_evidence.append(
            pattern
        )

    # A8.4 class-conditional evidence.
    class_evidence: List[Dict[str, Any]] = []

    labeled_total = len(
        label_by_relative_path
    )

    if labeled_total:
        totals: Dict[str, int] = {}

        for label in label_by_relative_path.values():
            totals[label] = (
                totals.get(label, 0) + 1
            )

        for pattern in pattern_evidence:
            member_labels = [
                label_by_relative_path[file]
                for file in pattern["files"]
                if file in label_by_relative_path
            ]

            member_count = len(member_labels)

            if member_count < min_pattern_images:
                continue

            counts: Dict[str, int] = {}

            for label in member_labels:
                counts[label] = (
                    counts.get(label, 0) + 1
                )

            top_class, top_count = max(
                counts.items(),
                key=lambda item: (
                    item[1],
                    item[0],
                ),
            )

            class_total = totals[top_class]

            member_share = (
                top_count
                / float(member_count)
            )

            class_prior = (
                class_total
                / float(labeled_total)
            )

            p_value = _hypergeom_tail(
                top_count,
                member_count,
                class_total,
                labeled_total,
            )

            disproportionate = (
                member_share >= class_min_share
                and p_value <= class_max_p
            )

            if disproportionate:
                detail = (
                    "Candidate trigger pattern %s is disproportionately "
                    "associated with class '%s' (%d of %d labelled member "
                    "images; class share of dataset %.2f; one-sided "
                    "hypergeometric p=%.2g). This is an association only "
                    "and does not establish a backdoor; requires analyst review."
                    % (
                        pattern["pattern_id"],
                        top_class,
                        top_count,
                        member_count,
                        class_prior,
                        p_value,
                    )
                )

                pattern["associated_class"] = (
                    top_class
                )
            else:
                detail = (
                    "Pattern %s shows no disproportionate association "
                    "with a single class under the configured thresholds."
                    % pattern["pattern_id"]
                )

            class_evidence.append(
                {
                    "pattern_id": pattern[
                        "pattern_id"
                    ],
                    "top_class": top_class,
                    "labelled_member_count": member_count,
                    "top_class_member_count": top_count,
                    "top_class_total": class_total,
                    "labelled_total": labeled_total,
                    "member_share": _r(
                        member_share
                    ),
                    "class_prior": _r(
                        class_prior
                    ),
                    "enrichment": _r(
                        member_share
                        / class_prior
                    ),
                    "p_value": round(
                        p_value,
                        8,
                    ),
                    "disproportionate": (
                        disproportionate
                    ),
                    "evidence_level": "heuristic",
                    "detail": detail,
                    "limitations": list(
                        FINDING_LIMITATIONS
                    ),
                }
            )

    findings: List[Dict[str, Any]] = []

    for candidate in all_candidates:
        pattern = (
            pattern_by_cluster.get(
                candidate["cluster"]
            )
            if candidate["cluster"] is not None
            else None
        )

        evidence = {
            "peak_high_frequency_energy": _r(
                candidate["peak_hf"]
            ),
            "background_median_high_frequency_energy": _r(
                candidate["background_median_hf"]
            ),
            "robust_z": _r(
                candidate["z"],
                2,
            ),
            "local_contrast": _r(
                candidate["local_contrast"],
                2,
            ),
            "local_edge_density": _r(
                candidate["local_edge_density"]
            ),
            "global_edge_density": _r(
                candidate["global_edge_density"]
            ),
            "center_x_norm": _r(
                candidate["cx"]
            ),
            "center_y_norm": _r(
                candidate["cy"]
            ),
            "region_norm": candidate[
                "region_norm"
            ],
        }

        if pattern is None:
            code = (
                "LOCALIZED_HIGH_FREQUENCY_ANOMALY"
            )
            severity = "low"
            evidence_level = "observation"

            detail = (
                "Suspicious localized artifact: compact region with "
                "high-frequency energy %.1f versus an image background "
                "median of %.1f (robust z=%.1f). Single-image observation; "
                "may be ordinary image content. Requires analyst review."
                % (
                    candidate["peak_hf"],
                    candidate[
                        "background_median_hf"
                    ],
                    candidate["z"],
                )
            )

            pattern_id = None

        elif pattern["spatial"]["concentrated"]:
            code = (
                "REPEATED_PATTERN_SPATIAL_CONCENTRATION"
            )

            severity = pattern["severity"]
            evidence_level = "heuristic"

            detail = (
                "Potential trigger-like pattern: the same localized "
                "patch (%s) appears in %d images, concentrated in the "
                "%s region. Candidate trigger evidence; requires "
                "analyst review and does not establish poisoning."
                % (
                    pattern["pattern_id"],
                    pattern["image_count"],
                    pattern["spatial"]["zone"],
                )
            )

            if pattern["associated_class"] is not None:
                detail += (
                    " Pattern is disproportionately associated with "
                    "class '%s'."
                    % pattern["associated_class"]
                )

            pattern_id = pattern["pattern_id"]

        else:
            code = "REPEATED_LOCALIZED_PATTERN"
            severity = "low"
            evidence_level = "heuristic"

            detail = (
                "Repeated localized pattern (%s) in %d images at "
                "varying locations; may be legitimate repeated "
                "structure. Requires analyst review."
                % (
                    pattern["pattern_id"],
                    pattern["image_count"],
                )
            )

            pattern_id = pattern["pattern_id"]

        findings.append(
            {
                "file": candidate["file"],
                "severity": severity,
                "evidence_level": evidence_level,
                "code": code,
                "detail": detail,
                "region": dict(
                    candidate["region"]
                ),
                "pattern_id": pattern_id,
                "evidence": evidence,
                "limitations": list(
                    FINDING_LIMITATIONS
                ),
            }
        )

    findings.sort(
        key=lambda finding: (
            finding["file"],
            finding["region"]["y"],
            finding["region"]["x"],
        )
    )

    candidate_files = {
        finding["file"]
        for finding in findings
        if finding["code"]
        == "REPEATED_PATTERN_SPATIAL_CONCENTRATION"
    }

    anomaly_files = {
        finding["file"]
        for finding in findings
    }

    limitations = list(LIMITATIONS)

    if not labeled_total:
        limitations.append(
            "No labels were supplied, so class-conditional "
            "analysis (A8.4) was not performed."
        )

    if suppressed:
        limitations.append(
            "%d image(s) were globally high-texture and were excluded "
            "from localized-anomaly analysis to avoid false positives; "
            "trigger-like patches in them cannot be assessed."
            % suppressed
        )

    return {
        "status": (
            "completed"
            if assessed_count
            else "insufficient_data"
        ),
        "method": METHOD,
        "disclaimer": DISCLAIMER,
        "parameters": {
            "work_size": WORK_SIZE,
            "window": WINDOW,
            "stride": STRIDE,
            **parameters,
            "hamming_tolerance": hamming_tolerance,
            "min_pattern_images": min_pattern_images,
            "spatial_tolerance": spatial_tolerance,
            "spatial_min_fraction": spatial_min_fraction,
            "class_min_share": class_min_share,
            "class_max_p": class_max_p,
        },
        "image_count": len(relative_paths),
        "images_assessed": assessed_count,
        "images_with_localized_anomaly": len(
            anomaly_files
        ),
        "suppressed_high_texture_images": suppressed,
        "candidate_trigger_count": len(
            candidate_files
        ),
        "repeated_pattern_count": len(
            pattern_evidence
        ),
        "labels_supplied": bool(
            labeled_total
        ),
        "spatial_concentration": spatial_concentration,
        "findings": findings,
        "pattern_evidence": pattern_evidence,
        "class_conditional_evidence": class_evidence,
        "skipped_files": skipped,
        "limitations": limitations,
    }
