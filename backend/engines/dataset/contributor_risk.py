from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
import csv
import math

from backend.core.hashing import sha256_file
REQUIRED_COLUMNS = {
    "file",
    "contributor",
    "class",
    "timestamp",
}


def _safe_float(value: str) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _entropy(values: list[str]) -> float:
    if not values:
        return 0.0

    counts = Counter(values)
    total = len(values)

    entropy = 0.0

    for count in counts.values():
        probability = count / total

        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def load_contributor_manifest(
    manifest_path: Path,
) -> list[dict]:
    manifest_path = manifest_path.resolve()

    if not manifest_path.is_file():
        raise ValueError(
            f"Contributor manifest does not exist: "
            f"{manifest_path}"
        )

    with manifest_path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        reader = csv.DictReader(file)

        if reader.fieldnames is None:
            raise ValueError(
                "Contributor manifest has no header."
            )

        missing_columns = (
            REQUIRED_COLUMNS
            - set(reader.fieldnames)
        )

        if missing_columns:
            raise ValueError(
                "Contributor manifest is missing "
                f"required columns: "
                f"{sorted(missing_columns)}"
            )

        rows = []

        for row_number, row in enumerate(
            reader,
            start=2,
        ):
            file_path = (
                row.get("file") or ""
            ).strip()

            contributor = (
                row.get("contributor") or ""
            ).strip()

            class_name = (
                row.get("class") or ""
            ).strip()

            timestamp = (
                row.get("timestamp") or ""
            ).strip()

            if not file_path:
                continue

            rows.append(
                {
                    "row_number": row_number,
                    "file": file_path,
                    "contributor": (
                        contributor
                        or "UNKNOWN"
                    ),
                    "class": (
                        class_name
                        or "UNKNOWN"
                    ),
                    "timestamp": timestamp,
                }
            )

    return rows


def _calculate_duplicate_evidence(
    rows: list[dict],
    dataset_root: Path | None = None,
) -> dict:
    """
    Calculate exact-duplicate evidence grouped by contributor.

    Files that cannot be resolved or hashed are skipped.
    """

    hash_to_records = defaultdict(list)

    for row in rows:
        file_path = Path(row["file"])

        if (
            dataset_root is not None
            and not file_path.is_absolute()
        ):
            file_path = (
                dataset_root / file_path
            )

        file_path = file_path.resolve()

        if not file_path.is_file():
            continue

        try:
            file_hash = sha256_file(
                file_path
            )
        except OSError:
            continue

        hash_to_records[file_hash].append(
            row
        )

    contributor_stats = defaultdict(
        lambda: {
            "images_hashed": 0,
            "duplicate_images": 0,
            "duplicate_groups": 0,
        }
    )

    for file_hash, records in (
        hash_to_records.items()
    ):
        for record in records:
            contributor = record[
                "contributor"
            ]

            contributor_stats[
                contributor
            ]["images_hashed"] += 1

        if len(records) <= 1:
            continue

        contributors_in_group = set()

        for record in records:
            contributor = record[
                "contributor"
            ]

            contributor_stats[
                contributor
            ]["duplicate_images"] += 1

            contributors_in_group.add(
                contributor
            )

        for contributor in (
            contributors_in_group
        ):
            contributor_stats[
                contributor
            ]["duplicate_groups"] += 1

    for contributor, stats in (
        contributor_stats.items()
    ):
        hashed = stats[
            "images_hashed"
        ]

        if hashed:
            stats[
                "duplicate_rate"
            ] = round(
                stats["duplicate_images"]
                / hashed,
                6,
            )
        else:
            stats[
                "duplicate_rate"
            ] = 0.0

    return dict(
        contributor_stats
    )

def _calculate_ood_evidence(
    rows: list[dict],
    ood_result: dict | None = None,
) -> dict:
    """
    Calculate potential-OOD evidence grouped by contributor.

    The OOD engine result must contain candidate records with
    file paths and a potential_ood boolean.
    """

    contributor_stats = defaultdict(
        lambda: {
            "ood_images": 0,
            "ood_rate": 0.0,
        }
    )

    if not ood_result:
        return {}

    candidate_results = ood_result.get(
        "results",
        []
    )
    contributor_by_file = {
        row["file"]: row["contributor"]
        for row in rows
    }

    for candidate in candidate_results:
        file_path = candidate.get("file")

        if not file_path:
            continue

        contributor = contributor_by_file.get(
            file_path
        )

        if contributor is None:
            continue

        contributor_stats[
            contributor
        ].setdefault(
            "images_assessed",
            0,
        )

        contributor_stats[
            contributor
        ]["images_assessed"] += 1

        if candidate.get(
            "potential_ood",
            False,
        ):
            contributor_stats[
                contributor
            ]["ood_images"] += 1

    for contributor, stats in (
        contributor_stats.items()
    ):
        assessed = stats.get(
            "images_assessed",
            0,
        )

        if assessed:
            stats["ood_rate"] = round(
                stats["ood_images"]
                / assessed,
                6,
            )

    return dict(
        contributor_stats
    )

def _calculate_label_conflict_evidence(
    rows: list[dict],
    label_result: dict | None = None,
) -> dict:
    """
    Calculate potential label-conflict evidence grouped
    by contributor.

    A5 conflicts are treated as reviewable evidence,
    not proof of incorrect labeling.
    """

    contributor_stats = defaultdict(
        lambda: {
            "images_assessed": 0,
            "conflict_images": 0,
            "label_conflict_rate": 0.0,
        }
    )

    if not label_result:
        return {}

    conflicting_pairs = label_result.get(
        "conflicting_pairs",
        []
    )

    contributor_by_file = {
        row["file"]: row["contributor"]
        for row in rows
    }

    for row in rows:
        contributor = row["contributor"]

        contributor_stats[
            contributor
        ]["images_assessed"] += 1

    for pair in conflicting_pairs:
        file_a = pair.get("file_a")
        file_b = pair.get("file_b")

        contributors = set()

        if file_a in contributor_by_file:
            contributors.add(
                contributor_by_file[file_a]
            )

        if file_b in contributor_by_file:
            contributors.add(
                contributor_by_file[file_b]
            )

        for contributor in contributors:
            contributor_stats[
                contributor
            ]["conflict_images"] += 1

    for contributor, stats in (
        contributor_stats.items()
    ):
        assessed = stats[
            "images_assessed"
        ]

        if assessed:
            stats[
                "label_conflict_rate"
            ] = round(
                stats["conflict_images"]
                / assessed,
                6,
            )

    return dict(
        contributor_stats
    )

def _build_contributor_profiles(
    rows: list[dict],
) -> list[dict]:
    grouped = defaultdict(list)

    for row in rows:
        grouped[row["contributor"]].append(row)

    profiles = []

    for contributor, contributor_rows in sorted(
        grouped.items()
    ):
        files = [
            row["file"]
            for row in contributor_rows
        ]

        classes = [
            row["class"]
            for row in contributor_rows
        ]

        timestamps = [
            row["timestamp"]
            for row in contributor_rows
            if row["timestamp"]
        ]

        class_counts = Counter(classes)

        total_images = len(files)

        dominant_class_count = (
            max(class_counts.values())
            if class_counts
            else 0
        )

        dominant_class_ratio = (
            dominant_class_count / total_images
            if total_images
            else 0.0
        )

        profiles.append(
            {
                "contributor": contributor,
                "image_count": total_images,
                "class_count": len(class_counts),
                "class_distribution": dict(
                    sorted(class_counts.items())
                ),
                "class_entropy": round(
                    _entropy(classes),
                    6,
                ),
                "dominant_class_ratio": round(
                    dominant_class_ratio,
                    6,
                ),
                "timestamp_count": len(
                    timestamps
                ),
            }
        )

    return profiles


def _score_profiles(
    profiles: list[dict],
) -> list[dict]:
    if not profiles:
        return []

    image_counts = [
        profile["image_count"]
        for profile in profiles
    ]

    class_entropies = [
        profile["class_entropy"]
        for profile in profiles
    ]

    mean_image_count = (
        sum(image_counts)
        / len(image_counts)
    )

    mean_entropy = (
        sum(class_entropies)
        / len(class_entropies)
    )

    for profile in profiles:
        findings = []
        risk_score = 0.0

        image_count = profile[
            "image_count"
        ]

        entropy = profile[
            "class_entropy"
        ]

        dominant_ratio = profile[
            "dominant_class_ratio"
        ]

        # ---------------------------------------------------------
        # Contribution-volume anomaly
        # ---------------------------------------------------------
        if (
            mean_image_count > 0
            and image_count
            > mean_image_count * 3
        ):
            findings.append(
                "unusually_high_contribution_volume"
            )
            risk_score += 25.0

        # ---------------------------------------------------------
        # Class concentration anomaly
        # ---------------------------------------------------------
        if (
            image_count >= 5
            and dominant_ratio >= 0.90
        ):
            findings.append(
                "high_class_concentration"
            )
            risk_score += 20.0

        # ---------------------------------------------------------
        # Low class diversity
        # ---------------------------------------------------------
        if (
            len(
                profile[
                    "class_distribution"
                ]
            ) == 1
            and len(profiles) > 1
        ):
            findings.append(
                "single_class_contribution"
            )
            risk_score += 10.0

        duplicate_rate = profile.get(
            "duplicate_rate",
            0.0,
        )

        duplicate_groups = profile.get(
            "duplicate_groups",
            0,
        )

        if duplicate_rate >= 0.25:
            findings.append(
                "elevated_duplicate_rate"
            )
            risk_score += 10.0

        if duplicate_rate >= 0.50:
            findings.append(
                "high_duplicate_rate"
            )
            risk_score += 10.0

        if duplicate_groups > 0:
            findings.append(
                "cross_contributor_duplicate_detected"
            )
            risk_score += 5.0

            ood_rate = profile.get(
            "ood_rate",
            0.0,
        )

        if ood_rate >= 0.25:
            findings.append(
                "elevated_ood_rate"
            )
            risk_score += 10.0

        if ood_rate >= 0.50:
            findings.append(
                "high_ood_rate"
            )
            risk_score += 10.0


        label_conflict_rate = profile.get(
            "label_conflict_rate",
            0.0,
        )

        if label_conflict_rate >= 0.25:
            findings.append(
                "elevated_label_conflict_rate"
            )
            risk_score += 10.0

        if label_conflict_rate >= 0.50:
            findings.append(
                "high_label_conflict_rate"
            )
            risk_score += 10.0


        # ---------------------------------------------------------
        # Entropy deviation
        # ---------------------------------------------------------
        if (
            len(profiles) >= 3
            and mean_entropy > 0
            and entropy
            < mean_entropy * 0.25
        ):
            findings.append(
                "unusually_low_class_entropy"
            )
            risk_score += 15.0

        risk_score = min(
            risk_score,
            100.0,
        )

        if risk_score >= 50:
            risk_level = "HIGH"
        elif risk_score >= 25:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        profile[
            "risk_score"
        ] = round(
            risk_score,
            2,
        )

        profile[
            "risk_level"
        ] = risk_level

        profile[
            "findings"
        ] = findings

    return profiles

def assess_contributor_risk(
    manifest_path: Path,
    dataset_root: Path | None = None,
    ood_result: dict | None = None,
    label_result: dict | None = None,

) -> dict:
    manifest_path = manifest_path.resolve()

    rows = load_contributor_manifest(
        manifest_path
    )

    duplicate_evidence = _calculate_duplicate_evidence(
        rows,
        dataset_root=dataset_root,
    )
    ood_evidence = _calculate_ood_evidence(
        rows,
        ood_result=ood_result,
    )
    label_conflict_evidence = (
        _calculate_label_conflict_evidence(
            rows,
            label_result=label_result,
        )
    )

    profiles = _build_contributor_profiles(
        rows
    )

    for profile in profiles:
        contributor = profile["contributor"]

        duplicate_stats = duplicate_evidence.get(
            contributor,
            {
                "images_hashed": 0,
                "duplicate_images": 0,
                "duplicate_groups": 0,
                "duplicate_rate": 0.0,
            },
        )
        profile.update(
            duplicate_stats
        )
        ood_stats = ood_evidence.get(
            contributor,
            {
                "images_assessed": 0,
                "ood_images": 0,
                "ood_rate": 0.0,
            },
        )

        profile.update(
            ood_stats
        )


        label_stats = label_conflict_evidence.get(
            contributor,
            {
                "conflict_images": 0,
                "label_conflict_rate": 0.0,
            },
        )

        profile.update(
            label_stats
        )




    profiles = _score_profiles(
        profiles
    )

    finding_count = sum(
        1
        for profile in profiles
        if profile["findings"]
    )

    high_risk_count = sum(
        1
        for profile in profiles
        if profile["risk_level"]
        == "HIGH"
    )

    medium_risk_count = sum(
        1
        for profile in profiles
        if profile["risk_level"]
        == "MEDIUM"
    )

    return {
        "status": "completed",
        "method": (
            "Contributor-level statistical "
            "profiling and anomaly scoring"
        ),
        "manifest": str(
            manifest_path
        ),
        "row_count": len(rows),
        "contributor_count": len(
            profiles
        ),
        "finding_count": finding_count,
        "high_risk_contributors": (
            high_risk_count
        ),
        "medium_risk_contributors": (
            medium_risk_count
        ),
        "profiles": profiles,
        "limitations": [
            (
                "Risk scores identify unusual "
                "contributor characteristics; "
                "they do not establish malicious intent."
            ),
            (
                "The current engine uses manifest "
                "metadata and class distributions "
                "rather than image-content embeddings."
            ),
            (
                "Source identity is assumed to be "
                "correctly represented in the manifest."
            ),
        ],
    }
