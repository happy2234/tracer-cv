"""A7 - Metadata / Acquisition Consistency.

Compares image-level acquisition metadata (format, resolution, colour mode,
EXIF camera/software/timestamps, JPEG quantisation tables) across a dataset
and across contributors, and reports inconsistencies as evidence for review.

Evidence levels:
  - observation: directly observed fact
  - heuristic: statistical divergence between a contributor and the rest

This module does not establish malicious intent or confirmed poisoning.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from statistics import median
from typing import Any, Iterable, Mapping

try:
    from PIL import Image
except ImportError:
    Image = None

METHOD = (
    "categorical-distribution divergence (total variation) "
    "+ per-image rule checks"
)

IMAGE_EXTENSIONS = frozenset(
    {".jpg", ".jpeg", ".jpe", ".png", ".bmp", ".tif", ".tiff", ".webp"}
)

FORMAT_EXTENSIONS: dict[str, frozenset[str]] = {
    "JPEG": frozenset({".jpg", ".jpeg", ".jpe"}),
    "PNG": frozenset({".png"}),
    "BMP": frozenset({".bmp"}),
    "TIFF": frozenset({".tif", ".tiff"}),
    "WEBP": frozenset({".webp"}),
}

EDITING_SOFTWARE_MARKERS = (
    "photoshop",
    "gimp",
    "lightroom",
    "paint.net",
    "affinity",
    "pixelmator",
    "snapseed",
    "canva",
    "imagemagick",
    "pillow",
    "opencv",
)

CATEGORICAL_ATTRIBUTES = (
    "format",
    "resolution",
    "mode",
    "camera",
    "software",
    "quant_hash",
    "has_exif",
)

LIMITATIONS = [
    "Metadata is trivially editable or strippable; consistent metadata does not establish authenticity.",
    "Missing EXIF is common and benign; it is reported as divergence, not tampering.",
    "Contributor divergence is a statistical heuristic; legitimate sensor or campaign differences can also be flagged.",
    "Small contributors below min_contributor_images are not profiled.",
    "Timestamp checks rely on camera clocks, which may be wrong or unset.",
    "Findings are evidence for analyst review and do not establish malicious intent, poisoning, or confirmed integrity violation.",
]

_EXIF_TIME_FORMAT = "%Y:%m:%d %H:%M:%S"
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def _clean(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return _CTRL.sub("", str(value)).strip()


def _parse_exif_time(value: Any) -> float | None:
    text = _clean(value)
    if not text:
        return None

    try:
        dt = datetime.strptime(text[:19], _EXIF_TIME_FORMAT)
    except ValueError:
        return None

    return dt.replace(tzinfo=timezone.utc).timestamp()


def _quant_hash(im: Any) -> str:
    tables = getattr(im, "quantization", None)

    if not tables:
        return "none"

    payload = repr(
        sorted((k, tuple(v)) for k, v in tables.items())
    ).encode()

    return hashlib.sha256(payload).hexdigest()[:12]


def extract_image_metadata(path: Path) -> dict[str, Any]:
    """Extract acquisition metadata from one image."""

    if Image is None:
        raise RuntimeError("Pillow is not installed")

    with Image.open(path) as im:
        width, height = im.size
        fmt = (im.format or "UNKNOWN").upper()

        exif = im.getexif()

        try:
            exif_ifd = exif.get_ifd(0x8769)
        except Exception:
            exif_ifd = {}

        make = _clean(exif.get(0x010F))
        model = _clean(exif.get(0x0110))
        software = _clean(exif.get(0x0131))

        captured = (
            _parse_exif_time(exif_ifd.get(0x9003))
            or _parse_exif_time(exif.get(0x0132))
        )

        return {
            "format": fmt,
            "width": int(width),
            "height": int(height),
            "resolution": f"{width}x{height}",
            "mode": im.mode,
            "camera": f"{make} {model}".strip() or "none",
            "software": software or "none",
            "quant_hash": _quant_hash(im),
            "has_exif": "yes" if len(exif) > 0 else "no",
            "has_gps": 0x8825 in exif,
            "capture_epoch": captured,
            "file_size": path.stat().st_size,
        }


def _distribution(values: Iterable[str]) -> dict[str, float]:
    counts = Counter(values)
    total = sum(counts.values())

    if not total:
        return {}

    return {
        key: counts[key] / total
        for key in sorted(counts)
    }


def total_variation_distance(
    p: Mapping[str, float],
    q: Mapping[str, float],
) -> float:
    """Total variation distance between categorical distributions."""

    keys = set(p) | set(q)

    return 0.5 * sum(
        abs(p.get(key, 0.0) - q.get(key, 0.0))
        for key in keys
    )


def _iso(epoch: float | None) -> str | None:
    if epoch is None:
        return None

    return datetime.fromtimestamp(
        epoch,
        tz=timezone.utc,
    ).isoformat()


def assess_metadata_consistency(
    dataset_dir: str | Path,
    contributor_map: Mapping[str, str] | None = None,
    contributor_from_path: bool = False,
    min_contributor_images: int = 3,
    elevated_divergence: float = 0.5,
    high_divergence: float = 0.8,
    rare_resolution_fraction: float = 0.05,
    rare_resolution_min_dataset: int = 20,
    time_outlier_days: float = 365.0,
    min_timestamps_for_outlier: int = 5,
    reference_time: float | None = None,
) -> dict[str, Any]:
    """Assess metadata consistency across a dataset."""

    root = Path(dataset_dir)

    base: dict[str, Any] = {
        "status": "completed",
        "method": METHOD,
        "limitations": list(LIMITATIONS),
    }

    if Image is None:
        return {
            **base,
            "status": "unavailable",
            "error": "Pillow is not installed",
            "results": [],
        }

    if not root.is_dir():
        return {
            **base,
            "status": "error",
            "error": f"dataset_dir is not a directory: {root}",
            "results": [],
        }

    contributor_map = dict(contributor_map or {})

    files = sorted(
        p
        for p in root.rglob("*")
        if p.is_file()
        and p.suffix.lower() in IMAGE_EXTENSIONS
    )

    records: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []

    for path in files:
        rel = path.relative_to(root).as_posix()

        try:
            meta = extract_image_metadata(path)
        except Exception as exc:
            skipped.append(
                {
                    "file": rel,
                    "reason": f"{type(exc).__name__}: {exc}",
                }
            )
            continue

        if rel in contributor_map:
            contributor = str(contributor_map[rel])
        elif contributor_from_path and "/" in rel:
            contributor = rel.split("/", 1)[0]
        else:
            contributor = "unassigned"

        meta.update(
            file=rel,
            contributor=contributor,
        )

        records.append(meta)

    dataset_profile = {
        attribute: _distribution(
            record[attribute]
            for record in records
        )
        for attribute in CATEGORICAL_ATTRIBUTES
    }

    image_findings: list[dict[str, Any]] = []

    def add(
        rec: dict[str, Any],
        code: str,
        severity: str,
        evidence: str,
        detail: str,
    ) -> None:
        image_findings.append(
            {
                "file": rec["file"],
                "contributor": rec["contributor"],
                "code": code,
                "severity": severity,
                "evidence_level": evidence,
                "detail": detail,
            }
        )

    resolution_counts = Counter(
        record["resolution"]
        for record in records
    )

    epochs = [
        record["capture_epoch"]
        for record in records
        if record["capture_epoch"] is not None
    ]

    median_epoch = (
        median(epochs)
        if len(epochs) >= min_timestamps_for_outlier
        else None
    )

    for rec in records:
        ext = Path(rec["file"]).suffix.lower()
        allowed = FORMAT_EXTENSIONS.get(rec["format"])

        if allowed is not None and ext not in allowed:
            add(
                rec,
                "format_extension_mismatch",
                "low",
                "observation",
                f"extension '{ext}' but content decodes as {rec['format']}",
            )

        if any(
            marker in rec["software"].lower()
            for marker in EDITING_SOFTWARE_MARKERS
        ):
            add(
                rec,
                "editing_software_tag",
                "info",
                "observation",
                f"EXIF Software tag: '{rec['software']}'",
            )

        if (
            len(records) >= rare_resolution_min_dataset
            and resolution_counts[rec["resolution"]] / len(records)
            < rare_resolution_fraction
        ):
            add(
                rec,
                "rare_resolution",
                "info",
                "heuristic",
                f"resolution {rec['resolution']} occurs in "
                f"{resolution_counts[rec['resolution']]}/{len(records)} images",
            )

        timestamp = rec["capture_epoch"]

        if timestamp is not None:
            if (
                reference_time is not None
                and timestamp > reference_time
            ):
                add(
                    rec,
                    "future_capture_time",
                    "medium",
                    "observation",
                    f"capture time {_iso(timestamp)} is after "
                    f"reference time {_iso(reference_time)}",
                )

            if (
                median_epoch is not None
                and abs(timestamp - median_epoch)
                > time_outlier_days * 86400
            ):
                add(
                    rec,
                    "capture_time_outlier",
                    "low",
                    "heuristic",
                    f"capture time {_iso(timestamp)} is "
                    f">{time_outlier_days:g} days from dataset "
                    f"median {_iso(median_epoch)}",
                )

    image_findings.sort(
        key=lambda finding: (
            finding["file"],
            finding["code"],
        )
    )

    by_contributor: dict[str, list[dict[str, Any]]] = {}

    for record in records:
        by_contributor.setdefault(
            record["contributor"],
            [],
        ).append(record)

    anomalous_files = {
        finding["file"]
        for finding in image_findings
        if finding["severity"] != "info"
    }

    contributor_profiles: list[dict[str, Any]] = []
    contributor_findings: list[dict[str, Any]] = []
    contributor_evidence: dict[str, dict[str, Any]] = {}

    for name in sorted(by_contributor):
        recs = by_contributor[name]
        rest = [
            record
            for record in records
            if record["contributor"] != name
        ]

        profiled = (
            len(recs) >= min_contributor_images
            and len(rest) >= min_contributor_images
        )

        divergences: dict[str, float] = {}
        findings: list[dict[str, Any]] = []

        if profiled:
            for attribute in CATEGORICAL_ATTRIBUTES:
                tvd = total_variation_distance(
                    _distribution(
                        record[attribute]
                        for record in recs
                    ),
                    _distribution(
                        record[attribute]
                        for record in rest
                    ),
                )

                divergences[attribute] = round(
                    tvd,
                    4,
                )

                if tvd >= elevated_divergence:
                    level = (
                        "high"
                        if tvd >= high_divergence
                        else "elevated"
                    )

                    findings.append(
                        {
                            "code": f"{level}_metadata_divergence",
                            "attribute": attribute,
                            "tv_distance": round(tvd, 4),
                            "contributor_values": _distribution(
                                record[attribute]
                                for record in recs
                            ),
                            "rest_values": _distribution(
                                record[attribute]
                                for record in rest
                            ),
                            "evidence_level": "heuristic",
                            "detail": (
                                f"'{attribute}' distribution differs "
                                f"from all other contributors "
                                f"(TV distance {tvd:.2f})"
                            ),
                        }
                    )

        anomalous = sum(
            1
            for record in recs
            if record["file"] in anomalous_files
        )

        rate = (
            anomalous / len(recs)
            if recs
            else 0.0
        )

        contributor_profiles.append(
            {
                "contributor": name,
                "image_count": len(recs),
                "profiled": profiled,
                "distributions": {
                    attribute: _distribution(
                        record[attribute]
                        for record in recs
                    )
                    for attribute in CATEGORICAL_ATTRIBUTES
                },
                "divergence": divergences,
            }
        )

        for finding in findings:
            contributor_findings.append(
                {
                    "contributor": name,
                    **finding,
                }
            )

        contributor_evidence[name] = {
            "images_assessed": len(recs),
            "metadata_anomaly_images": anomalous,
            "metadata_anomaly_rate": round(rate, 4),
            "max_divergence": max(
                divergences.values(),
                default=0.0,
            ),
            "divergent_attributes": sorted(
                finding["attribute"]
                for finding in findings
            ),
        }

    severity_counts = Counter(
        finding["severity"]
        for finding in image_findings
    )

    return {
        **base,
        "image_count": len(records),
        "contributor_count": len(by_contributor),
        "thresholds": {
            "min_contributor_images": min_contributor_images,
            "elevated_divergence": elevated_divergence,
            "high_divergence": high_divergence,
            "rare_resolution_fraction": rare_resolution_fraction,
            "time_outlier_days": time_outlier_days,
        },
        "dataset_profile": dataset_profile,
        "image_finding_count": len(image_findings),
        "image_findings_by_severity": dict(
            sorted(severity_counts.items())
        ),
        "image_findings": image_findings,
        "contributor_profiles": contributor_profiles,
        "contributor_findings": contributor_findings,
        "contributor_evidence": contributor_evidence,
        "skipped_files": skipped,
    }
