"""
TRACER-CV C5 — Assurance Report.

Combines the outputs of the TRACER-CV assurance engines into one
analyst-facing, deterministic report.

The report is evidence-oriented. It does not claim that an asset is
"safe" or "malicious". It reports observed findings, integrity states,
limitations, and recommended analyst actions.

Offline/local only.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence


ENGINE_VERSION = "c5-1.0"
METHOD = "evidence-oriented assurance report"
TASK = "assurance_reporting"


# ---------------------------------------------------------------------------
# Deterministic utilities
# ---------------------------------------------------------------------------

def canonical_json(value: Any) -> bytes:
    """Serialize an object deterministically."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    """Return SHA-256 hexadecimal digest."""
    return hashlib.sha256(data).hexdigest()


def digest_object(value: Any) -> str:
    """Create a deterministic SHA-256 digest of a JSON-compatible object."""
    return sha256_bytes(canonical_json(value))


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------

_VALID_SEVERITIES = {
    "none",
    "low",
    "medium",
    "high",
    "critical",
}

_SEVERITY_ORDER = {
    "none": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def normalize_severity(value: Any) -> str:
    """Normalize a severity value."""
    value = str(value or "none").strip().lower()

    if value not in _VALID_SEVERITIES:
        return "none"

    return value


def highest_severity(
    findings: Sequence[Dict[str, Any]],
) -> str:
    """Return the highest observed finding severity."""
    if not findings:
        return "none"

    return max(
        (
            normalize_severity(
                finding.get("severity", "none")
            )
            for finding in findings
        ),
        key=lambda item: _SEVERITY_ORDER[item],
    )


def count_severities(
    findings: Sequence[Dict[str, Any]],
) -> Dict[str, int]:
    """Count findings by severity."""
    result = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "none": 0,
    }

    for finding in findings:
        severity = normalize_severity(
            finding.get("severity", "none")
        )
        result[severity] += 1

    return result


# ---------------------------------------------------------------------------
# Input extraction
# ---------------------------------------------------------------------------

def _safe_dict(value: Any) -> Dict[str, Any]:
    """Return a dictionary or an empty dictionary."""
    return value if isinstance(value, dict) else {}


def _safe_list(value: Any) -> List[Any]:
    """Return a list or an empty list."""
    return value if isinstance(value, list) else []


def _extract_findings(
    findings_result: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Extract normalized finding dictionaries."""
    if not findings_result:
        return []

    findings = findings_result.get("findings", [])

    if not isinstance(findings, list):
        return []

    return [
        finding
        for finding in findings
        if isinstance(finding, dict)
    ]


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------

def build_coverage(
    *,
    dataset: Optional[Dict[str, Any]],
    model: Optional[Dict[str, Any]],
    provenance: Optional[Dict[str, Any]],
    shift: Optional[Dict[str, Any]],
    findings: Sequence[Dict[str, Any]],
    audit: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Describe which assurance areas were actually assessed.

    This is intentionally explicit so an unavailable engine is not silently
    presented as a successful assessment.
    """

    return {
        "dataset_integrity": {
            "assessed": dataset is not None,
            "status": (
                "available"
                if dataset is not None
                else "not_assessed"
            ),
        },
        "model_integrity": {
            "assessed": model is not None,
            "status": (
                "available"
                if model is not None
                else "not_assessed"
            ),
        },
        "inference_provenance": {
            "assessed": provenance is not None,
            "status": (
                "available"
                if provenance is not None
                else "not_assessed"
            ),
        },
        "distribution_shift": {
            "assessed": shift is not None,
            "status": (
                "available"
                if shift is not None
                else "not_assessed"
            ),
        },
        "findings_and_evidence": {
            "assessed": True,
            "finding_count": len(findings),
            "status": "available",
        },
        "audit_trail": {
            "assessed": audit is not None,
            "status": (
                "available"
                if audit is not None
                else "not_assessed"
            ),
        },
    }


# ---------------------------------------------------------------------------
# Executive summary
# ---------------------------------------------------------------------------

def build_executive_summary(
    *,
    findings: Sequence[Dict[str, Any]],
    coverage: Dict[str, Any],
    provenance: Optional[Dict[str, Any]],
    audit: Optional[Dict[str, Any]],
    shift: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build a concise evidence-oriented executive summary."""

    severity_counts = count_severities(findings)
    maximum = highest_severity(findings)

    provenance_valid = None
    if provenance is not None:
        # C1 producers historically supplied records without a top-level
        # `valid` flag. Verify serialized record dictionaries when present.
        records = provenance.get("records", [])
        if isinstance(records, list) and records:
            try:
                from backend.engines.provenance.inference_provenance import (
                    ProvenanceRecord, verify_chain,
                )
                parsed = [
                    item if isinstance(item, ProvenanceRecord)
                    else ProvenanceRecord(**item)
                    for item in records if isinstance(item, dict)
                ]
                if len(parsed) == len(records):
                    provenance_valid = bool(verify_chain(parsed).get("valid"))
            except (TypeError, ValueError, ImportError):
                provenance_valid = None
        if provenance_valid is None and isinstance(provenance.get("valid"), bool):
            provenance_valid = provenance["valid"]

    audit_valid = None
    if audit is not None:
        audit_valid = bool(
            audit.get("valid", False)
        )

    shift_detected = None
    if shift is not None:
        if shift.get("status") not in ("completed", "assessed", "available"):
            shift_detected = None
        else:
            findings_present = bool(shift.get("findings"))
            shift_detected = bool(
                shift.get("shift_detected") is True
                or (isinstance(shift.get("overall_shift"), (int, float))
                    and float(shift["overall_shift"]) > 0)
                or str(shift.get("severity", "none")).lower() not in ("", "none", "unavailable")
                or findings_present
            )

    return {
        "assessment_scope": (
            "TRACER-CV evidence-oriented integrity and "
            "assurance assessment"
        ),
        "finding_count": len(findings),
        "severity_counts": severity_counts,
        "highest_observed_severity": maximum,
        "provenance_chain_valid": provenance_valid,
        "audit_chain_valid": audit_valid,
        "distribution_shift_detected": shift_detected,
        "coverage": coverage,
        "interpretation": (
            "Results represent observed evidence from the configured "
            "assessment methods. A clean result does not establish the "
            "absence of all attack classes."
        ),
    }


# ---------------------------------------------------------------------------
# Dataset / model / provenance / shift sections
# ---------------------------------------------------------------------------

def build_dataset_section(
    result: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Normalize the dataset assessment section."""

    if result is None:
        return {
            "status": "not_assessed",
            "message": "Dataset integrity engine was not executed.",
        }

    return {
        "status": "assessed",
        "engine_result": result,
    }


def build_model_section(
    result: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Normalize the model assessment section."""

    if result is None:
        return {
            "status": "not_assessed",
            "message": "Model integrity engine was not executed.",
        }

    return {
        "status": "assessed",
        "engine_result": result,
    }


def build_provenance_section(
    result: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Normalize provenance results."""

    if result is None:
        return {
            "status": "not_assessed",
            "message": "Inference provenance was not assessed.",
        }

    valid = result.get("valid")
    records = result.get("records", [])
    if not isinstance(valid, bool) and isinstance(records, list) and records:
        try:
            from backend.engines.provenance.inference_provenance import (
                ProvenanceRecord, verify_chain,
            )
            parsed = [
                item if isinstance(item, ProvenanceRecord)
                else ProvenanceRecord(**item)
                for item in records if isinstance(item, dict)
            ]
            if len(parsed) == len(records):
                valid = bool(verify_chain(parsed).get("valid"))
        except (TypeError, ValueError, ImportError):
            valid = None
    return {
        "status": "assessed",
        "valid": valid if isinstance(valid, bool) else None,
        "engine_result": result,
    }


def build_shift_section(
    result: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Normalize distribution-shift results."""

    if result is None:
        return {
            "status": "not_assessed",
            "message": "Distribution shift engine was not executed.",
        }

    status = str(result.get("status", "")).lower()
    findings = result.get("findings", [])
    detected = None
    if status in ("completed", "assessed", "available"):
        detected = bool(
            result.get("shift_detected") is True
            or (isinstance(result.get("overall_shift"), (int, float))
                and float(result["overall_shift"]) > 0)
            or normalize_severity(result.get("severity", "none")) != "none"
            or bool(findings)
        )
    return {
        "status": "assessed",
        "shift_detected": detected,
        "severity": normalize_severity(
            result.get("severity", "none")
        ),
        "engine_result": result,
    }


def build_findings_section(
    findings: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build the analyst-facing findings section."""

    normalized = []

    for finding in findings:
        normalized.append(
            {
                "finding_id": finding.get("finding_id"),
                "category": finding.get("category"),
                "severity": normalize_severity(
                    finding.get("severity", "none")
                ),
                "confidence": finding.get("confidence"),
                "affected_asset": finding.get(
                    "affected_asset"
                ),
                "title": finding.get("title"),
                "explanation": finding.get(
                    "explanation"
                ),
                "evidence": finding.get("evidence", {}),
                "recommended_action": finding.get(
                    "recommended_action"
                ),
                "limitations": finding.get(
                    "limitations", []
                ),
                "source_engine": finding.get(
                    "source_engine"
                ),
            }
        )

    return {
        "count": len(normalized),
        "severity_counts": count_severities(normalized),
        "highest_severity": highest_severity(normalized),
        "findings": normalized,
    }


def build_audit_section(
    result: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Normalize audit-trail verification."""

    if result is None:
        return {
            "status": "not_assessed",
            "message": "Audit trail was not verified.",
        }

    return {
        "status": "assessed",
        "valid": bool(result.get("valid", False)),
        "entry_count": result.get("entry_count", 0),
        "finding_count": len(
            _safe_list(result.get("findings"))
        ),
        "verification": result,
    }


# ---------------------------------------------------------------------------
# Limitations
# ---------------------------------------------------------------------------

DEFAULT_LIMITATIONS = [
    (
        "TRACER-CV reports evidence observed by configured checks; "
        "it does not prove absence of every possible attack."
    ),
    (
        "Distribution shift can have benign operational causes and does "
        "not by itself establish malicious manipulation."
    ),
    (
        "Behavioral and trigger-like model findings are indicators for "
        "analyst review, not proof of a backdoor."
    ),
    (
        "Parameter and activation anomalies can arise from legitimate "
        "model differences."
    ),
    (
        "Appearance-based dataset checks do not establish semantic "
        "correctness for every image."
    ),
    (
        "White-box model methods depend on access to the model structure "
        "and supported execution format."
    ),
    (
        "Unsupported attack classes are outside the evidence presented "
        "by this assessment."
    ),
]


def build_limitations(
    extra: Optional[Iterable[str]] = None,
) -> List[str]:
    """Build a deterministic limitation list."""
    values = list(DEFAULT_LIMITATIONS)

    if extra:
        values.extend(
            str(item)
            for item in extra
            if str(item).strip()
        )

    # Preserve order while removing duplicates.
    return list(dict.fromkeys(values))


# ---------------------------------------------------------------------------
# Recommended actions
# ---------------------------------------------------------------------------

def build_recommended_actions(
    findings: Sequence[Dict[str, Any]],
    *,
    provenance: Optional[Dict[str, Any]] = None,
    audit: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """
    Produce evidence-driven analyst actions.

    These are actions associated with observed evidence, not automatic
    operational decisions.
    """

    actions: List[str] = []

    severities = count_severities(findings)

    if severities["critical"] > 0:
        actions.append(
            "Prioritize analyst review of critical findings and preserve "
            "the associated evidence artifacts."
        )

    if severities["high"] > 0:
        actions.append(
            "Review high-severity findings and verify the affected "
            "dataset, model, or inference artifact against a trusted source."
        )

    if provenance is not None and not provenance.get(
        "valid", False
    ):
        actions.append(
            "Investigate the broken or invalid inference provenance chain "
            "before relying on affected inference records."
        )

    if audit is not None and not audit.get(
        "valid", False
    ):
        actions.append(
            "Preserve the audit evidence and investigate audit-chain "
            "integrity failures."
        )

    if not actions:
        actions.append(
            "Retain the generated evidence and continue analyst review "
            "according to the configured assurance workflow."
        )

    return list(dict.fromkeys(actions))


# ---------------------------------------------------------------------------
# Main report builder
# ---------------------------------------------------------------------------

def build_assurance_report(
    *,
    assessment_id: str,
    dataset: Optional[Dict[str, Any]] = None,
    model: Optional[Dict[str, Any]] = None,
    provenance: Optional[Dict[str, Any]] = None,
    shift: Optional[Dict[str, Any]] = None,
    findings: Optional[Sequence[Dict[str, Any]]] = None,
    audit: Optional[Dict[str, Any]] = None,
    extra_limitations: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """
    Build the complete deterministic TRACER-CV assurance report.
    """

    if not assessment_id:
        raise ValueError(
            "assessment_id must not be empty"
        )

    normalized_findings = [
        dict(item)
        for item in (findings or [])
        if isinstance(item, dict)
    ]

    coverage = build_coverage(
        dataset=dataset,
        model=model,
        provenance=provenance,
        shift=shift,
        findings=normalized_findings,
        audit=audit,
    )

    executive_summary = build_executive_summary(
        findings=normalized_findings,
        coverage=coverage,
        provenance=provenance,
        audit=audit,
        shift=shift,
    )

    report = {
        "report_version": ENGINE_VERSION,
        "method": METHOD,
        "task": TASK,
        "assessment_id": assessment_id,

        "executive_summary": executive_summary,

        "asset_coverage": coverage,

        "dataset_integrity": build_dataset_section(
            dataset
        ),

        "model_integrity": build_model_section(
            model
        ),

        "inference_provenance": build_provenance_section(
            provenance
        ),

        "distribution_shift": build_shift_section(
            shift
        ),

        "findings_and_evidence": build_findings_section(
            normalized_findings
        ),

        "audit_trail": build_audit_section(
            audit
        ),

        "recommended_actions": build_recommended_actions(
            normalized_findings,
            provenance=provenance,
            audit=audit,
        ),

        "limitations": build_limitations(
            extra_limitations
        ),
    }

    report["report_digest"] = digest_object(report)

    return report


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def report_to_json(
    report: Dict[str, Any],
    *,
    indent: Optional[int] = 2,
) -> str:
    """Serialize a report as JSON."""
    return json.dumps(
        report,
        sort_keys=True,
        indent=indent,
        ensure_ascii=False,
    )


def report_from_json(
    value: str,
) -> Dict[str, Any]:
    """Load a report from JSON."""
    result = json.loads(value)

    if not isinstance(result, dict):
        raise ValueError(
            "assurance report must decode to an object"
        )

    return result


# ---------------------------------------------------------------------------
# Text rendering
# ---------------------------------------------------------------------------

def render_text_report(
    report: Dict[str, Any],
) -> str:
    """
    Render a compact analyst-readable text report.

    No terminal colors or external dependencies.
    """

    summary = _safe_dict(
        report.get("executive_summary")
    )

    findings_section = _safe_dict(
        report.get("findings_and_evidence")
    )

    lines = [
        "=" * 72,
        "TRACER-CV ASSURANCE REPORT",
        "=" * 72,
        f"Assessment ID: {report.get('assessment_id', '')}",
        f"Report Version: {report.get('report_version', '')}",
        "",
        "EXECUTIVE SUMMARY",
        "-" * 72,
        f"Findings: {summary.get('finding_count', 0)}",
        (
            "Highest Severity: "
            f"{summary.get('highest_observed_severity', 'none')}"
        ),
        (
            "Provenance Chain: "
            f"{summary.get('provenance_chain_valid')}"
        ),
        (
            "Audit Chain: "
            f"{summary.get('audit_chain_valid')}"
        ),
        (
            "Distribution Shift: "
            f"{summary.get('distribution_shift_detected')}"
        ),
        "",
        "FINDINGS",
        "-" * 72,
    ]

    findings = _safe_list(
        findings_section.get("findings")
    )

    if not findings:
        lines.append("No findings were generated.")

    for finding in findings:
        lines.extend(
            [
                (
                    f"[{str(finding.get('severity', 'none')).upper()}] "
                    f"{finding.get('finding_id', '')}"
                ),
                f"  Category: {finding.get('category', '')}",
                f"  Asset: {finding.get('affected_asset', '')}",
                f"  Title: {finding.get('title', '')}",
                (
                    "  Explanation: "
                    f"{finding.get('explanation', '')}"
                ),
                (
                    "  Recommended Action: "
                    f"{finding.get('recommended_action', '')}"
                ),
                "",
            ]
        )

    lines.extend(
        [
            "RECOMMENDED ACTIONS",
            "-" * 72,
        ]
    )

    for action in _safe_list(
        report.get("recommended_actions")
    ):
        lines.append(f"- {action}")

    lines.extend(
        [
            "",
            "LIMITATIONS",
            "-" * 72,
        ]
    )

    for limitation in _safe_list(
        report.get("limitations")
    ):
        lines.append(f"- {limitation}")

    lines.extend(
        [
            "",
            "REPORT DIGEST",
            "-" * 72,
            str(report.get("report_digest", "")),
            "=" * 72,
        ]
    )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "ENGINE_VERSION",
    "METHOD",
    "TASK",
    "canonical_json",
    "sha256_bytes",
    "digest_object",
    "normalize_severity",
    "highest_severity",
    "count_severities",
    "build_coverage",
    "build_executive_summary",
    "build_dataset_section",
    "build_model_section",
    "build_provenance_section",
    "build_shift_section",
    "build_findings_section",
    "build_audit_section",
    "build_limitations",
    "build_recommended_actions",
    "build_assurance_report",
    "report_to_json",
    "report_from_json",
    "render_text_report",
]
