"""
TRACER-CV C3 — Findings & Evidence.

Converts raw results from dataset, model, provenance, and distribution
analysis engines into human-readable assurance findings.

C3 does not independently determine malicious intent.
It normalizes measurable evidence into:
    - finding ID
    - category
    - severity
    - confidence
    - affected asset
    - evidence
    - explanation
    - recommended action
    - limitations
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence


ENGINE_VERSION = "c3-1.0"
METHOD = "evidence normalization and assurance finding aggregation"
TASK = "analyst_assurance"


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {
    "none": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _normalize_severity(value: Any) -> str:
    value = str(value).lower().strip()

    if value not in SEVERITY_ORDER:
        return "low"

    return value


def _max_severity(values: Iterable[str]) -> str:
    normalized = [
        _normalize_severity(value)
        for value in values
    ]

    if not normalized:
        return "none"

    return max(
        normalized,
        key=lambda value: SEVERITY_ORDER[value],
    )


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AssuranceFinding:
    finding_id: str
    category: str
    severity: str
    confidence: float

    affected_asset: str

    title: str
    explanation: str

    evidence: List[Dict[str, Any]]
    recommended_action: str
    limitations: List[str]

    source_engine: str

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _confidence(value: Any) -> float:
    try:
        value = float(value)
    except (TypeError, ValueError):
        return 0.0

    return max(0.0, min(1.0, value))


def _digest(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    return hashlib.sha256(payload).hexdigest()


def _finding_id(
    category: str,
    title: str,
    asset: str,
    evidence: Any,
) -> str:
    digest = _digest(
        {
            "category": category,
            "title": title,
            "asset": asset,
            "evidence": evidence,
        }
    )

    return f"C3-{digest[:12]}"


def _finding(
    *,
    category: str,
    severity: str,
    confidence: float,
    affected_asset: str,
    title: str,
    explanation: str,
    evidence: List[Dict[str, Any]],
    recommended_action: str,
    limitations: List[str],
    source_engine: str,
) -> AssuranceFinding:

    severity = _normalize_severity(severity)

    return AssuranceFinding(
        finding_id=_finding_id(
            category,
            title,
            affected_asset,
            evidence,
        ),
        category=category,
        severity=severity,
        confidence=_confidence(confidence),
        affected_asset=affected_asset,
        title=title,
        explanation=explanation,
        evidence=evidence,
        recommended_action=recommended_action,
        limitations=limitations,
        source_engine=source_engine,
    )


# ---------------------------------------------------------------------------
# Dataset findings
# ---------------------------------------------------------------------------

def findings_from_dataset(
    result: Dict[str, Any],
    *,
    affected_asset: str = "dataset",
) -> List[AssuranceFinding]:
    """Convert dataset integrity findings into C3 findings."""

    findings: List[AssuranceFinding] = []

    # Generic finding list emitted by A engines.
    raw_findings = result.get("findings", [])

    if isinstance(raw_findings, list):
        for index, item in enumerate(raw_findings):

            if not isinstance(item, dict):
                continue

            severity = _normalize_severity(
                item.get("severity", "medium")
            )

            evidence = [
                {
                    "source": "dataset_engine",
                    "finding_index": index,
                    "data": item,
                }
            ]

            findings.append(
                _finding(
                    category="dataset_integrity",
                    severity=severity,
                    confidence=_confidence(
                        item.get("confidence", 0.80)
                    ),
                    affected_asset=affected_asset,
                    title=str(
                        item.get(
                            "title",
                            item.get(
                                "type",
                                "Dataset integrity finding",
                            ),
                        )
                    ),
                    explanation=str(
                        item.get(
                            "message",
                            "Dataset analysis produced measurable evidence.",
                        )
                    ),
                    evidence=evidence,
                    recommended_action=str(
                        item.get(
                            "recommended_action",
                            "Review the affected samples and contributor evidence.",
                        )
                    ),
                    limitations=[
                        "Dataset evidence does not by itself establish malicious intent.",
                        "Findings should be reviewed against trusted reference data.",
                    ],
                    source_engine="dataset",
                )
            )

    # Explicit duplicate evidence.
    duplicate_groups = result.get(
        "duplicate_groups",
        result.get("exact_duplicate_groups", []),
    )
    # The Phase 6 runner persists A1–A8 under their engine IDs. Accept A2's
    # actual result envelope as well as the legacy flattened C3 input shape.
    if not duplicate_groups:
        a2_result = result.get("A2_exact_duplicates", {})
        if isinstance(a2_result, dict):
            duplicate_groups = a2_result.get("groups", [])
    if duplicate_groups:
        findings.append(
            _finding(
                category="dataset_integrity",
                severity="medium",
                confidence=0.90,
                affected_asset=affected_asset,
                title="Exact duplicate samples detected",
                explanation=(
                    "The dataset contains one or more groups of files "
                    "with identical content hashes."
                ),
                evidence=[
                    {
                        "type": "exact_duplicate_groups",
                        "groups": duplicate_groups,
                    }
                ],
                recommended_action=(
                    "Review duplicate groups and determine whether "
                    "duplication is expected."
                ),
                limitations=[
                    "Duplicates may be legitimate and do not prove poisoning."
                ],
                source_engine="A2",
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Model findings
# ---------------------------------------------------------------------------

def findings_from_model(
    result: Dict[str, Any],
    *,
    affected_asset: str = "model",
) -> List[AssuranceFinding]:
    """Convert B-series model assurance results into C3 findings."""

    findings: List[AssuranceFinding] = []

    raw_findings = result.get("findings", [])

    if isinstance(raw_findings, list):
        for index, item in enumerate(raw_findings):

            if not isinstance(item, dict):
                continue

            severity = _normalize_severity(
                item.get("severity", "medium")
            )

            findings.append(
                _finding(
                    category="model_integrity",
                    severity=severity,
                    confidence=_confidence(
                        item.get("confidence", 0.75)
                    ),
                    affected_asset=affected_asset,
                    title=str(
                        item.get(
                            "title",
                            item.get(
                                "type",
                                "Model assurance finding",
                            ),
                        )
                    ),
                    explanation=str(
                        item.get(
                            "message",
                            "Model analysis produced measurable evidence.",
                        )
                    ),
                    evidence=[
                        {
                            "source": "model_engine",
                            "finding_index": index,
                            "data": item,
                        }
                    ],
                    recommended_action=str(
                        item.get(
                            "recommended_action",
                            "Review model evidence against a trusted reference.",
                        )
                    ),
                    limitations=[
                        "Behavioral or statistical anomalies do not prove a malicious model.",
                        "Results depend on the selected probe/reference battery.",
                    ],
                    source_engine="model",
                )
            )

    # B4 candidate trigger-like behavior.
    candidate_count = int(
        result.get(
            "candidate_trigger_count",
            0,
        )
    )

    if candidate_count > 0:
        findings.append(
            _finding(
                category="model_integrity",
                severity="high",
                confidence=0.90,
                affected_asset=affected_asset,
                title="Candidate trigger-like behavior detected",
                explanation=(
                    "The trigger-search engine found a localized input "
                    "pattern that repeatedly changed model behavior "
                    "under the configured evidence criteria."
                ),
                evidence=[
                    {
                        "type": "candidate_trigger_count",
                        "value": candidate_count,
                    },
                    {
                        "type": "trigger_search_assessment",
                        "value": result.get("assessment"),
                    },
                ],
                recommended_action=(
                    "Inspect the candidate trigger pattern and compare "
                    "model behavior against a trusted reference model."
                ),
                limitations=[
                    "Candidate trigger-like behavior is not proof of a backdoor.",
                    "The search space is finite and configuration-dependent.",
                    "Only supported model/task adapters are evaluated.",
                ],
                source_engine="B4",
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Provenance findings
# ---------------------------------------------------------------------------

def findings_from_provenance(
    result: Dict[str, Any],
    *,
    affected_asset: str = "inference_provenance",
) -> List[AssuranceFinding]:
    """Convert C1 provenance verification results into C3 findings."""

    findings: List[AssuranceFinding] = []

    raw_findings = result.get("findings", [])

    if not isinstance(raw_findings, list):
        raw_findings = []

    for index, item in enumerate(raw_findings):

        if not isinstance(item, dict):
            continue

        finding_type = str(
            item.get(
                "type",
                "provenance_integrity",
            )
        )

        severity = "high"

        if finding_type in {
            "sequence_discontinuity",
            "nonce_reuse",
        }:
            severity = "medium"

        findings.append(
            _finding(
                category="inference_provenance",
                severity=severity,
                confidence=0.98,
                affected_asset=affected_asset,
                title=finding_type.replace("_", " ").title(),
                explanation=str(
                    item.get(
                        "message",
                        "Provenance integrity evidence was detected.",
                    )
                ),
                evidence=[
                    {
                        "source": "C1",
                        "finding_index": index,
                        "data": item,
                    }
                ],
                recommended_action=(
                    "Stop relying on the affected provenance chain until "
                    "the record integrity issue is reviewed."
                ),
                limitations=[
                    "A provenance failure identifies an integrity problem "
                    "with the recorded event; it does not identify the actor."
                ],
                source_engine="C1",
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Distribution-shift findings
# ---------------------------------------------------------------------------

def findings_from_shift(
    result: Dict[str, Any],
    *,
    affected_asset: str = "candidate_dataset",
) -> List[AssuranceFinding]:
    """Convert C2 distribution-shift results into C3 findings."""

    findings: List[AssuranceFinding] = []

    if result.get("status") != "completed":
        return findings

    severity = _normalize_severity(
        result.get("severity", "none")
    )

    if severity != "none":
        overall_shift = float(
            result.get(
                "overall_shift",
                0.0,
            )
        )

        shifted_features = result.get(
            "shifted_features",
            [],
        )

        confidence = min(
            1.0,
            0.50 + overall_shift,
        )

        findings.append(
            _finding(
                category="distribution_shift",
                severity=severity,
                confidence=confidence,
                affected_asset=affected_asset,
                title="Distribution shift detected",
                explanation=(
                    "The candidate image population differs measurably "
                    "from the configured reference population."
                ),
                evidence=[
                    {
                        "type": "overall_shift",
                        "value": overall_shift,
                    },
                    {
                        "type": "shifted_features",
                        "value": shifted_features,
                    },
                    {
                        "type": "distances",
                        "value": result.get("distances", {}),
                    },
                ],
                recommended_action=(
                    "Review affected samples, acquisition conditions, "
                    "and trusted reference data before relying on the "
                    "candidate population."
                ),
                limitations=[
                    "Distribution shift does not prove malicious manipulation.",
                    "Environmental or sensor changes can produce legitimate shift.",
                    "Appearance features do not establish semantic correctness.",
                ],
                source_engine="C2",
            )
        )

    anomalous_images = result.get(
        "anomalous_images",
        [],
    )

    if anomalous_images:
        findings.append(
            _finding(
                category="distribution_shift",
                severity="medium",
                confidence=0.85,
                affected_asset=affected_asset,
                title="Statistical image outliers detected",
                explanation=(
                    "One or more candidate images are statistical "
                    "outliers relative to the reference feature distribution."
                ),
                evidence=[
                    {
                        "type": "anomalous_images",
                        "count": len(anomalous_images),
                        "images": anomalous_images,
                    }
                ],
                recommended_action=(
                    "Inspect the listed images for acquisition, "
                    "format, sensor, illumination, or processing differences."
                ),
                limitations=[
                    "Statistical outliers may be legitimate observations.",
                    "Outlier detection does not establish malicious intent.",
                ],
                source_engine="C2",
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def aggregate_findings(
    *,
    dataset_results: Optional[Sequence[Dict[str, Any]]] = None,
    model_results: Optional[Sequence[Dict[str, Any]]] = None,
    provenance_results: Optional[Sequence[Dict[str, Any]]] = None,
    shift_results: Optional[Sequence[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Aggregate findings from the available assurance engines.

    Missing engine results are simply omitted.
    """

    findings: List[AssuranceFinding] = []

    for result in dataset_results or []:
        findings.extend(
            findings_from_dataset(result)
        )

    for result in model_results or []:
        findings.extend(
            findings_from_model(result)
        )

    for result in provenance_results or []:
        findings.extend(
            findings_from_provenance(result)
        )

    for result in shift_results or []:
        findings.extend(
            findings_from_shift(result)
        )

    finding_dicts = [
        finding.as_dict()
        for finding in findings
    ]

    severity = _max_severity(
        finding["severity"]
        for finding in finding_dicts
    )

    severity_counts = {
        level: sum(
            1
            for finding in finding_dicts
            if finding["severity"] == level
        )
        for level in (
            "critical",
            "high",
            "medium",
            "low",
            "none",
        )
    }

    digest_payload = {
        "findings": finding_dicts,
        "severity": severity,
        "severity_counts": severity_counts,
    }

    return {
        "status": "completed",
        "engine_version": ENGINE_VERSION,
        "method": METHOD,
        "task": TASK,
        "finding_count": len(finding_dicts),
        "overall_severity": severity,
        "severity_counts": severity_counts,
        "findings": finding_dicts,
        "evidence_digest": _digest(digest_payload),
        "limitations": [
            "Findings summarize evidence from upstream assurance engines.",
            "Severity is an assurance triage level, not a probability of attack.",
            "A finding does not independently establish malicious intent.",
            "Analyst review remains required for operational decisions.",
        ],
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "ENGINE_VERSION",
    "METHOD",
    "TASK",
    "AssuranceFinding",
    "findings_from_dataset",
    "findings_from_model",
    "findings_from_provenance",
    "findings_from_shift",
    "aggregate_findings",
]
