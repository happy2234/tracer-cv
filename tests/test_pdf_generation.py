"""PDF generation tests for TRACER-CV.

All tests are read-only with respect to assessment state:
they never modify reports, findings, audit records, or assessment data.
All tests use tmp_path — no permanent files are created.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


@pytest.fixture
def minimal_report():
    return {
        "assessment_id": "TEST-PDF-MINIMAL",
        "report_version": "c5-1.0",
        "report_digest": "a" * 64,
        "executive_summary": {
            "assessment_scope": "Synthetic test only",
            "finding_count": 2,
            "highest_observed_severity": "HIGH",
            "severity_counts": {"HIGH": 1, "MEDIUM": 1},
            "provenance_chain_valid": True,
            "audit_chain_valid": True,
            "distribution_shift_detected": False,
            "interpretation": "Test report — not an operational assessment.",
        },
        "findings_and_evidence": {
            "findings": [
                {
                    "finding_id": "TEST-001",
                    "title": "Test Finding HIGH",
                    "severity": "HIGH",
                    "confidence": "MEDIUM",
                    "category": "Dataset Integrity",
                    "affected_asset": "synthetic_dataset",
                    "explanation": "A" * 300,  # long explanation to test wrapping
                    "evidence": [{"type": "test", "value": "synthetic"}],
                    "source_engine": "A2",
                    "recommended_action": "Review duplicate images.",
                    "limitations": "Only byte-identical duplicates are detected.",
                },
                {
                    "finding_id": "TEST-002",
                    "title": "Test Finding MEDIUM",
                    "severity": "MEDIUM",
                    "confidence": "LOW",
                    "category": "Model Integrity",
                    "affected_asset": "synthetic_model",
                    "explanation": "Behavioral difference detected.",
                    "source_engine": "B2",
                    "recommended_action": "Compare with trusted baseline.",
                    "limitations": "Differences may have legitimate causes.",
                },
            ]
        },
        "distribution_shift": {
            "status": "completed",
            "shift_detected": True,
            "severity": "medium",
            "overall_shift": 0.42,
        },
        "limitations": [
            "Synthetic test data only.",
            "Not an operational assessment.",
        ],
    }


@pytest.fixture
def minimal_assessment():
    return {
        "assessment_id": "TEST-PDF-MINIMAL",
        "status": "completed",
        "started_at": "2026-10-01T00:00:00+00:00",
        "completed_at": "2026-10-01T01:00:00+00:00",
    }


@pytest.fixture
def real_report():
    path = Path("reports/tracer_cv_assurance_report.json")
    if not path.is_file():
        pytest.skip("Real persisted report not available")
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Full assurance PDF tests
# ---------------------------------------------------------------------------

def test_full_pdf_generates_with_minimal_report(qapp, tmp_path, minimal_report, minimal_assessment):
    """A minimal C5 report produces a valid non-empty PDF file."""
    from desktop.reporting import write_assurance_pdf
    result = write_assurance_pdf(minimal_report, minimal_assessment, tmp_path / "minimal.pdf")
    assert Path(result["path"]).is_file()
    assert Path(result["path"]).stat().st_size > 10_000
    assert len(result["sha256"]) == 64
    assert all(c in "0123456789abcdef" for c in result["sha256"])
    assert "T" in result["exported_at"]  # ISO timestamp


def test_full_pdf_generates_with_real_persisted_report(qapp, tmp_path, real_report):
    """The real persisted C5 report generates a valid PDF without error."""
    from desktop.reporting import write_assurance_pdf
    assessment = {
        "assessment_id": real_report.get("assessment_id", "TEST"),
        "status": "completed",
    }
    result = write_assurance_pdf(real_report, assessment, tmp_path / "real.pdf")
    size = Path(result["path"]).stat().st_size
    assert size > 50_000, f"PDF unexpectedly small: {size} bytes"
    assert len(result["sha256"]) == 64


def test_pdf_sha256_returned_matches_file(qapp, tmp_path, minimal_report, minimal_assessment):
    """The returned sha256 matches the actual file sha256."""
    from desktop.reporting import write_assurance_pdf
    result = write_assurance_pdf(minimal_report, minimal_assessment, tmp_path / "sha.pdf")
    actual = hashlib.sha256(Path(result["path"]).read_bytes()).hexdigest()
    assert result["sha256"] == actual


def test_pdf_does_not_modify_report_dict(qapp, tmp_path, minimal_report, minimal_assessment):
    """PDF generation must not mutate the report dict."""
    from desktop.reporting import write_assurance_pdf
    original = copy.deepcopy(minimal_report)
    write_assurance_pdf(minimal_report, minimal_assessment, tmp_path / "mut.pdf")
    assert minimal_report == original, "report dict was mutated during PDF generation"


def test_pdf_does_not_modify_assessment_dict(qapp, tmp_path, minimal_report, minimal_assessment):
    """Assessment dict is not mutated during PDF generation."""
    from desktop.reporting import write_assurance_pdf
    original = copy.deepcopy(minimal_assessment)
    write_assurance_pdf(minimal_report, minimal_assessment, tmp_path / "mut2.pdf")
    assert minimal_assessment == original, "assessment dict was mutated"


def test_pdf_with_empty_report_does_not_crash(qapp, tmp_path):
    """An empty report dict does not cause PDF generation to crash."""
    from desktop.reporting import write_assurance_pdf
    result = write_assurance_pdf({}, {}, tmp_path / "empty.pdf")
    assert Path(result["path"]).stat().st_size > 0


def test_pdf_with_none_sections_does_not_crash(qapp, tmp_path):
    """None-valued report sections do not cause PDF generation to crash."""
    from desktop.reporting import write_assurance_pdf
    report = {
        "executive_summary": None,
        "findings_and_evidence": None,
        "distribution_shift": None,
    }
    result = write_assurance_pdf(report, {}, tmp_path / "none_sections.pdf")
    assert Path(result["path"]).stat().st_size > 0


def test_pdf_path_parent_created_if_missing(qapp, tmp_path, minimal_report, minimal_assessment):
    """PDF target path parent is created if it does not exist."""
    from desktop.reporting import write_assurance_pdf
    nested = tmp_path / "nested" / "deep" / "report.pdf"
    result = write_assurance_pdf(minimal_report, minimal_assessment, nested)
    assert Path(result["path"]).is_file()


def test_pdf_with_findings_larger_than_without(qapp, tmp_path, minimal_assessment):
    """A report with findings produces a larger PDF than one without."""
    from desktop.reporting import write_assurance_pdf
    without = {"executive_summary": {"interpretation": "No findings."}}
    with_findings = {
        "executive_summary": {"interpretation": "Findings present."},
        "findings_and_evidence": {
            "findings": [
                {"finding_id": f"F-{i:03d}", "title": f"Finding {i}",
                 "severity": "HIGH", "explanation": "X" * 200,
                 "source_engine": "A2", "affected_asset": "dataset"}
                for i in range(5)
            ]
        },
    }
    r1 = write_assurance_pdf(without, minimal_assessment, tmp_path / "no_findings.pdf")
    r2 = write_assurance_pdf(with_findings, minimal_assessment, tmp_path / "with_findings.pdf")
    s1 = Path(r1["path"]).stat().st_size
    s2 = Path(r2["path"]).stat().st_size
    assert s2 > s1, f"PDF with findings ({s2}) not larger than without ({s1})"


def test_pdf_export_does_not_rerun_engines(qapp, tmp_path, minimal_report,
                                            minimal_assessment, monkeypatch):
    """PDF export does not invoke any assessment engine."""
    from desktop.reporting import write_assurance_pdf
    # If any engine module is accessed for side-effects, the monkeypatched
    # function will raise. The test passes if no engine is called.
    import backend.core.assessment_runner as runner
    original_run = getattr(runner, "run_assessment", None)
    called = []
    if original_run:
        monkeypatch.setattr(runner, "run_assessment", lambda *a, **kw: called.append(True))
    write_assurance_pdf(minimal_report, minimal_assessment, tmp_path / "no_engine.pdf")
    assert not called, "run_assessment was called during PDF export"


def test_pdf_stability_across_two_runs(qapp, tmp_path, minimal_report, minimal_assessment):
    """Two PDF generations from the same data produce similarly-sized files."""
    from desktop.reporting import write_assurance_pdf
    r1 = write_assurance_pdf(minimal_report, minimal_assessment, tmp_path / "run1.pdf")
    r2 = write_assurance_pdf(minimal_report, minimal_assessment, tmp_path / "run2.pdf")
    s1 = Path(r1["path"]).stat().st_size
    s2 = Path(r2["path"]).stat().st_size
    # Allow up to 30% difference (timestamps differ)
    ratio = abs(s1 - s2) / max(s1, s2)
    assert ratio < 0.30, f"PDF size varied too much: {s1} vs {s2}"


# ---------------------------------------------------------------------------
# Section PDF tests
# ---------------------------------------------------------------------------

def test_section_pdf_generates_with_table_data(qapp, tmp_path):
    """write_section_pdf produces a valid PDF from structured rows."""
    from desktop.reporting import write_section_pdf
    result = write_section_pdf(
        "Dataset Integrity Report",
        {"description": "A1–A8 analysis.", "rows": [("Status", "OK"), ("Files", "10")]},
        tmp_path / "section.pdf",
        assessment_id="TEST-001",
    )
    assert Path(result["path"]).stat().st_size > 5_000
    assert len(result["sha256"]) == 64


def test_section_pdf_with_empty_rows_does_not_crash(qapp, tmp_path):
    """write_section_pdf handles empty rows without crashing."""
    from desktop.reporting import write_section_pdf
    result = write_section_pdf("Empty Section", {"description": "Nothing.", "rows": []},
                               tmp_path / "empty_section.pdf")
    assert Path(result["path"]).stat().st_size > 0


def test_section_pdf_with_long_text_does_not_crash(qapp, tmp_path):
    """write_section_pdf handles very long text values without crashing."""
    from desktop.reporting import write_section_pdf
    rows = [("Long field", "A" * 1000), ("Short", "OK"), ("Another long", "B" * 500)]
    result = write_section_pdf("Long Text Test", {"description": "Test.", "rows": rows},
                               tmp_path / "long.pdf")
    assert Path(result["path"]).stat().st_size > 0


def test_section_pdf_with_findings(qapp, tmp_path):
    """write_section_pdf includes findings block when provided."""
    from desktop.reporting import write_section_pdf
    findings = [
        {"finding_id": "F-001", "title": "Test", "severity": "HIGH",
         "explanation": "Synthetic finding for PDF test."},
    ]
    result = write_section_pdf(
        "Findings Report",
        {"description": "Test.", "rows": [], "findings": findings},
        tmp_path / "findings_section.pdf",
    )
    assert Path(result["path"]).stat().st_size > 5_000


def test_section_pdf_sha256_matches_file(qapp, tmp_path):
    """write_section_pdf returned sha256 matches the actual file."""
    from desktop.reporting import write_section_pdf
    result = write_section_pdf("Hash Test", {"description": "x", "rows": [("A", "B")]},
                               tmp_path / "hash.pdf")
    actual = hashlib.sha256(Path(result["path"]).read_bytes()).hexdigest()
    assert result["sha256"] == actual


def test_section_pdf_does_not_modify_input_data(qapp, tmp_path):
    """write_section_pdf does not mutate its section_data argument."""
    from desktop.reporting import write_section_pdf
    data = {"description": "test", "rows": [("A", "B")], "findings": []}
    original = copy.deepcopy(data)
    write_section_pdf("Mutation Test", data, tmp_path / "mut.pdf")
    assert data == original


def test_section_pdf_no_assessment_id_does_not_crash(qapp, tmp_path):
    """write_section_pdf works without an assessment_id."""
    from desktop.reporting import write_section_pdf
    result = write_section_pdf("No ID Test", {"description": "x", "rows": []},
                               tmp_path / "noid.pdf")
    assert Path(result["path"]).stat().st_size > 0
