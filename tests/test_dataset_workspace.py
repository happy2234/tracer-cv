import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication

from desktop.pages.dataset_workspace import (
    DatasetIntegrityWorkspace,
    engine_finding_count,
    engine_severity,
    engine_status,
    sort_engine_rows,
)
from desktop.widgets.components import EvidenceViewerDialog


@pytest.fixture(scope="module")
def qt_app():
    return QApplication.instance() or QApplication([])


def sample_assessment(tmp_path, status="COMPLETED"):
    dataset = tmp_path / "local-dataset"
    dataset.mkdir(exist_ok=True)
    return {
        "assessment_id": "assessment-local-123",
        "name": "Persisted review",
        "status": status,
        "dataset": {"path": str(dataset), "selection_sha256": "abc"},
        "engines": {
            "A1_manifest": {"status": "completed"},
            "A2_exact_duplicates": {"status": "completed"},
            "A4_ood": {"status": "not_assessed", "reason": "Reference dataset unavailable."},
        },
    }


def sample_results():
    return {
        "A1_manifest": {"status": "completed", "dataset_sha256": "abc", "file_count": 2, "files": []},
        "A2_exact_duplicates": {"status": "completed", "duplicate_group_count": 1,
                                 "groups": [{"files": ["one.jpg", "two.jpg"], "sha256": "digest"}]},
        "A4_ood": {"status": "not_assessed", "reason": "Reference dataset unavailable."},
    }


def sample_findings():
    return [{"finding_id": "C3-dataset-1", "source_engine": "A2", "category": "duplicate",
             "severity": "MEDIUM", "title": "Identical files", "affected_asset": "one.jpg",
             "explanation": "Two files have matching SHA-256 digests.",
             "evidence": [{"files": ["one.jpg", "two.jpg"], "sha256": "digest"}],
             "limitations": ["Byte identity does not establish why the copies exist."]},
            {"finding_id": "C3-dataset-2", "source_engine": "A5", "category": "label",
             "severity": "LOW", "title": "Label observation", "affected_asset": "three.jpg",
             "explanation": "A recorded label observation.", "evidence": [], "limitations": []}]


def test_workspace_uses_persisted_assessment_results(qt_app, tmp_path):
    page = DatasetIntegrityWorkspace(sample_assessment(tmp_path), sample_results(), sample_findings())
    assert page.assessment["assessment_id"] == "assessment-local-123"
    assert page.engine_rows[0]["result"]["file_count"] == 2
    assert page.engine_rows[1]["count"] == 1
    assert page.engine_rows[3]["status"] == "NOT ASSESSED"
    assert "Reference dataset unavailable" in page.engine_rows[3]["explanation"]


def test_engine_status_counts_and_severity_mapping():
    assert engine_status("A1_manifest", {"file_count": 2}, {"A1_manifest": {"status": "completed"}}) == "COMPLETED"
    assert engine_status("A4_ood", {"status": "not_assessed"}, {}) == "NOT ASSESSED"
    assert engine_status("A1_manifest", {}, {"A1_manifest": {"status": "completed"}}) == "UNAVAILABLE"
    assert engine_finding_count("A2_exact_duplicates", {"duplicate_group_count": 3}) == 3
    assert engine_severity("A2_exact_duplicates", {}, sample_findings()) == "MEDIUM"


def test_filtering_category_search_and_engine_selection(qt_app, tmp_path):
    page = DatasetIntegrityWorkspace(sample_assessment(tmp_path), sample_results(), sample_findings())
    page.category_filter.setCurrentText("duplicate")
    page.apply_filters()
    assert not page.finding_table.isRowHidden(0)
    page.category_filter.setCurrentText("label")
    page.apply_filters()
    assert page.finding_table.isRowHidden(0)
    page.category_filter.setCurrentText("All categories")
    page.search.setEditText("C3-dataset-1")
    page.apply_filters()
    assert not page.finding_table.isRowHidden(0)
    page.engine_filter.setCurrentText("A1 Manifest Integrity")
    page.apply_filters()
    assert page.finding_table.isRowHidden(0)


def test_sorting_severity_and_finding_investigation(qt_app, tmp_path):
    rows = [{"spec": ("A1", "A1", "Manifest"), "severity": "NONE REPORTED", "count": 0,
             "samples": [], "status": "COMPLETED"},
            {"spec": ("A2", "A2", "Duplicates"), "severity": "HIGH", "count": 2,
             "samples": ["a", "b"], "status": "COMPLETED"}]
    assert sort_engine_rows(rows, "Severity", descending=True)[0]["severity"] == "HIGH"
    page = DatasetIntegrityWorkspace(sample_assessment(tmp_path), sample_results(), sample_findings())
    # The page itself keeps engine evidence separate from its technical drill-down.
    from desktop.pages.dataset_workspace import DatasetFindingDialog
    dialog = DatasetFindingDialog(sample_findings()[0], page.dataset_root)
    assert dialog.finding["finding_id"] == "C3-dataset-1"
    assert "not persisted or auditable" in dialog.decision_notice.text()


def test_evidence_viewer_keeps_raw_json_secondary(qt_app):
    dialog = EvidenceViewerDialog("Finding", "Readable explanation", "Structured values", {"secret": "raw"})
    assert dialog.json_view.isHidden()
    assert dialog.technical.isHidden()
    dialog.show_technical()
    dialog.show_raw()
    dialog.show_json()
    assert dialog.json_view.toPlainText().find('"secret"') >= 0


def test_malformed_and_missing_dataset_results_are_explicit(qt_app, tmp_path):
    assessment = sample_assessment(tmp_path, "COMPLETED_WITH_WARNINGS")
    results = sample_results()
    results["A3_near_duplicates"] = ["bad", "shape"]
    page = DatasetIntegrityWorkspace(assessment, results, [])
    assert page.engine_rows[2]["status"] == "FAILED"
    assert "malformed" in page.engine_rows[2]["explanation"].lower()
    assert page.assessment["status"] == "COMPLETED_WITH_WARNINGS"
    empty = DatasetIntegrityWorkspace(None, None, None)
    assert empty.assessment == {}
