import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication, QDialog, QLabel, QPushButton, QTableWidget

from desktop.pages.shift_workspace import (
    ShiftAnomalyDialog,
    ShiftFindingDialog,
    ShiftWorkspace,
    shift_status,
)
from desktop.widgets.components import EvidenceViewerDialog


@pytest.fixture(scope="module")
def qt_app():
    return QApplication.instance() or QApplication([])


def assessment(status="COMPLETED", c2_status="completed", dataset_path=None):
    return {
        "assessment_id": "TRACER-SHIFT-TEST",
        "name": "Local distribution review",
        "status": status,
        "dataset": {"path": str(dataset_path)} if dataset_path else {},
        "engines": {"C2_distribution_shift": {"status": c2_status, "evidence": "stored-result-digest"}},
    }


def result(status="completed"):
    shifted = [
        {"feature": "brightness", "distance": 0.3, "threshold": 0.08, "shifted": True},
        {"feature": "contrast", "distance": 0.02, "threshold": 0.08, "shifted": False},
    ]
    anomalies = [
        {"file": "candidate-a.png", "path": "/missing/candidate-a.png", "max_z_score": 4.5,
         "features": {"brightness": 4.5, "contrast": 1.2}},
        {"file": "candidate-b.png", "path": "/missing/candidate-b.png", "max_z_score": 3.2,
         "features": {"brightness": 1.0, "edge_density": 3.2}},
    ]
    return {
        "status": status,
        "engine_version": "c2-test",
        "method": "multifeature image distribution shift analysis",
        "config": {"brightness_threshold": 0.08, "image_anomaly_z": 3.0},
        "reference": {"image_count": 8, "error_count": 0, "summary": {
            "brightness": {"mean": 0.35, "std": 0.02, "count": 8},
            "contrast": {"mean": 0.10, "std": 0.01, "count": 8},
        }},
        "candidate": {"image_count": 9, "error_count": 0, "summary": {
            "brightness": {"mean": 0.65, "std": 0.03, "count": 9},
            "contrast": {"mean": 0.12, "std": 0.02, "count": 9},
        }},
        "distances": {"scalar": {"brightness": 0.3, "contrast": 0.02},
                      "histogram": {"red_hist": 0.4, "gray_hist": 0.5}},
        "shifted_features": shifted,
        "overall_shift": 0.42,
        "severity": "high",
        "anomalous_images": anomalies,
        "findings": [],
        "result_digest": "result-digest-c2",
        "limitations": ["Distribution shift does not prove malicious manipulation.",
                        "Appearance features do not establish semantic correctness."],
    }


def findings():
    return [
        {"finding_id": "C3-C2-1", "source_engine": "C2", "category": "distribution_shift",
         "severity": "HIGH", "confidence": 0.91, "title": "Distribution shift detected",
         "explanation": "The candidate population differs measurably from the configured reference.",
         "affected_asset": "candidate dataset",
         "evidence": [{"type": "overall_shift", "value": 0.42},
                      {"type": "shifted_features", "value": [{"feature": "brightness", "shifted": True}]}],
         "recommended_action": "Review acquisition conditions and trusted reference data.",
         "limitations": ["Distribution shift does not establish malicious intent."]},
        {"finding_id": "C3-C2-2", "source_engine": "C2", "category": "distribution_shift",
         "severity": "MEDIUM", "confidence": 0.85, "title": "Statistical image outliers detected",
         "explanation": "Candidate image feature values are outliers relative to the reference.",
         "affected_asset": "candidate dataset", "evidence": [{"type": "anomalous_images", "count": 2}]},
        {"finding_id": "C3-A2", "source_engine": "A2", "category": "dataset_integrity", "title": "Excluded"},
    ]


def test_workspace_construction_and_c2_persisted_values(qt_app):
    page = ShiftWorkspace(assessment(), result(), findings())
    assert page.state == "COMPLETED"
    assert page.finding_count == 2
    assert page.anomaly_table.rowCount() == 2
    assert page.finding_table.rowCount() == 2
    assert page.result["overall_shift"] == 0.42
    assert page.anomalies[0]["file"] == "candidate-a.png"


def test_missing_malformed_and_failed_results_are_honest(qt_app):
    missing = ShiftWorkspace(assessment(), None, None)
    assert missing.state == "UNAVAILABLE"
    assert any("Distribution shift assessment not available" in label.text()
               for label in missing.findChildren(QLabel))

    malformed = ShiftWorkspace(assessment(), ["bad", "shape"], [])
    assert malformed.state == "PARTIAL"
    assert malformed.anomaly_table.rowCount() == 0
    assert any("could not be interpreted" in label.text().lower()
               for label in malformed.findChildren(QLabel))

    malformed_dict = ShiftWorkspace(assessment(), {"status": "completed", "reference": []}, [])
    assert malformed_dict.state == "PARTIAL"

    failed = ShiftWorkspace(assessment("COMPLETED_WITH_WARNINGS", "error"),
                            {"status": "error", "reason": "C2 could not read the selected images."}, [])
    assert failed.state == "FAILED"
    assert any("C2 could not read" in label.text() for label in failed.findChildren(QLabel))
    assert failed.anomaly_table.rowCount() == 0


def test_completed_warning_and_unavailable_engine_statuses(qt_app):
    warning = result("completed_with_warnings")
    page = ShiftWorkspace(assessment("COMPLETED_WITH_WARNINGS", "completed_with_warnings"), warning, [])
    assert page.state == "COMPLETED WITH WARNINGS"
    assert page.result["overall_shift"] == 0.42
    assert shift_status({"status": "unavailable", "reason": "No reference images."},
                        {"C2_distribution_shift": {"status": "unavailable"}}) == "UNAVAILABLE"
    assert shift_status({"status": "not_assessed"}, {"C2_distribution_shift": {"status": "not_assessed"}}) == "NOT ASSESSED"
    not_assessed = ShiftWorkspace(assessment("COMPLETED_WITH_WARNINGS", "not_assessed"),
                                  {"status": "not_assessed", "reason": "Reference set not supplied."}, [])
    assert not_assessed.state == "NOT ASSESSED"


def test_reference_candidate_statistics_shift_and_overall_metric(qt_app):
    page = ShiftWorkspace(assessment(), result(), [])
    tables = page.findChildren(QTableWidget)
    feature_table = next(table for table in tables if table.columnCount() == 6 and table.rowCount() == 2)
    assert feature_table.item(0, 0).text() == "Brightness"
    assert feature_table.item(0, 1).text() == "0.35"
    assert feature_table.item(0, 2).text() == "0.65"
    shifted_table = next(table for table in tables if table.columnCount() == 7)
    assert shifted_table.cellWidget(0, 5).text() == "SHIFTED"
    labels = "\n".join(label.text() for label in page.findChildren(QLabel))
    assert "Overall distribution shift: 0.42" in labels
    assert "not an attack probability" in labels
    assert "red hist" in " ".join(cell.text() for table in tables for row in range(table.rowCount())
                                   for cell in [table.item(row, 0)] if cell).lower()


def test_no_shift_is_not_described_as_clean(qt_app):
    payload = result()
    payload["shifted_features"] = [{"feature": "brightness", "distance": 0.01, "threshold": 0.08, "shifted": False}]
    payload["overall_shift"] = 0.01
    payload["severity"] = "none"
    page = ShiftWorkspace(assessment(), payload, [])
    text = ("\n".join(label.text() for label in page.findChildren(QLabel)) + "\n" +
                " ".join(cell.text() for table in page.findChildren(QTableWidget)
                     for row in range(table.rowCount()) for col in range(table.columnCount())
                     for cell in [table.item(row, col)] if cell)).lower()
    assert "no configured distribution features exceeded their persisted thresholds" in text
    assert "no detected shift does not prove absence of manipulation" in text
    assert "does not establish that the dataset is clean" in text


def test_anomaly_filter_search_sort_detail_and_on_demand_image(qt_app, tmp_path, monkeypatch):
    image_path = tmp_path / "candidate.png"
    image_path.write_bytes(b"not an actual decodable image")
    payload = result()
    payload["anomalous_images"] = [
        {"file": "candidate.png", "path": str(image_path), "max_z_score": 5.1,
         "features": {"brightness": 5.1}},
        {"file": "candidate-b.png", "path": "/missing/candidate-b.png", "max_z_score": 3.0,
         "features": {"edge_density": 3.0}},
    ]
    page = ShiftWorkspace(assessment(dataset_path=tmp_path), payload, [])
    assert page.anomaly_table.item(0, 0).text() == "candidate.png"
    page.anomaly_feature.setCurrentText("Edge density")
    assert page.anomaly_table.isRowHidden(0)
    assert not page.anomaly_table.isRowHidden(1)
    page.anomaly_feature.setCurrentText("All features")
    page.anomaly_search.setEditText("candidate-b")
    assert page.anomaly_table.isRowHidden(0)
    assert not page.anomaly_table.isRowHidden(1)
    opened = []
    monkeypatch.setattr(QDialog, "exec", lambda self: opened.append(self) or 0)
    page.open_anomaly_row(1, 0)
    dialog = next(item for item in opened if isinstance(item, ShiftAnomalyDialog))
    assert dialog.sample_path is None
    page.anomaly_search.setEditText("")
    page.open_anomaly_row(0, 0)
    dialog = next(item for item in reversed(opened) if isinstance(item, ShiftAnomalyDialog))
    assert dialog.sample_path == image_path
    dialog.inspect_image()
    from desktop.pages.dataset_workspace import DatasetSampleDialog
    assert any(isinstance(item, DatasetSampleDialog) for item in opened)


def test_c3_findings_filter_search_sort_and_investigation(qt_app, monkeypatch):
    opened = []
    monkeypatch.setattr(QDialog, "exec", lambda self: opened.append(self) or 0)
    page = ShiftWorkspace(assessment(), result(), findings())
    assert page.finding_table.item(0, 3).text() == "C3-C2-1"
    page.finding_severity.setCurrentText("MEDIUM")
    assert page.finding_table.isRowHidden(0)
    assert not page.finding_table.isRowHidden(1)
    page.finding_severity.setCurrentText("All severities")
    page.finding_search.setEditText("C3-C2-1")
    assert not page.finding_table.isRowHidden(0)
    assert page.finding_table.isRowHidden(1)
    page.finding_search.setEditText("")
    page.open_finding_row(0, 0)
    dialog = next(item for item in opened if isinstance(item, ShiftFindingDialog))
    assert dialog.finding["finding_id"] == "C3-C2-1"
    dialog.evidence_button.click()
    viewer = next(item for item in opened if isinstance(item, EvidenceViewerDialog))
    assert viewer.technical.isHidden() and viewer.raw_section.isHidden() and viewer.json_view.isHidden()
    viewer.show_technical(); viewer.show_raw(); viewer.show_json()
    assert not viewer.json_view.isHidden()


def test_limitations_and_missing_c3_findings_are_explicit(qt_app):
    page = ShiftWorkspace(assessment(), result(), None)
    text = "\n".join(label.text() for label in page.findChildren(QLabel))
    assert "No persisted findings available." in text
    assert "Distribution shift does not prove malicious manipulation." in text
    assert "Appearance features do not establish semantic correctness." in text
    assert "No detected shift does not prove absence of manipulation." in text


def test_opening_workspace_does_not_rerun_c2(qt_app, monkeypatch):
    import backend.engines.shift.distribution_shift as engine
    def forbidden(*_args, **_kwargs):
        raise AssertionError("C2 must not run when opening the analyst workspace")
    monkeypatch.setattr(engine, "analyze_distribution_shift", forbidden)
    monkeypatch.setattr(engine, "analyze_image_directories", forbidden)
    page = ShiftWorkspace(assessment(), result(), findings())
    assert page.result["overall_shift"] == 0.42
