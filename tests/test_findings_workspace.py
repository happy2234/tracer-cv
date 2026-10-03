import json
import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication, QDialog, QLabel, QPushButton, QTableWidget

from desktop.pages.findings_workspace import (
    ENGINE_ROUTES,
    FindingInvestigationDialog,
    FindingsWorkspace,
    c3_status,
)
from desktop.widgets.components import EvidenceViewerDialog


@pytest.fixture(scope="module")
def qt_app():
    return QApplication.instance() or QApplication([])


def assessment(status="COMPLETED", c3_status_value="completed", dataset_path=None):
    return {
        "assessment_id": "TRACER-C3-TEST",
        "name": "Local persisted finding review",
        "status": status,
        "dataset": {"path": str(dataset_path)} if dataset_path else {},
        "engines": {"C3_findings": {
            "status": c3_status_value,
            "evidence": {"sha256": "c3-result-digest", "uri": "local-evidence-reference"},
        }},
    }


def finding(fid, *, severity="high", source="C2", category="distribution_shift",
            asset="candidate dataset", confidence=0.92, title="Distribution shift observation"):
    return {
        "finding_id": fid,
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "affected_asset": asset,
        "title": title,
        "explanation": "The candidate image population differs from the configured reference population.",
        "evidence": [
            {"type": "overall_shift", "value": 0.42},
            {"type": "shifted_features", "value": [{"feature": "brightness", "distance": 0.3, "shifted": True}]},
        ],
        "recommended_action": "Review acquisition conditions and trusted reference evidence.",
        "limitations": ["Distribution shift does not prove malicious manipulation."],
        "source_engine": source,
    }


def c3_result(status="completed", entries=None):
    items = entries if entries is not None else [
        finding("C3-c2-high", source="C2", severity="high", confidence=0.92),
        finding("C3-a2-medium", source="A2", category="dataset_integrity", severity="medium",
                asset="dataset root", confidence=0.88, title="Exact duplicate samples detected"),
        finding("C3-b4-low", source="B4", category="model_integrity", severity="low",
                asset="model file", confidence=0.73, title="Candidate behavior requires review"),
        finding("C3-c1-info", source="C1", category="inference_provenance", severity="info",
                asset="inference records", confidence=0.61, title="Provenance evidence"),
    ]
    return {"status": status, "finding_count": len(items), "findings": items}


def test_workspace_construction_and_persisted_result_loading(qt_app, tmp_path):
    result_path = tmp_path / "findings.json"
    result_path.write_text(json.dumps(c3_result()), encoding="utf-8")
    persisted = json.loads(result_path.read_text(encoding="utf-8"))
    page = FindingsWorkspace(assessment(dataset_path=tmp_path), persisted)
    assert page.assessment["assessment_id"] == "TRACER-C3-TEST"
    assert page.state == "COMPLETED"
    assert len(page.findings) == 4
    assert page.finding_table.rowCount() == 4
    assert "C3-result-digest" not in " ".join(label.text() for label in page.findChildren(QLabel))


def test_missing_malformed_completed_warning_and_failed_states(qt_app):
    missing = FindingsWorkspace(assessment(), None)
    assert missing.state == "UNAVAILABLE"
    assert any("Findings assessment is not available" in label.text() for label in missing.findChildren(QLabel))

    malformed = FindingsWorkspace(assessment(), ["not", "an", "object"])
    assert malformed.state == "PARTIAL"
    assert any("could not be interpreted" in label.text().lower() for label in malformed.findChildren(QLabel))

    malformed_items = FindingsWorkspace(assessment(), {"status": "completed", "findings": [finding("valid"), "bad"]})
    assert malformed_items.state == "PARTIAL"
    assert len(malformed_items.findings) == 1

    warning = FindingsWorkspace(assessment("COMPLETED_WITH_WARNINGS", "completed_with_warnings"),
                                c3_result("completed_with_warnings"))
    assert warning.state == "COMPLETED WITH WARNINGS"
    assert len(warning.findings) == 4

    failed = FindingsWorkspace(assessment("COMPLETED_WITH_WARNINGS", "error"),
                               {"status": "error", "reason": "C3 aggregation failed.", "findings": []})
    assert failed.state == "FAILED"
    assert any("C3 aggregation failed" in label.text() for label in failed.findChildren(QLabel))
    assert c3_status({"status": "not_assessed"}, {"C3_findings": {"status": "not_assessed"}}) == "NOT ASSESSED"
    assert c3_status({"status": "unavailable"}, {"C3_findings": {"status": "completed"}}) == "UNAVAILABLE"


def test_empty_findings_is_not_a_security_verdict(qt_app):
    page = FindingsWorkspace(assessment(), {"status": "completed", "finding_count": 0, "findings": []})
    labels = "\n".join(label.text() for label in page.findChildren(QLabel)).lower()
    assert "no persisted assurance findings were recorded" in labels
    assert "does not establish absence of attacks" in labels
    assert "secure" not in labels


def test_overview_aggregates_are_counts_of_persisted_findings(qt_app):
    page = FindingsWorkspace(assessment(), c3_result())
    assert page.finding_table.rowCount() == 4
    tables = page.findChildren(QTableWidget)
    def first_text(table):
        cell = table.cellWidget(0, 0) or table.item(0, 0)
        return cell.text()
    severity_table = next(table for table in tables if table.columnCount() == 2 and first_text(table) == "high")
    assert severity_table.item(0, 1).text() == "1"
    source_table = next(table for table in tables if table.columnCount() == 2 and first_text(table) == "A2")
    assert source_table.item(0, 1).text() == "1"
    overview_text = "\n".join(label.text() for label in page.findChildren(QLabel))
    assert "Assessment ID: TRACER-C3-TEST" in overview_text
    assert "C3 status: COMPLETED" in overview_text
    assert "c3-result-digest" in overview_text


def test_severity_category_source_asset_search_and_clear(qt_app):
    page = FindingsWorkspace(assessment(), c3_result())
    page.severity_filter.setCurrentText("high")
    assert sum(not page.finding_table.isRowHidden(row) for row in range(page.finding_table.rowCount())) == 1
    page.category_filter.setCurrentText("dataset_integrity")
    assert all(page.finding_table.isRowHidden(row) for row in range(page.finding_table.rowCount()))
    page.clear_filters()
    page.source_filter.setCurrentText("A2")
    assert sum(not page.finding_table.isRowHidden(row) for row in range(page.finding_table.rowCount())) == 1
    page.source_filter.setCurrentIndex(0)
    page.asset_filter.setCurrentText("model file")
    assert sum(not page.finding_table.isRowHidden(row) for row in range(page.finding_table.rowCount())) == 1
    page.asset_filter.setCurrentIndex(0)
    page.search.setEditText("exact duplicate samples")
    assert sum(not page.finding_table.isRowHidden(row) for row in range(page.finding_table.rowCount())) == 1
    page.search.setEditText("C3-a2-medium")
    assert sum(not page.finding_table.isRowHidden(row) for row in range(page.finding_table.rowCount())) == 1
    page.clear_filters()
    assert sum(not page.finding_table.isRowHidden(row) for row in range(page.finding_table.rowCount())) == 4


def test_sorting_and_finding_investigation(qt_app, monkeypatch):
    opened = []
    monkeypatch.setattr(QDialog, "exec", lambda self: opened.append(self) or 0)
    page = FindingsWorkspace(assessment(), c3_result())
    page.sort_by.setCurrentText("Confidence")
    assert page.finding_table.item(0, 1).text() == "0.92"
    page.sort_order.setCurrentText("Ascending")
    assert page.finding_table.item(0, 1).text() == "0.61"
    page.sort_by.setCurrentText("Finding ID")
    page.sort_order.setCurrentText("Ascending")
    assert page.finding_table.item(0, 6).text() == "C3-a2-medium"
    page.open_finding_row(0, 0)
    dialog = next(item for item in opened if isinstance(item, FindingInvestigationDialog))
    assert dialog.finding["finding_id"] == "C3-a2-medium"
    values = "\n".join(label.text() for label in dialog.findChildren(QLabel))
    assert "Source engine: A2" in values
    assert "What was observed" in values
    assert "Recommended action" in values
    assert "Limitations" in values


def test_missing_fields_display_unavailable_without_crashing(qt_app):
    page = FindingsWorkspace(assessment(), {"status": "completed", "findings": [{"source_engine": "A1"}]})
    assert page.finding_table.rowCount() == 1
    values = [page.finding_table.item(0, column).text() for column in range(1, 7)]
    assert "Unavailable" in values
    dialog = FindingInvestigationDialog({"source_engine": "A1"})
    text = "\n".join(label.text() for label in dialog.findChildren(QLabel))
    assert "Finding ID: Unavailable" in text
    assert "Confidence: Unavailable" in text


def test_evidence_viewer_progressive_disclosure_and_sample_references(qt_app, tmp_path, monkeypatch):
    image_path = tmp_path / "sample.png"
    image_path.write_bytes(b"placeholder")
    item = finding("C3-sample", source="A2")
    item["evidence"] = [{"files": [str(image_path)], "sha256": "actual-persisted-hash"}]
    opened = []
    monkeypatch.setattr(QDialog, "exec", lambda self: opened.append(self) or 0)
    dialog = FindingInvestigationDialog(item, dataset_root=tmp_path)
    assert dialog.sample_refs == [str(image_path)]
    dialog.evidence_button.click()
    viewer = next(entry for entry in opened if isinstance(entry, EvidenceViewerDialog))
    assert viewer.technical.isHidden() and viewer.raw_section.isHidden() and viewer.json_view.isHidden()
    viewer.show_technical(); viewer.show_raw(); viewer.show_json()
    assert not viewer.json_view.isHidden()


def test_source_engine_traceability_and_session_review_reuse(qt_app, monkeypatch):
    opened_routes = []
    review_calls = []
    item = finding("C3-route", source="C2 Distribution Shift")
    page = FindingsWorkspace(assessment(), {"status": "completed", "findings": [item]},
                             on_navigate=opened_routes.append,
                             on_review=lambda value: review_calls.append(value["finding_id"]) or True)
    dialog = FindingInvestigationDialog(item, on_navigate=page.on_navigate, on_review=page.on_review)
    assert dialog.source_button.text() == "Open Distribution Shift"
    dialog.open_source_workspace()
    assert opened_routes == [4]
    dialog.review_in_session()
    assert review_calls == ["C3-route"]
    assert "session only" in dialog.review_state.text()
    unknown = FindingInvestigationDialog(finding("unknown", source="C5"), on_navigate=opened_routes.append)
    assert not unknown.source_button.isEnabled()
    assert ENGINE_ROUTES["A1"][0] == 1 and ENGINE_ROUTES["B1"][0] == 2 and ENGINE_ROUTES["C1"][0] == 3


def test_workspace_open_does_not_rerun_c3(qt_app, monkeypatch):
    import backend.engines.risk.findings as c3
    def forbidden(*_args, **_kwargs):
        raise AssertionError("C3 must not run when opening the findings workspace")
    for name in ("findings_from_dataset", "findings_from_model", "findings_from_provenance",
                 "findings_from_shift", "aggregate_findings"):
        if hasattr(c3, name):
            monkeypatch.setattr(c3, name, forbidden)
    page = FindingsWorkspace(assessment(), c3_result())
    assert page.finding_table.rowCount() == 4
