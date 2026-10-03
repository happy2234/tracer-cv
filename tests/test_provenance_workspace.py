import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication, QDialog, QLabel, QTableWidget

from desktop.pages.provenance_workspace import (
    ProvenanceFindingDialog,
    ProvenanceRecordDialog,
    ProvenanceWorkspace,
    provenance_status,
)
from desktop.widgets.components import EvidenceViewerDialog


@pytest.fixture(scope="module")
def qt_app():
    return QApplication.instance() or QApplication([])


def assessment(status="COMPLETED", c1_status="completed"):
    return {
        "assessment_id": "TRACER-PROVENANCE-TEST",
        "name": "Local provenance review",
        "status": status,
        "engines": {"C1_provenance": {"status": c1_status, "evidence": "persisted-result-digest"}},
    }


def record(sequence=1, previous="0" * 64, signature=None):
    return {
        "sequence": sequence, "nonce": f"nonce-{sequence}", "timestamp": f"2026-01-01T00:00:0{sequence}+00:00",
        "input_digest": f"input-{sequence}", "model_id": "sha256:model-id",
        "preprocessing_digest": f"preprocessing-{sequence}", "output_digest": f"output-{sequence}",
        "previous_record_hash": previous, "record_hash": f"record-{sequence}", "signature": signature,
    }


def result(status="completed"):
    first = record()
    second = record(2, first["record_hash"])
    return {
        "status": status,
        "engine_version": "c1-test",
        "method": "cryptographically bound inference provenance",
        "model_id": first["model_id"],
        "record_count": 2,
        "records": [first, second],
        "verification": {"valid": True, "record_count": 2, "findings": []},
        "limitations": ["A chain inconsistency does not identify its actor."],
    }


def provenance_findings():
    return [
        {"finding_id": "C3-prov-1", "source_engine": "C1", "category": "inference_provenance",
         "severity": "HIGH", "confidence": 0.98, "title": "Broken Chain",
         "explanation": "Previous-record hash did not match its predecessor.",
         "affected_asset": "local dataset", "evidence": [{"source": "C1", "data": {"type": "broken_chain", "sequence": 2}}],
         "recommended_action": "Review recorded provenance evidence.", "limitations": ["Actor is not established."]},
        {"finding_id": "C3-other", "source_engine": "A2", "category": "dataset_integrity", "severity": "LOW", "title": "Excluded"},
    ]


def test_workspace_construction_and_persisted_c1_result(qt_app):
    page = ProvenanceWorkspace(assessment(), result(), provenance_findings())
    assert page.result["record_count"] == 2
    assert page.chain_table.rowCount() == 2
    assert page.finding_table.rowCount() == 1
    assert provenance_status(page.result, page.assessment["engines"]) == "COMPLETED"
    assert page.chain_table.item(0, 0).text() == "1"
    assert page.chain_table.item(0, 4).text() == "record-1"


def test_missing_malformed_and_partial_results_are_not_success(qt_app):
    empty = ProvenanceWorkspace(assessment(), None, None)
    assert provenance_status(empty.result, empty.assessment["engines"]) == "UNAVAILABLE"
    assert not empty.records
    assert any("C1 result is missing" in label.text() for label in empty.findChildren(QLabel))

    malformed = ProvenanceWorkspace(assessment(), {"status": "completed", "records": "bad-shape"}, [])
    assert provenance_status(malformed.result, malformed.assessment["engines"]) == "PARTIAL / INCOMPLETE"
    assert not malformed.records

    malformed_record = ProvenanceWorkspace(assessment(), {"status": "completed", "records": [None]}, [])
    assert provenance_status(malformed_record.result, malformed_record.assessment["engines"]) == "PARTIAL / INCOMPLETE"
    assert "Malformed record" in " ".join(cell.text() for table in malformed_record.findChildren(QTableWidget)
                                            for row in range(table.rowCount()) for cell in [table.item(row, 1)] if cell)


def test_engine_status_failed_warning_and_not_assessed(qt_app):
    assert provenance_status({"status": "completed"}, {"C1_provenance": {"status": "error"}}) == "FAILED"
    assert provenance_status({"status": "completed_with_warnings", "records": []},
                             {"C1_provenance": {"status": "completed_with_warnings"}}) == "COMPLETED WITH WARNINGS"
    assert provenance_status({"status": "not_assessed"}, {"C1_provenance": {"status": "not_assessed"}}) == "NOT ASSESSED"
    assert provenance_status({"status": "unavailable"}, {"C1_provenance": {"status": "completed"}}) == "UNAVAILABLE"
    assert provenance_status({"status": "unavailable"}, {"C1_provenance": {"status": "not_assessed"}}) == "NOT ASSESSED"
    failed = ProvenanceWorkspace(assessment("COMPLETED_WITH_WARNINGS", "error"), {"status": "error", "reason": "local verifier failed"}, [])
    assert any("FAILED" in label.text() for label in failed.findChildren(QLabel))


def test_chain_integrity_unsigned_signature_and_replay_unavailable(qt_app):
    page = ProvenanceWorkspace(assessment(), result(), [])
    labels = "\n".join(label.text() for label in page.findChildren(QLabel))
    assert "Chain verification: VERIFIED" in labels
    assert "Signature evidence: UNSIGNED" in labels
    assert "Replay detection: Unavailable" in labels
    assert "Replay detection evidence unavailable." in labels
    assert "unsigned status alone is not evidence of misuse" in labels

    signed_result = result()
    signed_result["records"][0]["signature"] = "signature-value"
    signed = ProvenanceWorkspace(assessment(), signed_result, [])
    signed_text = "\n".join(label.text() for label in signed.findChildren(QLabel))
    assert "PRESENT · VERIFICATION UNAVAILABLE" in signed_text


def test_record_detail_shows_recorded_bindings_and_full_hashes(qt_app):
    item = record(signature="signed-value")
    dialog = ProvenanceRecordDialog(item, 0, "VALIDATED", [])
    values = " ".join(label.text() for label in dialog.findChildren(QLabel))
    assert "Link evidence: VALIDATED" in values
    assert any("preprocessing-1" in table.item(row, 1).text()
               for table in dialog.findChildren(QTableWidget) for row in range(table.rowCount())
               if table.item(row, 1))
    assert any("signed-value" in table.item(row, 1).text()
               for table in dialog.findChildren(QTableWidget) for row in range(table.rowCount())
               if table.item(row, 1))


def test_provenance_finding_filter_sort_and_investigation(qt_app, monkeypatch):
    opened = []
    monkeypatch.setattr(QDialog, "exec", lambda self: opened.append(self) or 0)
    page = ProvenanceWorkspace(assessment(), result(), provenance_findings())
    page.finding_search.setEditText("broken chain")
    page.apply_finding_filters()
    assert not page.finding_table.isRowHidden(0)
    page.finding_search.setEditText("no match")
    page.apply_finding_filters()
    assert page.finding_table.isRowHidden(0)
    page.finding_search.setEditText("")
    page.open_finding_row(0, 0)
    finding = next(dialog for dialog in opened if isinstance(dialog, ProvenanceFindingDialog))
    assert finding.finding["finding_id"] == "C3-prov-1"
    finding.evidence_button.click()
    viewer = next(dialog for dialog in opened if isinstance(dialog, EvidenceViewerDialog))
    assert viewer.technical.isHidden() and viewer.raw_section.isHidden() and viewer.json_view.isHidden()
    viewer.show_technical(); viewer.show_raw(); viewer.show_json()
    assert not viewer.technical.isHidden() and not viewer.raw_section.isHidden() and not viewer.json_view.isHidden()


def test_record_selection_opens_detail_and_viewer_is_progressive(qt_app, monkeypatch):
    opened = []
    monkeypatch.setattr(QDialog, "exec", lambda self: opened.append(self) or 0)
    page = ProvenanceWorkspace(assessment(), result(), [])
    page.open_record_row(0, 0)
    detail = next(dialog for dialog in opened if isinstance(dialog, ProvenanceRecordDialog))
    button = next(button for button in detail.findChildren(__import__("PySide6.QtWidgets", fromlist=["QPushButton"]).QPushButton)
                  if button.text() == "Technical Details")
    button.click()
    viewer = next(dialog for dialog in opened if isinstance(dialog, EvidenceViewerDialog))
    assert viewer.technical.isHidden() and viewer.raw_section.isHidden() and viewer.json_view.isHidden()


def test_opening_workspace_does_not_call_c1_engine(qt_app, monkeypatch):
    import backend.engines.provenance.inference_provenance as engine
    def forbidden(*_args, **_kwargs):
        raise AssertionError("C1 must not be rerun when opening the workspace")
    for name in ("create_inference_record", "verify_chain", "detect_replay"):
        monkeypatch.setattr(engine, name, forbidden)
    page = ProvenanceWorkspace(assessment(), result(), provenance_findings())
    assert page.chain_table.rowCount() == 2
