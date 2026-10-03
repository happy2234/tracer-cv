import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication, QDialog, QLabel, QTableWidget

from desktop.pages.audit_workspace import AuditEntryDialog, AuditFindingDialog, AuditWorkspace, audit_state
from desktop.widgets.components import EvidenceViewerDialog


@pytest.fixture(scope="module")
def qt_app():
    return QApplication.instance() or QApplication([])


def assessment(status="completed", c4_status="completed"):
    return {
        "assessment_id": "TRACER-C4-TEST",
        "name": "Local audit review",
        "status": status,
        "engines": {"C4_audit_trail": {"status": c4_status, "reason": None}},
    }


def entry(sequence=1, *, event_id=None, event_type="ENGINE_COMPLETED", source="A1_manifest", asset="dataset/root", when=None):
    return {
        "sequence": sequence,
        "event_id": event_id or f"event-{sequence}",
        "timestamp": when or f"2026-09-01T00:00:{sequence:02d}+00:00",
        "event_type": event_type,
        "source_engine": source,
        "affected_asset": asset,
        "payload_digest": f"payload-digest-{sequence}-" + "a" * 45,
        "previous_entry_hash": "0" * 64 if sequence == 1 else f"previous-{sequence}-" + "b" * 48,
        "entry_hash": f"entry-hash-{sequence}-" + "c" * 48,
    }


def result(status="completed", entries=None, valid=True, **extra):
    actual_entries = entries if entries is not None else [entry(1), entry(2, event_type="FINDING_CREATED", source="C3")]
    return {"status": status, "valid": valid, "entry_count": len(actual_entries), "entries": actual_entries,
            "evidence": {"sha256": "persisted-c4-result-digest"}, **extra}


def visible_rows(table):
    return [row for row in range(table.rowCount()) if not table.isRowHidden(row)]


def test_workspace_construction_and_persisted_c4_loading(qt_app):
    page = AuditWorkspace(assessment(), result())
    assert page.state == "COMPLETED"
    assert len(page.entries) == 2
    assert page.entry_table.rowCount() == 2
    assert "TRACER-C4-TEST" in "\n".join(label.text() for label in page.findChildren(QLabel))


def test_missing_malformed_completed_warning_and_failed_states(qt_app):
    missing = AuditWorkspace(assessment(), None)
    assert missing.state == "UNAVAILABLE"
    assert any("not available" in label.text().lower() for label in missing.findChildren(QLabel))
    malformed = AuditWorkspace(assessment(), {"status": "completed", "entries": "invalid"})
    assert malformed.state == "PARTIAL"
    malformed_entry = AuditWorkspace(assessment(), result(entries=[entry(), "not an entry"]))
    assert malformed_entry.state == "PARTIAL" and len(malformed_entry.entries) == 1
    warning = AuditWorkspace(assessment("completed_with_warnings", "completed_with_warnings"), result("completed_with_warnings"))
    assert warning.state == "COMPLETED WITH WARNINGS"
    failed = AuditWorkspace(assessment("completed_with_warnings", "error"), {"status": "error", "reason": "verification failed", "entries": []})
    assert failed.state == "FAILED"
    assert audit_state({"status": "not_assessed"}, {"C4_audit_trail": {"status": "not_assessed"}}) == "NOT ASSESSED"
    assert audit_state({"status": "unavailable"}, {"C4_audit_trail": {"status": "completed"}}) == "UNAVAILABLE"


def test_empty_audit_chain_is_not_a_pass(qt_app):
    page = AuditWorkspace(assessment(), result(entries=[], valid=True))
    labels = "\n".join(label.text() for label in page.findChildren(QLabel)).lower()
    assert page.entry_table.rowCount() == 0
    assert "no persisted audit entries" in labels
    assert "does not establish" in labels


def test_timeline_integrity_and_entry_details(qt_app, monkeypatch):
    opened = []
    monkeypatch.setattr(QDialog, "exec", lambda self: opened.append(self) or 0)
    issue = {"type": "broken_chain", "sequence": 2, "event_id": "event-2", "message": "Previous-entry hash mismatch."}
    stored = result(valid=False, verification={"valid": False, "findings": [issue]})
    page = AuditWorkspace(assessment(), stored)
    assert page.entry_table.item(1, 6).text() == "Issue identified"
    assert "INCONSISTENCY REPORTED" in "\n".join(label.text() for label in page.findChildren(QLabel))
    page.open_entry_row(1, 0)
    dialog = next(item for item in opened if isinstance(item, AuditEntryDialog))
    labels = "\n".join(label.text() for label in dialog.findChildren(QLabel))
    detail_tables = dialog.findChildren(QTableWidget)
    assert "event-2" in labels
    assert any("Previous-entry hash mismatch" in (table.item(row, 1).text() if table.item(row, 1) else "")
               for table in detail_tables for row in range(table.rowCount()))
    from desktop.pages.audit_workspace import HashValue
    full_hash = dialog.findChild(HashValue)
    assert "…" in full_hash.label.text()
    full_hash.button.click()
    assert "…" not in full_hash.label.text()


def test_integrity_issue_types_are_only_shown_when_persisted(qt_app):
    issue_types = ["entry_tampering", "broken_chain", "sequence_discontinuity", "duplicate_sequence", "event_id_reuse"]
    issues = [{"type": kind, "sequence": 3, "message": f"Persisted {kind}"} for kind in issue_types]
    page = AuditWorkspace(assessment(), result(entries=[entry(3)], valid=False, verification={"valid": False, "findings": issues}))
    text = "\n".join(page.entry_table.item(0, col).text() for col in range(page.entry_table.columnCount()))
    assert "Issue identified" in text
    rows = page.findChildren(QTableWidget)
    check_table = next(table for table in rows if table.columnCount() == 3)
    assert check_table.rowCount() == len(issue_types)
    assert all(check_table.item(row, 1).text().startswith("Reported") for row in range(check_table.rowCount()))
    valid_page = AuditWorkspace(assessment(), result(valid=True))
    assert all("No issue reported" in valid_page.findChildren(QTableWidget)[0].item(row, 1).text()
               for row in range(5))
    missing_fields = AuditWorkspace(assessment(), result(entries=[{"event_type": "UNSPECIFIED"}], valid=False,
        verification={"valid": False, "findings": [{"type": "broken_chain", "message": "Sequence 4 linkage mismatch."}]}))
    assert missing_fields.entry_table.item(0, 6).text() == "Not individually identified"


def test_event_type_source_asset_search_sort_and_clear(qt_app):
    entries = [entry(1, event_type="ENGINE_STARTED", source="A1_manifest", asset="dataset/one", when="2026-01-01T00:00:00Z"),
               entry(2, event_type="FINDING_CREATED", source="C3", asset="model/file", when="2026-01-03T00:00:00Z"),
               entry(3, event_type="ENGINE_COMPLETED", source="C4", asset="dataset/two", when="2026-01-02T00:00:00Z")]
    page = AuditWorkspace(assessment(), result(entries=entries))
    assert page.entry_table.item(0, 0).text() == "1"
    page.type_filter.setCurrentText("FINDING_CREATED"); assert len(visible_rows(page.entry_table)) == 1
    page.type_filter.setCurrentIndex(0); page.source_filter.setCurrentText("C4"); assert len(visible_rows(page.entry_table)) == 1
    page.source_filter.setCurrentIndex(0); page.asset_filter.setCurrentText("dataset/one"); assert len(visible_rows(page.entry_table)) == 1
    page.asset_filter.setCurrentIndex(0); page.search.setEditText("event-2"); assert len(visible_rows(page.entry_table)) == 1
    page.clear_filters(); page.sort_by.setCurrentText("Timestamp"); page.sort_order.setCurrentText("Descending")
    assert page.entry_table.item(0, 0).text() == "2"
    page.sort_by.setCurrentText("Event type"); page.sort_order.setCurrentText("Ascending")
    assert page.entry_table.item(0, 2).text() == "ENGINE_COMPLETED"
    page.clear_filters(); assert len(visible_rows(page.entry_table)) == 3


def test_integrity_filter_and_adjacent_navigation(qt_app, monkeypatch):
    opened = []
    monkeypatch.setattr(QDialog, "exec", lambda self: opened.append(self) or 0)
    entries = [entry(1), entry(2), entry(3)]
    stored = result(valid=False, entries=entries, verification={"valid": False, "findings": [{"type": "sequence_discontinuity", "sequence": 2, "message": "Gap"}]})
    page = AuditWorkspace(assessment(), stored)
    page.integrity_filter.setCurrentText("Issue identified")
    assert len(visible_rows(page.entry_table)) == 1
    page.integrity_filter.setCurrentIndex(0); page.open_entry_row(1, 0)
    dialog = next(item for item in opened if isinstance(item, AuditEntryDialog))
    assert dialog.previous_button.isEnabled()  # sequence 2 has a displayed predecessor
    dialog.next_button.click()
    assert dialog.entry["sequence"] == 3


def test_c3_audit_findings_and_investigation(qt_app, monkeypatch):
    opened = []
    monkeypatch.setattr(QDialog, "exec", lambda self: opened.append(self) or 0)
    audit_finding = {"finding_id": "C3-audit-1", "category": "audit_integrity", "source_engine": "C4", "severity": "high", "confidence": .8,
                     "title": "Audit chain inconsistency", "explanation": "Stored C4 verification reported an inconsistency.",
                     "affected_asset": "assessment", "evidence": [{"sequence": 2, "message": "Hash link mismatch"}],
                     "recommended_action": "Review the recorded audit evidence.", "limitations": ["Cause and intent are not established."]}
    page = AuditWorkspace(assessment(), result(), [audit_finding, {"source_engine": "C2", "category": "distribution_shift"}])
    assert page.finding_table.rowCount() == 1
    page.open_finding_row(0, 0)
    dialog = next(item for item in opened if isinstance(item, AuditFindingDialog))
    labels = "\n".join(label.text() for label in dialog.findChildren(QLabel))
    assert "Cause and intent are not established" in labels
    assert "Confidence: 0.8" in labels
    dialog.source_button.click()


def test_evidence_viewer_progressive_disclosure(qt_app, monkeypatch):
    opened = []
    monkeypatch.setattr(QDialog, "exec", lambda self: opened.append(self) or 0)
    page = AuditWorkspace(assessment(), result())
    page.open_entry_row(0, 0)
    detail = next(item for item in opened if isinstance(item, AuditEntryDialog))
    detail.evidence_button.click()
    viewer = next(item for item in opened if isinstance(item, EvidenceViewerDialog))
    assert viewer.technical.isHidden() and viewer.raw_section.isHidden() and viewer.json_view.isHidden()
    viewer.show_technical(); viewer.show_raw(); viewer.show_json()
    assert not viewer.json_view.isHidden()
    page.technical_button.click()
    assert sum(isinstance(item, EvidenceViewerDialog) for item in opened) == 2


def test_source_traceability_and_c4_is_read_only(qt_app, monkeypatch):
    import backend.engines.provenance.audit_trail as c4
    opened = []
    monkeypatch.setattr(QDialog, "exec", lambda self: opened.append(self) or 0)
    def forbidden(*_args, **_kwargs):
        raise AssertionError("C4 must not run when the audit workspace opens")
    for name in ("create_audit_entry", "append_audit_entry", "verify_audit_chain"):
        monkeypatch.setattr(c4, name, forbidden)
    routes = []
    page = AuditWorkspace(assessment(), result(), on_navigate=routes.append)
    page.open_entry_row(0, 0)
    dialog = next(item for item in opened if isinstance(item, AuditEntryDialog))
    assert dialog.source_button.text() == "Open Dataset Integrity"
    dialog.open_source("A1_manifest")
    assert routes == [1]
    c4_finding = {"finding_id": "audit", "source_engine": "C4", "category": "audit_trail"}
    assert len(AuditWorkspace._audit_findings([c4_finding])) == 1
