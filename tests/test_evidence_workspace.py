import json
import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication, QDialog, QLabel

from desktop.pages.evidence_workspace import (
    ENGINE_ROUTES,
    EvidenceDetailDialog,
    EvidenceWorkspace,
    load_engine_evidence,
)
from desktop.widgets.components import EvidenceViewerDialog


@pytest.fixture(scope="module")
def qt_app():
    return QApplication.instance() or QApplication([])


def assessment(engines=None, *, dataset_path=None):
    return {
        "assessment_id": "TRACER-EVIDENCE-TEST",
        "name": "Local evidence review",
        "status": "completed",
        "dataset": {"path": str(dataset_path)} if dataset_path else {},
        "engines": engines or {},
    }


def engine_payload(engine_id, data, digest=None, *, storage_uri=None, result_path=None, status="completed"):
    record = {"status": status}
    if result_path:
        record["result_path"] = str(result_path)
    if digest:
        record["evidence"] = {"sha256": digest, "uri": str(storage_uri or "")}
    return {"record": record, "data": data, "storage_status": "Loaded persisted test record"}


def persisted_findings():
    return [
        {
            "finding_id": "C3-A2-001", "category": "dataset_integrity", "severity": "medium", "confidence": 0.9,
            "affected_asset": "candidate dataset", "title": "Exact duplicate group",
            "explanation": "Two files share identical persisted SHA-256 values.",
            "recommended_action": "Review whether duplication is expected.", "limitations": ["Duplicates may be legitimate."],
            "source_engine": "A2", "evidence": [{"type": "duplicate group", "sha256": "d" * 64, "groups": [{"files": ["candidate/image.jpg"], "sha256": "d" * 64}]}],
        },
        {
            "finding_id": "C3-C2-002", "category": "distribution_shift", "severity": "high", "confidence": 0.84,
            "affected_asset": "candidate population", "title": "Brightness difference",
            "explanation": "Brightness differs from the reference population.", "source_engine": "C2",
            "evidence": [{"type": "shifted feature", "feature": "brightness", "distance": 0.3}],
        },
    ]


def records(dataset_path=None):
    return {
        "A2_exact_duplicates": engine_payload("A2_exact_duplicates", {
            "status": "completed", "duplicate_group_count": 1,
            "groups": [{"sha256": "a" * 64, "files": ["candidate/image.jpg", "candidate/copy.jpg"]}],
            "limitations": ["Duplicate content does not establish intent."],
        }, "1" * 64, storage_uri="/local/evidence/objects/11/result.json"),
        "C1_provenance": engine_payload("C1_provenance", {
            "status": "completed", "records": [{"sequence": 1, "model_id": "model-sha", "input_digest": "input-sha", "preprocessing_digest": "prep-sha", "output_digest": "output-sha", "record_hash": "2" * 64, "timestamp": "2026-01-01T00:00:00+00:00"}],
            "limitations": ["Record relationship is cryptographic, not semantic."],
        }),
        "C4_audit_trail": engine_payload("C4_audit_trail", {
            "status": "completed", "valid": True, "entries": [{"sequence": 1, "event_id": "evt-1", "event_type": "ENGINE_COMPLETED", "source_engine": "A2", "affected_asset": "candidate dataset", "timestamp": "2026-01-01T00:00:02+00:00", "entry_hash": "3" * 64}],
        }),
    }


def visible_rows(table):
    return [row for row in range(table.rowCount()) if not table.isRowHidden(row)]


def test_workspace_construction_and_persisted_assessment_evidence(qt_app, tmp_path):
    page = EvidenceWorkspace(assessment(records(), dataset_path=tmp_path), records(), persisted_findings())
    assert page.assessment["assessment_id"] == "TRACER-EVIDENCE-TEST"
    assert len(page.items) == 7  # 3 engine snapshots + 2 C3 evidence + C1 record + C4 entry
    assert page.table.rowCount() == 7
    assert page.result_count.text() == "Showing 7 of 7 persisted evidence items"
    audit_record = next(item for item in page.items if item.get("producer") == "C4_audit_trail" and item.get("raw_data", {}).get("event_id") == "evt-1")
    assert audit_record["source_engine"] == "A2" and audit_record["producer"] == "C4_audit_trail"
    assert "Evidence items" in " ".join(label.text() for label in page.findChildren(QLabel))


def test_persisted_engine_blob_loader_and_safe_result_fallback(qt_app, tmp_path, monkeypatch):
    reports = tmp_path / "reports"; assessment_root = reports / "assessments" / "LOCAL-ID"
    evidence_root = tmp_path / "evidence" / "objects"
    assessment_root.mkdir(parents=True); (evidence_root / "aa").mkdir(parents=True)
    blob = evidence_root / "aa" / "aa.json"; blob.write_text(json.dumps({"status": "completed", "summary": "from evidence object"}), encoding="utf-8")
    fallback = assessment_root / "A2.json"; fallback.write_text(json.dumps({"status": "completed", "summary": "from report result"}), encoding="utf-8")
    selected = assessment({
        "A1_manifest": {"status": "completed", "evidence": {"sha256": "aa", "uri": str(blob)}, "result_path": str(assessment_root / "missing.json")},
        "A2_exact_duplicates": {"status": "completed", "evidence": {"sha256": "bad", "uri": str(tmp_path / "outside.json")}, "result_path": str(fallback)},
    })
    selected["assessment_id"] = "LOCAL-ID"
    loaded = load_engine_evidence(selected, reports, tmp_path / "evidence")
    assert loaded["A1_manifest"]["data"]["summary"] == "from evidence object"
    assert loaded["A2_exact_duplicates"]["data"]["summary"] == "from report result"
    assert "unavailable" in loaded["A2_exact_duplicates"]["storage_status"].lower()
    assert loaded["A2_exact_duplicates"].get("error")


def test_missing_evidence_and_empty_state(qt_app):
    no_assessment = EvidenceWorkspace(None, {})
    assert not no_assessment.items
    assert any("No assessment selected" in label.text() for label in no_assessment.findChildren(QLabel))
    empty = EvidenceWorkspace(assessment(), {})
    assert not empty.items
    assert any("No persisted evidence is available" in label.text() for label in empty.findChildren(QLabel))


def test_malformed_and_partial_evidence_continue_rendering(qt_app):
    data = records()
    data["A2_exact_duplicates"] = {"record": {}, "data": ["malformed shape"], "error": "bad result"}
    data["C1_provenance"]["data"]["records"].append(None)
    page = EvidenceWorkspace(assessment(), data, [None, *persisted_findings()])
    assert page.items
    assert page.load_errors
    assert any("Some persisted evidence could not be interpreted" in label.text() for label in page.findChildren(QLabel))


def test_dynamic_source_category_asset_finding_severity_and_confidence_filters(qt_app):
    page = EvidenceWorkspace(assessment(), records(), persisted_findings())
    assert "A2" in [page.source_filter.itemText(i) for i in range(page.source_filter.count())]
    assert "duplicate group" in [page.category_filter.itemText(i) for i in range(page.category_filter.count())]
    assert "candidate dataset" in [page.asset_filter.itemText(i) for i in range(page.asset_filter.count())]
    page.source_filter.setCurrentText("A2"); assert len(visible_rows(page.table)) == 3
    page.source_filter.setCurrentIndex(0); page.category_filter.setCurrentText("shifted feature"); assert len(visible_rows(page.table)) == 1
    page.category_filter.setCurrentIndex(0); page.asset_filter.setCurrentText("candidate population"); assert len(visible_rows(page.table)) == 1
    page.asset_filter.setCurrentIndex(0); page.finding_filter.setCurrentText("Linked"); assert len(visible_rows(page.table)) == 2
    page.finding_filter.setCurrentIndex(0); page.severity_filter.setCurrentText("high"); assert len(visible_rows(page.table)) == 1
    page.severity_filter.setCurrentIndex(0); page.confidence_filter.setCurrentText("0.84"); assert len(visible_rows(page.table)) == 1
    page.clear_filters(); assert len(visible_rows(page.table)) == len(page.items)


def test_search_nested_evidence_digest_and_asset_path(qt_app):
    page = EvidenceWorkspace(assessment(), records(), persisted_findings())
    page.search.setEditText("input-sha"); assert len(visible_rows(page.table)) == 2
    page.search.setEditText("brightness"); assert len(visible_rows(page.table)) == 1
    page.search.setEditText("candidate/image.jpg"); assert len(visible_rows(page.table)) == 2
    page.clear_filters()
    item = next(item for item in page.items if item.get("finding_id") == "C3-A2-001")
    assert item["digest"] == "d" * 64
    assert item["sample_refs"] == ["candidate/image.jpg"]


def test_sorting_and_grouping_is_stable_and_display_only(qt_app):
    page = EvidenceWorkspace(assessment(), records(), persisted_findings())
    page.sort_by.setCurrentText("Source engine")
    first_sources = [page.items[page.table.item(row, 0).data(256)]["source_engine"] for row in range(page.table.rowCount())]
    assert first_sources == sorted(first_sources, key=str.casefold)
    page.group_by.setCurrentText("Category")
    grouped_categories = [page.items[page.table.item(row, 0).data(256)]["category"] for row in range(page.table.rowCount())]
    assert grouped_categories == sorted(grouped_categories, key=str.casefold)
    assert len(page.items) == 7


def test_detail_relationships_digest_limitations_and_navigation(qt_app, monkeypatch):
    opened = []
    monkeypatch.setattr(QDialog, "exec", lambda self: opened.append(self) or 0)
    routes, finding_routes = [], []
    page = EvidenceWorkspace(assessment(), records(), persisted_findings(), on_navigate=routes.append, on_open_finding=finding_routes.append)
    row = next(row for row in range(page.table.rowCount()) if page.table.item(row, 4).text() == "C3-A2-001")
    page.open_detail_row(row, 0)
    dialog = next(item for item in opened if isinstance(item, EvidenceDetailDialog))
    labels = "\n".join(label.text() for label in dialog.findChildren(QLabel))
    assert "C3-A2-001" in labels and "candidate dataset" in labels
    assert "Confidence in finding evidence: 0.9" in labels
    assert "Recommended action: Review whether duplication is expected." in labels
    assert "Duplicates may be legitimate" in labels
    digest_widget = dialog.findChild(__import__("desktop.pages.evidence_workspace", fromlist=["DigestValue"]).DigestValue)
    assert digest_widget is not None and "…" in digest_widget.value_label.text()
    digest_widget.full_button.click(); assert "…" not in digest_widget.value_label.text()
    dialog.open_source(ENGINE_ROUTES["A2"]); assert routes == [1]
    dialog.open_finding("C3-A2-001"); assert finding_routes == ["C3-A2-001"]


def test_sample_inspection_is_on_demand_and_missing_path_is_explicit(qt_app, tmp_path, monkeypatch):
    from PIL import Image
    opened = []
    monkeypatch.setattr(QDialog, "exec", lambda self: opened.append(self) or 0)
    image_path = tmp_path / "candidate" / "sample.png"; image_path.parent.mkdir(); Image.new("RGB", (4, 3), "blue").save(image_path)
    data = {"A2_exact_duplicates": engine_payload("A2", {"groups": [{"files": ["candidate/sample.png"]}]})}
    page = EvidenceWorkspace(assessment(dataset_path=tmp_path), data)
    item = page.items[0]
    assert item["sample_refs"] == ["candidate/sample.png"]
    page.open_detail_row(0, 0)
    dialog = next(entry for entry in opened if isinstance(entry, EvidenceDetailDialog))
    assert dialog.inspect_button.isEnabled()
    dialog.sample_table.selectRow(0); dialog.inspect_button.click()
    assert len(opened) == 2
    missing = EvidenceWorkspace(assessment(dataset_path=tmp_path), {"A2": engine_payload("A2", {"path": "missing.png"})})
    missing.open_detail_row(0, 0)
    missing_dialog = next(entry for entry in opened if isinstance(entry, EvidenceDetailDialog) and entry is not dialog)
    assert not missing_dialog.inspect_button.isEnabled()
    assert any("Sample inspection unavailable" in (missing_dialog.sample_table.item(0, 1).text() or "") for _ in [0])


def test_evidence_viewer_keeps_raw_json_secondary(qt_app, monkeypatch):
    opened = []
    monkeypatch.setattr(QDialog, "exec", lambda self: opened.append(self) or 0)
    page = EvidenceWorkspace(assessment(), records(), persisted_findings())
    page.open_detail_row(0, 0)
    detail = next(item for item in opened if isinstance(item, EvidenceDetailDialog))
    detail.viewer_button.click()
    viewer = next(item for item in opened if isinstance(item, EvidenceViewerDialog))
    assert viewer.technical.isHidden() and viewer.raw_section.isHidden() and viewer.json_view.isHidden()
    viewer.show_technical(); viewer.show_raw(); viewer.show_json()
    assert not viewer.json_view.isHidden()


def test_engine_routes_and_no_engine_reruns_on_open_filter_and_detail(qt_app, monkeypatch):
    opened = []
    monkeypatch.setattr(QDialog, "exec", lambda self: opened.append(self) or 0)
    import backend.engines.risk.findings as c3
    import backend.engines.provenance.inference_provenance as c1
    import backend.engines.provenance.audit_trail as c4
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Evidence browsing must not rerun assessment engines")
    for module, names in ((c3, ("findings_from_dataset", "findings_from_model", "findings_from_provenance", "findings_from_shift", "aggregate_findings")),
                          (c1, ("create_record", "verify_record", "verify_chain", "detect_replay", "create_inference_record")),
                          (c4, ("create_audit_entry", "append_audit_entry", "verify_audit_chain"))):
        for name in names:
            if hasattr(module, name): monkeypatch.setattr(module, name, forbidden)
    page = EvidenceWorkspace(assessment(), records(), persisted_findings())
    page.search.setEditText("C3-A2"); page.clear_filters(); page.open_detail_row(0, 0)
    assert len(ENGINE_ROUTES) == 17
