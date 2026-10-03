import hashlib
import json
import os
import socket
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtPdf import QPdfDocument
from PySide6.QtWidgets import QApplication, QDialog, QLabel, QTableWidget

from desktop.pages.report_workspace import ReportWorkspace, c5_state, digest_state, report_findings
from desktop.reporting.report_pdf import section_content
from desktop.widgets.components import EvidenceViewerDialog


@pytest.fixture(scope="module")
def qt_app():
    return QApplication.instance() or QApplication([])


def assessment(status="completed"):
    return {
        "assessment_id": "TRACER-REPORT-TEST",
        "name": "Local report test",
        "status": status,
        "created_at": "2026-01-01T00:00:00+00:00",
        "completed_at": "2026-01-01T00:03:00+00:00",
        "dataset": {"path": "/local/datasets/small-set"},
        "model": {"path": "/local/models/classifier.ts"},
        "engines": {
            "A1_manifest": {"status": "completed", "evidence": {"sha256": "a" * 64}},
            "B3_model_statistics": {"status": "error", "reason": "Activation hooks unavailable"},
            "C1_provenance": {"status": "completed"},
            "C5_assurance_report": {"status": "completed"},
        },
    }


def report():
    return {
        "assessment_id": "TRACER-REPORT-TEST",
        "report_version": "c5-1.0",
        "method": "evidence-oriented assurance report",
        "task": "assurance_reporting",
        "report_digest": "d" * 64,
        "executive_summary": {
            "assessment_scope": "Local computer vision assurance assessment",
            "finding_count": 1,
            "highest_observed_severity": "medium",
            "severity_counts": {"medium": 1},
            "provenance_chain_valid": True,
            "audit_chain_valid": None,
            "distribution_shift_detected": False,
            "interpretation": "Observed evidence is limited to the configured assessment methods.",
        },
        "asset_coverage": {
            "dataset_integrity": {"assessed": True, "status": "available"},
            "model_integrity": {"assessed": True, "status": "available"},
            "inference_provenance": {"assessed": True, "status": "available"},
            "distribution_shift": {"assessed": False, "status": "not_assessed"},
            "findings_and_evidence": {"assessed": True, "status": "available", "finding_count": 1},
            "audit_trail": {"assessed": False, "status": "not_assessed"},
        },
        "dataset_integrity": {"status": "assessed", "engine_result": {
            "A1_manifest": {"status": "completed", "file_count": 3, "dataset_sha256": "e" * 64},
            "A4_ood": {"status": "not_assessed", "reason": "Reference dataset unavailable"},
        }},
        "model_integrity": {"status": "assessed", "engine_result": {
            "B1_identity": {"status": "completed", "format": "TorchScript", "sha256": "f" * 64},
            "B3_model_statistics": {"status": "error", "reason": "TorchScript activation hooks unavailable", "limitations": ["Activation statistics were unavailable."]},
        }},
        "inference_provenance": {"status": "assessed", "valid": True, "engine_result": {"record_count": 2, "model_id": "sha256:abc", "valid": True}},
        "distribution_shift": {"status": "not_assessed", "shift_detected": None},
        "findings_and_evidence": {"count": 1, "findings": [{
            "finding_id": "C3-A2-001", "category": "duplicate_evidence", "severity": "medium", "confidence": 0.88,
            "affected_asset": "candidate dataset", "title": "Repeated file content",
            "explanation": "Two files have the same persisted SHA-256 digest.",
            "evidence": [{"sha256": "a" * 64, "files": ["one.png", "copy.png"]}],
            "recommended_action": "Review whether the repeated content is expected.",
            "limitations": ["Repeated content does not establish intent."], "source_engine": "A2",
        }]},
        "audit_trail": {"status": "not_assessed", "entry_count": 0, "valid": None},
        "recommended_actions": ["Review the recorded duplicate evidence."],
        "limitations": ["Distribution shift does not by itself establish malicious manipulation.",
                        "Absence of findings does not establish the absence of attacks."],
    }


def rendered_text(widget):
    values = [label.text() for label in widget.findChildren(QLabel)]
    for table in widget.findChildren(QTableWidget):
        for row in range(table.rowCount()):
            for column in range(table.columnCount()):
                item = table.item(row, column)
                if item:
                    values.append(item.text())
                child = table.cellWidget(row, column)
                if child and hasattr(child, "text"):
                    values.append(child.text())
    return "\n".join(values)


def persisted_files(tmp_path, payload=None):
    root = tmp_path / "assessment"; root.mkdir()
    c5 = root / "tracer_cv_assurance_report.json"
    c5.write_text(json.dumps(payload or report()), encoding="utf-8")
    text = root / "tracer_cv_assurance_report.txt"
    text.write_text("Persisted C5 text report\n", encoding="utf-8")
    assessment_file = root / "assessment.json"
    assessment_file.write_text(json.dumps(assessment()), encoding="utf-8")
    return root, c5, text, assessment_file


def test_report_module_import_and_workspace_construction(qt_app):
    page = ReportWorkspace(assessment(), report())
    text = rendered_text(page)
    assert "Report Center" in text
    assert "Executive Summary" in text
    assert "TRACER-REPORT-TEST" in text
    assert page.status == "COMPLETED"


def test_persisted_c5_report_loaded_without_rebuilding(tmp_path, qt_app):
    _, c5, text, _ = persisted_files(tmp_path)
    persisted = json.loads(c5.read_text())
    page = ReportWorkspace(assessment(), persisted, report_path=c5, text_report_path=text)
    assert page.report["report_digest"] == report()["report_digest"]
    assert page.export_text_button.isEnabled()


@pytest.mark.parametrize(("assessment_status", "expected"), [
    ("completed", "COMPLETED"),
    ("completed_with_warnings", "COMPLETED WITH WARNINGS"),
    ("completed_with_errors", "COMPLETED WITH WARNINGS"),
    ("failed", "FAILED"),
])
def test_assessment_status_mapping(qt_app, assessment_status, expected):
    assert c5_state(assessment(assessment_status), report())[0] == expected


def test_missing_report_state(qt_app):
    page = ReportWorkspace(assessment(), None)
    assert page.status == "UNAVAILABLE"
    assert "not available" in rendered_text(page).lower()
    assert not page.export_pdf_button.isEnabled()


def test_malformed_report_state(tmp_path, qt_app):
    path = tmp_path / "tracer_cv_assurance_report.json"; path.write_text("{invalid", encoding="utf-8")
    page = ReportWorkspace(assessment(), {"status": "unavailable", "message": "decode error"}, report_path=path)
    assert page.status == "MALFORMED"
    assert "could not be interpreted" in rendered_text(page)


def test_unrecognized_schema_and_invalid_digest(qt_app):
    invalid = {"unknown": "shape"}
    page = ReportWorkspace(assessment(), invalid)
    assert page.status == "MALFORMED"
    assert digest_state("not-a-digest").startswith("Invalid")
    page2 = ReportWorkspace(assessment(), {**report(), "report_digest": "bad"})
    assert any("expected SHA-256" in warning for warning in page2.load_warnings)


@pytest.mark.parametrize("section", ["dataset_integrity", "model_integrity", "inference_provenance", "distribution_shift", "audit_trail"])
def test_missing_individual_report_sections_are_explicit(qt_app, section):
    data = report(); del data[section]
    page = ReportWorkspace(assessment(), data)
    area = section.replace("_", " ").title()
    assert area in rendered_text(page)
    row = next(row for row in range(page.coverage_table.rowCount()) if page.coverage_table.item(row, 0).text() == area)
    assert page.coverage_table.item(row, 3).text() == "Section unavailable in C5 report"


def test_missing_findings_and_empty_findings(qt_app):
    missing = report(); del missing["findings_and_evidence"]
    assert "Findings section unavailable" in rendered_text(ReportWorkspace(assessment(), missing))
    empty = report(); empty["findings_and_evidence"] = {"count": 0, "findings": []}
    assert "No findings recorded" in rendered_text(ReportWorkspace(assessment(), empty))


def test_findings_render_severity_confidence_and_evidence(qt_app):
    page = ReportWorkspace(assessment(), report())
    text = rendered_text(page)
    assert "C3-A2-001" in text and "Repeated file content" in text
    assert "medium" in text.lower() and "0.88" in text
    assert "A2" in text and "candidate dataset" in text


def test_malformed_findings_are_omitted_and_reported(qt_app):
    data = report(); data["findings_and_evidence"]["findings"] = [None, {"finding_id": "partial"}]
    page = ReportWorkspace(assessment(), data)
    assert len(page.findings) == 1
    assert any("malformed" in item for item in page.load_warnings)
    assert "Unavailable" in rendered_text(page)


def test_coverage_engine_states_and_partial_b3_visible(qt_app):
    page = ReportWorkspace(assessment("completed_with_errors"), report())
    text = rendered_text(page)
    assert page.status == "COMPLETED WITH WARNINGS"
    assert "COMPLETED WITH ERRORS" in text
    assert "B3_model_statistics" in text
    assert "error" in text.lower()
    assert "Activation statistics were unavailable." in text or "activation hooks unavailable" in text.lower()


def test_recommendations_and_limitations_are_persisted(qt_app):
    text = rendered_text(ReportWorkspace(assessment(), report()))
    assert "Review the recorded duplicate evidence." in text
    assert "Distribution shift does not by itself establish malicious manipulation." in text
    assert "Absence of findings does not establish the absence of attacks." in text


def test_report_json_and_text_export_preserve_persisted_bytes(tmp_path, qt_app):
    _, c5, text_path, _ = persisted_files(tmp_path)
    page = ReportWorkspace(assessment(), report(), report_path=c5, text_report_path=text_path)
    json_out = page.export_json(tmp_path / "export.json")
    text_out = page.export_text(tmp_path / "export.txt")
    assert json_out.read_bytes() == c5.read_bytes()
    assert text_out.read_bytes() == text_path.read_bytes()


def test_export_cannot_overwrite_authoritative_c5_file(tmp_path, qt_app):
    _, c5, _, _ = persisted_files(tmp_path)
    page = ReportWorkspace(assessment(), report(), report_path=c5)
    before = hashlib.sha256(c5.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="authoritative"):
        page.export_json(c5)
    assert hashlib.sha256(c5.read_bytes()).hexdigest() == before


def test_pdf_export_validity_text_and_document_digest(tmp_path, qt_app):
    page = ReportWorkspace(assessment(), report())
    result = page.export_pdf(tmp_path / "assurance.pdf")
    path = Path(result["path"])
    assert path.is_file() and path.stat().st_size > 1000
    assert path.read_bytes().startswith(b"%PDF-")
    assert len(result["sha256"]) == 64
    assert hashlib.sha256(path.read_bytes()).hexdigest() == result["sha256"]
    document = QPdfDocument(None)
    assert document.load(str(path)) == QPdfDocument.Error.None_
    assert document.pageCount() > 0
    content = "\n".join(document.getAllText(index).text() for index in range(document.pageCount()))
    for text in ("TRACER-REPORT-TEST", "Executive Summary", "Dataset Integrity", "Model Integrity",
                 "Inference Provenance", "Distribution Shift", "Findings & Evidence", "Audit Trail",
                 "Recommended Actions", "Limitations & Coverage"):
        assert text in content


def test_pdf_escapes_untrusted_report_text(qt_app, tmp_path):
    data = report(); data["executive_summary"]["interpretation"] = "<script>not executed</script>"
    page = ReportWorkspace(assessment(), data)
    result = page.export_pdf(tmp_path / "escaped.pdf")
    doc = QPdfDocument(None); assert doc.load(result["path"]) == QPdfDocument.Error.None_
    text = "\n".join(doc.getAllText(i).text() for i in range(doc.pageCount()))
    assert "<script>not executed</script>" in text


def test_evidence_viewer_keeps_raw_json_secondary(qt_app, monkeypatch):
    opened = []
    monkeypatch.setattr(QDialog, "exec", lambda dialog: opened.append(dialog) or 0)
    page = ReportWorkspace(assessment(), report())
    page.open_json_viewer()
    viewer = next(dialog for dialog in opened if isinstance(dialog, EvidenceViewerDialog))
    assert viewer.technical.isHidden() and viewer.raw_section.isHidden() and viewer.json_view.isHidden()
    viewer.show_technical(); viewer.show_raw(); viewer.show_json()
    assert not viewer.json_view.isHidden()


def test_finding_investigation_and_findings_workspace_navigation(qt_app, monkeypatch):
    opened = []; routes = []; found = []
    monkeypatch.setattr(QDialog, "exec", lambda dialog: opened.append(dialog) or 0)
    page = ReportWorkspace(assessment(), report(), on_navigate=routes.append, on_open_finding=found.append)
    page.open_finding_row(0, 0)
    dialog = opened[-1]
    assert "C3-A2-001" in rendered_text(dialog)
    for button in dialog.findChildren(__import__("PySide6.QtWidgets", fromlist=["QPushButton"]).QPushButton):
        if button.text() == "Open in Findings workspace":
            button.click()
    assert found == ["C3-A2-001"]
    for button in page.findChildren(__import__("PySide6.QtWidgets", fromlist=["QPushButton"]).QPushButton):
        if button.text() == "Open Evidence Explorer":
            button.click(); break
    assert routes == ["evidence"]


def test_c5_sections_are_summarized_without_raw_json_primary(qt_app):
    page = ReportWorkspace(assessment(), report())
    text = rendered_text(page)
    assert "file count 3" in text
    assert "sha256" in text.lower()
    assert page.json_button.text() == "View C5 JSON (technical)"


def test_open_and_pdf_export_do_not_call_c5_or_other_engines(tmp_path, qt_app, monkeypatch):
    from importlib import import_module
    import backend.engines.risk.assurance_report as c5
    import backend.engines.provenance.inference_provenance as c1
    import backend.engines.provenance.audit_trail as c4
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Report Center/export must only read persisted results")
    engine_functions = {
        "backend.engines.dataset.manifest": ("build_manifest",),
        "backend.engines.dataset.duplicates": ("find_exact_duplicates",),
        "backend.engines.dataset.near_duplicates": ("find_near_duplicates",),
        "backend.engines.dataset.ood": ("assess_ood",),
        "backend.engines.dataset.label_consistency": ("assess_label_consistency",),
        "backend.engines.dataset.contributor_risk": ("assess_contributor_risk",),
        "backend.engines.dataset.metadata_consistency": ("assess_metadata_consistency",),
        "backend.engines.dataset.poison_trigger": ("analyze_poison_trigger",),
        "backend.engines.model.identity": ("inspect_model",),
        "backend.engines.model.behavioral_fingerprint": ("try_load_torchscript_adapter", "compute_behavioral_fingerprint"),
        "backend.engines.model.model_statistics": ("load_torchscript_model", "analyze_model"),
        "backend.engines.model.trigger_search": ("search_triggers",),
        "backend.engines.provenance.inference_provenance": ("verify_chain", "create_inference_record"),
        "backend.engines.shift.distribution_shift": ("analyze_distribution_shift", "analyze_image_directories"),
        "backend.engines.risk.findings": ("aggregate_findings", "findings_from_dataset", "findings_from_model", "findings_from_provenance", "findings_from_shift"),
        "backend.engines.provenance.audit_trail": ("verify_audit_chain", "append_audit_entry", "create_audit_entry"),
        "backend.engines.risk.assurance_report": ("build_assurance_report", "render_text_report"),
        "backend.core.assessment_runner": ("run_assessment",),
    }
    for module_name, names in engine_functions.items():
        module = import_module(module_name)
        for name in names:
            if hasattr(module, name):
                monkeypatch.setattr(module, name, forbidden)
    page = ReportWorkspace(assessment(), report())
    page.export_pdf(tmp_path / "no-engine.pdf")


def test_report_center_performs_no_network_calls(qt_app, tmp_path, monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Report Center must remain offline")
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    ReportWorkspace(assessment(), report()).export_pdf(tmp_path / "offline.pdf")


def test_authoritative_assessment_artifacts_unchanged_by_exports(tmp_path, qt_app):
    _, c5, text_path, assessment_path = persisted_files(tmp_path)
    findings_path = c5.parent / "findings.json"; findings_path.write_text('{"findings":[]}', encoding="utf-8")
    audit_path = c5.parent / "audit_chain.json"; audit_path.write_text('{"entries":[]}', encoding="utf-8")
    evidence_path = tmp_path / "evidence" / "object.json"; evidence_path.parent.mkdir(); evidence_path.write_text('{"persisted":true}', encoding="utf-8")
    authoritative = [c5, text_path, assessment_path, findings_path, audit_path, evidence_path]
    before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in authoritative}
    page = ReportWorkspace(assessment(), report(), report_path=c5, text_report_path=text_path, protected_paths=authoritative)
    page.export_pdf(tmp_path / "separate-export.pdf"); page.export_json(tmp_path / "separate-export.json"); page.export_text(tmp_path / "separate-export.txt")
    after = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in authoritative}
    assert before == after


def test_engine_rerun_is_not_needed_for_filter_free_report_inspection(qt_app):
    page = ReportWorkspace(assessment(), report())
    assert len(page.findings) == 1
    assert "C5 report digest" in rendered_text(page)


def test_text_export_unavailable_is_explicit(qt_app, tmp_path):
    page = ReportWorkspace(assessment(), report())
    with pytest.raises(FileNotFoundError, match="Persisted C5 text report"):
        page.export_text(tmp_path / "no-text.txt")


def test_section_model_preserves_unavailable_engine_states():
    sections = dict(section_content(report()))
    dataset = dict(sections["3. Dataset Integrity"])
    assert "A4_ood" in dataset
    assert "not_assessed" in dataset["A4_ood"]
    model = dict(sections["4. Model Integrity"])
    assert "B3_model_statistics" in model
    assert "error" in model["B3_model_statistics"]
