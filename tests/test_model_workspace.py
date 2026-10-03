import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication, QDialog, QLabel, QTableWidget

from desktop.pages.model_workspace import (
    ENGINE_SPECS,
    ModelEngineDialog,
    ModelFindingDialog,
    ModelIntegrityWorkspace,
    engine_finding_count,
    engine_severity,
    model_engine_status,
    sort_engine_rows,
)
from desktop.widgets.components import EvidenceViewerDialog


@pytest.fixture(scope="module")
def qt_app():
    return QApplication.instance() or QApplication([])


def assessment(status="COMPLETED"):
    return {
        "assessment_id": "TRACER-MODEL-TEST",
        "name": "Persisted model review",
        "status": status,
        "model": {"path": "/local/models/model.torchscript", "sha256": "abc"},
        "compute": {"device": "cpu"},
        "engines": {key: {"status": "completed"} for key, _, _ in ENGINE_SPECS},
    }


def results():
    return {
        "B1_identity": {"status": "completed", "model_id": "sha256:abc", "sha256": "abc", "file_name": "model.torchscript",
                        "format": "TorchScript", "format_confidence": "extension_inferred", "file_size_bytes": 123,
                        "verification": {"requested": False, "match": None}, "content_signature": {"detected": "zip_container"},
                        "limitations": ["SHA-256 establishes byte identity only."]},
        "B2_behavioral_fingerprint": {"status": "completed", "probe_count": 2,
                                      "model": {"adapter": "local adapter", "class_count": 2, "probabilities_available": True},
                                      "dataset": {"image_shape": [32, 32, 3]},
                                      "fingerprint": {"digest": "fingerprint", "dataset_digest": "dataset"},
                                      "probes": [{"probe": "clean", "transform": "identity", "images": 2,
                                                  "prediction_agreement": 1.0, "mean_confidence": 0.8,
                                                  "mean_entropy": 0.2, "prediction_distribution": {"0": 2}},
                                                 {"probe": "flip", "transform": "horizontal_flip", "images": 2,
                                                  "prediction_agreement": 0.5, "mean_confidence": 0.7,
                                                  "mean_entropy": 0.3, "prediction_distribution": {"1": 1, "0": 1}}],
                                      "limitations": ["Behavioral differences may have legitimate causes."]},
        "B3_model_statistics": {"status": "completed", "model": {"access": "white_box", "model_type": "ScriptModule"},
                                "parameters": {"status": "completed", "totals": {"total_parameter_count": 8,
                                               "trainable_parameter_count": 8, "non_trainable_parameter_count": 0,
                                               "parameter_tensor_count": 2},
                                               "tensors": [{"name": "layer.weight", "kind": "parameter", "num_elements": 8,
                                                            "statistics": {"mean": 0.2, "std": 0.1, "min": 0.0, "max": 0.4,
                                                                           "nan_count": 0, "posinf_count": 0, "neginf_count": 0}}]},
                                "structure": {"status": "available", "module_count": 1},
                                "activations": {"status": "error", "reason": "Forward hooks unsupported for this representation.", "layers": []},
                                "limitations": ["Statistics do not establish malicious modification."]},
        "B4_trigger_search": {"status": "completed", "candidate_trigger_count": 1,
                              "assessment": {"status": "candidate_trigger_like_behavior", "interpretation": "Candidate evidence requires review."},
                              "search": {"images_assessed": 3, "images_requested": 3,
                                         "configuration": {"patch_sizes": [8], "grid_fractions": [0.5], "patterns": ["white"]}},
                              "candidate_evidence": [{"candidate": {"patch_size": 8, "x_fraction": 0.5, "y_fraction": 0.5, "pattern": "white"},
                                                      "target_class": 1, "class_change_rate": 1.0,
                                                      "mean_confidence_gain": 0.12, "mean_probability_l1_change": 0.6,
                                                      "candidate_trigger_like": True}],
                              "limitations": ["Candidate trigger-like evidence does not prove a backdoor."]},
    }


def model_findings():
    return [{"finding_id": "C3-b4", "source_engine": "B4", "category": "model_integrity", "severity": "HIGH",
             "confidence": 0.9, "title": "Candidate trigger-like behavior", "affected_asset": "model.torchscript",
             "explanation": "A localized perturbation repeatedly changed predictions.",
             "evidence": [{"type": "class_change_rate", "value": 1.0}, {"type": "trigger_location", "value": {"x": 0.5, "y": 0.5}}],
             "limitations": ["Does not prove a backdoor."]}]


def test_model_workspace_loads_persisted_results_and_b1_identity(qt_app):
    page = ModelIntegrityWorkspace(assessment(), results(), model_findings())
    assert [row["spec"][0] for row in page.engine_rows] == [spec[0] for spec in ENGINE_SPECS]
    assert page.results["B1_identity"]["model_id"] == "sha256:abc"
    assert page.results["B1_identity"]["file_size_bytes"] == 123
    assert page.engine_rows[3]["finding_count"] == 1
    assert page.engine_rows[3]["severity"] == "HIGH"


def test_status_counts_severity_and_sorting():
    assert model_engine_status("B2_behavioral_fingerprint", {"status": "not_assessed"}, {}) == "NOT ASSESSED"
    assert model_engine_status("B3_model_statistics", {}, {"B3_model_statistics": {"status": "completed"}}) == "UNAVAILABLE"
    assert engine_finding_count("B4_trigger_search", model_findings(), True) == 1
    assert engine_severity("B4_trigger_search", {}, model_findings()) == "HIGH"
    rows = [{"spec": ("B1", "B1", "Identity"), "status": "COMPLETED", "severity": "NONE REPORTED", "finding_count": 0},
            {"spec": ("B4", "B4", "Trigger"), "status": "COMPLETED", "severity": "HIGH", "finding_count": 1}]
    assert sort_engine_rows(rows, "Severity", True)[0]["spec"][1] == "B4"
    assert sort_engine_rows(rows, "Finding count", True)[0]["finding_count"] == 1


def test_b2_probe_comparison_and_b3_metric_availability(qt_app):
    data = results()
    b2 = ModelEngineDialog(ENGINE_SPECS[1], data["B2_behavioral_fingerprint"], {"status": "completed"}, [], None)
    assert "no compatible reference fingerprint" in " ".join(x.text() for x in b2.findChildren(QLabel)).lower()
    assert any("flip" in " ".join(table.item(row, col).text() for row in range(table.rowCount())
                                       for col in range(table.columnCount()) if table.item(row, col)).lower()
               for table in b2.findChildren(QTableWidget))
    from desktop.widgets.components import MetricBarChart
    assert b2.findChildren(MetricBarChart)
    b3 = ModelEngineDialog(ENGINE_SPECS[2], data["B3_model_statistics"], {"status": "completed"}, [], None)
    labels = " ".join(x.text() for x in b3.findChildren(QLabel))
    assert "Activation statistics unavailable" in labels
    assert "do not establish malicious modification" in labels


def test_b4_candidate_wording_is_limited(qt_app):
    dialog = ModelEngineDialog(ENGINE_SPECS[3], results()["B4_trigger_search"], {"status": "completed"}, model_findings())
    text = " ".join(label.text() for label in dialog.findChildren(QLabel)).lower()
    assert "candidate trigger-like" in text
    assert "does not prove a backdoor" in text
    assert any("white" in " ".join(table.item(row, col).text() for row in range(table.rowCount())
                                     for col in range(table.columnCount()) if table.item(row, col)).lower()
               for table in dialog.findChildren(QTableWidget))


def test_finding_investigation_and_progressive_evidence(qt_app, monkeypatch):
    import desktop.pages.model_workspace as workspace_module
    opened = []
    def nonblocking_exec(dialog):
        opened.append(dialog)
        return 0
    monkeypatch.setattr(QDialog, "exec", nonblocking_exec)
    page = ModelIntegrityWorkspace(assessment(), results(), model_findings())
    page.open_finding_row(0, 0)
    investigation = next(item for item in opened if isinstance(item, ModelFindingDialog))
    assert investigation.finding["finding_id"] == "C3-b4"
    investigation.evidence_button.click()
    viewer = next(item for item in opened if isinstance(item, EvidenceViewerDialog))
    assert viewer.technical.isHidden() and viewer.raw_section.isHidden() and viewer.json_view.isHidden()
    viewer.show_technical(); viewer.show_raw(); viewer.show_json()
    assert not viewer.json_view.isHidden()


def test_filters_search_and_malformed_or_missing_engines(qt_app):
    page = ModelIntegrityWorkspace(assessment("COMPLETED_WITH_WARNINGS"), results(), model_findings())
    page.engine_filter.setCurrentText("B4 Trigger Search / Reconstruction"); page.apply_filters()
    assert sum(not page.engine_table.isRowHidden(i) for i in range(page.engine_table.rowCount())) == 1
    page.engine_filter.setCurrentText("All engines")
    page.category_filter.setCurrentText("model_integrity"); page.apply_filters()
    assert not page.finding_table.isRowHidden(0)
    page.search.setEditText("C3-b4"); page.apply_filters(); assert not page.finding_table.isRowHidden(0)
    malformed = results(); malformed["B3_model_statistics"] = ["bad", "shape"]
    page = ModelIntegrityWorkspace(assessment("COMPLETED_WITH_WARNINGS"), malformed, None)
    assert page.engine_rows[2]["status"] == "ERROR"
    assert "malformed" in page.engine_rows[2]["explanation"].lower()
    missing = ModelIntegrityWorkspace(None, None, None)
    assert missing.assessment == {}


def test_unavailable_engine_status_and_missing_finding_evidence(qt_app):
    assessment_data = assessment("COMPLETED_WITH_WARNINGS")
    assessment_data["engines"]["B3_model_statistics"] = {"status": "unavailable", "reason": "Unsupported model representation."}
    assessment_data["engines"]["B4_trigger_search"] = {"status": "unavailable", "reason": "Prediction adapter unavailable."}
    payload = results(); payload.pop("B3_model_statistics")
    payload["B4_trigger_search"] = {"status": "unavailable", "reason": "Prediction adapter unavailable."}
    page = ModelIntegrityWorkspace(assessment_data, payload, [])
    assert page.engine_rows[2]["status"] == "UNAVAILABLE"
    assert page.engine_rows[3]["status"] == "UNAVAILABLE"
    assert page.engine_rows[2]["finding_count"] is None
    empty_evidence = dict(model_findings()[0], evidence=[])
    dialog = ModelFindingDialog(empty_evidence, "model.torchscript")
    assert any("No structured evidence is available" in table.item(row, 2).text()
               for table in dialog.findChildren(QTableWidget)
               for row in range(table.rowCount()) if table.item(row, 2))
