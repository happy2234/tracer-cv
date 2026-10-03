from __future__ import annotations

import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import hashlib
import json
import tempfile

import numpy as np
import pytest

pytestmark = pytest.mark.filterwarnings("ignore:Image.Image.getdata is deprecated:DeprecationWarning")

from backend.application.disposition_manager import DispositionManager, finding_digest
from backend.core.capabilities import CAPABILITIES, MODEL_FORMATS, PRODUCT_CAPABILITIES
from backend.core.provenance_demo import run_provenance_demonstration
from backend.engines.model.onnx_adapter import ONNXAdapterError, ONNXClassificationAdapter, try_load_onnx_adapter
from backend.engines.model.identity import inspect_model
from demos.benchmark.run_benchmark import run_benchmark


class _Meta:
    def __init__(self, name, shape, type_="tensor(float)"):
        self.name, self.shape, self.type = name, shape, type_


class _Session:
    def get_inputs(self): return [_Meta("image", [None, 3, 8, 8])]
    def get_outputs(self): return [_Meta("scores", [None, 2])]
    def run(self, _names, feed):
        count = len(next(iter(feed.values())))
        return [np.tile(np.array([[0.25, 1.5]], dtype=np.float32), (count, 1))]


def test_onnx_adapter_import_and_b1_identity(tmp_path):
    model = tmp_path / "model.onnx"; model.write_bytes(b"local-onnx-placeholder")
    result = inspect_model(model)
    assert result["format"] == "ONNX"
    assert result["sha256"] == hashlib.sha256(model.read_bytes()).hexdigest()


def test_onnx_load_failure_is_explicit_for_missing_file(tmp_path):
    result = try_load_onnx_adapter(tmp_path / "missing.onnx")
    assert result["status"] in {"unavailable", "error"}
    assert "onnx" in result["reason"].lower() or "local" in result["reason"].lower()


def test_onnx_adapter_predict_is_deterministic_and_batch_compatible():
    adapter = ONNXClassificationAdapter(_Session(), input_size=(8, 8))
    batch = np.full((2, 8, 8, 3), 120, dtype=np.uint8)
    first = adapter.predict(batch); second = adapter.predict(batch)
    np.testing.assert_array_equal(first.predicted_classes, second.predicted_classes)
    np.testing.assert_allclose(first.probabilities, second.probabilities)
    assert adapter.class_count == 2


def test_onnx_adapter_rejects_unsupported_input_layout():
    class InvalidSession(_Session):
        def get_inputs(self): return [_Meta("x", [None, 4, 8, 8])]
    with pytest.raises(ONNXAdapterError): ONNXClassificationAdapter(InvalidSession())


def test_onnx_probability_output_contract():
    adapter = ONNXClassificationAdapter(_Session(), input_size=(8, 8), output_type="probabilities")
    assert adapter.predict_scores(np.zeros((1, 8, 8, 3), dtype=np.uint8)).shape == (1, 2)


def test_onnx_batch_inference_preserves_one_result_per_image():
    adapter = ONNXClassificationAdapter(_Session(), input_size=(8, 8))
    results = adapter.predict(np.zeros((5, 8, 8, 3), dtype=np.uint8))
    assert len(results.predicted_classes) == 5


def test_onnx_rejects_invalid_output_type():
    with pytest.raises(ValueError): ONNXClassificationAdapter(_Session(), output_type="labels")


def test_onnx_rejects_nonfinite_runtime_output():
    class BadSession(_Session):
        def run(self, _names, feed): return [np.full((len(next(iter(feed.values()))), 2), np.nan)]
    adapter = ONNXClassificationAdapter(BadSession(), input_size=(8, 8))
    with pytest.raises(ONNXAdapterError): adapter.predict_scores(np.zeros((1, 8, 8, 3), dtype=np.uint8))


def test_onnx_rejects_non_uint8_image_batch():
    adapter = ONNXClassificationAdapter(_Session(), input_size=(8, 8))
    with pytest.raises(ValueError): adapter.predict_scores(np.zeros((1, 8, 8, 3), dtype=np.float32))


def test_onnx_adapter_integrates_with_existing_b2_fingerprint():
    from backend.engines.model.behavioral_fingerprint import compute_behavioral_fingerprint
    adapter = ONNXClassificationAdapter(_Session(), input_size=(8, 8))
    image = np.full((8, 8, 3), 64, dtype=np.uint8)
    result = compute_behavioral_fingerprint([image], adapter, model_id="sha256:" + "a" * 64)
    assert result["status"] == "completed"
    assert result["probe_count"] > 0


@pytest.mark.parametrize("scenario", ["C1-VALID-SIGNED", "C1-INVALID-SIGNATURE", "C1-OUTPUT-TAMPERING", "C1-INPUT-SUBSTITUTION", "C1-MODEL-SUBSTITUTION", "C1-PREVIOUS-HASH-TAMPERING", "C1-REPLAY"])
def test_signed_provenance_demo_scenarios(scenario):
    case = next(item for item in run_provenance_demonstration()["cases"] if item["scenario_id"] == scenario)
    assert case["detected"] is True
    if scenario == "C1-VALID-SIGNED": assert case["evidence"]["signature_valid"] is True


def test_provenance_demo_uses_deterministic_case_identifiers():
    first=run_provenance_demonstration(); second=run_provenance_demonstration()
    ids=[row["scenario_id"] for row in first["cases"]]
    assert ids == [row["scenario_id"] for row in second["cases"]]
    assert {"C1-VALID-SIGNED", "C1-INVALID-SIGNATURE", "C1-OUTPUT-TAMPERING", "C1-INPUT-SUBSTITUTION", "C1-MODEL-SUBSTITUTION", "C1-PREVIOUS-HASH-TAMPERING", "C1-REPLAY"} <= set(ids)


def test_disposition_persists_separately_and_audits_each_change(tmp_path):
    finding = {"finding_id": "A2-001", "source_engine": "A2", "affected_asset": "sample.png", "evidence": [{"sha256": "abc"}]}
    original = json.loads(json.dumps(finding)); manager = DispositionManager(tmp_path, "TEST-1")
    first = manager.save(finding, "REVIEW", "inspect pair")
    second = manager.save(finding, "QUARANTINE", "reviewed duplicate evidence")
    stored = json.loads(manager.path.read_text())
    assert finding == original and first["old_disposition"] is None
    assert second["old_disposition"] == "REVIEW"
    assert second["finding_digest"] == finding_digest(finding)
    assert stored["audit_verification"]["valid"] is True
    assert [row["sequence"] for row in stored["audit_entries"]] == [1, 2]
    assert manager.decision_for("A2-001")["disposition"] == "QUARANTINE"


def test_disposition_chains_from_existing_c4_entries(tmp_path):
    from backend.engines.provenance.audit_trail import create_audit_entry
    base = create_audit_entry(sequence=1, event_type="BASE", source_engine="C4", affected_asset="x", payload={}, timestamp="t").as_dict()
    manager = DispositionManager(tmp_path, "TEST-2", [base])
    manager.save({"finding_id": "C2-1", "affected_asset": "dataset"}, "ACCEPT")
    event = json.loads(manager.path.read_text())["audit_entries"][0]
    assert event["sequence"] == 2 and event["previous_entry_hash"] == base["entry_hash"]


def test_disposition_rejects_invalid_values_and_finding_identity(tmp_path):
    manager = DispositionManager(tmp_path, "TEST-3")
    with pytest.raises(ValueError): manager.save({"finding_id": "x"}, "MALICIOUS")
    with pytest.raises(ValueError): manager.save({}, "REVIEW")


def test_disposition_rejects_unsafe_assessment_identifier(tmp_path):
    with pytest.raises(ValueError): DispositionManager(tmp_path, "../other")


def test_disposition_note_length_is_bounded(tmp_path):
    manager = DispositionManager(tmp_path, "NOTE-TEST")
    with pytest.raises(ValueError): manager.save({"finding_id": "x"}, "REVIEW", "x" * 4001)


def test_malformed_disposition_store_is_not_silently_overwritten(tmp_path):
    manager=DispositionManager(tmp_path,"MALFORMED")
    manager.path.write_text("{not json",encoding="utf-8")
    with pytest.raises(ValueError): manager.save({"finding_id":"x"},"REVIEW")
    assert manager.path.read_text(encoding="utf-8") == "{not json"


def test_disposition_note_tampering_breaks_persisted_c4_payload_binding(tmp_path):
    manager=DispositionManager(tmp_path,"PAYLOAD-BIND")
    manager.save({"finding_id":"A1-x","affected_asset":"dataset"},"REVIEW","original note")
    value=json.loads(manager.path.read_text(encoding="utf-8")); value["decisions"][0]["analyst_note"]="edited"
    manager.path.write_text(json.dumps(value),encoding="utf-8")
    assert manager.load().get("error")
    with pytest.raises(ValueError): manager.save({"finding_id":"A1-x"},"ACCEPT")


def test_disposition_audit_payload_binds_old_new_note_and_finding_digest(tmp_path):
    manager=DispositionManager(tmp_path,"BIND-TEST")
    finding={"finding_id":"C2-01","affected_asset":"candidate","severity":"MEDIUM"}
    first=manager.save(finding,"REVIEW","investigate acquisition")
    second=manager.save(finding,"ACCEPT","reference clarified")
    document=json.loads(manager.path.read_text())
    assert second["old_disposition"] == "REVIEW"
    assert second["analyst_note"] == "reference clarified"
    assert document["audit_entries"][1]["payload_digest"]
    assert first["finding_digest"] == second["finding_digest"]


def test_disposition_source_finding_digest_changes_with_evidence(tmp_path):
    a = {"finding_id": "x", "evidence": [1]}; b = {"finding_id": "x", "evidence": [2]}
    saved = DispositionManager(tmp_path, "TEST-4").save(a, "REVIEW")
    assert saved["finding_digest"] == finding_digest(a) != finding_digest(b)


def test_finding_dialog_exposes_persistent_disposition_control(tmp_path):
    from PySide6.QtWidgets import QApplication
    from backend.application.disposition_manager import DispositionManager
    from desktop.pages.findings_workspace import FindingInvestigationDialog
    app = QApplication.instance() or QApplication([])
    manager = DispositionManager(tmp_path, "UI-TEST")
    finding = {"finding_id": "B2-UI-1", "source_engine": "B2", "severity": "LOW", "evidence": []}
    dialog = FindingInvestigationDialog(finding, disposition_manager=manager)
    assert dialog.disposition.currentText() == "ACCEPT"
    dialog.disposition.setCurrentText("REVIEW"); dialog.disposition_note.setText("synthetic note")
    dialog.save_disposition()
    assert manager.decision_for("B2-UI-1")["disposition"] == "REVIEW"
    assert "C4 event" in dialog.review_state.text()
    dialog.close()


def test_provenance_demonstration_dialog_is_explicitly_synthetic():
    from PySide6.QtWidgets import QApplication
    from desktop.pages.provenance_demo import ProvenanceDemonstrationDialog
    app = QApplication.instance() or QApplication([])
    dialog = ProvenanceDemonstrationDialog()
    assert dialog.table.rowCount() == 7
    assert dialog.record_table.rowCount() == 9
    assert dialog.result_data["label"] == "SYNTHETIC VALIDATION DATA"
    dialog._select_case(2, 0)
    assert dialog.record_table.item(5, 1).text() != dialog.record_table.item(5, 2).text()
    dialog.close()


def test_distribution_shift_disclosure_registry_is_uncalibrated():
    c2 = next(item for item in CAPABILITIES if item["id"] == "C2")
    assert "not probabilistically calibrated" in c2["limitations"].lower()
    assert next(item for item in PRODUCT_CAPABILITIES if item["id"] == "C2_CALIBRATION")["status"] == "UNAVAILABLE"


def test_distribution_shift_workspace_labels_score_as_not_calibrated():
    from PySide6.QtWidgets import QApplication, QLabel
    from desktop.pages.shift_workspace import ShiftWorkspace
    app=QApplication.instance() or QApplication([])
    result={"status":"completed","reference":{"summary":{},"image_count":1},"candidate":{"summary":{},"image_count":1},
            "shifted_features":[{"feature":"brightness","shifted":True}],"distances":{},"overall_shift":0.45,"severity":"high"}
    page=ShiftWorkspace({"assessment_id":"SYNTHETIC"},result,[])
    text=" ".join(label.text() for label in page.findChildren(QLabel))
    assert "NOT CALIBRATED" in text and "not an attack probability" in text


def test_report_pdf_section_adds_noncalibration_disclosure_without_mutation():
    from desktop.reporting.report_pdf import section_content
    source={"distribution_shift":{"status":"completed","overall_shift":0.45}}
    original=json.loads(json.dumps(source)); sections=dict((name,rows) for name,rows in section_content(source))
    assert any("NOT CALIBRATED" in value for _,value in sections["6. Distribution Shift"])
    assert source == original


def test_onnx_registry_is_conditional_and_partial():
    onnx = next(item for item in MODEL_FORMATS if item["format"] == "ONNX")
    assert (onnx["B1"], onnx["B2"], onnx["B3"], onnx["B4"]) == ("SUPPORTED", "CONDITIONAL", "PARTIAL", "CONDITIONAL")


def test_benchmark_is_labeled_and_scenario_set_is_stable():
    first = run_benchmark(); second = run_benchmark()
    assert first["label"] == "DEMONSTRATION DATA" == second["label"]
    assert [x["scenario_id"] for x in first["scenarios"]] == [x["scenario_id"] for x in second["scenarios"]]
    assert all("limitations" in row and row["data_label"] == "DEMONSTRATION DATA" for row in first["scenarios"])
    assert any(row["scenario_id"] == "C1-REPLAY" and row["detected"] for row in first["scenarios"])
    by_id = {row["scenario_id"]: row for row in first["scenarios"]}
    assert by_id["DATA-LABEL-CONFLICT"]["detected"] is True
    for expected in ("DATA-CLEAN", "DATA-EXACT-DUPLICATE-FLOODING", "DATA-NEAR-DUPLICATE", "DATA-LABEL-CONFLICT", "DATA-OOD-INSERTION", "DATA-METADATA", "DATA-REPEATED-PATTERN", "MODEL-CLEAN", "MODEL-MODIFIED-WEIGHTS", "MODEL-TRIGGER-SENSITIVE-SYNTHETIC"):
        assert expected in by_id


def test_benchmark_results_are_deterministic_after_temp_path_normalization():
    first = json.dumps(run_benchmark(), sort_keys=True, default=str)
    second = json.dumps(run_benchmark(), sort_keys=True, default=str)
    assert first == second


def test_benchmark_does_not_claim_accuracy_score():
    result = run_benchmark()
    assert "accuracy" not in result and "score" not in result


def test_benchmark_has_no_network_dependency(monkeypatch):
    import socket
    def denied(*_args, **_kwargs): raise AssertionError("network access is prohibited in local benchmark")
    monkeypatch.setattr(socket.socket, "connect", denied)
    assert run_benchmark()["label"] == "DEMONSTRATION DATA"


def test_coverage_registry_has_only_declared_capability_states():
    from backend.core.capabilities import STATES
    assert all(item["status"] in STATES for item in CAPABILITIES)


def test_coverage_registry_does_not_claim_universal_model_support():
    from backend.core.capabilities import PRODUCT_CAPABILITIES
    scope=next(item["scope"] for item in PRODUCT_CAPABILITIES if item["id"]=="MODEL_AGNOSTIC_ADAPTER_ARCHITECTURE")
    assert "format-" in scope and "currently centered on image classification" in scope


def test_readme_has_scope_security_and_execution_sections():
    from pathlib import Path
    content=Path("README.md").read_text()
    for section in ("## Supported Formats and Scope", "## Offline / Air-Gapped Operation", "## Coverage and Limitations", "## Installation", "## Running", "## Reports", "## License"):
        assert section in content


def test_license_is_complete_apache_text():
    from pathlib import Path
    content=Path("LICENSE").read_text()
    for required in ("1. Definitions.", "4. Redistribution.", "7. Disclaimer of Warranty.", "8. Limitation of Liability.", "9. Accepting Warranty or Additional Liability.", "END OF TERMS AND CONDITIONS"):
        assert required in content


def test_license_and_readme_problem_statement_identity():
    from pathlib import Path
    readme = Path("README.md").read_text(); license_text = Path("LICENSE").read_text()
    assert "PS-26228" in readme and "Apache-2.0" in readme
    assert "Apache License" in license_text and "TERMS AND CONDITIONS" in license_text
    for forbidden in ("SIH26228", "Indian Army", "DGIS", "Ministry of Defence", "Team DevZ"):
        assert forbidden not in readme


def test_no_legacy_problem_statement_name_in_public_docs():
    from pathlib import Path
    for path in [Path("README.md"), *Path("docs").glob("*.md"), Path("demos/benchmark/README.md")]:
        data = path.read_text(errors="replace")
        assert "SIH26228" not in data and "Team DevZ" not in data
