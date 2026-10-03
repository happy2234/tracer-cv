from __future__ import annotations

import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

import pytest
from PySide6.QtWidgets import QApplication

from backend.core.deployment_readiness import REQUIRED_CHECKS, readiness_for
from backend.core.self_test import run_self_tests
from desktop.pages.self_test_workspace import SelfTestWorkspace


@dataclass
class Config:
    project_root: Path
    datasets_dir: Path
    models_dir: Path
    evidence_dir: Path
    reports_dir: Path
    offline_mode: bool = True


@dataclass
class Compute:
    device: str = "cpu"
    cuda_available: bool | None = None
    device_name: str = "CPU"


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def config(tmp_path):
    root = Path(__file__).resolve().parents[1]
    paths = [tmp_path / name for name in ("datasets", "models", "evidence", "reports")]
    for path in paths: path.mkdir()
    return Config(root, *paths)


def test_runtime_self_test_passes_required_imports(config):
    result = run_self_tests(config, Compute())
    assert next(row for row in result["checks"] if row["test_id"] == "runtime_core")["status"] == "PASS"


def test_storage_check_uses_and_cleans_unique_temp_file(config):
    result = run_self_tests(config, Compute())
    row = next(row for row in result["checks"] if row["test_id"] == "storage_evidence")
    assert row["status"] == "PASS"
    assert list(config.evidence_dir.iterdir()) == []


def test_missing_evidence_path_is_reported_not_created(config, tmp_path):
    config.evidence_dir = tmp_path / "absent"
    result = run_self_tests(config, Compute())
    assert next(row for row in result["checks"] if row["test_id"] == "storage_evidence")["status"] == "FAIL"
    assert not config.evidence_dir.exists()


def test_sha256_and_canonical_hash_check(config):
    result = run_self_tests(config, Compute())
    assert next(row for row in result["checks"] if row["test_id"] == "sha256")["status"] == "PASS"


def test_ed25519_roundtrip_and_bad_signature_rejection(config):
    result = run_self_tests(config, Compute())
    evidence = next(row for row in result["checks"] if row["test_id"] == "ed25519")["evidence"]
    assert evidence["signature_valid"] and evidence["changed_message_rejected"]
    assert evidence["private_key_persisted"] is False


def test_merkle_self_test(config):
    result = run_self_tests(config, Compute())
    assert next(row for row in result["checks"] if row["test_id"] == "merkle")["status"] == "PASS"


def test_audit_chain_valid_and_tamper_detection(config):
    result = run_self_tests(config, Compute())
    evidence = next(row for row in result["checks"] if row["test_id"] == "audit")["evidence"]
    assert evidence["valid_chain"] and evidence["tamper_rejected"] and evidence["sequence_issue_detected"]


def test_provenance_chain_and_signatures(config):
    result = run_self_tests(config, Compute())
    evidence = next(row for row in result["checks"] if row["test_id"] == "provenance")["evidence"]
    assert evidence["valid_chain_and_signatures"] and evidence["tamper_rejected"]


def test_report_json_text_roundtrip(config):
    result = run_self_tests(config, Compute())
    assert next(row for row in result["checks"] if row["test_id"] == "report_rendering")["status"] == "PASS"


def test_pdf_self_test_produces_temp_pdf(config, app):
    result = run_self_tests(config, Compute())
    row = next(row for row in result["checks"] if row["test_id"] == "pdf_generation")
    assert row["status"] == "PASS" and row["evidence"]["valid_pdf_signature"]


def test_offline_check_makes_no_network_requests(config):
    with patch("socket.socket", side_effect=AssertionError("network blocked")), patch("urllib.request.urlopen", side_effect=AssertionError("network blocked")):
        result = run_self_tests(config, Compute())
    assert result["network_requests_made"] is False
    assert next(row for row in result["checks"] if row["test_id"] == "offline_configuration")["status"] == "PASS"


def test_offline_disabled_fails_required_config(config):
    config.offline_mode = False
    result = run_self_tests(config, Compute())
    assert next(row for row in result["checks"] if row["test_id"] == "offline_configuration")["status"] == "FAIL"


def test_model_loading_check_does_not_load_model(config):
    result = run_self_tests(config, Compute())
    row = next(row for row in result["checks"] if row["test_id"] == "model_loading_posture")
    assert row["status"] == "PASS" and row["evidence"]["model_loaded"] is False


def test_cpu_only_is_not_a_failure(config):
    result = run_self_tests(config, Compute("cpu", False, "CPU"))
    row = next(row for row in result["checks"] if row["test_id"] == "device")
    assert row["status"] == "PASS" and row["evidence"]["cuda_available"] is False


def test_cuda_optional_does_not_block_readiness():
    rows = [{"test_id": key, "status": "PASS"} for key in REQUIRED_CHECKS]
    rows.append({"test_id": "device", "status": "WARN"})
    assert readiness_for(rows)[0] == "READY WITH WARNINGS"


def test_required_failure_means_not_ready():
    rows = [{"test_id": key, "status": "PASS"} for key in REQUIRED_CHECKS]
    rows[0]["status"] = "FAIL"
    assert readiness_for(rows)[0] == "NOT READY"


def test_all_required_pass_means_ready():
    rows = [{"test_id": key, "status": "PASS"} for key in REQUIRED_CHECKS]
    assert readiness_for(rows)[0] == "READY"


def test_missing_required_check_means_not_ready():
    assert readiness_for([])[0] == "NOT READY"


def test_result_has_test_evidence_and_durations(config):
    result = run_self_tests(config, Compute())
    assert result["checks"] and all("evidence" in row and "duration_ms" in row for row in result["checks"])


def test_self_test_does_not_read_assessment_data(config):
    result = run_self_tests(config, Compute())
    assert result["assessment_data_read"] is False


def test_self_test_does_not_mutate_assessment_or_results(config):
    protected = [config.project_root / "reports/active_assessment.json", config.project_root / "reports/assessments/TRACER-F9BDED6BD6E5/assessment.json"]
    before = {p: p.read_bytes() if p.is_file() else None for p in protected}
    run_self_tests(config, Compute())
    after = {p: p.read_bytes() if p.is_file() else None for p in protected}
    assert before == after


def test_no_assessment_engine_entrypoints_invoked(config):
    with patch("backend.core.assessment_runner.run_assessment", side_effect=AssertionError("assessment invoked"), create=True):
        run_self_tests(config, Compute())


def test_self_test_has_no_network_configuration_or_endpoint(config):
    result = run_self_tests(config, Compute())
    assert result["network_requests_made"] is False
    assert all("http" not in str(row.get("evidence", {})).lower() for row in result["checks"])


def test_qt_self_test_page_constructs_without_running_checks(config, app):
    page = SelfTestWorkspace(config, Compute())
    assert page.result is None
    assert page.readiness


def test_qt_page_runs_and_displays_results(config, app):
    page = SelfTestWorkspace(config, Compute())
    result = page.run_checks()
    assert result["readiness"] in {"READY", "READY WITH WARNINGS", "NOT READY"}
    assert not page.result_card.isHidden()


def test_pdf_check_does_not_write_report_store(config, app):
    run_self_tests(config, Compute())
    assert list(config.reports_dir.iterdir()) == []


def test_temporary_crypto_keys_are_not_written(config):
    run_self_tests(config, Compute())
    assert list(config.evidence_dir.iterdir()) == []


def test_ui_importability_check(config):
    result = run_self_tests(config, Compute())
    assert next(row for row in result["checks"] if row["test_id"] == "ui_imports")["status"] == "PASS"


def test_self_test_timestamp_is_generated_for_run(config):
    result = run_self_tests(config, Compute())
    assert result["generated_at"].endswith("+00:00")


def test_no_full_assessment_or_model_loading(config):
    result = run_self_tests(config, Compute())
    assert all(row["test_id"] not in {"assessment_runner", "model_inference"} for row in result["checks"])


def test_check_statuses_are_documented_values(config):
    result = run_self_tests(config, Compute())
    assert {row["status"] for row in result["checks"]} <= {"PASS", "WARN", "FAIL", "NOT_APPLICABLE"}


def test_global_readiness_explains_scope(config):
    result = run_self_tests(config, Compute())
    assert "does not assess" in result["readiness_reason"] or result["readiness"] != "READY"


def test_self_test_categories_cover_expected_domains(config):
    result = run_self_tests(config, Compute())
    categories = {row["category"] for row in result["checks"]}
    assert {"Runtime", "Storage", "Cryptography", "Integrity", "Reporting", "Network posture", "Model handling"} <= categories
