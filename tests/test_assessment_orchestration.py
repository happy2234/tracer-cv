from pathlib import Path
from threading import Event

import pytest

from backend.application.assessment_manager import AssessmentManager
from backend.application.assessment_state import AssessmentState, transition
from backend.core.assessment import Assessment
from backend.core.local_config import LocalConfig
from backend.core.local_storage import AssessmentStore


def make_config(tmp_path: Path) -> LocalConfig:
    root = tmp_path / "local"
    return LocalConfig(project_root=root, app_data_dir=root, config_file=root / "config.toml",
                       datasets_dir=root / "datasets", models_dir=root / "models",
                       evidence_dir=root / "evidence", reports_dir=root / "reports",
                       logs_dir=root / "logs", resources_dir=root / "resources")


def make_assessment(tmp_path: Path) -> Assessment:
    dataset = tmp_path / "dataset"; dataset.mkdir()
    model = tmp_path / "model.onnx"; model.write_bytes(b"local model fixture")
    return Assessment(name="Synthetic assessment", analyst="test operator",
                      dataset={"path": str(dataset)}, model={"path": str(model)})


def test_assessment_creation_and_state_transitions(tmp_path):
    config = make_config(tmp_path)
    store = AssessmentStore(config.evidence_dir / "assessments.sqlite3")
    manager = AssessmentManager(config=config, assessment_store=store, runner=lambda *a, **k: a[0])
    assessment = manager.create(make_assessment(tmp_path))
    assert assessment.status == AssessmentState.CREATED
    assert store.load(assessment.assessment_id)["status"] == AssessmentState.CREATED
    assert transition("CREATED", AssessmentState.QUEUED) == "QUEUED"
    with pytest.raises(ValueError):
        transition("COMPLETED", AssessmentState.RUNNING)
    manager.close()


def test_success_pipeline_and_persistence_reopen(tmp_path):
    config = make_config(tmp_path)
    store = AssessmentStore(config.evidence_dir / "assessments.sqlite3")

    def runner(assessment, **kwargs):
        assessment.engines["A1_manifest"] = {"status": "completed"}
        return assessment

    manager = AssessmentManager(config=config, assessment_store=store, runner=runner)
    assessment = manager.create(make_assessment(tmp_path))
    result = manager.queue(assessment).result(timeout=3)
    assert result.status == AssessmentState.COMPLETED
    reopened = AssessmentStore(config.evidence_dir / "assessments.sqlite3").load(assessment.assessment_id)
    assert reopened["status"] == AssessmentState.COMPLETED
    assert isinstance(reopened["duration_seconds"], (int, float))
    assert reopened["duration_seconds"] >= 0
    assert reopened["engines"]["A1_manifest"]["status"] == "completed"
    manager.close()


def test_unavailable_stage_completes_with_warnings(tmp_path):
    config = make_config(tmp_path)
    store = AssessmentStore(config.evidence_dir / "assessments.sqlite3")

    def runner(assessment, **kwargs):
        assessment.engines["B3_statistics"] = {"status": "unavailable", "reason": "unsupported format"}
        return assessment

    manager = AssessmentManager(config=config, assessment_store=store, runner=runner)
    assessment = manager.create(make_assessment(tmp_path))
    assert manager.queue(assessment).result(timeout=3).status == AssessmentState.COMPLETED_WITH_WARNINGS
    manager.close()


def test_runner_failure_is_persisted(tmp_path):
    config = make_config(tmp_path)
    store = AssessmentStore(config.evidence_dir / "assessments.sqlite3")

    def runner(*_args, **_kwargs):
        raise RuntimeError("synthetic runner error")

    manager = AssessmentManager(config=config, assessment_store=store, runner=runner)
    assessment = manager.create(make_assessment(tmp_path))
    result = manager.queue(assessment).result(timeout=3)
    assert result.status == AssessmentState.FAILED
    assert "synthetic runner error" in result.technical_error
    assert store.load(assessment.assessment_id)["status"] == AssessmentState.FAILED
    manager.close()


def test_cancel_and_interrupted_recovery_policy(tmp_path):
    config = make_config(tmp_path)
    store = AssessmentStore(config.evidence_dir / "assessments.sqlite3")
    manager = AssessmentManager(config=config, assessment_store=store, runner=lambda *a, **k: a[0])
    queued = manager.create(make_assessment(tmp_path))
    queued.status = AssessmentState.QUEUED
    queued.engines["A1_manifest"] = {"status": "completed"}
    store.save(queued.to_dict())
    assert manager.recoverable()[0]["assessment_id"] == queued.assessment_id
    assert manager.resume_if_safe(queued.assessment_id) is None  # existing outputs require checkpoint-aware resume
    interrupted = manager.mark_interrupted(queued.assessment_id)
    assert interrupted["status"] == AssessmentState.FAILED
    assert "interrupted" in interrupted["error"]
    manager.close()


def test_cancellation_is_persisted_after_safe_operation_boundary(tmp_path):
    config = make_config(tmp_path)
    store = AssessmentStore(config.evidence_dir / "assessments.sqlite3")
    started = Event(); release = Event()

    def runner(assessment, execution_context, **kwargs):
        started.set()
        release.wait(timeout=2)
        assessment.engines["A1_manifest"] = {"status": "completed"}
        return assessment

    manager = AssessmentManager(config=config, assessment_store=store, runner=runner)
    assessment = manager.create(make_assessment(tmp_path))
    future = manager.queue(assessment)
    assert started.wait(timeout=2)
    assert manager.cancel(assessment.assessment_id)
    release.set()
    result = future.result(timeout=3)
    assert result.status == AssessmentState.CANCELLED
    assert result.engines["A1_manifest"]["status"] == "completed"
    assert store.load(assessment.assessment_id)["status"] == AssessmentState.CANCELLED
    manager.close()
