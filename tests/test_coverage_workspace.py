from __future__ import annotations

import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication, QTableWidget

from backend.core.capabilities import ACCESS_MODES, CAPABILITIES, DATASET_FORMATS, LIMITATIONS, MODEL_FORMATS, STATES, UNSUPPORTED_ATTACK_CLASSES, capability_by_id
from desktop.pages.coverage_workspace import CoverageWorkspace


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def test_registry_loads_and_has_state_contract():
    assert CAPABILITIES and all(row["status"] in STATES for row in CAPABILITIES)


@pytest.mark.parametrize("engine", ["A1", "A8", "B1", "B4", "C1", "C5"])
def test_required_engines_present(engine):
    assert capability_by_id(engine) is not None


def test_all_engine_ids_unique():
    ids = [item["id"] for item in CAPABILITIES]
    assert len(ids) == len(set(ids)) == 17


def test_model_format_matrix_includes_torchscript_onnx_blackbox():
    names = {item["format"] for item in MODEL_FORMATS}
    assert {"TorchScript", "ONNX", "Black-box / inference-only"} <= names


def test_model_format_states_are_explicit():
    assert all(item[key] in STATES for item in MODEL_FORMATS for key in ("B1", "B2", "B3", "B4"))


def test_dataset_format_matrix_covers_generic_yolo_coco_reference():
    names = " ".join(item["format"] for item in DATASET_FORMATS).lower()
    assert all(name in names for name in ("generic", "yolo", "coco", "reference"))


def test_segmentation_is_explicitly_unavailable():
    assert next(row for row in DATASET_FORMATS if "Segmentation" in row["format"])["status"] == "UNAVAILABLE"


def test_access_matrix_has_white_black_box_dimensions():
    assert ACCESS_MODES and all("white_box" in row and "black_box" in row for row in ACCESS_MODES)


def test_black_box_parameter_analysis_unavailable():
    row = next(row for row in ACCESS_MODES if row["capability"] == "B3 Parameter statistics")
    assert row["black_box"] == "Unavailable"


@pytest.mark.parametrize("engine", ["A4", "A6", "A7", "A8", "B2", "B3", "B4", "C1", "C2", "C4"])
def test_engine_limitations_registered(engine):
    assert LIMITATIONS[engine]


def test_global_limitations_registered():
    assert LIMITATIONS["GLOBAL"]


def test_unsupported_attack_classes_explicit():
    assert len(UNSUPPORTED_ATTACK_CLASSES) >= 5
    assert any("Not assessed" in item or "not assessed" in item.lower() for item in UNSUPPORTED_ATTACK_CLASSES)


def test_registry_does_not_define_a_security_score():
    assert all("score" not in " ".join(map(str, row.values())).lower() or row["id"] in {"B3"} for row in CAPABILITIES)


def test_no_secure_capability_state():
    assert "SECURE" not in STATES


def test_conditional_and_unavailable_states_exist():
    assert any(row["status"] == "CONDITIONAL" for row in CAPABILITIES)
    assert any(row["status"] == "UNAVAILABLE" for row in DATASET_FORMATS)


def test_capabilities_explicitly_offline():
    assert all(item["offline"] is True for item in CAPABILITIES)


def test_capability_record_contains_analyst_metadata():
    row = capability_by_id("A8")
    assert all(key in row for key in ("supported_task", "required_access", "evidence_produced", "limitations", "white_box", "black_box"))


def test_unknown_capability_returns_none():
    assert capability_by_id("Z99") is None


def test_coverage_workspace_constructs(app):
    workspace = CoverageWorkspace()
    assert workspace.objectName() == "coverageWorkspace"


def test_coverage_workspace_has_capability_tables(app):
    workspace = CoverageWorkspace()
    assert workspace.findChildren(QTableWidget)


def test_capability_selection_shows_registry_detail(app):
    workspace = CoverageWorkspace()
    table = next(item for item in workspace.findChildren(QTableWidget) if item.objectName() == "capabilityTable")
    workspace._select(table, 0, "Dataset Integrity")
    assert workspace.selected_capability is not None


def test_no_fake_capability_ids():
    assert {item["id"] for item in CAPABILITIES} == {*(f"A{i}" for i in range(1, 9)), *(f"B{i}" for i in range(1, 5)), *(f"C{i}" for i in range(1, 6))}
