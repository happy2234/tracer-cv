from dataclasses import dataclass
import os
import socket
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication, QLabel, QPushButton, QTableWidget

from desktop.pages.settings_workspace import (
    CAPABILITIES, LIMITATIONS, SettingsWorkspace, readonly_checks,
    runtime_facts, storage_rows,
)


@dataclass
class Config:
    datasets_dir: Path
    models_dir: Path
    evidence_dir: Path
    reports_dir: Path
    config_file: Path
    offline_mode: bool = True
    theme: str = "dark"
    # Deliberately sensitive/unlisted values must never be rendered.
    api_key: str = "DO-NOT-RENDER-SECRET"
    private_key: str = "PRIVATE-KEY-MATERIAL"


@dataclass
class Compute:
    device: str = "cpu"
    device_name: str = "CPU"
    cuda_available: bool | None = None
    torch_version: str = "not queried"


@pytest.fixture(scope="module")
def qt_app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def config(tmp_path):
    paths = [tmp_path / name for name in ("datasets", "models", "evidence", "reports")]
    for path in paths:
        path.mkdir()
    return Config(*paths, tmp_path / "tracer.toml")


def labels(page):
    rendered = [widget.text() for widget in page.findChildren(QLabel)]
    for table in page.findChildren(QTableWidget):
        rendered.extend(table.horizontalHeaderItem(i).text() for i in range(table.columnCount()))
        for row in range(table.rowCount()):
            rendered.extend(table.item(row, column).text() for column in range(table.columnCount()) if table.item(row, column))
            rendered.extend(table.cellWidget(row, column).text() for column in range(table.columnCount()) if table.cellWidget(row, column) and hasattr(table.cellWidget(row, column), "text"))
    return "\n".join(rendered)


def test_workspace_construction_and_configuration_loading(qt_app, config):
    page = SettingsWorkspace(config, Compute())
    text = labels(page)
    assert "Settings & Security Center" in text
    assert "OFFLINE MODE CONFIGURED · ENABLED" in text
    assert str(config.datasets_dir) in text
    assert "dark" in text


def test_offline_status_separates_configuration_from_environment(qt_app, config):
    page = SettingsWorkspace(config, Compute())
    text = labels(page)
    assert "OFFLINE MODE CONFIGURED · ENABLED" in text
    assert "No network connectivity test was performed" in text
    assert "physical host isolation is not verified" in text
    config.offline_mode = False
    assert "OFFLINE MODE CONFIGURED · DISABLED" in labels(SettingsWorkspace(config, Compute()))


def test_runtime_facts_use_real_local_values_without_cuda_probe(monkeypatch):
    facts = dict(runtime_facts(Compute(cuda_available=None)))
    assert facts["Python"]
    assert facts["Operating system"]
    assert facts["Architecture"]
    assert facts["Active device"] == "CPU"
    assert facts["CUDA availability"] == "Not probed"
    assert facts["Connectivity observation"] == "No network connectivity test performed"


@pytest.mark.parametrize("cuda,expected", [(True, "Available"), (False, "Unavailable"), (None, "Not probed")])
def test_cuda_state_reflects_active_context(cuda, expected):
    assert expected in dict(runtime_facts(Compute(cuda_available=cuda)))["CUDA availability"]


def test_storage_paths_and_missing_path_are_reported_without_creation(tmp_path, config):
    missing = tmp_path / "missing-data"
    config.datasets_dir = missing
    rows = storage_rows(config)
    dataset = next(row for row in rows if row[0] == "Datasets")
    assert str(missing) == dataset[1]
    assert "does not currently exist" in dataset[2]
    assert not missing.exists()


def test_model_loading_posture_and_asset_trust_caveat(qt_app, config):
    text = labels(SettingsWorkspace(config, Compute()))
    assert "B1 computes identity without loading a model" in text
    assert "not sandboxed" in text
    assert "trusted=True" in text
    assert "Pickle-based checkpoints" in text
    assert "not a persisted assessment of execution safety" in text


def test_secret_values_are_not_rendered(qt_app, config):
    text = labels(SettingsWorkspace(config, Compute()))
    assert "DO-NOT-RENDER-SECRET" not in text
    assert "PRIVATE-KEY-MATERIAL" not in text


def test_capability_matrix_and_limitations_are_visible(qt_app, config):
    text = labels(SettingsWorkspace(config, Compute()))
    assert "Security Capability Matrix" in text
    assert "ONNX" in text and "CPU execution" in text
    assert "COCO / YOLO" in text and "no complete COCO/YOLO dataset adapter" in text
    assert "B4 trigger-like candidate evidence does not prove a backdoor" in text
    assert CAPABILITIES and LIMITATIONS


def test_readonly_self_checks_report_pass_and_warning_without_mutation(qt_app, config, tmp_path):
    missing = tmp_path / "not-created"
    config.models_dir = missing
    rows = readonly_checks(config, Compute())
    by_name = {row[0]: row for row in rows}
    assert by_name["Offline configuration"][1] == "PASS"
    assert by_name["Model storage"][1] == "WARNING"
    assert "does not create directories" in by_name["Model storage"][3]
    assert not missing.exists()
    page = SettingsWorkspace(config, Compute())
    page.run_checks_button.click()
    assert not page.check_table.isHidden()
    assert page.last_checks == readonly_checks(config, Compute())


def test_checks_do_not_probe_network_or_call_assessment_engines(qt_app, config, monkeypatch):
    def network_forbidden(*_args, **_kwargs):
        raise AssertionError("Settings must not use the network")
    monkeypatch.setattr(socket, "create_connection", network_forbidden)
    monkeypatch.setattr(socket, "socket", network_forbidden)
    page = SettingsWorkspace(config, Compute())
    page.run_checks_button.click()
    assert page.last_checks


def test_navigation_links_reuse_existing_destinations(qt_app, config):
    routes = []
    page = SettingsWorkspace(config, Compute(), on_navigate=routes.append)
    for button in page.findChildren(QPushButton):
        if button.text() in {"Evidence Explorer", "Findings", "Audit Trail", "Reports"}:
            button.click()
    assert routes == ["evidence", "findings", "audit", "reports"]


def test_existing_device_and_theme_controls_are_reused(qt_app, config):
    from PySide6.QtWidgets import QComboBox
    device = QComboBox(); device.addItems(["Automatic", "CPU", "CUDA"])
    theme = QPushButton("Light theme")
    page = SettingsWorkspace(config, Compute(), device_selector=device, theme_button=theme)
    assert device.parent() is not None and theme.parent() is not None
    assert "Execution device preference (existing application setting)" in labels(page)


def test_page_open_does_not_run_assessment_engines(qt_app, config, monkeypatch):
    from importlib import import_module
    modules = tuple(import_module(name) for name in (
        "backend.engines.dataset.manifest", "backend.engines.dataset.duplicates",
        "backend.engines.dataset.near_duplicates", "backend.engines.dataset.ood",
        "backend.engines.dataset.label_consistency", "backend.engines.dataset.contributor_risk",
        "backend.engines.dataset.metadata_consistency", "backend.engines.dataset.poison_trigger",
        "backend.engines.model.identity", "backend.engines.model.behavioral_fingerprint",
        "backend.engines.model.model_statistics", "backend.engines.model.trigger_search",
        "backend.engines.provenance.inference_provenance", "backend.engines.provenance.audit_trail",
        "backend.engines.shift.distribution_shift", "backend.engines.risk.findings",
        "backend.engines.risk.assurance_report"))
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Settings must not execute assessment code")
    for module in modules:
        for name in dir(module):
            if name.startswith(("analyze_", "findings_from_", "aggregate_findings", "verify_", "create_", "append_", "build_")):
                candidate = getattr(module, name)
                if callable(candidate):
                    monkeypatch.setattr(module, name, forbidden)
    page = SettingsWorkspace(config, Compute())
    page.run_checks_button.click()
    assert page.last_checks


def test_unavailable_runtime_values_are_human_readable():
    facts = dict(runtime_facts(object()))
    assert facts["Active device"] == "UNAVAILABLE"
    assert facts["Active device name"] == "Unavailable"
    assert facts["CUDA availability"] == "Not probed"
