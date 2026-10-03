from pathlib import Path

import pytest

from backend.core.compute import DeviceUnavailableError, resolve_compute
from backend.core.local_config import LocalConfig
from backend.core.local_resources import load_resource
from backend.core.local_storage import AssetRegistry, EvidenceStore, ReportStore
from backend.core.offline_status import offline_capability_check


def test_cpu_compute_is_always_resolvable():
    context = resolve_compute("cpu")
    assert context.device == "cpu"
    assert context.device_name == "CPU"


def test_invalid_device_is_rejected():
    with pytest.raises(ValueError):
        resolve_compute("remote")


def test_evidence_is_content_addressed_and_repeatable(tmp_path):
    store = EvidenceStore(tmp_path / "evidence")
    first = store.put_json({"a": 1, "b": 2})
    second = store.put_json({"b": 2, "a": 1})
    assert first["sha256"] == second["sha256"]
    assert Path(first["uri"]).read_bytes() == b'{"a":1,"b":2}'


def test_report_store_rejects_traversal_and_preserves_existing(tmp_path):
    store = ReportStore(tmp_path / "reports")
    path = store.save("nested/report.txt", b"first")
    assert path.read_bytes() == b"first"
    with pytest.raises(FileExistsError):
        store.save("nested/report.txt", b"second")
    with pytest.raises(ValueError):
        store.save("../escape.txt", b"bad")


def test_asset_registry_rejects_symlinks_and_registers_files(tmp_path):
    actual = tmp_path / "actual.bin"
    actual.write_bytes(b"local")
    registry = AssetRegistry(tmp_path / "registry.sqlite3", 100)
    result = registry.register(actual, "model")
    assert result["sha256"]
    link = tmp_path / "link.bin"
    link.symlink_to(actual)
    with pytest.raises(ValueError):
        registry.register(link, "model")


def test_resource_loader_rejects_traversal_and_remote_paths(tmp_path):
    (tmp_path / "local.qss").write_text("QWidget{}", encoding="utf-8")
    assert load_resource(tmp_path, "local.qss") == b"QWidget{}"
    with pytest.raises(ValueError):
        load_resource(tmp_path, "../outside")
    with pytest.raises(ValueError):
        load_resource(tmp_path, "https://example.invalid/style.qss")


def test_offline_check_never_probes_network():
    result = offline_capability_check(LocalConfig.load())
    assert result["network_probes_performed"] is False
    assert result["status"] == "pass"
