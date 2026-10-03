"""Local installation self-test; never contacts a network service."""
from __future__ import annotations

import importlib.util
import tempfile
from pathlib import Path
from typing import Any

from backend.core.compute import resolve_compute
from backend.core.local_config import LocalConfig
from backend.core.local_storage import AssetRegistry, EvidenceStore, ReportStore
from backend.core.offline_status import offline_capability_check
from backend.core.local_resources import load_stylesheet


def self_test(config: LocalConfig | None = None) -> dict[str, Any]:
    config = config or LocalConfig.load()
    checks: list[dict[str, Any]] = []

    def check(name: str, fn) -> None:
        try:
            result = fn()
            detail = result[-1] if isinstance(result, tuple) else result
            checks.append({"name": name, "status": "pass", "detail": str(detail or "ok")})
        except Exception as exc:
            checks.append({"name": name, "status": "fail", "detail": f"{type(exc).__name__}: {exc}"})

    check("local_directories", lambda: (config.ensure_local_directories(), "created/available"))
    check("asset_registry", lambda: (AssetRegistry(config.evidence_dir / "asset_registry.sqlite3", config.max_file_bytes), "SQLite local registry ready"))

    def stores_roundtrip():
        with tempfile.TemporaryDirectory(prefix="tracer-selftest-", dir=config.app_data_dir) as temp:
            root = Path(temp)
            evidence = EvidenceStore(root / "evidence")
            saved = evidence.put_json({"self_test": True})
            report = ReportStore(root / "reports").save("self-test.txt", b"local report", overwrite=False)
            return f"evidence sha256={saved['sha256']}; report={report.name}"
    check("local_evidence_and_report_storage", stores_roundtrip)

    def resource_check():
        data = load_stylesheet(config.resources_dir)
        if not data.strip():
            raise RuntimeError("stylesheet is empty")
        return f"loaded {len(data)} local stylesheet bytes"
    check("local_resources", resource_check)

    for module in ("PySide6", "numpy", "PIL", "torch"):
        def module_check(name=module):
            available = importlib.util.find_spec(name) is not None
            if name in {"PySide6", "numpy", "PIL"} and not available:
                raise RuntimeError(f"required local module {name} is not installed")
            return "available" if available else "optional/unavailable"
        check(f"dependency_{module}", module_check)

    def engines_import():
        from backend.engines.dataset.manifest import build_manifest  # noqa: F401
        from backend.engines.dataset.duplicates import find_exact_duplicates  # noqa: F401
        from backend.engines.dataset.near_duplicates import find_near_duplicates  # noqa: F401
        from backend.engines.dataset.ood import assess_ood  # noqa: F401
        from backend.engines.dataset.label_consistency import assess_label_consistency  # noqa: F401
        from backend.engines.dataset.contributor_risk import assess_contributor_risk  # noqa: F401
        from backend.engines.dataset.metadata_consistency import assess_metadata_consistency  # noqa: F401
        from backend.engines.dataset.poison_trigger import analyze_poison_trigger  # noqa: F401
        from backend.engines.model.identity import inspect_model  # noqa: F401
        from backend.engines.model.behavioral_fingerprint import compute_behavioral_fingerprint  # noqa: F401
        from backend.engines.model.model_statistics import analyze_model  # noqa: F401
        from backend.engines.model.trigger_search import search_triggers  # noqa: F401
        from backend.engines.provenance.inference_provenance import verify_chain  # noqa: F401
        from backend.engines.provenance.audit_trail import verify_audit_chain  # noqa: F401
        from backend.engines.risk.assurance_report import build_assurance_report  # noqa: F401
        from backend.engines.risk.findings import aggregate_findings  # noqa: F401
        from backend.engines.shift.distribution_shift import analyze_image_directories  # noqa: F401
        return "A1-A8, B1-B4, C1-C5 engine entry points import"
    check("engine_imports", engines_import)

    def compute_check():
        context = resolve_compute(config.device)
        if context.device == "cuda" and not context.cuda_available:
            raise RuntimeError("CUDA was selected without a detected CUDA runtime")
        return f"requested={context.requested}, active={context.device}, device={context.device_name}, torch={context.torch_version}"
    check("compute_resolution", compute_check)

    offline = offline_capability_check(config)
    checks.append({"name": "offline_source_check", "status": offline["status"], "detail": offline})
    return {"status": "pass" if all(x["status"] == "pass" for x in checks) else "fail",
            "checks": checks, "network_requests_made": False}
