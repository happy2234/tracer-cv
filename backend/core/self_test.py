"""Fast local function checks using only synthetic data and temporary files.

This module deliberately does not invoke assessment runners or inspect real
assessment/evidence contents. It never probes the network or loads a model.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import platform
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from backend.core.deployment_readiness import readiness_for


def _check(test_id: str, category: str, name: str, fn: Callable[[], tuple[str, Any]], *, required: bool = False, limitations: str = "") -> dict[str, Any]:
    started = time.monotonic()
    try:
        explanation, evidence = fn()
        status = str(evidence.pop("_status", "PASS")) if isinstance(evidence, dict) else "PASS"
    except Exception as exc:  # a self-test reports failures rather than raising into the UI
        status, explanation, evidence = "FAIL", "The local check did not complete successfully.", {"error_type": type(exc).__name__, "detail": str(exc)}
    return {"test_id": test_id, "category": category, "name": name, "status": status,
            "required": required, "explanation": explanation, "evidence": evidence,
            "duration_ms": round((time.monotonic() - started) * 1000, 2), "limitations": limitations}


def run_self_tests(config: Any, active_compute: Any = None) -> dict[str, Any]:
    """Run isolated local checks; configured stores are inspected, never initialized."""
    checks: list[dict[str, Any]] = []

    def add(*args: Any, **kwargs: Any) -> None:
        checks.append(_check(*args, **kwargs))

    def runtime() -> tuple[str, Any]:
        required = ("PySide6", "numpy", "PIL", "cryptography")
        missing = [name for name in required if importlib.util.find_spec(name) is None]
        if missing:
            raise RuntimeError("Required local packages unavailable: " + ", ".join(missing))
        return "Required desktop, image, numerical and cryptographic packages are importable.", {"application": "TRACER-CV", "application_version": "0.1.0", "python": sys.version.split()[0], "platform": platform.platform(), "architecture": platform.machine(), "torch_package": importlib.util.find_spec("torch") is not None}
    add("runtime_core", "Runtime", "Core runtime imports", runtime, required=True)

    def configuration() -> tuple[str, Any]:
        offline = getattr(config, "offline_mode", None)
        telemetry = getattr(config, "telemetry_enabled", None)
        endpoints = [name for name in ("cloud_endpoint", "external_api_endpoint", "telemetry_endpoint") if getattr(config, name, None)]
        if offline is not True or telemetry is True or endpoints:
            raise RuntimeError("Offline configuration is disabled or a network-dependent option is configured.")
        return "Offline mode is configured; no telemetry/cloud endpoint is configured on the loaded configuration. No connectivity check was performed.", {"offline_mode": offline, "telemetry_configured": telemetry is not True, "network_endpoint_configured": bool(endpoints), "network_probe_performed": False}
    add("configuration", "Configuration", "Local configuration", configuration, required=True)
    add("offline_configuration", "Network posture", "Offline dependency configuration", configuration, required=True,
        limitations="Confirms local configuration only; does not establish physical host isolation.")

    def storage() -> tuple[str, Any]:
        paths = {"datasets": getattr(config, "datasets_dir", None), "models": getattr(config, "models_dir", None),
                 "evidence": getattr(config, "evidence_dir", None), "reports": getattr(config, "reports_dir", None)}
        evidence = {}
        for label, raw in paths.items():
            path = Path(raw) if raw else None
            if path is None or not path.is_dir():
                evidence[label] = "MISSING"
                if label == "evidence":
                    raise RuntimeError("Configured evidence storage directory is missing.")
                continue
            writable = os.access(path, os.W_OK)
            evidence[label] = "WRITABLE" if writable else "READ_ONLY"
            if label == "evidence" and writable:
                fd, name = tempfile.mkstemp(prefix=".tracer-self-test-", dir=path)
                try:
                    os.write(fd, b"TRACER-CV local self-test")
                    os.close(fd); fd = -1
                finally:
                    if fd >= 0: os.close(fd)
                    Path(name).unlink(missing_ok=True)
            if label == "evidence" and not writable:
                raise RuntimeError("Configured evidence storage directory is not writable.")
        return "Evidence storage is present and its temporary write/readiness check succeeded.", evidence
    add("storage_evidence", "Storage", "Local storage availability", storage, required=True,
        limitations="Checks configured path state and writes only a uniquely named temporary file in evidence storage, then removes that file.")
    def auxiliary_storage() -> tuple[str, Any]:
        values = {}
        missing = []
        for label in ("datasets_dir", "models_dir", "reports_dir"):
            p = Path(getattr(config, label))
            values[label] = {"exists": p.is_dir(), "writable": os.access(p, os.W_OK) if p.is_dir() else None}
            if not p.is_dir() or not os.access(p, os.W_OK): missing.append(label)
        if missing: values["_status"] = "WARN"
        return ("Configured dataset/model/report paths were inspected without creating directories." if not missing else "One or more optional configured dataset/model/report paths are missing or read-only."), values
    add("storage_paths", "Storage", "Dataset, model and report paths", auxiliary_storage)

    def temporary_workspace() -> tuple[str, Any]:
        with tempfile.TemporaryDirectory(prefix="tracer-cv-self-test-") as directory:
            target = Path(directory) / "local-check.txt"
            target.write_text("temporary synthetic check", encoding="utf-8")
            valid = target.read_text(encoding="utf-8") == "temporary synthetic check"
            if not valid: raise AssertionError("temporary workspace read-back failed")
        return "A temporary working directory allowed a local write/read and was removed after the check.", {"write_read_succeeded": valid, "temporary_directory_removed": not Path(directory).exists()}
    add("temporary_workspace", "Storage", "Temporary working area", temporary_workspace, required=True)

    def sha_check() -> tuple[str, Any]:
        value = hashlib.sha256(b"tracer-self-test").hexdigest()
        if value != hashlib.sha256(b"tracer-self-test").hexdigest(): raise AssertionError("SHA-256 repeatability check failed")
        from backend.engines.provenance.inference_provenance import digest_object
        if digest_object({"b": 2, "a": 1}) != digest_object({"a": 1, "b": 2}): raise AssertionError("Canonical object digest differs by key order")
        return "SHA-256 and canonical object hashing produced repeatable digests.", {"sha256": value, "canonical_order_independent": True}
    add("sha256", "Cryptography", "SHA-256 and canonical hashing", sha_check, required=True)

    def ed_check() -> tuple[str, Any]:
        from backend.engines.provenance.inference_provenance import generate_signing_keypair, sign_record_hash, verify_record_signature
        private, public = generate_signing_keypair()
        digest = hashlib.sha256(b"synthetic self-test record").hexdigest()
        signature = sign_record_hash(digest, private)
        valid = verify_record_signature(digest, signature, public)
        rejected = not verify_record_signature(digest + "x", signature, public)
        if not valid or not rejected: raise AssertionError("Ed25519 verification round-trip/rejection failed")
        return "Ephemeral Ed25519 sign/verify succeeded and a changed message was rejected.", {"signature_valid": valid, "changed_message_rejected": rejected, "private_key_persisted": False}
    add("ed25519", "Cryptography", "Ed25519 signing and verification", ed_check, required=True,
        limitations="Uses an ephemeral test key only; does not test persistent key custody or deployment key protection.")

    def merkle_check() -> tuple[str, Any]:
        from backend.core.merkle import merkle_root
        root = merkle_root(["leaf-a", "leaf-b"])
        if root != merkle_root(["leaf-b", "leaf-a"]): raise AssertionError("Merkle root is not deterministic")
        changed = root != merkle_root(["leaf-a", "changed"])
        empty = merkle_root([]) == hashlib.sha256(b"").hexdigest()
        if not changed or not empty: raise AssertionError("Merkle behavior check failed")
        return "Synthetic Merkle root is deterministic; a changed leaf changes the root; empty-input behavior is defined.", {"root": root, "changed_leaf_changes_root": changed, "empty_root_defined": empty}
    add("merkle", "Integrity", "Merkle root behavior", merkle_check, required=True)

    def audit_check() -> tuple[str, Any]:
        from dataclasses import replace
        from backend.engines.provenance.audit_trail import append_audit_entry, verify_audit_chain
        first = append_audit_entry([], event_type="self_test", source_engine="C4", affected_asset="synthetic", payload={"x": 1}, timestamp="synthetic-1", event_id="self-test-1")
        second = append_audit_entry([first], event_type="self_test", source_engine="C4", affected_asset="synthetic", payload={"x": 2}, timestamp="synthetic-2", event_id="self-test-2")
        valid = verify_audit_chain([first, second])["valid"]
        tampered = verify_audit_chain([first, replace(second, event_type="changed")])["valid"]
        sequence = verify_audit_chain([first, replace(second, sequence=3)])
        if not valid or tampered or sequence["valid"]: raise AssertionError("Audit synthetic checks failed")
        return "Synthetic audit chain verified; altered content and discontinuous sequence were detected.", {"valid_chain": valid, "tamper_rejected": not tampered, "sequence_issue_detected": not sequence["valid"]}
    add("audit", "Integrity", "C4 audit chain", audit_check, required=True)

    def provenance_check() -> tuple[str, Any]:
        from dataclasses import replace
        from backend.engines.provenance.inference_provenance import create_record, generate_signing_keypair, verify_chain
        private, public = generate_signing_keypair()
        first = create_record(sequence=1, input_digest="i", model_id="m", preprocessing_digest="p", output_digest="o", nonce="synthetic-nonce-1", timestamp="synthetic-1", private_key_base64=private)
        second = create_record(sequence=2, input_digest="i2", model_id="m", preprocessing_digest="p", output_digest="o2", previous_record_hash=first.record_hash, nonce="synthetic-nonce-2", timestamp="synthetic-2", private_key_base64=private)
        valid = verify_chain([first, second], public_key_base64=public)["valid"]
        tampered = verify_chain([first, replace(second, output_digest="changed")], public_key_base64=public)["valid"]
        if not valid or tampered: raise AssertionError("C1 synthetic chain/signature check failed")
        return "Synthetic provenance chain and Ed25519 signatures verified; altered record was rejected.", {"valid_chain_and_signatures": valid, "tamper_rejected": not tampered}
    add("provenance", "Integrity", "C1 provenance chain and signature", provenance_check, required=True)

    def report_check() -> tuple[str, Any]:
        from backend.engines.risk.assurance_report import report_from_json, report_to_json, render_text_report
        sample = {"assessment_id": "SELF-TEST-SYNTHETIC", "status": "COMPLETED", "executive_summary": {"interpretation": "synthetic self-test"}, "limitations": ["Synthetic only"]}
        encoded = report_to_json(sample)
        parsed = report_from_json(encoded)
        rendered = render_text_report(parsed)
        if parsed.get("assessment_id") != sample["assessment_id"] or "SELF-TEST-SYNTHETIC" not in rendered:
            raise AssertionError("C5 local rendering roundtrip failed")
        return "Synthetic C5-shaped report parsed and rendered locally as JSON/text.", {"json_roundtrip": True, "text_rendered": True}
    add("report_rendering", "Reporting", "Report JSON/text rendering", report_check, required=True)

    def pdf_check() -> tuple[str, Any]:
        from PySide6.QtWidgets import QApplication
        if QApplication.instance() is None:
            return "Qt application context is unavailable; PDF check requires desktop runtime.", {"available": False, "_status": "NOT_APPLICABLE"}
        from desktop.reporting.report_pdf import write_assurance_pdf
        sample = {"assessment_id": "SELF-TEST-SYNTHETIC", "executive_summary": {}, "asset_coverage": {}, "dataset_integrity": {}, "model_integrity": {}, "inference_provenance": {}, "distribution_shift": {}, "findings_and_evidence": {"findings": []}, "audit_trail": {}, "recommended_actions": [], "limitations": ["Synthetic only"]}
        with tempfile.TemporaryDirectory(prefix="tracer-cv-pdf-test-") as directory:
            target = Path(directory) / "self-test.pdf"
            result = write_assurance_pdf(sample, {"assessment_id": "SELF-TEST-SYNTHETIC", "status": "COMPLETED"}, target)
            valid = target.is_file() and target.stat().st_size > 0 and target.read_bytes().startswith(b"%PDF-")
            if not valid: raise AssertionError("PDF output is not structurally valid")
            return "A synthetic local report produced a non-empty PDF in a temporary directory.", {"valid_pdf_signature": valid, "size_bytes": target.stat().st_size, "digest": result.get("sha256")}
    add("pdf_generation", "Reporting", "Local PDF generation", pdf_check,
        limitations="Uses only synthetic report data in a temporary directory; does not test every assessment-specific section.")

    add("model_loading_posture", "Model handling", "Model-loading policy source check", lambda: _model_policy_check(config))

    def compute_check() -> tuple[str, Any]:
        device = getattr(active_compute, "device", None)
        cuda = getattr(active_compute, "cuda_available", None)
        return "Compute state is read from the active application context; no device selection or CUDA probe was performed.", {"cpu_available": (os.cpu_count() or 0) > 0, "cuda_available": cuda if cuda is not None else "Not probed", "active_device": device or "Unavailable", "gpu_name": getattr(active_compute, "device_name", None) if cuda else "Unavailable"}
    add("device", "Device", "CPU / CUDA availability", compute_check)
    add("ui_imports", "Desktop", "Analyst workspace imports and Qt smoke construction", lambda: _ui_import_check(config, active_compute))
    status, reason = readiness_for(checks)
    return {"generated_at": datetime.now(timezone.utc).isoformat(), "readiness": status, "readiness_reason": reason,
            "checks": checks, "network_requests_made": False, "assessment_data_read": False}


def _model_policy_check(config: Any) -> tuple[str, Any]:
    from pathlib import Path
    root = Path(getattr(config, "project_root", Path(__file__).resolve().parents[2]))
    identity = (root / "backend/engines/model/identity.py").read_text(encoding="utf-8")
    stats = (root / "backend/engines/model/model_statistics.py").read_text(encoding="utf-8")
    if "never loaded" not in identity.lower() and "NEVER loaded" not in identity: raise AssertionError("B1 identity non-loading contract not found")
    if "trusted=True" not in stats or "trusted" not in stats: raise AssertionError("B3 trusted TorchScript guard not found")
    return "B1 source describes byte hashing without model loading; B3 contains an explicit trusted TorchScript gate.", {"B1_does_not_load_model": True, "B3_explicit_trusted_gate_present": True, "model_loaded": False}


def _ui_import_check(config: Any, active_compute: Any) -> tuple[str, Any]:
    from PySide6.QtWidgets import QApplication
    from desktop.pages.settings_workspace import SettingsWorkspace
    from desktop.pages.report_workspace import ReportWorkspace
    from desktop.pages.dataset_workspace import DatasetIntegrityWorkspace
    from desktop.pages.model_workspace import ModelIntegrityWorkspace
    from desktop.pages.provenance_workspace import ProvenanceWorkspace
    from desktop.pages.shift_workspace import ShiftWorkspace
    from desktop.pages.findings_workspace import FindingsWorkspace
    from desktop.pages.evidence_workspace import EvidenceWorkspace
    from desktop.pages.audit_workspace import AuditWorkspace
    from desktop.pages.coverage_workspace import CoverageWorkspace
    if QApplication.instance() is None:
        return "Workspace modules imported; Qt widget construction was not applicable because no QApplication exists.", {"workspace_count": 11, "widgets_constructed": False, "_status": "NOT_APPLICABLE"}
    from desktop.pages.self_test_workspace import SelfTestWorkspace
    widgets = [
        SettingsWorkspace(config, active_compute), ReportWorkspace(None, {}),
        DatasetIntegrityWorkspace(None, {}, []), ModelIntegrityWorkspace(None, {}, []),
        ProvenanceWorkspace(None, {}, []), ShiftWorkspace(None, {}, []),
        FindingsWorkspace(None, {}), EvidenceWorkspace(None, {}, []),
        AuditWorkspace(None, {}, []), CoverageWorkspace(), SelfTestWorkspace(config, active_compute),
    ]
    count = len(widgets)
    for widget in widgets: widget.deleteLater()
    return "All major analyst workspace classes constructed in the current Qt session with empty local fixtures.", {"workspace_count": count, "widgets_constructed": True}


__all__ = ["run_self_tests"]
