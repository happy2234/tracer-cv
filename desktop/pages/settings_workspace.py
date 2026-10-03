"""Read-only operational posture and security capability workspace."""
from __future__ import annotations

import importlib.metadata
import importlib.util
import os
import platform
import sys
from pathlib import Path
from typing import Any, Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox, QHBoxLayout, QLabel, QPushButton, QScrollArea, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from desktop.widgets.components import AnalystTable, MetricCard, SectionCard, SeverityBadge


def _value(value: Any) -> str:
    return str(value) if value not in (None, "") else "Unavailable"


def runtime_facts(active_compute: Any) -> list[tuple[str, str]]:
    """Collect cheap local facts without importing torch or probing devices."""
    try:
        torch_version = importlib.metadata.version("torch")
    except importlib.metadata.PackageNotFoundError:
        torch_version = "Unavailable"
    except Exception:
        torch_version = "Unavailable"
    cuda = getattr(active_compute, "cuda_available", None)
    if cuda is True:
        cuda_text = "Available (known from active compute context)"
    elif cuda is False:
        cuda_text = "Unavailable (known from active compute context)"
    else:
        cuda_text = "Not probed"
    torch_module = sys.modules.get("torch")
    cuda_runtime = getattr(getattr(torch_module, "version", None), "cuda", None) if cuda is True else None
    return [
        ("Application", "TRACER-CV"),
        ("Application version", "0.1.0"),
        ("Python", sys.version.split()[0]),
        ("Operating system", f"{platform.system()} {platform.release()}".strip() or "Unavailable"),
        ("Architecture", platform.machine() or "Unavailable"),
        ("CPU availability", "Available" if (os.cpu_count() or 0) > 0 else "Unavailable"),
        ("CPU logical count", str(os.cpu_count()) if os.cpu_count() is not None else "Unavailable"),
        ("PyTorch package", torch_version),
        ("CUDA availability", cuda_text),
        ("Active device", _value(getattr(active_compute, "device", None)).upper()),
        ("Active device name", _value(getattr(active_compute, "device_name", None))),
        ("CUDA runtime", _value(cuda_runtime or getattr(active_compute, "cuda_version", None)) if cuda is True else "Unavailable"),
        ("Compute fallback", _value(getattr(active_compute, "fallback_reason", None))),
        ("Git/build identity", "Unavailable (build metadata is not configured)"),
        ("Connectivity observation", "No network connectivity test performed"),
    ]


def storage_rows(config: Any, assessment_store_path: Path | None = None) -> list[list[str]]:
    rows = []
    paths = [
        ("Datasets", getattr(config, "datasets_dir", None)),
        ("Models", getattr(config, "models_dir", None)),
        ("Evidence", getattr(config, "evidence_dir", None)),
        ("Reports", getattr(config, "reports_dir", None)),
        ("Configuration", getattr(config, "config_file", None)),
        ("Assessment registry", assessment_store_path),
    ]
    for name, raw_path in paths:
        if raw_path is None:
            rows.append([name, "Unavailable", "Unavailable", "Permission status unavailable"])
            continue
        path = Path(raw_path).expanduser()
        try:
            exists = path.exists()
            kind = "Directory" if exists and path.is_dir() else "File" if exists and path.is_file() else "Other" if exists else "Missing"
            state = "Present" if exists else "Configured path does not currently exist"
            if exists:
                try:
                    access = f"Read {'available' if os.access(path, os.R_OK) else 'unavailable'}; write {'available' if os.access(path, os.W_OK) else 'unavailable'}"
                except OSError:
                    access = "Permission status unavailable"
            else:
                access = "Permission status unavailable"
            rows.append([name, str(path), f"{kind} · {state}", access])
        except (OSError, RuntimeError, ValueError):
            rows.append([name, str(path), "State unavailable", "Permission status unavailable"])
    return rows


def readonly_checks(config: Any, active_compute: Any) -> list[list[str]]:
    """Fast, read-only local checks; never creates paths or loads engines/models."""
    offline = getattr(config, "offline_mode", None)
    rows = [["Offline configuration", "PASS" if offline is True else "WARNING",
             "Offline mode is configured." if offline is True else "Offline mode is not configured as enabled.",
             "Review the local TRACER-CV configuration."]]
    for label, path in (("Dataset storage", getattr(config, "datasets_dir", None)),
                        ("Model storage", getattr(config, "models_dir", None)),
                        ("Evidence storage", getattr(config, "evidence_dir", None)),
                        ("Report storage", getattr(config, "reports_dir", None))):
        try:
            exists = path is not None and Path(path).is_dir()
        except (OSError, RuntimeError, TypeError, ValueError):
            exists = False
        rows.append([label, "PASS" if exists else "WARNING",
                     "Configured directory exists." if exists else "Configured directory is missing or unavailable.",
                     "Review the configured local path; this check does not create directories."])
    try:
        crypto = importlib.util.find_spec("cryptography") is not None
    except (ImportError, ValueError):
        crypto = False
    rows.append(["Cryptography package", "PASS" if crypto else "WARNING",
                 "Local cryptography package is available." if crypto else "Cryptography package is unavailable.",
                 "Install only from an approved offline package source if required."])
    cuda = getattr(active_compute, "cuda_available", None)
    rows.append(["CUDA state", "PASS" if cuda is True or getattr(active_compute, "device", None) == "cpu" else "UNAVAILABLE",
                 "CUDA is available in the active compute context." if cuda is True else "CPU mode is active; CUDA was not probed." if cuda is None else "CUDA is unavailable; CPU fallback may be used.",
                 "No CUDA probe is performed by this check."])
    return rows


CAPABILITIES = [
    ["Offline operation", "Available", "Core assessment workflows use local files and local computation."],
    ["Dataset integrity A1–A8", "Available", "Implemented dataset evidence engines; results depend on inputs and engine limits."],
    ["B1 model identity", "Available", "SHA-256 identity and format hints; identity is not trustworthiness."],
    ["B2 behavioral fingerprint", "Partial", "Classification-oriented probe comparison; trusted model execution is required."],
    ["B3 parameter / activation statistics", "Partial", "Supported white-box models; access/representation may limit activations."],
    ["B4 trigger-like search", "Partial", "Configured candidate search; not definitive backdoor detection."],
    ["C1 inference provenance", "Available", "Local hash chain; Ed25519 signatures are optional."],
    ["C2 distribution shift", "Available", "Appearance/statistical differences; does not establish manipulation or semantics."],
    ["C3 findings / evidence", "Available", "Persisted engine-derived findings; absence does not prove absence of attacks."],
    ["C4 audit trail", "Available", "Local tamper-evident chain; not an external trust anchor."],
    ["C5 report generation", "Available", "Local evidence-oriented report generation."],
    ["TorchScript", "Partial", "Supported adapter paths execute code; B3 loader requires trusted=True; not sandboxed."],
    ["ONNX", "Partial", "B1 recognizes an ONNX format hint; general ONNX inference is not established."],
    ["PyTorch checkpoint (.pt/.pth)", "Unavailable", "General safe checkpoint execution is not established; pickle deserialization can execute code."],
    ["COCO / YOLO", "Partial", "Some label validation/inputs exist; no complete COCO/YOLO dataset adapter."],
    ["Segmentation assurance", "Unavailable", "Not implemented in the current classification-focused model assurance scope."],
    ["Black-box model access", "Partial", "Behavioral interfaces support limited outputs; parameter/activation inspection is unavailable."],
]


LIMITATIONS = [
    "Model assurance is classification-oriented; detection and segmentation model assurance are not established.",
    "COCO/YOLO label handling is partial and does not constitute complete object-detection model assurance.",
    "TorchScript execution is not sandboxed and must be limited to trusted model artifacts. Pickle-based checkpoints are unsafe for untrusted inputs.",
    "B4 trigger-like candidate evidence does not prove a backdoor; zero candidates do not prove absence.",
    "Distribution shift is a statistical/appearance difference and does not establish malicious manipulation or semantic correctness.",
    "Contributor risk is heuristic and does not establish malicious intent; metadata anomalies do not prove tampering.",
    "Absence of findings does not prove absence of attacks or manipulation.",
    "Local evidence, reports, and audit state remain mutable to a privileged local user; hashes are not a remote trust anchor.",
    "Operation is designed for offline use with public/synthetic data and local storage; this UI does not verify physical network isolation.",
    "Compute and memory limits depend on the host; no hardware performance guarantee is made.",
]


class SettingsWorkspace(QWidget):
    """Read-only Settings / Security Center over current local configuration."""

    def __init__(self, config: Any, active_compute: Any, *, device_selector: QComboBox | None = None,
                 theme_button: QPushButton | None = None, on_navigate: Callable[[str], None] | None = None,
                 assessment_store_path: Path | None = None, parent=None):
        super().__init__(parent)
        self.config, self.active_compute = config, active_compute
        self.on_navigate = on_navigate
        self.assessment_store_path = assessment_store_path
        self.last_checks: list[list[str]] = []
        outer = QVBoxLayout(self); outer.setContentsMargins(24, 18, 24, 18)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); outer.addWidget(scroll)
        body = QWidget(); layout = QVBoxLayout(body); layout.setSpacing(12); scroll.setWidget(body)
        heading = QLabel("Settings & Security Center"); heading.setObjectName("pageTitle"); layout.addWidget(heading)
        layout.addWidget(QLabel("Operational posture first. Values below describe local configuration and available implementation capabilities; they are not a security score."))

        posture = SectionCard("Operational Posture")
        posture.content.addWidget(SeverityBadge("OFFLINE MODE CONFIGURED · ENABLED" if getattr(config, "offline_mode", False) else "OFFLINE MODE CONFIGURED · DISABLED", "available" if getattr(config, "offline_mode", False) else "warning"))
        posture.content.addWidget(QLabel("TRACER-CV is designed for offline / air-gapped operation. Core assessment workflows use local computation and storage. No network connectivity test was performed; physical host isolation is not verified."))
        posture.content.addWidget(QLabel(f"Configured network-dependent features: {_value(getattr(config, 'network_dependent_features', None))} · Telemetry: {_value(getattr(config, 'telemetry_enabled', None))} · External APIs: not required for core workflows"))
        layout.addWidget(posture)

        summary = SectionCard("Runtime & Compute")
        summary.content.addWidget(AnalystTable(["Runtime fact", "Current value"], runtime_facts(active_compute)))
        summary.content.addWidget(QLabel(f"Theme preference: {_value(getattr(config, 'theme', None))}"))
        if device_selector is not None:
            row = QHBoxLayout(); row.addWidget(QLabel("Execution device preference (existing application setting)")); row.addWidget(device_selector); row.addStretch(); summary.content.addLayout(row)
        requested = getattr(active_compute, "requested", None)
        fallback = getattr(active_compute, "fallback_reason", None)
        if requested == "auto" and getattr(active_compute, "device", None) == "cpu":
            summary.content.addWidget(QLabel(f"Automatic device selection is using CPU. Fallback detail: {_value(fallback)}"))
        elif requested == "cpu":
            summary.content.addWidget(QLabel("CPU is explicitly selected. CUDA was not probed by the CPU-only selection path."))
        if theme_button is not None:
            row = QHBoxLayout(); row.addWidget(QLabel(f"Theme preference: {_value(getattr(config, 'theme', None))}")); row.addWidget(theme_button); row.addStretch(); summary.content.addLayout(row)
        layout.addWidget(summary)

        storage = SectionCard("Local Storage")
        storage.content.addWidget(AnalystTable(["Location", "Configured path", "Observed state", "Access"], storage_rows(config, assessment_store_path)))
        layout.addWidget(storage)

        configuration = SectionCard("Configuration Summary · Non-secret values")
        configuration.content.addWidget(AnalystTable(["Setting", "Configured value"], [
            ["Offline mode", _value(getattr(config, "offline_mode", None))],
            ["Device preference", _value(getattr(config, "device", None))],
            ["Batch size", _value(getattr(config, "batch_size", None))],
            ["Worker count", _value(getattr(config, "workers", None))],
            ["Maximum file size (bytes)", _value(getattr(config, "max_file_bytes", None))],
            ["Maximum image pixels", _value(getattr(config, "max_image_pixels", None))],
            ["Logging level", _value(getattr(config, "logging_level", None))],
            ["Configuration file", _value(getattr(config, "config_file", None))],
        ])); layout.addWidget(configuration)

        loading = SectionCard("Model-Loading Security")
        loading.content.addWidget(QLabel("B1 computes identity without loading a model. Supported TorchScript adapter paths deserialize and execute model content; they are not sandboxed. The B3 loader requires an explicit trusted=True argument. Pickle-based checkpoints (.pt/.pth/.ckpt and related formats) must not be loaded from untrusted sources. No model is loaded by this page."))
        loading.content.addWidget(QLabel("Asset registry trust states describe registration/hash handling (for example, trusted_for_hashing); they are not a persisted assessment of execution safety or model trustworthiness."))
        layout.addWidget(loading)

        crypto = SectionCard("Cryptographic / Integrity Capabilities")
        crypto.content.addWidget(AnalystTable(["Mechanism", "Implementation status", "Scope / limitation"], [
            ["SHA-256", "Available", "Byte identity relative to a known digest; does not establish safety."],
            ["Dataset Merkle root", "Available", "Dataset digest summary; no independent trusted anchor is implied."],
            ["Ed25519", "Supported · optional", "C1 signatures depend on trusted public-key custody; current records may be unsigned."],
            ["C1 provenance hash chain", "Available", "Local inference-record linkage; does not establish semantic correctness."],
            ["C4 audit hash chain", "Available", "Tamper evidence relative to a protected expected head; local files remain mutable."],
        ])); layout.addWidget(crypto)

        capability = SectionCard("Security Capability Matrix")
        capability.content.addWidget(AnalystTable(["Capability", "Availability", "Scope"], CAPABILITIES)); layout.addWidget(capability)

        limits = SectionCard("Coverage & Limitations")
        for limitation in LIMITATIONS:
            label = QLabel("• " + limitation); label.setWordWrap(True); limits.content.addWidget(label)
        layout.addWidget(limits)

        check_card = SectionCard("Read-Only Local Self-Checks")
        check_card.content.addWidget(QLabel("Checks inspect configured paths and local package metadata only. They do not create files, scan datasets, load models, probe the network, or run assessment engines."))
        self.run_checks_button = QPushButton("Run Read-Only Checks"); self.run_checks_button.clicked.connect(self.run_checks); check_card.content.addWidget(self.run_checks_button)
        self.check_table = AnalystTable(["Check", "Status", "Observation", "Suggested action"], [])
        self.check_table.setVisible(False); self.check_layout = check_card.content; check_card.content.addWidget(self.check_table); layout.addWidget(check_card)

        nav = SectionCard("Related Workspaces")
        links = QHBoxLayout()
        for label, route in (("Evidence Explorer", "evidence"), ("Findings", "findings"), ("Audit Trail", "audit"), ("Reports", "reports")):
            button = QPushButton(label); button.clicked.connect(lambda checked=False, target=route: self.on_navigate(target) if self.on_navigate else None); links.addWidget(button)
        nav.content.addLayout(links); layout.addWidget(nav)
        layout.addStretch()

    def run_checks(self) -> None:
        self.last_checks = readonly_checks(self.config, self.active_compute)
        table = AnalystTable(["Check", "Status", "Observation", "Suggested action"], self.last_checks)
        old = self.check_table
        index = self.check_layout.indexOf(old)
        self.check_layout.removeWidget(old); old.deleteLater()
        self.check_table = table; self.check_layout.insertWidget(index, table)
        self.check_table.setVisible(True)
