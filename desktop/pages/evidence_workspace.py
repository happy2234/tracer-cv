"""Central read-only browser for persisted assessment evidence."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox, QDialog, QHBoxLayout, QLabel, QPushButton, QScrollArea,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from desktop.pages.dataset_workspace import DatasetSampleDialog, _resolve_sample, _walk_samples
from desktop.pages.findings_workspace import _evidence_rows, _flatten_evidence, _text
from desktop.widgets.components import AnalystTable, EvidenceViewerDialog, MetricCard, SectionCard, SeverityBadge


ENGINE_ROUTES = {
    **{f"A{index}": (1, "Dataset Integrity") for index in range(1, 9)},
    **{f"B{index}": (2, "Model Integrity") for index in range(1, 5)},
    "C1": (3, "Inference Provenance"), "C2": (4, "Distribution Shift"),
    "C3": (5, "Findings"), "C4": (6, "Audit Trail"), "C5": (7, "Reports"),
}
SEVERITY_ORDER = {"critical": 6, "high": 5, "medium": 4, "low": 3, "info": 2, "informational": 2}


def _engine_code(engine_id: Any) -> str:
    value = str(engine_id or "").upper()
    return value.split("_", 1)[0] if value else ""


def _display(value: Any, fallback: str = "Unavailable") -> str:
    if value is None or value == "":
        return fallback
    if isinstance(value, float):
        return f"{value:.8g}"
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, ensure_ascii=False, default=str)
    return str(value)


def _truncate(value: Any, width: int = 28) -> str:
    text = str(value) if value is not None else ""
    if len(text) <= width:
        return text
    return f"{text[:width - 11]}…{text[-10:]}"


def _walk_text(value: Any, limit: int = 20_000) -> str:
    parts: list[str] = []
    def visit(item):
        if len(parts) >= limit:
            return
        if isinstance(item, dict):
            for key, child in item.items():
                parts.append(str(key))
                visit(child)
        elif isinstance(item, (list, tuple)):
            for child in item:
                visit(child)
        elif item is not None:
            parts.append(str(item))
    visit(value)
    return " ".join(parts).casefold()


def _persisted_digest(value: dict[str, Any]) -> tuple[str | None, str | None]:
    """Return only a digest field explicitly present in the persisted record."""
    for key in ("sha256", "digest", "evidence_digest", "result_digest", "record_hash", "entry_hash"):
        digest = value.get(key)
        if isinstance(digest, str) and digest:
            return digest, "SHA-256" if key == "sha256" else ("SHA-256" if key in {"record_hash", "entry_hash"} else None)
    return None, None


def _finding_key(finding: dict[str, Any]) -> str:
    return str(finding.get("finding_id", ""))


def load_engine_evidence(assessment: Any, reports_root: Path, evidence_root: Path) -> dict[str, dict[str, Any]]:
    """Read only evidence/result references named by the selected assessment."""
    if not isinstance(assessment, dict):
        return {}
    assessment_id = str(assessment.get("assessment_id", ""))
    if not assessment_id or Path(assessment_id).name != assessment_id:
        return {}
    reports = Path(reports_root).resolve()
    assessment_root = (reports / "assessments" / assessment_id).resolve()
    allowed_assessments = (reports / "assessments").resolve()
    if not assessment_root.is_relative_to(allowed_assessments):
        return {}
    object_root = (Path(evidence_root).resolve() / "objects").resolve()
    engine_records = assessment.get("engines") if isinstance(assessment.get("engines"), dict) else {}
    loaded: dict[str, dict[str, Any]] = {}

    def load_json(path: Path, allowed_root: Path):
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(allowed_root) or not resolved.is_file():
            raise ValueError("Persisted evidence reference is outside its local storage root.")
        return json.loads(resolved.read_text(encoding="utf-8"))

    for engine_id, record in engine_records.items():
        if not isinstance(record, dict):
            continue
        evidence_ref = record.get("evidence") if isinstance(record.get("evidence"), dict) else {}
        data = None
        storage_status = "No evidence-store object reference"
        errors = []
        uri = evidence_ref.get("uri")
        if uri:
            try:
                blob_path = Path(str(uri))
                if not blob_path.is_absolute():
                    blob_path = object_root / blob_path
                resolved_blob = blob_path.resolve(strict=True)
                if evidence_ref.get("sha256") and resolved_blob.stem != str(evidence_ref["sha256"]):
                    raise ValueError("Evidence URI filename does not match its persisted SHA-256 reference.")
                data = load_json(resolved_blob, object_root)
                storage_status = "Loaded persisted content-addressed evidence object"
            except (OSError, ValueError, TypeError, RuntimeError) as exc:
                errors.append(f"evidence object: {type(exc).__name__}: {exc}")
                storage_status = "Evidence-store object unavailable"
        if data is None:
            result_path = record.get("result_path")
            if result_path:
                try:
                    path = Path(str(result_path))
                    if not path.is_absolute():
                        path = assessment_root / path
                    data = load_json(path, assessment_root)
                    if uri:
                        storage_status = "Evidence-store object unavailable; loaded persisted assessment result file"
                    else:
                        storage_status = "Loaded persisted assessment result file"
                except (OSError, ValueError, TypeError, RuntimeError) as exc:
                    errors.append(f"assessment result: {type(exc).__name__}: {exc}")
        payload = {"record": record, "data": data, "storage_status": storage_status}
        if errors:
            payload["error"] = "; ".join(errors)
        if data is None and not payload.get("error"):
            payload["error"] = "No persisted result file or evidence object was available."
        loaded[str(engine_id)] = payload
    return loaded


class DigestValue(QWidget):
    """Truncated digest with explicit full-value disclosure."""
    def __init__(self, digest: Any, algorithm: Any = None, parent=None):
        super().__init__(parent)
        self.digest = str(digest) if digest not in (None, "") else ""
        self.algorithm = str(algorithm) if algorithm else None
        self.value_label = QLabel(self._text()); self.value_label.setWordWrap(True)
        self.value_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.full_button = QPushButton("Show full" if self.digest else "Unavailable")
        self.full_button.setEnabled(bool(self.digest)); self.full_button.clicked.connect(self.toggle)
        self.copy_button = QPushButton("Copy"); self.copy_button.setEnabled(bool(self.digest)); self.copy_button.clicked.connect(self.copy)
        row = QHBoxLayout(self); row.setContentsMargins(0, 0, 0, 0); row.addWidget(self.value_label, 1); row.addWidget(self.full_button); row.addWidget(self.copy_button)

    def _text(self, full: bool = False):
        label = f"{self.algorithm}: " if self.algorithm else "Digest: "
        if not self.digest:
            return label + "Unavailable"
        value = self.digest if full or len(self.digest) <= 28 else f"{self.digest[:14]}…{self.digest[-10:]}"
        return label + value

    def toggle(self):
        full = self.full_button.text() == "Show full"
        self.value_label.setText(self._text(full))
        self.full_button.setText("Show less" if full else "Show full")

    def copy(self):
        from PySide6.QtWidgets import QApplication
        QApplication.clipboard().setText(self.digest)


class EvidenceDetailDialog(QDialog):
    def __init__(self, item: dict[str, Any], *, dataset_root: Path | None = None,
                 on_navigate: Callable[[int], None] | None = None, on_open_finding=None, parent=None):
        super().__init__(parent)
        self.item = item
        self.dataset_root = dataset_root
        self.on_navigate = on_navigate
        self.on_open_finding = on_open_finding
        self.setWindowTitle(f"Evidence detail · {item.get('display_key', 'Evidence')}")
        self.resize(920, 760)
        outer = QVBoxLayout(self); scroll = QScrollArea(); scroll.setWidgetResizable(True); outer.addWidget(scroll)
        body = QWidget(); layout = QVBoxLayout(body); layout.setSpacing(12); scroll.setWidget(body)
        title = QLabel(_display(item.get("title"), item.get("category", "Evidence record"))); title.setObjectName("pageTitle"); layout.addWidget(title)

        identity = SectionCard("Identity")
        identity.content.addWidget(QLabel(f"Evidence key: {item.get('display_key', 'Unavailable')} ({'derived UI key' if item.get('key_derived') else 'persisted identifier'})"))
        identity.content.addWidget(QLabel(f"Source engine: {_display(item.get('source_engine'), 'Unknown source engine')}"))
        identity.content.addWidget(QLabel(f"Category / type: {_display(item.get('category'))}{' · derived display type' if item.get('category_derived') else ''}"))
        layout.addWidget(identity)

        relationship = SectionCard("Relationships")
        relationship.content.addWidget(QLabel(f"Assessment ID: {_display(item.get('assessment_id'))}"))
        relationship.content.addWidget(QLabel(f"Affected asset: {_display(item.get('affected_asset'))}"))
        finding_id = item.get("finding_id")
        relationship.content.addWidget(QLabel(f"Related finding: {_display(finding_id, 'Not linked to a persisted finding.')}"))
        relationship.content.addWidget(QLabel(f"Producer record: {_display(item.get('producer'))}"))
        layout.addWidget(relationship)
        if finding_id:
            finding_card = SectionCard("Persisted finding relationship")
            severity = item.get("severity")
            finding_card.content.addWidget(SeverityBadge(str(severity).upper()) if severity is not None else QLabel("Severity: Unavailable"))
            finding_card.content.addWidget(QLabel(f"Confidence in finding evidence: {_display(item.get('confidence'))}"))
            finding_card.content.addWidget(QLabel(f"Finding title: {_display(item.get('title'))}"))
            finding_card.content.addWidget(QLabel(f"Finding explanation: {_display(item.get('explanation'))}"))
            finding_card.content.addWidget(QLabel(f"Recommended action: {_display(item.get('recommended_action'))}"))
            layout.addWidget(finding_card)

        observation = SectionCard("Observation")
        explanation = item.get("explanation") or item.get("summary") or "Persisted evidence object; consult its structured fields below."
        note = QLabel(str(explanation)); note.setWordWrap(True); observation.content.addWidget(note)
        raw_data = item.get("raw_data")
        structured = _evidence_rows(raw_data) if isinstance(raw_data, list) else _flatten_evidence(raw_data) if isinstance(raw_data, dict) else []
        observation.content.addWidget(AnalystTable(["Persisted evidence field", "Value"], structured[:100] or [["Evidence", "No structured values were recorded."]]))
        layout.addWidget(observation)

        integrity = SectionCard("Evidence integrity")
        integrity.content.addWidget(QLabel(f"Digest field: {_display(item.get('digest_field'))}"))
        integrity.content.addWidget(DigestValue(item.get("digest"), item.get("digest_algorithm")))
        if item.get("digest"):
            integrity.content.addWidget(QLabel("Digest is shown as persisted; this read-only view does not recompute it."))
        if item.get("storage_uri"):
            integrity.content.addWidget(QLabel(f"Persisted evidence-store reference: {item['storage_uri']}"))
        layout.addWidget(integrity)

        sample_refs = item.get("sample_refs", [])
        self.sample_paths: dict[int, Path | None] = {}
        sample = SectionCard("Persisted sample references")
        rows = []
        for index, reference in enumerate(sample_refs):
            resolved = _resolve_sample(dataset_root, reference)
            self.sample_paths[index] = resolved
            rows.append([reference, "Available for on-demand inspection" if resolved else "Sample inspection unavailable"])
        self.sample_table = AnalystTable(["Persisted path/reference", "Local inspection"], rows or [["No sample reference recorded", "Sample inspection unavailable"]])
        sample.content.addWidget(self.sample_table)
        self.inspect_button = QPushButton("Inspect Selected Sample")
        self.inspect_button.setEnabled(any(path is not None and path.suffix.lower() in {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".tif", ".tiff"} for path in self.sample_paths.values()))
        self.inspect_button.clicked.connect(lambda: self.inspect_sample(self.sample_table.currentRow()))
        sample.content.addWidget(self.inspect_button); layout.addWidget(sample)

        limits = SectionCard("Limitations")
        limitations = item.get("limitations")
        values = limitations if isinstance(limitations, list) else [limitations] if limitations else []
        limits.content.addWidget(QLabel("\n".join(f"• {value}" for value in values) or "No source-engine limitation text was persisted with this evidence item."))
        layout.addWidget(limits)

        actions = QHBoxLayout()
        self.source_button = QPushButton("Open Source Workspace")
        route = ENGINE_ROUTES.get(_engine_code(item.get("source_engine")))
        self.source_button.setEnabled(bool(route and on_navigate))
        self.source_button.clicked.connect(lambda: self.open_source(route)); actions.addWidget(self.source_button)
        producer_code = _engine_code(item.get("producer"))
        producer_route = ENGINE_ROUTES.get(producer_code)
        source_code = _engine_code(item.get("source_engine"))
        if producer_route and producer_code != source_code and not finding_id:
            self.producer_button = QPushButton(f"Open Producer Workspace · {producer_route[1]}")
            self.producer_button.clicked.connect(lambda: self.open_source(producer_route)); actions.addWidget(self.producer_button)
        self.finding_button = QPushButton("Open Related Finding")
        self.finding_button.setEnabled(bool(finding_id and on_open_finding))
        self.finding_button.clicked.connect(lambda: self.open_finding(finding_id)); actions.addWidget(self.finding_button)
        self.viewer_button = QPushButton("Open Evidence Viewer")
        self.viewer_button.clicked.connect(self.open_viewer); actions.addWidget(self.viewer_button)
        layout.addLayout(actions)
        layout.addWidget(QLabel("Persisted evidence may show measured observations or cryptographic linkages. It does not by itself establish malicious intent, attribution, or root cause."))
        close = QPushButton("Back to Evidence Explorer"); close.clicked.connect(self.accept); outer.addWidget(close)

    def inspect_sample(self, row: int):
        path = self.sample_paths.get(row)
        if path is None or path.suffix.lower() not in {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".tif", ".tiff"}:
            return
        DatasetSampleDialog(path, path.name, self.dataset_root, self).exec()

    def open_source(self, route):
        if route and self.on_navigate:
            self.accept(); self.on_navigate(route[0])

    def open_finding(self, finding_id):
        if finding_id and self.on_open_finding:
            self.accept(); self.on_open_finding(finding_id)

    def open_viewer(self):
        summary = str(self.item.get("explanation") or self.item.get("summary") or "Persisted evidence as recorded.")
        raw_data = self.item.get("raw_data")
        rows = _evidence_rows(raw_data) if isinstance(raw_data, list) else _flatten_evidence(raw_data) if isinstance(raw_data, dict) else []
        structured = "\n".join(f"{row[0]}: {row[1]}" for row in rows)
        EvidenceViewerDialog("Persisted evidence", summary, structured or "No structured evidence fields are available.", self.item.get("raw_data"), self).exec()


class EvidenceWorkspace(QWidget):
    """Central evidence index normalized from one selected assessment's stored results."""
    def __init__(self, assessment: dict[str, Any] | None, engine_results: Any, findings: Any = None,
                 *, dataset_root: Path | None = None, on_navigate: Callable[[int], None] | None = None,
                 on_open_finding=None, parent=None):
        super().__init__(parent)
        self.assessment = assessment if isinstance(assessment, dict) else {}
        self.malformed_engine_results = engine_results is not None and not isinstance(engine_results, dict)
        self.engine_results = engine_results if isinstance(engine_results, dict) else {}
        self.malformed_findings = findings is not None and not isinstance(findings, list)
        self.malformed_finding_items = isinstance(findings, list) and any(not isinstance(item, dict) for item in findings)
        self.finding_records = [item for item in findings if isinstance(item, dict)] if isinstance(findings, list) else []
        self.dataset_root = dataset_root
        self.on_navigate = on_navigate
        self.on_open_finding = on_open_finding
        self.items, self.load_errors = self._normalize()
        if self.malformed_engine_results:
            self.load_errors.append("Engine evidence index: stored references could not be interpreted.")
        if self.malformed_findings or self.malformed_finding_items:
            self.load_errors.append("C3 findings: malformed persisted finding entries were skipped.")
        self._build()

    def _normalize(self):
        assessment_id = str(self.assessment.get("assessment_id") or "Unavailable")
        items: list[dict[str, Any]] = []
        errors: list[str] = []
        def add(item):
            item.setdefault("assessment_id", assessment_id)
            item.setdefault("source_engine", "")
            item["sample_refs"] = _walk_samples(item.get("raw_data"))
            item["search_text"] = " ".join(str(item.get(key, "")) for key in ("display_key", "source_engine", "category", "affected_asset", "finding_id", "title", "explanation", "digest", "summary", "sample_refs", "raw_data")).casefold()
            items.append(item)

        for engine_id, payload in self.engine_results.items():
            if not isinstance(payload, dict):
                errors.append(f"{engine_id}: malformed persisted engine reference")
                continue
            if not isinstance(payload.get("data"), (dict, list)):
                if payload.get("error"):
                    errors.append(f"{engine_id}: {payload['error']}")
                else:
                    errors.append(f"{engine_id}: stored result could not be interpreted")
                continue
            data = payload["data"]
            record = payload.get("record") if isinstance(payload.get("record"), dict) else {}
            evidence_ref = record.get("evidence") if isinstance(record.get("evidence"), dict) else {}
            embedded_ref = data.get("evidence") if isinstance(data, dict) and isinstance(data.get("evidence"), dict) else {}
            digest = evidence_ref.get("sha256") or embedded_ref.get("sha256")
            digest_field = "sha256" if digest else None
            digest_algorithm = "SHA-256" if digest else None
            if not digest and isinstance(data, dict):
                digest, digest_algorithm = _persisted_digest(data)
                digest_field = "persisted digest field" if digest else None
            source_code = _engine_code(engine_id)
            display_id = f"UI-{source_code}-{str(digest)[:12]}" if digest else f"UI-{source_code}-{Path(str(record.get('result_path') or engine_id)).name}"
            category = data.get("type") if isinstance(data, dict) else None
            add({
                "display_key": display_id, "key_derived": True, "native_id": None,
                "source_engine": source_code or "", "producer": engine_id,
                "category": category or "Engine result snapshot", "category_derived": category is None,
                "affected_asset": data.get("affected_asset") if isinstance(data, dict) else None,
                "timestamp": data.get("timestamp") if isinstance(data, dict) else None,
                "finding_id": data.get("finding_id") if isinstance(data, dict) else None,
                "severity": data.get("severity") if isinstance(data, dict) else None,
                "confidence": data.get("confidence") if isinstance(data, dict) else None,
                "title": data.get("title") if isinstance(data, dict) else None,
                "explanation": data.get("explanation") or data.get("reason") if isinstance(data, dict) else None,
                "summary": f"Persisted {engine_id} assessment result; status {_display(data.get('status')) if isinstance(data, dict) else 'recorded'}.",
                "digest": digest, "digest_field": digest_field, "digest_algorithm": digest_algorithm,
                "storage_uri": evidence_ref.get("uri") or embedded_ref.get("uri"),
                "storage_status": payload.get("storage_status", "Not recorded"),
                "limitations": (data.get("limitations") if isinstance(data, dict) else None) or record.get("limitations"),
                "raw_data": data,
            })

        for finding in self.finding_records:
            evidence = finding.get("evidence")
            if not isinstance(evidence, list):
                continue
            for index, evidence_item in enumerate(evidence):
                digest = None; algorithm = None; digest_field = None
                if isinstance(evidence_item, dict):
                    digest, algorithm = _persisted_digest(evidence_item)
                    digest_field = next((key for key in ("sha256", "digest", "evidence_digest", "result_digest", "record_hash", "entry_hash") if evidence_item.get(key) == digest), None) if digest else None
                source = finding.get("source_engine")
                native_id = evidence_item.get("evidence_id") if isinstance(evidence_item, dict) else None
                key = native_id or (f"UI-EVIDENCE-{finding.get('finding_id', 'unknown')}-{index + 1}")
                add({
                    "display_key": key, "key_derived": not bool(native_id), "native_id": native_id,
                    "source_engine": source or "", "producer": "C3 findings record",
                    "category": evidence_item.get("type") if isinstance(evidence_item, dict) and evidence_item.get("type") else finding.get("category") or "Finding evidence",
                    "category_derived": not (isinstance(evidence_item, dict) and bool(evidence_item.get("type"))),
                    "affected_asset": finding.get("affected_asset"), "finding_id": _finding_key(finding),
                    "timestamp": evidence_item.get("timestamp") if isinstance(evidence_item, dict) else None,
                    "severity": finding.get("severity"), "confidence": finding.get("confidence"),
                    "title": finding.get("title"), "explanation": finding.get("explanation"),
                    "recommended_action": finding.get("recommended_action"), "limitations": finding.get("limitations"),
                    "digest": digest, "digest_field": digest_field, "digest_algorithm": algorithm,
                    "storage_uri": None, "storage_status": "Embedded in persisted C3 finding",
                    "summary": finding.get("explanation"), "raw_data": evidence_item,
                })

        for engine_id in ("C1_provenance", "C4_audit_trail"):
            payload = self.engine_results.get(engine_id)
            data = payload.get("data") if isinstance(payload, dict) else None
            if not isinstance(data, dict):
                continue
            records_key = "records" if engine_id == "C1_provenance" else "entries"
            records = data.get(records_key)
            if not isinstance(records, list):
                continue
            for index, record in enumerate(records):
                if not isinstance(record, dict):
                    errors.append(f"{engine_id}: malformed {records_key} item {index}")
                    continue
                producer_code = _engine_code(engine_id)
                source = producer_code if producer_code == "C1" else str(record.get("source_engine") or "")
                native_id = (record.get("record_hash") if source == "C1" else record.get("event_id")) or None
                digest, algorithm = _persisted_digest(record)
                add({
                    "display_key": native_id or f"UI-{producer_code}-RECORD-{index + 1}", "key_derived": not bool(native_id),
                    "native_id": native_id, "source_engine": source, "producer": engine_id,
                    "category": record.get("event_type") if producer_code == "C4" else "Provenance record",
                    "category_derived": producer_code != "C4", "affected_asset": record.get("affected_asset"),
                    "timestamp": record.get("timestamp"),
                    "finding_id": None, "severity": None, "confidence": None,
                    "title": record.get("event_type") if producer_code == "C4" else "Persisted provenance record",
                    "explanation": None, "limitations": data.get("limitations"),
                    "digest": digest, "digest_field": next((key for key in ("sha256", "digest", "evidence_digest", "result_digest", "record_hash", "entry_hash") if record.get(key) == digest), None) if digest else None,
                    "digest_algorithm": algorithm, "storage_uri": None,
                    "storage_status": "Embedded in persisted C1 result" if producer_code == "C1" else "Embedded in persisted C4 result",
                    "summary": f"Persisted {records_key[:-1]} record from {producer_code}.", "raw_data": record,
                })
        return items, errors

    def _dataset_root(self):
        if self.dataset_root:
            try:
                root = Path(self.dataset_root).resolve(strict=True)
                return root if root.is_dir() else None
            except (OSError, RuntimeError, ValueError):
                return None
        dataset = self.assessment.get("dataset")
        try:
            root = Path(str(dataset.get("path"))).resolve(strict=True) if isinstance(dataset, dict) and dataset.get("path") else None
            return root if root and root.is_dir() else None
        except (OSError, RuntimeError, ValueError):
            return None

    def _build(self):
        outer = QVBoxLayout(self); outer.setContentsMargins(24, 20, 24, 24); outer.setSpacing(12)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); outer.addWidget(scroll)
        body = QWidget(); layout = QVBoxLayout(body); layout.setSpacing(12); scroll.setWidget(body)
        title = QLabel("Evidence Explorer"); title.setObjectName("pageTitle"); layout.addWidget(title)
        if not self.assessment:
            empty = SectionCard("No assessment selected"); empty.content.addWidget(QLabel("Select a saved assessment to browse its persisted evidence.")); layout.addWidget(empty); return

        status = str(self.assessment.get("status", "Unavailable")).replace("_", " ").upper()
        overview = SectionCard("Evidence overview")
        overview.content.addWidget(QLabel(f"Assessment: {_display(self.assessment.get('name'))}\nAssessment ID: {_display(self.assessment.get('assessment_id'))}\nAssessment status: {status}"))
        overview.content.addWidget(SeverityBadge(status))
        linked = sum(bool(item.get("finding_id")) for item in self.items)
        with_samples = sum(bool(item.get("sample_refs")) for item in self.items)
        with_digest = sum(bool(item.get("digest")) for item in self.items)
        sources = {item.get("source_engine") for item in self.items if item.get("source_engine")}
        assets = {str(item.get("affected_asset")) for item in self.items if item.get("affected_asset") is not None}
        metrics = QHBoxLayout()
        for card in (
            MetricCard("Evidence items", str(len(self.items)), "Persisted assessment/result evidence"),
            MetricCard("Source engines", str(len(sources)), "Distinct persisted producer IDs"),
            MetricCard("Affected assets", str(len(assets)), "Distinct persisted asset identifiers"),
            MetricCard("Finding-linked", str(linked), "Explicit persisted finding relationship"),
            MetricCard("Sample references", str(with_samples), "Evidence items with persisted paths"),
            MetricCard("Digest-bearing", str(with_digest), "Persisted digest fields"),
        ):
            metrics.addWidget(card)
        overview.content.addLayout(metrics)
        layout.addWidget(overview)
        if self.load_errors:
            warning = SectionCard("Evidence availability")
            warning.content.addWidget(QLabel("Some persisted evidence could not be interpreted or loaded. Available evidence remains listed; details are under Technical Details."))
            layout.addWidget(warning)
        if not self.items:
            empty = SectionCard("No evidence available")
            empty.content.addWidget(QLabel("No persisted evidence is available for this assessment."))
            if self.load_errors:
                empty.content.addWidget(QLabel("Evidence storage or assessment result files could not be read."))
            layout.addWidget(empty)
            layout.addStretch()
            return

        counts = SectionCard("Evidence coverage")
        source_counts = self._counts("source_engine")
        category_counts = self._counts("category")
        counts.content.addWidget(AnalystTable(["Source engine", "Items"], [[key, value] for key, value in source_counts.items()]))
        counts.content.addWidget(AnalystTable(["Evidence category", "Items"], [[key, value] for key, value in category_counts.items()]))
        counts.content.addWidget(AnalystTable(["Finding linkage", "Items"], [["Linked to persisted finding", linked], ["Not linked to a persisted finding", len(self.items) - linked]]))
        layout.addWidget(counts)

        listing = SectionCard("Persisted evidence")
        controls = QHBoxLayout()
        self.search = QComboBox(); self.search.setEditable(True); self.search.setInsertPolicy(QComboBox.InsertPolicy.NoInsert); self.search.lineEdit().setPlaceholderText("Search key, engine, finding, asset, path, digest, evidence text…")
        self.source_filter = self._filter_combo("All source engines", "source_engine")
        self.category_filter = self._filter_combo("All categories", "category")
        self.asset_filter = self._filter_combo("All affected assets", "affected_asset")
        self.finding_filter = QComboBox(); self.finding_filter.addItems(["All finding links", "Linked", "Unlinked"])
        self.severity_filter = self._filter_combo("All severities", "severity")
        self.confidence_filter = self._filter_combo("All confidence values", "confidence")
        self.sort_by = QComboBox(); self.sort_by.addItems(["Stable evidence key", "Source engine", "Category", "Affected asset", "Severity", "Confidence", "Finding ID", "Digest", "Timestamp"])
        self.sort_order = QComboBox(); self.sort_order.addItems(["Ascending", "Descending"])
        self.group_by = QComboBox(); self.group_by.addItems(["No grouping", "Source engine", "Category", "Affected asset", "Finding", "Assessment"])
        for control in (self.search, self.source_filter, self.category_filter, self.asset_filter, self.finding_filter, self.severity_filter, self.confidence_filter, self.sort_by, self.sort_order, self.group_by): controls.addWidget(control)
        self.clear_button = QPushButton("Clear Filters"); self.clear_button.clicked.connect(self.clear_filters); controls.addWidget(self.clear_button)
        listing.content.addLayout(controls)
        self.active_filters = QLabel("No active filters"); listing.content.addWidget(self.active_filters)
        self.result_count = QLabel(""); listing.content.addWidget(self.result_count)
        self.table = QTableWidget(0, 10); self.table.setHorizontalHeaderLabels(["Evidence key", "Source engine", "Category / type", "Affected asset", "Finding ID", "Severity", "Confidence", "Digest", "Timestamp", "Sample reference"])
        self.table.setAlternatingRowColors(True); self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows); self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers); self.table.verticalHeader().setVisible(False)
        listing.content.addWidget(self.table); self.table.cellDoubleClicked.connect(self.open_detail_row)
        inspect = QPushButton("Open Evidence Detail"); inspect.clicked.connect(lambda: self.open_detail_row(self.table.currentRow(), 0)); listing.content.addWidget(inspect)
        layout.addWidget(listing)

        technical = SectionCard("Technical details")
        technical.content.addWidget(QLabel(f"Loaded evidence items: {len(self.items)}\nAssessment result references loaded: {len(self.engine_results)}\nLoad issues: {len(self.load_errors)}"))
        if self.load_errors:
            errors = QTableWidget(len(self.load_errors), 2); errors.setHorizontalHeaderLabels(["Reference", "Read status"])
            for row, message in enumerate(self.load_errors):
                errors.setItem(row, 0, QTableWidgetItem(message.split(":", 1)[0]))
                errors.setItem(row, 1, QTableWidgetItem(message.split(":", 1)[-1]))
            technical.content.addWidget(errors)
        technical.content.addWidget(QLabel("Select an item and use its Evidence Viewer to inspect that exact persisted object. Raw JSON is available there through Technical Details → Raw Evidence → View JSON."))
        layout.addWidget(technical)

        self.dataset_root = self._dataset_root()
        self.search.lineEdit().textChanged.connect(self.apply_filters)
        for control in (self.source_filter, self.category_filter, self.asset_filter, self.finding_filter, self.severity_filter, self.confidence_filter, self.sort_by, self.sort_order, self.group_by): control.currentTextChanged.connect(self.apply_filters)
        self._render()
        layout.addStretch()

    def _filter_combo(self, title, field):
        values = sorted({_display(item.get(field), "Unknown source engine" if field == "source_engine" else "Unavailable") for item in self.items}, key=str.casefold)
        combo = QComboBox(); combo.addItems([title, *values]); return combo

    def _counts(self, field):
        counts: dict[str, int] = {}
        for item in self.items:
            value = _display(item.get(field), "Unknown source engine" if field == "source_engine" else "Unavailable")
            counts[value] = counts.get(value, 0) + 1
        return dict(sorted(counts.items(), key=lambda pair: pair[0].casefold()))

    def _sort_value(self, item, mode):
        mapping = {"Source engine": "source_engine", "Category": "category", "Affected asset": "affected_asset", "Severity": "severity", "Confidence": "confidence", "Finding ID": "finding_id", "Digest": "digest", "Timestamp": "timestamp"}
        field = mapping.get(mode)
        value = item.get(field) if field else item.get("display_key")
        if mode == "Severity":
            return SEVERITY_ORDER.get(str(value or "").lower(), 0)
        if mode == "Confidence":
            try: return (0, float(value)) if value is not None else (1, 0.0)
            except (TypeError, ValueError): return (1, 0.0)
        return str(value or "").casefold()

    def _group_value(self, item):
        mapping = {"Source engine": "source_engine", "Category": "category", "Affected asset": "affected_asset", "Finding": "finding_id", "Assessment": "assessment_id"}
        field = mapping.get(self.group_by.currentText())
        return str(item.get(field) or "").casefold() if field else ""

    def _render(self):
        indices = list(range(len(self.items)))
        mode = self.sort_by.currentText() if hasattr(self, "sort_by") else "Stable evidence key"
        reverse = self.sort_order.currentText() == "Descending" if hasattr(self, "sort_order") else False
        indices.sort(key=lambda index: (self._group_value(self.items[index]) if hasattr(self, "group_by") else "", self._sort_value(self.items[index], mode), str(self.items[index].get("display_key", "")).casefold()), reverse=reverse)
        self.visible_indices = indices
        self.table.setRowCount(len(indices))
        search = self.search.currentText().casefold().strip()
        source, category, asset = self.source_filter.currentText(), self.category_filter.currentText(), self.asset_filter.currentText()
        finding = self.finding_filter.currentText(); severity = self.severity_filter.currentText(); confidence = self.confidence_filter.currentText()
        matches = 0
        for row, index in enumerate(indices):
            item = self.items[index]
            source_value = _display(item.get("source_engine"), "Unknown source engine")
            category_value = _display(item.get("category"))
            asset_value = _display(item.get("affected_asset"))
            finding_value = _display(item.get("finding_id"), "Not linked")
            severity_value = _display(item.get("severity"))
            confidence_value = _display(item.get("confidence"))
            digest_value = item.get("digest")
            sample_value = item.get("sample_refs", [None])[0] if item.get("sample_refs") else None
            values = [_truncate(item.get("display_key"), 32), source_value, category_value, asset_value, finding_value, severity_value, confidence_value, _truncate(digest_value), _display(item.get("timestamp")), _display(sample_value)]
            for column, value in enumerate(values):
                if column == 5 and severity_value != "Unavailable":
                    self.table.setCellWidget(row, column, SeverityBadge(severity_value.upper()))
                else:
                    cell = QTableWidgetItem(value)
                    if column == 0:
                        cell.setToolTip(str(item.get("display_key")))
                    elif column == 7 and digest_value:
                        cell.setToolTip(str(digest_value))
                    self.table.setItem(row, column, cell)
            self.table.item(row, 0).setData(Qt.ItemDataRole.UserRole, index)
            visible = (
                (not search or search in item["search_text"])
                and (source == "All source engines" or source_value == source)
                and (category == "All categories" or category_value == category)
                and (asset == "All affected assets" or asset_value == asset)
                and (finding == "All finding links" or (finding == "Linked" and bool(item.get("finding_id"))) or (finding == "Unlinked" and not item.get("finding_id")))
                and (severity == "All severities" or severity_value == severity)
                and (confidence == "All confidence values" or confidence_value == confidence)
            )
            self.table.setRowHidden(row, not visible)
            matches += int(visible)
        self.table.resizeColumnsToContents(); self.table.horizontalHeader().setStretchLastSection(True)
        self.result_count.setText(f"Showing {matches} of {len(self.items)} persisted evidence items")
        active = []
        for combo, initial in ((self.source_filter, "All source engines"), (self.category_filter, "All categories"), (self.asset_filter, "All affected assets"), (self.finding_filter, "All finding links"), (self.severity_filter, "All severities"), (self.confidence_filter, "All confidence values")):
            if combo.currentText() != initial: active.append(combo.currentText())
        if search: active.append(f"Search: {search}")
        self.active_filters.setText("Active filters: " + (", ".join(active) if active else "None"))

    def apply_filters(self, *_):
        self._render()

    def clear_filters(self):
        self.search.setEditText("")
        for control in (self.source_filter, self.category_filter, self.asset_filter, self.finding_filter, self.severity_filter, self.confidence_filter, self.sort_by, self.sort_order, self.group_by): control.setCurrentIndex(0)
        self._render()

    def open_detail_row(self, row: int, _column: int):
        if not 0 <= row < self.table.rowCount(): return
        cell = self.table.item(row, 0)
        index = cell.data(Qt.ItemDataRole.UserRole) if cell else None
        if isinstance(index, int) and 0 <= index < len(self.items):
            EvidenceDetailDialog(self.items[index], dataset_root=self.dataset_root, on_navigate=self.on_navigate,
                                 on_open_finding=self.on_open_finding, parent=self).exec()
