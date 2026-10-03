"""Central read-only analyst workspace over persisted C3 findings."""
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
from desktop.widgets.components import AnalystTable, EvidenceViewerDialog, MetricCard, SectionCard, SeverityBadge


ENGINE_ROUTES = {
    **{f"A{index}": (1, "Dataset Integrity") for index in range(1, 9)},
    **{f"B{index}": (2, "Model Integrity") for index in range(1, 5)},
    "C1": (3, "Inference Provenance"),
    "C2": (4, "Distribution Shift"),
}
SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "informational": 1}


def c3_status(result: Any, engine_records: Any = None) -> str:
    """Map assessment and stored result status without implying missing is clear."""
    engines = engine_records if isinstance(engine_records, dict) else {}
    record = engines.get("C3_findings", {}) if isinstance(engines.get("C3_findings"), dict) else {}
    engine_state = str(record.get("status", "")).strip().lower()
    if result is not None and not isinstance(result, dict):
        return "PARTIAL"
    data = result if isinstance(result, dict) else {}
    missing = not data or data.get("status") == "unavailable"
    if missing:
        if engine_state in {"not_assessed", "unavailable", "error", "failed", "running", "queued", "created", "cancelled"}:
            state = engine_state
        else:
            return "UNAVAILABLE"
    else:
        result_state = str(data.get("status", "")).strip().lower()
        if result_state in {"error", "failed"}:
            state = result_state
        else:
            state = engine_state or result_state or "unavailable"
    if state in {"completed", "completed_with_warnings", "completed_with_errors"}:
        if data.get("status") == "unavailable":
            return "UNAVAILABLE"
        if data.get("status") not in {"completed", "completed_with_warnings", "completed_with_errors"}:
            return "PARTIAL"
        if not isinstance(data.get("findings"), list):
            return "PARTIAL"
        if any(not isinstance(item, dict) for item in data["findings"]):
            return "PARTIAL"
    return {
        "completed": "COMPLETED",
        "completed_with_warnings": "COMPLETED WITH WARNINGS",
        "completed_with_errors": "COMPLETED WITH WARNINGS",
        "error": "FAILED",
        "failed": "FAILED",
        "not_assessed": "NOT ASSESSED",
        "unavailable": "UNAVAILABLE",
        "running": "RUNNING",
        "queued": "QUEUED",
        "created": "QUEUED",
        "cancelled": "CANCELLED",
    }.get(state, state.upper() or "UNAVAILABLE")


def _text(value: Any, fallback: str = "Unavailable") -> str:
    if value is None or value == "":
        return fallback
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, ensure_ascii=False, default=str)
    return str(value)


def _meaningful_search_text(finding: dict[str, Any]) -> str:
    fields = ("finding_id", "title", "category", "explanation", "affected_asset", "source_engine", "recommended_action")
    return " ".join(str(finding.get(field, "")) for field in fields).casefold()


def _flatten_evidence(value: Any, prefix: str = "") -> list[list[str]]:
    rows: list[list[str]] = []
    def walk(item: Any, name: str):
        if isinstance(item, dict):
            for key, child in item.items():
                label = f"{name} · {str(key).replace('_', ' ').capitalize()}" if name else str(key).replace("_", " ").capitalize()
                walk(child, label)
        elif isinstance(item, list) and item and all(isinstance(child, dict) for child in item):
            for index, child in enumerate(item, 1):
                walk(child, f"{name} {index}")
        elif isinstance(item, list):
            rows.append([name or "Evidence", ", ".join(str(child) for child in item)])
        else:
            rows.append([name or "Evidence", _text(item)])
    walk(value, prefix)
    return rows[:120]


def _evidence_rows(evidence: Any) -> list[list[str]]:
    if not isinstance(evidence, list):
        return []
    output: list[list[str]] = []
    for entry in evidence:
        if isinstance(entry, dict):
            output.extend(_flatten_evidence(entry))
        else:
            output.append(["Evidence", _text(entry)])
    return output[:120]


class FindingInvestigationDialog(QDialog):
    def __init__(self, finding: dict[str, Any], *, dataset_root: Path | None = None,
                 on_navigate: Callable[[int], None] | None = None,
                 on_review: Callable[[dict[str, Any]], bool] | None = None, parent=None):
        super().__init__(parent)
        self.finding = finding
        self.dataset_root = dataset_root
        self.on_navigate = on_navigate
        self.on_review = on_review
        self.setWindowTitle(f"Finding investigation · {_text(finding.get('finding_id'))}")
        self.resize(900, 760)
        outer = QVBoxLayout(self)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); outer.addWidget(scroll)
        body = QWidget(); layout = QVBoxLayout(body); layout.setSpacing(12); scroll.setWidget(body)
        heading = QLabel(_text(finding.get("title"), "Assurance finding")); heading.setObjectName("pageTitle"); layout.addWidget(heading)
        severity = _text(finding.get("severity")).upper()
        layout.addWidget(SeverityBadge(severity))
        identity = SectionCard("Finding identity and assessment")
        for label, key in (
            ("Finding ID", "finding_id"), ("Category", "category"), ("Source engine", "source_engine"),
            ("Affected asset", "affected_asset"), ("Confidence", "confidence"),
        ):
            identity.content.addWidget(QLabel(f"{label}: {_text(finding.get(key))}"))
        layout.addWidget(identity)
        explanation = SectionCard("What was observed")
        explanation.content.addWidget(QLabel(_text(finding.get("explanation"))))
        layout.addWidget(explanation)
        evidence_data = finding.get("evidence")
        evidence = SectionCard("Evidence")
        rows = _evidence_rows(evidence_data)
        evidence.content.addWidget(AnalystTable(["Evidence item", "Persisted value"], rows or [["Evidence", "No evidence was recorded."]]))
        if finding.get("evidence_digest"):
            evidence.content.addWidget(QLabel(f"Evidence digest: {finding['evidence_digest']}"))
        layout.addWidget(evidence)
        self.sample_refs = [ref for ref in _walk_samples(evidence_data) if ref]
        sample_card = SectionCard("Affected samples referenced by evidence")
        sample_rows = []
        self.sample_paths: dict[int, Path | None] = {}
        for index, ref in enumerate(self.sample_refs):
            resolved = _resolve_sample(dataset_root, ref)
            self.sample_paths[index] = resolved
            sample_rows.append([ref, "Locally available" if resolved else "Local sample unavailable"])
        self.sample_table = AnalystTable(["Persisted sample reference", "Local inspection"], sample_rows or [["No sample paths in evidence", "Not applicable"]])
        self.sample_table.cellDoubleClicked.connect(self.open_sample_row)
        sample_card.content.addWidget(self.sample_table)
        self.inspect_sample_button = QPushButton("Inspect Selected Image")
        self.inspect_sample_button.setEnabled(any(path is not None and path.suffix.lower() in {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".tif", ".tiff"} for path in self.sample_paths.values()))
        self.inspect_sample_button.clicked.connect(lambda: self.open_sample_row(self.sample_table.currentRow(), 0))
        sample_card.content.addWidget(self.inspect_sample_button)
        layout.addWidget(sample_card)
        action = SectionCard("Recommended action and limitations")
        action.content.addWidget(QLabel("Recommended action: " + _text(finding.get("recommended_action"))))
        limitation = finding.get("limitations")
        limitation_text = "\n".join(f"• {item}" for item in limitation) if isinstance(limitation, list) else _text(limitation)
        action.content.addWidget(QLabel("Limitations:\n" + limitation_text))
        layout.addWidget(action)
        layout.addWidget(QLabel("Findings are source-engine evidence for analyst review. They do not by themselves establish malicious intent; absence of findings does not prove absence of attacks or manipulation."))

        actions = QHBoxLayout()
        self.source_button = QPushButton(self._source_button_text())
        self.source_button.setEnabled(bool(on_navigate and self._source_route()))
        self.source_button.clicked.connect(self.open_source_workspace)
        actions.addWidget(self.source_button)
        self.evidence_button = QPushButton("Open Evidence Viewer")
        self.evidence_button.clicked.connect(lambda: EvidenceViewerDialog(
            f"Finding evidence · {_text(finding.get('finding_id'))}",
            _text(finding.get("explanation"), "No explanation was recorded."),
            "\n".join(f"{row[0]}: {row[1]}" for row in rows) or "No structured evidence was recorded.",
            finding, self).exec())
        actions.addWidget(self.evidence_button)
        self.review_button = QPushButton("Review in This Session")
        self.review_button.setEnabled(on_review is not None)
        self.review_button.clicked.connect(self.review_in_session)
        actions.addWidget(self.review_button)
        self.review_state = QLabel("Session-only review; not saved to the assessment or audit trail.")
        layout.addLayout(actions); layout.addWidget(self.review_state)
        close = QPushButton("Back to Findings"); close.clicked.connect(self.accept); outer.addWidget(close)

    def _source_route(self):
        source = str(self.finding.get("source_engine", "")).upper()
        if source in ENGINE_ROUTES:
            return ENGINE_ROUTES[source]
        return next((route for code, route in ENGINE_ROUTES.items() if source.startswith(code + " ")), None)

    def _source_button_text(self):
        route = self._source_route()
        return f"Open {route[1]}" if route else f"Source: {_text(self.finding.get('source_engine'))} · no dedicated workspace"

    def open_source_workspace(self):
        route = self._source_route()
        if route and self.on_navigate:
            self.accept()
            self.on_navigate(route[0])

    def review_in_session(self):
        if self.on_review and self.on_review(self.finding):
            self.review_state.setText("Reviewed in this session only; the assessment and audit trail were not changed.")

    def open_sample_row(self, row: int, _column: int):
        path = self.sample_paths.get(row)
        if path is None or path.suffix.lower() not in {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".tif", ".tiff"}:
            return
        DatasetSampleDialog(path, path.name, self.dataset_root, self).exec()


class FindingsWorkspace(QWidget):
    """Central analyst interface over a persisted C3 result document."""
    def __init__(self, assessment: dict[str, Any] | None, result: Any,
                 *, on_navigate: Callable[[int], None] | None = None,
                 on_review: Callable[[dict[str, Any]], bool] | None = None, parent=None):
        super().__init__(parent)
        self.assessment = assessment if isinstance(assessment, dict) else {}
        self.malformed_result = result is not None and not isinstance(result, dict)
        self.result = result if isinstance(result, dict) else {}
        raw = self.result.get("findings")
        self.findings_available = isinstance(raw, list)
        self.malformed_findings = isinstance(raw, list) and any(not isinstance(item, dict) for item in raw)
        self.findings = [item for item in raw if isinstance(item, dict)] if isinstance(raw, list) else []
        self.on_navigate = on_navigate
        self.on_review = on_review
        self.dataset_root = self._dataset_root()
        self.state = "PARTIAL" if self.malformed_result else c3_status(self.result, self.assessment.get("engines"))
        self._build()

    def _dataset_root(self) -> Path | None:
        dataset = self.assessment.get("dataset")
        if not isinstance(dataset, dict) or not dataset.get("path"):
            return None
        try:
            root = Path(str(dataset["path"])).resolve(strict=True)
            return root if root.is_dir() else None
        except (OSError, RuntimeError, ValueError):
            return None

    def _build(self):
        outer = QVBoxLayout(self); outer.setContentsMargins(24, 20, 24, 24); outer.setSpacing(12)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); outer.addWidget(scroll)
        body = QWidget(); layout = QVBoxLayout(body); layout.setSpacing(12); scroll.setWidget(body)
        title = QLabel("Findings & Investigation"); title.setObjectName("pageTitle"); layout.addWidget(title)
        if not self.assessment:
            card = SectionCard("No assessment selected")
            card.content.addWidget(QLabel("Open a saved assessment to inspect persisted C3 assurance findings."))
            layout.addWidget(card)
            return

        engine_records = self.assessment.get("engines") if isinstance(self.assessment.get("engines"), dict) else {}
        engine_record = engine_records.get("C3_findings") if isinstance(engine_records.get("C3_findings"), dict) else {}
        assessment_state = str(self.assessment.get("status", "Unavailable")).replace("_", " ").upper()
        count = len(self.findings)
        overview = SectionCard("Findings overview")
        overview.content.addWidget(QLabel(
            f"Assessment: {_text(self.assessment.get('name'))}\n"
            f"Assessment ID: {_text(self.assessment.get('assessment_id'))}\n"
            f"Assessment status: {assessment_state}\nC3 status: {self.state}"
        ))
        overview.content.addWidget(SeverityBadge(self.state))
        if self.state == "UNAVAILABLE":
            overview.content.addWidget(QLabel("Findings assessment is not available for this assessment."))
        elif self.state == "PARTIAL" or self.malformed_findings:
            overview.content.addWidget(QLabel("Stored findings evidence could not be interpreted completely. Valid persisted findings remain available below."))
        elif self.state == "FAILED":
            overview.content.addWidget(QLabel(str(self.result.get("reason") or engine_record.get("reason") or "C3 failed; inspect available technical details.")))
        result_digest = self.result.get("result_digest")
        if not result_digest:
            evidence_ref = engine_record.get("evidence")
            if isinstance(evidence_ref, dict):
                result_digest = evidence_ref.get("sha256")
        summary = QHBoxLayout()
        summary.addWidget(MetricCard("Persisted findings", str(count), "Interpretable C3 findings"))
        summary.addWidget(MetricCard("Categories", str(len({str(item.get('category')) for item in self.findings if item.get('category') is not None})), "Distinct persisted categories"))
        summary.addWidget(MetricCard("Source engines", str(len({str(item.get('source_engine')) for item in self.findings if item.get('source_engine') is not None})), "Distinct persisted sources"))
        summary.addWidget(MetricCard("Affected assets", str(len({str(item.get('affected_asset')) for item in self.findings if item.get('affected_asset') is not None})), "Distinct persisted asset identifiers"))
        overview.content.addLayout(summary)
        overview.content.addWidget(SeverityBadge(f"Result digest: {result_digest or 'Unavailable'}", "info"))
        layout.addWidget(overview)

        aggregates = SectionCard("Finding counts")
        severity_counts: dict[str, int] = {}
        category_counts: dict[str, int] = {}
        source_counts: dict[str, int] = {}
        for finding in self.findings:
            severity = str(finding.get("severity") or "Unavailable")
            category = str(finding.get("category") or "Unavailable")
            source = str(finding.get("source_engine") or "Unavailable")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            category_counts[category] = category_counts.get(category, 0) + 1
            source_counts[source] = source_counts.get(source, 0) + 1
        aggregates.content.addWidget(AnalystTable(["Severity", "Count"], [[key, value] for key, value in sorted(severity_counts.items())] or [["No persisted findings", 0]]))
        aggregates.content.addWidget(AnalystTable(["Category", "Count"], [[key, value] for key, value in sorted(category_counts.items())] or [["No persisted findings", 0]]))
        aggregates.content.addWidget(AnalystTable(["Source engine", "Count"], [[key, value] for key, value in sorted(source_counts.items())] or [["No persisted findings", 0]]))
        layout.addWidget(aggregates)

        list_card = SectionCard("Persisted findings")
        controls = QHBoxLayout()
        self.search = QComboBox(); self.search.setEditable(True); self.search.setInsertPolicy(QComboBox.InsertPolicy.NoInsert); self.search.lineEdit().setPlaceholderText("Search finding ID, title, explanation, asset, recommendation…")
        self.severity_filter = QComboBox(); self.severity_filter.addItems(["All severities", *sorted({str(item.get("severity") or "Unavailable") for item in self.findings}, key=str.casefold)])
        self.category_filter = QComboBox(); self.category_filter.addItems(["All categories", *sorted({str(item.get("category") or "Unavailable") for item in self.findings}, key=str.casefold)])
        self.source_filter = QComboBox(); self.source_filter.addItems(["All sources", *sorted({str(item.get("source_engine") or "Unavailable") for item in self.findings}, key=str.casefold)])
        self.asset_filter = QComboBox(); self.asset_filter.addItems(["All affected assets", *sorted({str(item.get("affected_asset") or "Unavailable") for item in self.findings}, key=str.casefold)])
        self.sort_by = QComboBox(); self.sort_by.addItems(["Severity", "Confidence", "Finding ID", "Title", "Source engine"])
        self.sort_order = QComboBox(); self.sort_order.addItems(["Descending", "Ascending"])
        for control in (self.search, self.severity_filter, self.category_filter, self.source_filter, self.asset_filter, self.sort_by, self.sort_order):
            controls.addWidget(control)
        self.clear_button = QPushButton("Clear Filters"); self.clear_button.clicked.connect(self.clear_filters); controls.addWidget(self.clear_button)
        list_card.content.addLayout(controls)
        self.finding_table = QTableWidget(0, 7)
        self.finding_table.setHorizontalHeaderLabels(["Severity", "Confidence", "Title", "Category", "Affected asset", "Source engine", "Finding ID"])
        self.finding_table.setAlternatingRowColors(True); self.finding_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.finding_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers); self.finding_table.verticalHeader().setVisible(False)
        list_card.content.addWidget(self.finding_table)
        self.finding_table.cellDoubleClicked.connect(self.open_finding_row)
        investigation = QPushButton("Investigate Selected Finding")
        investigation.clicked.connect(lambda: self.open_finding_row(self.finding_table.currentRow(), 0))
        list_card.content.addWidget(investigation)
        if not self.findings:
            if self.state in {"COMPLETED", "COMPLETED WITH WARNINGS"} and self.findings_available:
                message = "No persisted assurance findings were recorded for this assessment."
            elif self.state == "FAILED":
                message = "C3 failed; no findings are available for review."
            elif self.state == "NOT ASSESSED":
                message = "C3 findings were not assessed for this assessment."
            elif self.state == "PARTIAL":
                message = "No interpretable persisted findings are available."
            else:
                message = "Findings assessment is not available for this assessment."
            list_card.content.addWidget(QLabel(message))
        layout.addWidget(list_card)
        self.search.lineEdit().textChanged.connect(self.apply_filters)
        for control in (self.severity_filter, self.category_filter, self.source_filter, self.asset_filter, self.sort_by, self.sort_order):
            control.currentTextChanged.connect(self.apply_filters)
        self._render_findings()

        technical = SectionCard("Technical details")
        technical.content.addWidget(QLabel(
            f"C3 engine status: {_text(engine_record.get('status'), self.result.get('status', 'Unavailable'))}\n"
            f"Engine version: {_text(self.result.get('engine_version'))}\n"
            f"Method: {_text(self.result.get('method'))}\n"
            f"Persisted finding count: {_text(self.result.get('finding_count'))}\n"
            f"Result digest: {_text(result_digest)}\n"
            f"Load detail: {_text(self.result.get('message', self.result.get('technical_error')))}"
        ))
        raw = QPushButton("Open C3 Evidence")
        raw.clicked.connect(lambda: EvidenceViewerDialog(
            "C3 persisted assurance findings",
            "This page presents findings recorded by the completed assessment. Source-engine evidence and limitations remain attached to each finding.",
            f"C3 status: {self.state}; interpretable findings: {count}; result digest: {_text(result_digest)}.",
            self.result, self).exec())
        technical.content.addWidget(raw); layout.addWidget(technical)
        if count == 0 and self.findings_available and self.state in {"COMPLETED", "COMPLETED WITH WARNINGS"}:
            layout.addWidget(QLabel("No persisted assurance findings were recorded. This does not establish absence of attacks, manipulation, or other issues."))
        layout.addStretch()

    def _render_findings(self):
        needle = self.search.currentText().casefold().strip()
        severity = self.severity_filter.currentText()
        category = self.category_filter.currentText()
        source = self.source_filter.currentText()
        asset = self.asset_filter.currentText()
        order = self.sort_order.currentText() == "Descending"
        mode = self.sort_by.currentText()
        indices = list(range(len(self.findings)))
        if mode == "Severity":
            indices.sort(key=lambda i: SEVERITY_ORDER.get(str(self.findings[i].get("severity", "")).lower(), 0), reverse=order)
        elif mode == "Confidence":
            indices.sort(key=lambda i: float(self.findings[i].get("confidence"))
                         if isinstance(self.findings[i].get("confidence"), (int, float)) else -1, reverse=order)
        elif mode == "Source engine":
            indices.sort(key=lambda i: str(self.findings[i].get("source_engine", "")).casefold(), reverse=order)
        elif mode == "Title":
            indices.sort(key=lambda i: str(self.findings[i].get("title", "")).casefold(), reverse=order)
        else:
            indices.sort(key=lambda i: str(self.findings[i].get("finding_id", "")).casefold(), reverse=order)
        self.finding_table.setRowCount(len(indices))
        self.visible_indices = indices
        for row, index in enumerate(indices):
            finding = self.findings[index]
            values = [
                str(finding.get("severity") or "Unavailable").upper(),
                _text(finding.get("confidence")),
                _text(finding.get("title")),
                _text(finding.get("category")),
                _text(finding.get("affected_asset")),
                _text(finding.get("source_engine")),
                _text(finding.get("finding_id")),
            ]
            self.finding_table.setCellWidget(row, 0, SeverityBadge(values[0]))
            for column, value in enumerate(values[1:], 1):
                self.finding_table.setItem(row, column, QTableWidgetItem(value))
            self.finding_table.item(row, 6).setData(Qt.ItemDataRole.UserRole, index)
            searchable = _meaningful_search_text(finding)
            visible = (
                (severity == "All severities" or str(finding.get("severity") or "Unavailable") == severity)
                and (category == "All categories" or str(finding.get("category") or "Unavailable") == category)
                and (source == "All sources" or str(finding.get("source_engine") or "Unavailable") == source)
                and (asset == "All affected assets" or str(finding.get("affected_asset") or "Unavailable") == asset)
                and (not needle or needle in searchable)
            )
            self.finding_table.setRowHidden(row, not visible)
        self.finding_table.resizeColumnsToContents()
        self.finding_table.horizontalHeader().setStretchLastSection(True)

    def apply_filters(self, *_):
        self._render_findings()

    def clear_filters(self):
        self.search.setEditText("")
        for control in (self.severity_filter, self.category_filter, self.source_filter, self.asset_filter, self.sort_by, self.sort_order):
            control.setCurrentIndex(0)
        self._render_findings()

    def open_finding_row(self, row: int, _column: int):
        if not 0 <= row < self.finding_table.rowCount():
            return
        cell = self.finding_table.item(row, 6)
        index = cell.data(Qt.ItemDataRole.UserRole) if cell else None
        if isinstance(index, int) and 0 <= index < len(self.findings):
            FindingInvestigationDialog(self.findings[index], dataset_root=self.dataset_root,
                on_navigate=self.on_navigate, on_review=self.on_review, parent=self).exec()
