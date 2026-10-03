"""Read-only analyst workspace for persisted C4 audit-chain evidence."""
from __future__ import annotations

import json
from typing import Any, Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox, QDialog, QHBoxLayout, QLabel, QPushButton, QScrollArea,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from desktop.pages.findings_workspace import _evidence_rows, _text
from desktop.widgets.components import AnalystTable, EvidenceViewerDialog, MetricCard, SectionCard, SeverityBadge


SOURCE_ROUTES = {
    **{f"A{index}": (1, "Dataset Integrity") for index in range(1, 9)},
    **{f"B{index}": (2, "Model Integrity") for index in range(1, 5)},
    "C1": (3, "Inference Provenance"), "C2": (4, "Distribution Shift"),
    "C3": (5, "Findings"), "C4": (6, "Audit Trail"),
}
ISSUE_LABELS = {
    "entry_tampering": "Entry hash verification",
    "broken_chain": "Previous-entry linkage",
    "sequence_discontinuity": "Sequence continuity",
    "duplicate_sequence": "Duplicate sequence",
    "event_id_reuse": "Event ID reuse",
}


def audit_state(result: Any, engine_records: Any = None) -> str:
    """Map persisted C4 status and shape without treating missing evidence as pass."""
    record_map = engine_records if isinstance(engine_records, dict) else {}
    record = record_map.get("C4_audit_trail", {}) if isinstance(record_map.get("C4_audit_trail"), dict) else {}
    engine_state = str(record.get("status", "")).strip().lower()
    if result is not None and not isinstance(result, dict):
        return "PARTIAL"
    data = result if isinstance(result, dict) else {}
    state = str(data.get("status", "")).strip().lower()
    if not data or state == "unavailable":
        if engine_state in {"failed", "error", "not_assessed", "unavailable", "running", "queued", "cancelled"}:
            state = engine_state
        else:
            return "UNAVAILABLE"
    elif state in {"error", "failed"}:
        pass
    else:
        state = engine_state or state
    if state in {"completed", "completed_with_warnings", "completed_with_errors"}:
        entries = data.get("entries")
        if data.get("status") == "unavailable":
            return "UNAVAILABLE"
        if not isinstance(entries, list):
            return "PARTIAL"
        if any(not isinstance(entry, dict) for entry in entries):
            return "PARTIAL"
    return {
        "completed": "COMPLETED",
        "completed_with_warnings": "COMPLETED WITH WARNINGS",
        "completed_with_errors": "COMPLETED WITH WARNINGS",
        "failed": "FAILED", "error": "FAILED", "not_assessed": "NOT ASSESSED",
        "unavailable": "UNAVAILABLE", "running": "RUNNING", "queued": "QUEUED",
        "created": "QUEUED", "cancelled": "CANCELLED",
    }.get(state, state.upper() or "UNAVAILABLE")


def _verification(result: dict[str, Any]) -> dict[str, Any]:
    for key in ("verification", "verification_result", "integrity"):
        value = result.get(key)
        if isinstance(value, dict):
            return value
    return {}


def _issue_list(result: dict[str, Any]) -> list[dict[str, Any]]:
    verification = _verification(result)
    values = verification.get("findings", verification.get("issues", result.get("verification_findings", [])))
    return [item for item in values if isinstance(item, dict)] if isinstance(values, list) else []


def _first_value(*values: Any) -> Any:
    return next((value for value in values if value is not None), None)


def _entry_search_text(entry: dict[str, Any]) -> str:
    fields = ("event_id", "event_type", "source_engine", "affected_asset", "sequence", "timestamp")
    return " ".join(str(entry.get(key, "")) for key in fields).casefold()


def _source_route(source: Any):
    value = str(source or "").strip().upper()
    if value in SOURCE_ROUTES:
        return SOURCE_ROUTES[value]
    return next((route for code, route in SOURCE_ROUTES.items() if value.startswith(code + "_")), None)


class HashValue(QWidget):
    """Show a compact digest with explicit in-place full-value disclosure."""
    def __init__(self, label: str, value: Any, parent=None):
        super().__init__(parent)
        self.value = str(value) if value not in (None, "") else ""
        row = QHBoxLayout(self); row.setContentsMargins(0, 0, 0, 0)
        self.label = QLabel(f"{label}: {self._display()}"); self.label.setWordWrap(True)
        self.label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        row.addWidget(self.label, 1)
        self.button = QPushButton("Show full" if self.value else "Unavailable")
        self.button.setEnabled(bool(self.value)); self.button.clicked.connect(self.toggle)
        row.addWidget(self.button)

    def _display(self):
        if not self.value:
            return "Unavailable"
        if len(self.value) <= 24:
            return self.value
        return f"{self.value[:12]}…{self.value[-8:]}"

    def toggle(self):
        full = self.button.text() == "Show full"
        self.label.setText(f"{self.label.text().split(':', 1)[0]}: {self.value if full else self._display()}")
        self.button.setText("Show less" if full else "Show full")


class AuditEntryDialog(QDialog):
    def __init__(self, entries: list[dict[str, Any]], entry_index: int,
                 result: dict[str, Any], *, on_navigate: Callable[[int], None] | None = None, parent=None):
        super().__init__(parent)
        self.entries = entries
        self.entry_index = entry_index
        self.result = result
        self.on_navigate = on_navigate
        self.setWindowTitle("Audit entry investigation")
        self.resize(850, 700)
        self.outer = QVBoxLayout(self)
        self.render()

    @property
    def entry(self):
        return self.entries[self.entry_index]

    def render(self):
        while self.outer.count():
            item = self.outer.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        scroll = QScrollArea(); scroll.setWidgetResizable(True); self.outer.addWidget(scroll)
        body = QWidget(); layout = QVBoxLayout(body); layout.setSpacing(12); scroll.setWidget(body)
        entry = self.entry
        heading = QLabel(f"Audit entry · sequence {_text(entry.get('sequence'))}"); heading.setObjectName("pageTitle"); layout.addWidget(heading)
        identity = SectionCard("Identity and event")
        for label, key in (("Sequence", "sequence"), ("Event ID", "event_id"), ("Timestamp", "timestamp"), ("Event type", "event_type"), ("Source engine", "source_engine"), ("Affected asset", "affected_asset")):
            identity.content.addWidget(QLabel(f"{label}: {_text(entry.get(key))}"))
        layout.addWidget(identity)
        integrity = SectionCard("Integrity evidence")
        integrity.content.addWidget(QLabel(f"Entry status: {self._entry_integrity_status(entry)}"))
        integrity.content.addWidget(HashValue("Previous entry hash", entry.get("previous_entry_hash")))
        integrity.content.addWidget(HashValue("Current entry hash", entry.get("entry_hash")))
        integrity.content.addWidget(HashValue("Payload digest", entry.get("payload_digest")))
        layout.addWidget(integrity)
        issues = self._issues_for_entry(entry)
        if issues:
            issue_card = SectionCard("Persisted verification detail")
            issue_card.content.addWidget(AnalystTable(["Check", "Recorded evidence"], [[_text(issue.get("type")), _text(issue.get("message"))] for issue in issues]))
            layout.addWidget(issue_card)
        payload = {key: entry[key] for key in ("event_type", "source_engine", "affected_asset", "payload_digest") if key in entry}
        payload_card = SectionCard("Recorded event evidence")
        payload_card.content.addWidget(AnalystTable(["Field", "Persisted value"], [[key.replace("_", " ").capitalize(), _text(value)] for key, value in payload.items()] or [["Evidence", "No event fields were recorded."]]))
        layout.addWidget(payload_card)
        layout.addWidget(QLabel("A valid chain establishes consistency only under the recorded verification rules. An inconsistency does not identify its cause or establish intent."))
        actions = QHBoxLayout()
        self.previous_button = QPushButton("Previous Entry"); self.previous_button.setEnabled(self.entry_index > 0)
        self.previous_button.clicked.connect(lambda: self.move(-1)); actions.addWidget(self.previous_button)
        self.next_button = QPushButton("Next Entry"); self.next_button.setEnabled(self.entry_index < len(self.entries) - 1)
        self.next_button.clicked.connect(lambda: self.move(1)); actions.addWidget(self.next_button)
        self.source_button = QPushButton(self._source_button_text(entry.get("source_engine")))
        self.source_button.setEnabled(bool(self.on_navigate and _source_route(entry.get("source_engine"))))
        self.source_button.clicked.connect(lambda: self.open_source(entry.get("source_engine"))); actions.addWidget(self.source_button)
        self.evidence_button = QPushButton("Open Evidence Viewer")
        self.evidence_button.clicked.connect(lambda: self.open_evidence(entry)); actions.addWidget(self.evidence_button)
        layout.addLayout(actions)
        self.outer.addWidget(QPushButton("Back to Audit Trail", clicked=self.accept))

    def _issues_for_entry(self, entry):
        sequence = entry.get("sequence")
        event_id = entry.get("event_id")
        entry_hash = entry.get("entry_hash")
        return [issue for issue in _issue_list(self.result)
                if (sequence is not None and issue.get("sequence") == sequence)
                or (event_id is not None and issue.get("event_id") == event_id)
                or (entry_hash is not None and issue.get("entry_hash") == entry_hash)]

    def _entry_integrity_status(self, entry):
        issues = self._issues_for_entry(entry)
        if issues:
            return "Issue identified by persisted verification result"
        verification = _verification(self.result)
        valid = _first_value(verification.get("valid"), self.result.get("valid"))
        if valid is True:
            return "Included in the valid persisted chain result"
        if valid is False:
            return "Chain inconsistency reported; this entry was not individually identified"
        return "Not individually reported"

    def _source_button_text(self, source):
        route = _source_route(source)
        return f"Open {route[1]}" if route else f"Source: {_text(source)} · no dedicated workspace"

    def move(self, delta):
        target = self.entry_index + delta
        if 0 <= target < len(self.entries):
            self.entry_index = target
            self.render()

    def open_source(self, source):
        route = _source_route(source)
        if route and self.on_navigate:
            self.accept(); self.on_navigate(route[0])

    def open_evidence(self, entry):
        issues = self._issues_for_entry(entry)
        summary = f"Persisted { _text(entry.get('event_type'))} event at sequence {_text(entry.get('sequence'))}. This view does not rerun C4 verification."
        details = {"entry": entry, "persisted_verification": _verification(self.result), "entry_issues": issues}
        EvidenceViewerDialog("Audit entry evidence", summary, "\n".join(f"{key}: {_text(value)}" for key, value in entry.items()), details, self).exec()


class AuditFindingDialog(QDialog):
    def __init__(self, finding: dict[str, Any], *, on_navigate=None, parent=None):
        super().__init__(parent)
        self.finding = finding
        self.on_navigate = on_navigate
        self.setWindowTitle(f"Audit finding · {_text(finding.get('finding_id'))}")
        self.resize(760, 620)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(_text(finding.get("title"), "Audit-trail finding")))
        card = SectionCard("Finding identity and assessment")
        for label, key in (("Finding ID", "finding_id"), ("Category", "category"), ("Severity", "severity"), ("Confidence", "confidence"), ("Source engine", "source_engine"), ("Affected asset", "affected_asset")):
            value = _text(finding.get(key))
            card.content.addWidget(SeverityBadge(value) if key == "severity" else QLabel(f"{label}: {value}"))
        layout.addWidget(card)
        explanation = SectionCard("What was observed"); explanation.content.addWidget(QLabel(_text(finding.get("explanation")))); layout.addWidget(explanation)
        evidence_rows = _evidence_rows(finding.get("evidence"))
        evidence = SectionCard("Persisted evidence"); evidence.content.addWidget(AnalystTable(["Evidence item", "Persisted value"], evidence_rows or [["Evidence", "No evidence was recorded."]])); layout.addWidget(evidence)
        action = SectionCard("Recommended action and limitations")
        action.content.addWidget(QLabel("Recommended action: " + _text(finding.get("recommended_action"))))
        limitations = finding.get("limitations")
        action.content.addWidget(QLabel("Limitations:\n" + ("\n".join(f"• {item}" for item in limitations) if isinstance(limitations, list) else _text(limitations))))
        layout.addWidget(action)
        row = QHBoxLayout()
        self.source_button = QPushButton("Open Audit Trail")
        self.source_button.setEnabled(bool(on_navigate))
        self.source_button.clicked.connect(lambda: (self.accept(), on_navigate(6)) if on_navigate else None)
        row.addWidget(self.source_button)
        self.evidence_button = QPushButton("Open Evidence Viewer")
        self.evidence_button.clicked.connect(lambda: EvidenceViewerDialog("Audit finding evidence", _text(finding.get("explanation")), "\n".join(f"{a}: {b}" for a, b in evidence_rows), finding, self).exec())
        row.addWidget(self.evidence_button)
        close = QPushButton("Back"); close.clicked.connect(self.accept); row.addWidget(close); layout.addLayout(row)


class AuditWorkspace(QWidget):
    """Analyst workspace backed exclusively by persisted C4/C3 assessment data."""
    def __init__(self, assessment: dict[str, Any] | None, result: Any, findings: Any = None,
                 *, on_navigate: Callable[[int], None] | None = None, parent=None):
        super().__init__(parent)
        self.assessment = assessment if isinstance(assessment, dict) else {}
        self.malformed_result = result is not None and not isinstance(result, dict)
        self.result = result if isinstance(result, dict) else {}
        raw_entries = self.result.get("entries")
        self.entries_available = isinstance(raw_entries, list)
        self.malformed_entries = self.entries_available and any(not isinstance(item, dict) for item in raw_entries)
        self.entries = [dict(item) for item in raw_entries if isinstance(item, dict)] if isinstance(raw_entries, list) else []
        self.findings = self._audit_findings(findings)
        self.on_navigate = on_navigate
        self.state = "PARTIAL" if self.malformed_result else audit_state(self.result, self.assessment.get("engines"))
        self._build()

    @staticmethod
    def _audit_findings(value):
        if not isinstance(value, list):
            return []
        related = []
        for item in value:
            if not isinstance(item, dict):
                continue
            source = str(item.get("source_engine", "")).upper()
            category = str(item.get("category", "")).lower().replace("-", "_")
            if source == "C4" or category in {"audit", "audit_trail", "audit_integrity", "audit_chain", "provenance_integrity"}:
                related.append(item)
        return related

    def _build(self):
        outer = QVBoxLayout(self); outer.setContentsMargins(24, 20, 24, 24); outer.setSpacing(12)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); outer.addWidget(scroll)
        body = QWidget(); layout = QVBoxLayout(body); layout.setSpacing(12); scroll.setWidget(body)
        title = QLabel("Audit Trail Integrity"); title.setObjectName("pageTitle"); layout.addWidget(title)
        if not self.assessment:
            card = SectionCard("No assessment selected"); card.content.addWidget(QLabel("Open a saved assessment to inspect persisted C4 audit evidence.")); layout.addWidget(card); return

        engine_records = self.assessment.get("engines") if isinstance(self.assessment.get("engines"), dict) else {}
        engine_record = engine_records.get("C4_audit_trail") if isinstance(engine_records.get("C4_audit_trail"), dict) else {}
        verification = _verification(self.result)
        valid = _first_value(verification.get("valid"), self.result.get("valid"))
        issues = _issue_list(self.result)
        integrity_state = "VALID" if valid is True else "INCONSISTENCY REPORTED" if valid is False else "NOT REPORTED"
        digest_ref = self.result.get("evidence")
        result_digest = self.result.get("result_digest") or (digest_ref.get("sha256") if isinstance(digest_ref, dict) else None)
        overview = SectionCard("Audit integrity overview")
        overview.content.addWidget(QLabel(
            f"Assessment: {_text(self.assessment.get('name'))}\n"
            f"Assessment ID: {_text(self.assessment.get('assessment_id'))}\n"
            f"Assessment status: {_text(self.assessment.get('status')).replace('_', ' ').upper()}\n"
            f"C4 status: {self.state}"
        ))
        overview.content.addWidget(SeverityBadge(self.state))
        if self.state == "UNAVAILABLE":
            overview.content.addWidget(QLabel("Audit trail assessment is not available for this assessment."))
        elif self.state == "PARTIAL" or self.malformed_entries:
            overview.content.addWidget(QLabel("Stored audit-trail evidence could not be interpreted completely. Valid entries remain available below."))
        elif self.state == "FAILED":
            overview.content.addWidget(QLabel(_text(self.result.get("reason") or engine_record.get("reason"), "C4 failed; inspect technical details.")))
        elif self.result.get("message"):
            overview.content.addWidget(QLabel(_text(self.result.get("message"))))
        overview.content.addWidget(MetricCard("Persisted audit entries", str(len(self.entries)), "Entries stored with this assessment"))
        overview.content.addWidget(SeverityBadge(f"Chain verification: {integrity_state}", "valid" if valid is True else "invalid" if valid is False else "unavailable"))
        overview.content.addWidget(SeverityBadge(f"Verification details: {len(issues)} persisted issue record(s)" if issues else ("Verification details: no inconsistency reported" if valid is True else "Verification details: unavailable"), "info"))
        digest_label = "Base C4 result digest" if self.result.get("audit_digest_scope") else "Result digest"
        overview.content.addWidget(SeverityBadge(f"{digest_label}: {result_digest or 'Unavailable'}", "info"))
        if self.result.get("audit_digest_scope"):
            overview.content.addWidget(QLabel(str(self.result["audit_digest_scope"])))
        layout.addWidget(overview)

        integrity = SectionCard("Chain integrity checks")
        check_rows = self._integrity_rows(valid, issues)
        integrity.content.addWidget(AnalystTable(["Check", "Persisted result", "Evidence"], check_rows))
        if valid is False:
            integrity.content.addWidget(QLabel("Audit-chain integrity verification reported an inconsistency. The stored result does not by itself identify who or what caused it."))
        elif valid is True:
            integrity.content.addWidget(QLabel("The persisted verifier marked the recorded chain valid under its implemented checks. This is not attribution and does not cover events outside the recorded chain."))
        else:
            integrity.content.addWidget(QLabel("Verification status is unavailable; missing verification evidence is not a passing result."))
        layout.addWidget(integrity)

        timeline = SectionCard("Persisted audit timeline")
        controls = QHBoxLayout()
        self.search = QComboBox(); self.search.setEditable(True); self.search.setInsertPolicy(QComboBox.InsertPolicy.NoInsert); self.search.lineEdit().setPlaceholderText("Search event ID, type, source, asset, sequence, timestamp…")
        self.type_filter = QComboBox(); self.type_filter.addItems(["All event types", *sorted({str(item.get("event_type") or "Unavailable") for item in self.entries}, key=str.casefold)])
        self.source_filter = QComboBox(); self.source_filter.addItems(["All sources", *sorted({str(item.get("source_engine") or "Unavailable") for item in self.entries}, key=str.casefold)])
        self.asset_filter = QComboBox(); self.asset_filter.addItems(["All affected assets", *sorted({str(item.get("affected_asset") or "Unavailable") for item in self.entries}, key=str.casefold)])
        self.integrity_filter = QComboBox(); self.integrity_filter.addItems(["All integrity states", "Issue identified", "No issue reported", "Not reported"])
        self.sort_by = QComboBox(); self.sort_by.addItems(["Sequence", "Timestamp", "Event type"])
        self.sort_order = QComboBox(); self.sort_order.addItems(["Ascending", "Descending"])
        for control in (self.search, self.type_filter, self.source_filter, self.asset_filter, self.integrity_filter, self.sort_by, self.sort_order): controls.addWidget(control)
        self.clear_button = QPushButton("Clear Filters"); self.clear_button.clicked.connect(self.clear_filters); controls.addWidget(self.clear_button)
        timeline.content.addLayout(controls)
        self.entry_table = QTableWidget(0, 7); self.entry_table.setHorizontalHeaderLabels(["Sequence", "Timestamp", "Event type", "Source engine", "Affected asset", "Event ID", "Chain status"])
        self.entry_table.setAlternatingRowColors(True); self.entry_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows); self.entry_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers); self.entry_table.verticalHeader().setVisible(False)
        timeline.content.addWidget(self.entry_table); self.entry_table.cellDoubleClicked.connect(self.open_entry_row)
        audit_actions = QHBoxLayout()
        self.inspect_entry_button = QPushButton("Inspect Selected Entry"); self.inspect_entry_button.clicked.connect(lambda: self.open_entry_row(self.entry_table.currentRow(), 0))
        export_audit_pdf_btn = QPushButton("Export Audit Trail PDF"); export_audit_pdf_btn.clicked.connect(self._export_audit_pdf)
        audit_actions.addWidget(self.inspect_entry_button); audit_actions.addWidget(export_audit_pdf_btn); audit_actions.addStretch()
        timeline.content.addLayout(audit_actions)
        if not self.entries:
            timeline.content.addWidget(QLabel("No persisted audit entries are available. This does not establish that activity outside this stored chain was absent."))
        layout.addWidget(timeline)

        finding_card = SectionCard("Persisted C3 audit-trail findings")
        self.finding_table = QTableWidget(0, 6); self.finding_table.setHorizontalHeaderLabels(["Severity", "Confidence", "Title", "Affected asset", "Source engine", "Finding ID"])
        self.finding_table.setAlternatingRowColors(True); self.finding_table.setSelectionBehavior(QTableWidget.SelectRows); self.finding_table.setEditTriggers(QTableWidget.NoEditTriggers); self.finding_table.verticalHeader().setVisible(False)
        for row, item in enumerate(self.findings):
            self.finding_table.insertRow(row)
            self.finding_table.setCellWidget(row, 0, SeverityBadge(_text(item.get("severity")).upper()))
            values = (_text(item.get("confidence")), _text(item.get("title")), _text(item.get("affected_asset")), _text(item.get("source_engine")), _text(item.get("finding_id")))
            for column, value in enumerate(values, 1): self.finding_table.setItem(row, column, QTableWidgetItem(value))
            self.finding_table.item(row, 5).setData(Qt.ItemDataRole.UserRole, row)
        finding_card.content.addWidget(self.finding_table)
        if not self.findings:
            finding_card.content.addWidget(QLabel("No persisted audit-trail findings were recorded. This is not proof that the audit trail is secure."))
        self.open_finding_button = QPushButton("Investigate Selected Finding"); self.open_finding_button.setEnabled(bool(self.findings)); self.open_finding_button.clicked.connect(lambda: self.open_finding_row(self.finding_table.currentRow(), 0)); finding_card.content.addWidget(self.open_finding_button)
        layout.addWidget(finding_card)

        limitations = SectionCard("Interpretation and limitations")
        for text in (
            "A valid chain establishes consistency only according to the implemented verification rules.",
            "A broken chain indicates an integrity inconsistency in recorded evidence; it does not establish cause, attribution, or malicious intent.",
            "Audit evidence may be incomplete, and absence of a detected inconsistency does not establish integrity outside the recorded chain.",
        ):
            label = QLabel("• " + text); label.setWordWrap(True); limitations.content.addWidget(label)
        layout.addWidget(limitations)

        technical = SectionCard("Technical details")
        technical.content.addWidget(QLabel(
            f"C4 engine status: {_text(engine_record.get('status'), self.result.get('status', 'Unavailable'))}\n"
            f"Engine version: {_text(self.result.get('engine_version'))}\n"
            f"Method: {_text(self.result.get('method'))}\n"
            f"Persisted entry count: {_text(self.result.get('entry_count'))}\n"
            f"Verification result: {_text(valid)}\n"
            f"Result digest: {_text(result_digest)}\n"
            f"Digest scope: {_text(self.result.get('audit_digest_scope'))}\n"
            f"Verification error: {_text(self.result.get('reason') or verification.get('error'))}"
        ))
        self.technical_button = QPushButton("Open C4 Evidence")
        self.technical_button.clicked.connect(lambda: EvidenceViewerDialog("C4 persisted audit chain", f"Persisted status: {self.state}; entries: {len(self.entries)}; chain verification: {integrity_state}.", "\n".join(f"{key}: {_text(value)}" for key, value in self.result.items() if key != "entries") or "No technical evidence was recorded.", self.result, self).exec())
        technical.content.addWidget(self.technical_button); layout.addWidget(technical)
        self.search.lineEdit().textChanged.connect(self.apply_filters)
        for control in (self.type_filter, self.source_filter, self.asset_filter, self.integrity_filter, self.sort_by, self.sort_order): control.currentTextChanged.connect(self.apply_filters)
        self._render_entries()
        layout.addStretch()

    def _integrity_rows(self, valid, issues):
        by_type: dict[str, list[dict[str, Any]]] = {}
        for issue in issues:
            by_type.setdefault(str(issue.get("type", "unknown")), []).append(issue)
        result = []
        for key, label in ISSUE_LABELS.items():
            matches = by_type.get(key, [])
            if matches:
                evidence = "; ".join(_text(item.get("message"), key.replace("_", " ")) for item in matches)
                state = f"Reported ({len(matches)})"
            elif valid is True:
                state, evidence = "No issue reported", "Covered by the persisted valid chain result; no per-check record was stored."
            elif valid is False:
                state, evidence = "Not specified", "The persisted result reports an inconsistency but does not identify this check."
            else:
                state, evidence = "Unavailable", "No persisted check detail is available."
            result.append([label, state, evidence])
        return result

    def _entry_status(self, entry):
        sequence = entry.get("sequence")
        event_id = entry.get("event_id")
        entry_hash = entry.get("entry_hash")
        matches = [item for item in _issue_list(self.result)
                   if (sequence is not None and item.get("sequence") == sequence)
                   or (event_id is not None and item.get("event_id") == event_id)
                   or (entry_hash is not None and item.get("entry_hash") == entry_hash)]
        if matches:
            return "Issue identified"
        valid = _first_value(_verification(self.result).get("valid"), self.result.get("valid"))
        if valid is True:
            return "No issue reported"
        if valid is False:
            return "Not individually identified"
        return "Not reported"

    def _render_entries(self):
        entries = list(enumerate(self.entries))
        mode = self.sort_by.currentText() if hasattr(self, "sort_by") else "Sequence"
        descending = self.sort_order.currentText() == "Descending" if hasattr(self, "sort_order") else False
        if mode == "Timestamp": entries.sort(key=lambda pair: str(pair[1].get("timestamp", "")), reverse=descending)
        elif mode == "Event type": entries.sort(key=lambda pair: str(pair[1].get("event_type", "")).casefold(), reverse=descending)
        else:
            def sequence_key(pair):
                sequence = pair[1].get("sequence")
                if isinstance(sequence, (int, float)):
                    return (0, float(sequence))
                if sequence is None:
                    return (2, "")
                return (1, str(sequence).casefold())
            entries.sort(key=sequence_key, reverse=descending)
        self.visible_entry_indices = [index for index, _entry in entries]
        self.entry_table.setRowCount(len(entries))
        needle = self.search.currentText().casefold().strip()
        event_type, source, asset, state = self.type_filter.currentText(), self.source_filter.currentText(), self.asset_filter.currentText(), self.integrity_filter.currentText()
        for row, (index, entry) in enumerate(entries):
            status = self._entry_status(entry)
            values = [_text(entry.get("sequence")), _text(entry.get("timestamp")), _text(entry.get("event_type")), _text(entry.get("source_engine")), _text(entry.get("affected_asset")), _text(entry.get("event_id")), status]
            for column, value in enumerate(values):
                self.entry_table.setItem(row, column, QTableWidgetItem(value))
            self.entry_table.item(row, 0).setData(Qt.ItemDataRole.UserRole, index)
            visible = ((not needle or needle in _entry_search_text(entry))
                       and (event_type == "All event types" or str(entry.get("event_type") or "Unavailable") == event_type)
                       and (source == "All sources" or str(entry.get("source_engine") or "Unavailable") == source)
                       and (asset == "All affected assets" or str(entry.get("affected_asset") or "Unavailable") == asset)
                       and (state == "All integrity states" or (state == "Issue identified" and status == "Issue identified")
                            or (state == "No issue reported" and status == "No issue reported")
                            or (state == "Not reported" and status in {"Not reported", "Not individually identified"})))
            self.entry_table.setRowHidden(row, not visible)
        self.entry_table.resizeColumnsToContents(); self.entry_table.horizontalHeader().setStretchLastSection(True)

    def apply_filters(self, *_):
        self._render_entries()

    def clear_filters(self):
        self.search.setEditText("")
        for control in (self.type_filter, self.source_filter, self.asset_filter, self.integrity_filter, self.sort_by, self.sort_order): control.setCurrentIndex(0)
        self._render_entries()

    def open_entry_row(self, row: int, _column: int):
        if not 0 <= row < self.entry_table.rowCount(): return
        item = self.entry_table.item(row, 0)
        index = item.data(Qt.ItemDataRole.UserRole) if item else None
        if isinstance(index, int) and 0 <= index < len(self.entries):
            AuditEntryDialog(self.entries, index, self.result, on_navigate=self.on_navigate, parent=self).exec()

    def open_finding_row(self, row: int, _column: int):
        if not 0 <= row < self.finding_table.rowCount(): return
        item = self.finding_table.item(row, 5)
        index = item.data(Qt.ItemDataRole.UserRole) if item else None
        if isinstance(index, int) and 0 <= index < len(self.findings):
            AuditFindingDialog(self.findings[index], on_navigate=self.on_navigate, parent=self).exec()

    def _export_audit_pdf(self):
        from desktop.reporting import write_section_pdf
        from PySide6.QtWidgets import QFileDialog, QMessageBox
        from pathlib import Path
        target, _ = QFileDialog.getSaveFileName(
            self, "Export Audit Trail PDF", "audit_trail_report.pdf", "PDF (*.pdf)"
        )
        if not target:
            return
        try:
            assessment_id = str(self.assessment.get("assessment_id", "")) if self.assessment else ""
            rows = [
                ("Chain status", self.state),
                ("Entry count", str(len(self.entries))),
                ("Integrity", "Valid" if self.result.get("valid") is True else
                              "Invalid" if self.result.get("valid") is False else "Unavailable"),
            ]
            for entry in self.entries[:30]:
                if isinstance(entry, dict):
                    rows.append((
                        f"#{entry.get('sequence', '?')} · {entry.get('timestamp', '—')}",
                        f"{entry.get('event_type', '—')} · {entry.get('source_engine', '—')} · "
                        f"{entry.get('affected_asset', '—')}",
                    ))
            result = write_section_pdf(
                "Audit Trail Report",
                {"description": f"C4 tamper-evident audit chain from assessment {assessment_id}.",
                 "rows": rows},
                target,
                assessment_id=assessment_id,
            )
            QMessageBox.information(
                self, "Export complete",
                f"PDF saved: {Path(result['path']).name}\nSHA-256: {result['sha256'][:32]}…",
            )
        except Exception as exc:
            QMessageBox.warning(self, "PDF export failed", str(exc))
