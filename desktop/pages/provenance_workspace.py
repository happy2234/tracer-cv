"""Assessment-backed C1 inference provenance analyst workspace."""
from __future__ import annotations

import json
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox, QDialog, QHBoxLayout, QLabel, QPushButton, QScrollArea,
    QVBoxLayout, QWidget,
)

from desktop.widgets.components import AnalystTable, EvidenceViewerDialog, SectionCard, SeverityBadge


def _evidence_rows(items: list[Any]) -> list[list[str]]:
    rows: list[list[str]] = []
    for evidence in items:
        if isinstance(evidence, dict):
            source = str(evidence.get("source", "C1"))
            data = evidence.get("data", evidence)
            if isinstance(data, dict):
                for key, value in data.items():
                    rendered = ", ".join(str(part) for part in value) if isinstance(value, list) else str(value)
                    rows.append((str(key).replace("_", " ").capitalize(), rendered, source))
            else:
                rows.append(("Recorded evidence", str(data), source))
        else:
            rows.append(("Recorded evidence", str(evidence), "C1"))
    return rows


def provenance_status(result: Any, engine_records: Any = None) -> str:
    """Map persisted C1 state without treating missing evidence as success."""
    records = engine_records if isinstance(engine_records, dict) else {}
    record = records.get("C1_provenance", {}) if isinstance(records.get("C1_provenance", {}), dict) else {}
    result_data = result if isinstance(result, dict) else {}
    result_missing = not result_data or result_data.get("status") == "unavailable"
    raw = str(record.get("status", result_data.get("status", "unavailable"))).lower()
    if result_missing and raw in {"completed", "completed_with_warnings", "completed_with_errors"}:
        return "UNAVAILABLE"
    if result_missing and raw not in {"not_assessed", "unavailable", "error", "failed", "running", "queued", "created", "cancelled"}:
        return "UNAVAILABLE"
    if raw in {"completed", "completed_with_warnings", "completed_with_errors"}:
        if "records" not in result or not isinstance(result.get("records"), list):
            return "PARTIAL / INCOMPLETE"
        if any(not isinstance(item, dict) for item in result["records"]):
            return "PARTIAL / INCOMPLETE"
        if raw == "completed" and not isinstance(result.get("verification"), dict):
            return "PARTIAL / INCOMPLETE"
    return {
        "completed": "COMPLETED", "completed_with_warnings": "COMPLETED WITH WARNINGS",
        "completed_with_errors": "COMPLETED WITH WARNINGS", "failed": "FAILED", "error": "FAILED",
        "not_assessed": "NOT ASSESSED", "unavailable": "UNAVAILABLE", "running": "RUNNING",
        "queued": "QUEUED", "cancelled": "CANCELLED",
    }.get(raw, raw.upper() or "UNAVAILABLE")


def _short(value: Any, size: int = 18) -> str:
    if not isinstance(value, str) or not value:
        return "Not recorded"
    return value if len(value) <= size else f"{value[:size]}…{value[-6:]}"


def _verification_issues(result: dict[str, Any]) -> list[dict[str, Any]]:
    verification = result.get("verification")
    if not isinstance(verification, dict):
        return []
    findings = verification.get("findings")
    return [item for item in findings if isinstance(item, dict)] if isinstance(findings, list) else []


def _issue_for_record(record: dict[str, Any], index: int, issues: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seq = record.get("sequence")
    return [item for item in issues if item.get("sequence") == seq or item.get("index") == index]


class ProvenanceRecordDialog(QDialog):
    def __init__(self, record: dict[str, Any], index: int, chain_state: str, issues: list[dict[str, Any]], parent=None):
        super().__init__(parent)
        self.record = record
        self.setWindowTitle(f"Provenance record · sequence {record.get('sequence', 'not recorded')}")
        self.resize(780, 650)
        outer = QVBoxLayout(self)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); outer.addWidget(scroll)
        body = QWidget(); layout = QVBoxLayout(body); scroll.setWidget(body)
        situation = SectionCard("Record situation")
        situation.content.addWidget(QLabel(f"Chain position: {index + 1}\nLink evidence: {chain_state}"))
        if issues:
            situation.content.addWidget(QLabel("\n".join(str(item.get("message", item.get("type", "Integrity evidence recorded."))) for item in issues)))
        layout.addWidget(situation)
        identity = SectionCard("Identity")
        identity.content.addWidget(AnalystTable(["Field", "Recorded value"], [
            ["Sequence", record.get("sequence", "Not recorded")], ["Timestamp", record.get("timestamp", "Not recorded")],
            ["Nonce", record.get("nonce", "Not recorded")], ["Model ID", record.get("model_id", "Not recorded")],
        ]))
        layout.addWidget(identity)
        bindings = SectionCard("Input and output bindings")
        bindings.content.addWidget(AnalystTable(["Binding", "Digest"], [
            ["Input", record.get("input_digest", "Not recorded")],
            ["Preprocessing", record.get("preprocessing_digest", "Not recorded")],
            ["Output", record.get("output_digest", "Not recorded")],
        ]))
        layout.addWidget(bindings)
        chain = SectionCard("Chain and authentication")
        chain.content.addWidget(AnalystTable(["Field", "Recorded value"], [
            ["Previous record hash", record.get("previous_record_hash", "Not recorded")],
            ["Record hash", record.get("record_hash", "Not recorded")],
            ["Signature", record.get("signature") or "Unsigned"],
            ["Signature verification", "Unavailable" if not record.get("signature") else "Not recorded"],
        ]))
        layout.addWidget(chain)
        button = QPushButton("Technical Details")
        button.clicked.connect(lambda: EvidenceViewerDialog("Provenance record evidence",
            "This record binds inference input, model, preprocessing, and output digests with sequence and chain information.",
            "Cryptographic fields are shown as recorded. A chain inconsistency does not identify its cause or actor.", record, self).exec())
        layout.addWidget(button)
        close = QPushButton("Close"); close.clicked.connect(self.accept); outer.addWidget(close)


class ProvenanceFindingDialog(QDialog):
    def __init__(self, finding: dict[str, Any], parent=None):
        super().__init__(parent)
        self.finding = finding
        self.setWindowTitle(f"Provenance finding · {finding.get('finding_id', 'Finding')}")
        self.resize(780, 650)
        layout = QVBoxLayout(self)
        title = QLabel(str(finding.get("title", "Provenance finding"))); title.setObjectName("pageTitle"); layout.addWidget(title)
        layout.addWidget(SeverityBadge(str(finding.get("severity", "NOT ASSIGNED"))))
        card = SectionCard("Finding")
        for label, key in (("Finding ID", "finding_id"), ("Category", "category"), ("Confidence", "confidence"),
                           ("Affected asset", "affected_asset"), ("Source engine", "source_engine")):
            card.content.addWidget(QLabel(f"{label}: {finding.get(key, 'Not recorded')}"))
        layout.addWidget(card)
        explanation = SectionCard("Why this was flagged")
        explanation.content.addWidget(QLabel(str(finding.get("explanation", "No explanation was recorded."))))
        layout.addWidget(explanation)
        evidence = finding.get("evidence") if isinstance(finding.get("evidence"), list) else []
        evidence_card = SectionCard("Evidence")
        rows = _evidence_rows(evidence)
        evidence_card.content.addWidget(AnalystTable(["Evidence item", "Recorded value", "Source"], rows or [["Evidence", "No structured evidence recorded", "C1"]]))
        layout.addWidget(evidence_card)
        for label, key in (("Recommended action", "recommended_action"), ("Limitations", "limitations")):
            part = SectionCard(label); part.content.addWidget(QLabel(str(finding.get(key, "Not recorded")))); layout.addWidget(part)
        self.evidence_button = QPushButton("Technical Details")
        self.evidence_button.clicked.connect(lambda: EvidenceViewerDialog("Provenance finding evidence",
            str(finding.get("explanation", "Recorded provenance evidence.")),
            json.dumps(evidence, ensure_ascii=False, indent=2, default=str) if evidence else "No structured evidence recorded.", finding, self).exec())
        layout.addWidget(self.evidence_button)
        close = QPushButton("Close"); close.clicked.connect(self.accept); layout.addWidget(close)


class ProvenanceWorkspace(QWidget):
    """Read-only analyst presentation of persisted C1 records and C3 findings."""
    def __init__(self, assessment: dict[str, Any] | None, result: Any, findings: list[dict[str, Any]] | None, parent=None):
        super().__init__(parent)
        self.assessment = assessment if isinstance(assessment, dict) else {}
        self.result = result if isinstance(result, dict) else {}
        self.findings_available = isinstance(findings, list)
        self.findings = [item for item in (findings or []) if isinstance(item, dict)
                         and str(item.get("source_engine", "")).upper() == "C1"]
        self.records = self.result.get("records") if isinstance(self.result.get("records"), list) else []
        self.issues = _verification_issues(self.result)
        self._build()

    def _build(self):
        outer = QVBoxLayout(self); outer.setContentsMargins(24, 20, 24, 24); outer.setSpacing(12)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); outer.addWidget(scroll)
        body = QWidget(); layout = QVBoxLayout(body); layout.setSpacing(12); scroll.setWidget(body)
        heading = QLabel("Inference Provenance"); heading.setObjectName("pageTitle"); layout.addWidget(heading)
        if not self.assessment:
            card = SectionCard("No assessment selected"); card.content.addWidget(QLabel("Open a saved assessment to inspect its persisted C1 provenance evidence.")); layout.addWidget(card); return

        state = provenance_status(self.result, self.assessment.get("engines"))
        overview = SectionCard("Provenance overview")
        assessment_status = str(self.assessment.get("status", "Not recorded")).replace("_", " ").upper()
        overview.content.addWidget(QLabel(f"Assessment: {self.assessment.get('name', 'Unnamed assessment')}\nAssessment ID: {self.assessment.get('assessment_id', 'Not recorded')}\nAssessment status: {assessment_status}\nC1 status: {state}"))
        verification = self.result.get("verification") if isinstance(self.result.get("verification"), dict) else None
        chain_state = "VERIFIED" if verification and verification.get("valid") is True else "FAILED" if verification and verification.get("valid") is False else "UNAVAILABLE"
        signature_values = [record.get("signature") for record in self.records if isinstance(record, dict)]
        signature_state = ("UNSIGNED" if signature_values and all(not value for value in signature_values)
                           else "PRESENT · VERIFICATION UNAVAILABLE" if any(signature_values) else "UNAVAILABLE")
        replay_state = self.result.get("replay_detection")
        replay_text = "Unavailable" if replay_state is None else str(replay_state.get("status", "Recorded")) if isinstance(replay_state, dict) else str(replay_state)
        overview.content.addWidget(QLabel(f"Records: {len(self.records) if 'records' in self.result else 'Not recorded'}\nChain verification: {chain_state}\nSignature evidence: {signature_state}\nReplay detection: {replay_text}\nSequence continuity: {'Recorded valid' if verification and verification.get('valid') is True else 'Review findings or unavailable'}"))
        overview.content.addWidget(SeverityBadge(state))
        if state == "PARTIAL / INCOMPLETE":
            overview.content.addWidget(QLabel("The persisted C1 result is incomplete or malformed. Missing fields are not treated as verified evidence."))
        elif state == "UNAVAILABLE" and self.result.get("message"):
            overview.content.addWidget(QLabel("The persisted C1 result could not be loaded. Recorded parsing or storage details are available under Technical Details."))
        elif state in {"UNAVAILABLE", "NOT ASSESSED"}:
            overview.content.addWidget(QLabel(str(self.result.get("reason") or "C1 provenance evidence is unavailable or was not assessed.")))
        if state in {"COMPLETED WITH WARNINGS", "FAILED"}:
            overview.content.addWidget(QLabel("The assessment did not produce an unqualified completed C1 result. Review recorded engine reasons and evidence."))
        if not self.result:
            overview.content.addWidget(QLabel("Persisted C1 result is unavailable for this assessment."))
        layout.addWidget(overview)

        integrity = SectionCard("Chain integrity")
        if verification is None:
            integrity.content.addWidget(QLabel("Chain verification evidence is unavailable; no verification state is inferred."))
        else:
            integrity.content.addWidget(QLabel(f"Persisted record hash and chain verification: {chain_state}\nRecords checked: {verification.get('record_count', 'Not recorded')}"))
            if self.issues:
                integrity.content.addWidget(AnalystTable(["Evidence type", "Sequence", "Recorded explanation"], [
                    [item.get("type", "Integrity evidence"), item.get("sequence", "Not recorded"), item.get("message", "No explanation recorded")]
                    for item in self.issues]))
            elif verification.get("valid") is True:
                integrity.content.addWidget(QLabel("The persisted verifier reported the available record chain as valid."))
            else:
                integrity.content.addWidget(QLabel("The persisted verifier did not report a valid chain."))
        if replay_state is None:
            integrity.content.addWidget(QLabel("Replay detection evidence unavailable."))
        if signature_state == "UNSIGNED":
            integrity.content.addWidget(QLabel("Records are unsigned. No signing key or signature verification evidence was recorded; unsigned status alone is not evidence of misuse."))
        layout.addWidget(integrity)

        chain = SectionCard("Provenance chain")
        if not self.records:
            reason = self.result.get("reason") or ("No provenance records were persisted." if self.result else "C1 result is missing or unavailable.")
            chain.content.addWidget(QLabel(str(reason)))
        else:
            rows = []
            for index, item in enumerate(self.records):
                if not isinstance(item, dict):
                    rows.append([str(index + 1), "Malformed record", "Not recorded", "Not recorded", "Not recorded", "Partial"]); continue
                issues = _issue_for_record(item, index, self.issues)
                link = "BROKEN / REVIEW" if issues else "VALIDATED" if verification and verification.get("valid") is True else "NOT VERIFIED"
                sig = "UNSIGNED" if not item.get("signature") else "Signature present; verification status not recorded"
                rows.append([str(item.get("sequence", "Not recorded")), str(item.get("timestamp", "Not recorded")),
                             _short(item.get("model_id")), _short(item.get("output_digest")), _short(item.get("record_hash")), f"{link} · {sig}"])
            self.chain_table = AnalystTable(["Sequence", "Timestamp", "Model ID", "Output digest", "Record hash", "Integrity / signature"], rows)
            self.chain_table.cellDoubleClicked.connect(self.open_record_row)
            genesis = self.records[0].get("previous_record_hash") if isinstance(self.records[0], dict) else None
            chain.content.addWidget(QLabel(f"GENESIS · predecessor hash {_short(genesis)}\n↓\nRecords shown in persisted sequence order. Select a row to inspect its recorded bindings and full hash fields."))
            chain.content.addWidget(self.chain_table)
            button = QPushButton("Open Selected Record"); button.clicked.connect(lambda: self.open_record_row(self.chain_table.currentRow(), 0)); chain.content.addWidget(button)
        layout.addWidget(chain)

        findings_card = SectionCard("C3 provenance findings")
        controls = QHBoxLayout()
        self.finding_search = QComboBox(); self.finding_search.setEditable(True); self.finding_search.setInsertPolicy(QComboBox.InsertPolicy.NoInsert); self.finding_search.lineEdit().setPlaceholderText("Search finding ID, category, title…")
        self.severity_filter = QComboBox(); self.severity_filter.addItems(["All severities", *sorted({str(x.get('severity', 'NOT ASSIGNED')).upper() for x in self.findings})])
        self.sort_by = QComboBox(); self.sort_by.addItems(["Severity", "Finding", "Confidence"])
        controls.addWidget(self.finding_search); controls.addWidget(self.severity_filter); controls.addWidget(self.sort_by); findings_card.content.addLayout(controls)
        self.finding_table_layout = findings_card.content
        self._render_findings()
        if not self.findings:
            findings_card.content.addWidget(QLabel("No persisted C1 provenance findings are recorded." if self.findings_available else "C3 findings are unavailable for this assessment."))
        layout.addWidget(findings_card)

        technical = SectionCard("Technical details")
        engine_record = self.assessment.get("engines", {}).get("C1_provenance", {}) if isinstance(self.assessment.get("engines"), dict) else {}
        technical.content.addWidget(QLabel(f"Engine status: {engine_record.get('status', self.result.get('status', 'Not recorded'))}\nEngine version: {self.result.get('engine_version', 'Not recorded')}\nMethod: {self.result.get('method', 'Not recorded')}\nResult digest: {engine_record.get('evidence', 'Not recorded')}\nLoad detail: {self.result.get('message', self.result.get('technical_error', 'Not recorded'))}"))
        evidence = QPushButton("Open C1 Evidence"); evidence.clicked.connect(lambda: EvidenceViewerDialog("C1 provenance evidence",
            "C1 binds recorded inference inputs, model identity, preprocessing, outputs, and chain metadata using local cryptographic evidence.",
            f"Status: {state}; persisted records: {len(self.records)}; chain verification: {chain_state}; signatures: {signature_state}; replay detection: {replay_text}.", self.result, self).exec())
        technical.content.addWidget(evidence); layout.addWidget(technical)
        self.finding_search.lineEdit().textChanged.connect(self.apply_finding_filters)
        self.severity_filter.currentTextChanged.connect(self.apply_finding_filters)
        self.sort_by.currentTextChanged.connect(self._render_findings)
        layout.addStretch()

    def open_record_row(self, row: int, _column: int):
        if not 0 <= row < len(self.records): return
        record = self.records[row]
        if not isinstance(record, dict): return
        verification = self.result.get("verification") if isinstance(self.result.get("verification"), dict) else None
        state = "VALIDATED" if verification and verification.get("valid") is True else "NOT VERIFIED"
        ProvenanceRecordDialog(record, row, state, _issue_for_record(record, row, self.issues), self).exec()

    def open_finding_row(self, row: int, _column: int):
        if not 0 <= row < self.finding_table.rowCount(): return
        index = self.finding_table.item(row, 3).data(Qt.ItemDataRole.UserRole)
        if isinstance(index, int) and 0 <= index < len(self.findings):
            ProvenanceFindingDialog(self.findings[index], self).exec()

    def _render_findings(self):
        if hasattr(self, "finding_table"):
            self.finding_table_layout.removeWidget(self.finding_table)
            self.finding_table.deleteLater()
        indices = list(range(len(self.findings)))
        if self.sort_by.currentText() == "Severity":
            order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
            indices.sort(key=lambda i: order.get(str(self.findings[i].get("severity", "")).upper(), 0), reverse=True)
        elif self.sort_by.currentText() == "Confidence":
            indices.sort(key=lambda i: float(self.findings[i].get("confidence")) if isinstance(self.findings[i].get("confidence"), (int, float)) else -1, reverse=True)
        else:
            indices.sort(key=lambda i: str(self.findings[i].get("title", "")).casefold())
        self.finding_table = AnalystTable(["Severity", "Category", "Confidence", "Finding ID", "Finding"], [
            [str(self.findings[i].get("severity", "NOT ASSIGNED")).upper(), self.findings[i].get("category", "Not recorded"),
             self.findings[i].get("confidence", "Not recorded"), self.findings[i].get("finding_id", "Not recorded"),
             self.findings[i].get("title", "Finding")] for i in indices])
        for row, index in enumerate(indices):
            self.finding_table.item(row, 3).setData(Qt.ItemDataRole.UserRole, index)
        self.finding_table.cellDoubleClicked.connect(self.open_finding_row)
        self.finding_table_layout.addWidget(self.finding_table)
        self.apply_finding_filters()

    def apply_finding_filters(self, *_):
        if not hasattr(self, "finding_table"): return
        needle = self.finding_search.currentText().casefold().strip()
        severity = self.severity_filter.currentText()
        for row in range(self.finding_table.rowCount()):
            item = self.finding_table.item(row, 3)
            index = item.data(Qt.ItemDataRole.UserRole) if item else -1
            if not isinstance(index, int) or not 0 <= index < len(self.findings):
                self.finding_table.setRowHidden(row, True)
                continue
            finding = self.findings[index]
            blob = json.dumps(finding, ensure_ascii=False, default=str).casefold()
            visible = (severity == "All severities" or str(finding.get("severity", "")).upper() == severity) and (not needle or needle in blob)
            self.finding_table.setRowHidden(row, not visible)
