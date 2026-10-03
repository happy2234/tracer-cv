"""Analyst Report Center backed by the persisted C5 assurance report."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from PySide6.QtWidgets import (
    QDialog, QFileDialog, QHBoxLayout, QLabel, QMessageBox, QPushButton,
    QScrollArea, QVBoxLayout, QWidget,
)

from desktop.reporting.report_pdf import display, write_assurance_pdf
from desktop.widgets.components import AnalystTable, EvidenceViewerDialog, SectionCard, SeverityBadge
from backend.core.capabilities import LIMITATIONS as PRODUCT_LIMITATIONS


UNAVAILABLE = "Unavailable"
CORE_REPORT_KEYS = {"assessment_id", "executive_summary", "asset_coverage", "dataset_integrity", "model_integrity",
                    "inference_provenance", "distribution_shift", "findings_and_evidence", "audit_trail",
                    "recommended_actions", "limitations", "report_digest"}


def _text(value: Any, default: str = UNAVAILABLE) -> str:
    if value is None or value == "":
        return default
    if isinstance(value, (dict, list)):
        return display(value)
    return str(value)


def report_findings(report: dict[str, Any]) -> tuple[list[dict[str, Any]], bool]:
    block = report.get("findings_and_evidence")
    if not isinstance(block, dict):
        return [], True
    value = block.get("findings")
    if value is None:
        return [], True
    if not isinstance(value, list):
        return [], True
    invalid_items = any(not isinstance(item, dict) for item in value)
    return [item for item in value if isinstance(item, dict)], invalid_items


def c5_state(assessment: Any, report: Any, report_path: Path | None = None) -> tuple[str, str]:
    if not isinstance(report, dict) or report.get("status") == "unavailable":
        exists = bool(report_path and report_path.is_file())
        if exists:
            return "MALFORMED", "Stored C5 report could not be interpreted."
        return "UNAVAILABLE", "Assurance report is not available for this assessment."
    if not (set(report) & CORE_REPORT_KEYS):
        return "MALFORMED", "Stored C5 report uses an unrecognized schema."
    missing = CORE_REPORT_KEYS - set(report)
    if missing:
        return "PARTIAL", "Stored C5 report is incomplete; unavailable sections are identified below."
    expected_shapes = {
        "executive_summary": dict, "asset_coverage": dict,
        "dataset_integrity": dict, "model_integrity": dict,
        "inference_provenance": dict, "distribution_shift": dict,
        "findings_and_evidence": dict, "audit_trail": dict,
        "recommended_actions": list, "limitations": list,
    }
    if any(not isinstance(report.get(key), shape) for key, shape in expected_shapes.items()):
        return "PARTIAL", "Stored C5 report contains malformed sections; valid persisted sections remain available below."
    assessment_status = str(assessment.get("status", "")).strip().lower() if isinstance(assessment, dict) else ""
    if assessment_status in {"error", "failed"}:
        return "FAILED", "Assessment execution failed; available persisted C5 content is shown as recorded."
    if assessment_status in {"completed_with_errors", "completed_with_warnings"}:
        return "COMPLETED WITH WARNINGS", "Assessment completed with recorded engine warnings or errors."
    if assessment_status in {"completed", "complete"}:
        return "COMPLETED", "Persisted C5 assurance report loaded."
    return "PARTIAL", f"Assessment lifecycle status: {_text(assessment_status)}."


def digest_state(value: Any) -> str:
    digest = str(value or "")
    if len(digest) == 64 and all(char in "0123456789abcdefABCDEF" for char in digest):
        return "Recorded SHA-256-shaped digest (not independently verified here)"
    return "Invalid or unavailable digest format"


def _engine_summary(section: Any, group_keys: tuple[str, ...], assessment: dict[str, Any]) -> list[list[str]]:
    coverage = section.get("status") if isinstance(section, dict) else None
    rows = [["C5 coverage", _text(coverage)]]
    engine_map = assessment.get("engines", {}) if isinstance(assessment.get("engines"), dict) else {}
    for key in group_keys:
        records = [(name, item) for name, item in engine_map.items() if name.startswith(key)]
        for name, record in records:
            rows.append([name, _text(record.get("status") if isinstance(record, dict) else None)])
    if len(rows) == 1 and isinstance(section, dict) and section.get("message"):
        rows.append(["Recorded reason", _text(section.get("message"))])
    return rows


class ReportFindingDialog(QDialog):
    def __init__(self, finding: dict[str, Any], parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Report finding · {_text(finding.get('finding_id'))}")
        self.resize(820, 680)
        layout = QVBoxLayout(self)
        heading = QLabel(_text(finding.get("title"), "Assurance finding")); heading.setObjectName("pageTitle"); layout.addWidget(heading)
        layout.addWidget(SeverityBadge(_text(finding.get("severity")).upper()))
        details = SectionCard("Finding identity and assessment")
        for label, key in (("Finding ID", "finding_id"), ("Category", "category"), ("Confidence", "confidence"),
                           ("Affected asset", "affected_asset"), ("Source engine", "source_engine")):
            details.content.addWidget(QLabel(f"{label}: {_text(finding.get(key))}"))
        layout.addWidget(details)
        explanation = SectionCard("What was observed")
        explanation.content.addWidget(QLabel(_text(finding.get("explanation")))); layout.addWidget(explanation)
        evidence = finding.get("evidence")
        evidence_card = SectionCard("Evidence")
        evidence_card.content.addWidget(AnalystTable(["Evidence", "Persisted value"], [["Evidence", display(evidence)]]))
        layout.addWidget(evidence_card)
        actions = SectionCard("Recommended action and limitations")
        actions.content.addWidget(QLabel("Recommended action: " + _text(finding.get("recommended_action"))))
        actions.content.addWidget(QLabel("Limitations: " + _text(finding.get("limitations"))))
        layout.addWidget(actions)
        viewer = QPushButton("Open Evidence Viewer")
        viewer.clicked.connect(lambda: EvidenceViewerDialog(
            _text(finding.get("finding_id")), _text(finding.get("explanation")), display(evidence), finding, self).exec())
        layout.addWidget(viewer)
        close = QPushButton("Close"); close.clicked.connect(self.accept); layout.addWidget(close)


class ReportWorkspace(QWidget):
    """Read-only analyst workspace; exports are separate local artifacts."""

    def __init__(self, assessment: Any, report: Any, *, report_path: Path | None = None,
                 text_report_path: Path | None = None, protected_paths: list[Path] | None = None,
                 on_navigate: Callable[[str], None] | None = None,
                 on_open_finding: Callable[[str], None] | None = None, parent=None):
        super().__init__(parent)
        self.assessment = assessment if isinstance(assessment, dict) else {}
        self.report = report if isinstance(report, dict) else {}
        self.report_path = Path(report_path) if report_path else None
        self.text_report_path = Path(text_report_path) if text_report_path else None
        self.protected_paths = {Path(path).expanduser().resolve() for path in protected_paths or [] if path}
        if self.report_path:
            self.protected_paths.add(self.report_path.expanduser().resolve())
        if self.text_report_path:
            self.protected_paths.add(self.text_report_path.expanduser().resolve())
        self.on_navigate = on_navigate
        self.on_open_finding = on_open_finding
        self.findings, malformed_findings = report_findings(self.report)
        self.status, self.state_message = c5_state(assessment, report, self.report_path)
        self.load_warnings: list[str] = []
        expected_shapes = {"executive_summary": dict, "asset_coverage": dict, "dataset_integrity": dict,
                           "model_integrity": dict, "inference_provenance": dict, "distribution_shift": dict,
                           "findings_and_evidence": dict, "audit_trail": dict, "recommended_actions": list,
                           "limitations": list}
        if self.report and any(key in self.report and not isinstance(self.report.get(key), shape)
                               for key, shape in expected_shapes.items()):
            self.load_warnings.append("One or more persisted C5 sections have malformed data; unaffected sections are still shown.")
        if malformed_findings:
            self.load_warnings.append("Some finding records were malformed and have been omitted from the analyst list.")
        if self.report and not isinstance(self.report.get("report_digest"), str):
            self.load_warnings.append("C5 report digest is missing or malformed.")
        elif self.report and digest_state(self.report.get("report_digest")).startswith("Invalid"):
            self.load_warnings.append("C5 report digest does not have the expected SHA-256 hexadecimal shape.")

        outer = QVBoxLayout(self); outer.setContentsMargins(24, 18, 24, 18)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); outer.addWidget(scroll)
        body = QWidget(); layout = QVBoxLayout(body); layout.setSpacing(12); scroll.setWidget(body)
        title = QLabel("Report Center"); title.setObjectName("pageTitle"); layout.addWidget(title)
        layout.addWidget(QLabel("Persisted C5 assurance report · analyst view. This page reads stored results and does not rerun assessment engines."))

        header = SectionCard("TRACER-CV · Trust, Reliability & Assurance for Computer Vision")
        header.content.addWidget(QLabel("Assurance Report"))
        assessment_id = self.report.get("assessment_id") or self.assessment.get("assessment_id")
        header.content.addWidget(QLabel(f"Assessment ID: {_text(assessment_id)}"))
        header.content.addWidget(SeverityBadge(f"Assessment status: {_text(self.assessment.get('status')).replace('_', ' ').upper()}", self.status))
        header.content.addWidget(QLabel(f"Assessment timestamp: {_text(self.assessment.get('completed_at') or self.assessment.get('started_at'))}"))
        header.content.addWidget(QLabel(f"C5 report version: {_text(self.report.get('report_version'))} · method: {_text(self.report.get('method'))}"))
        engine_map = self.assessment.get("engines", {}) if isinstance(self.assessment.get("engines"), dict) else {}
        c5_record = engine_map.get("C5_assurance_report") if isinstance(engine_map.get("C5_assurance_report"), dict) else {}
        header.content.addWidget(QLabel(f"C5 report generation status: {_text(c5_record.get('status'))}"))
        header.content.addWidget(QLabel(f"C5 report digest: {self.report.get('report_digest') or UNAVAILABLE} · {digest_state(self.report.get('report_digest'))}"))
        dataset = self.assessment.get("dataset") if isinstance(self.assessment.get("dataset"), dict) else {}
        model = self.assessment.get("model") if isinstance(self.assessment.get("model"), dict) else {}
        header.content.addWidget(QLabel(f"Asset scope: Dataset {_text(Path(str(dataset.get('path'))).name if dataset.get('path') else None)} · Model {_text(Path(str(model.get('path'))).name if model.get('path') else None)}"))
        header.content.addWidget(SeverityBadge("OFFLINE / LOCAL REPORT · NO NETWORK SERVICE REQUIRED", "verified"))
        header.content.addWidget(QLabel(self.state_message))
        for warning in self.load_warnings:
            header.content.addWidget(SeverityBadge(warning, "warning"))
        layout.addWidget(header)

        summary = self.report.get("executive_summary") if isinstance(self.report.get("executive_summary"), dict) else None
        summary_card = SectionCard("Executive Summary")
        if summary:
            summary_card.content.addWidget(QLabel("Assessment scope: " + _text(summary.get("assessment_scope"))))
            summary_card.content.addWidget(QLabel("Interpretation: " + _text(summary.get("interpretation"))))
            summary_card.content.addWidget(AnalystTable(["Persisted indicator", "Recorded value"], [
                ["Findings", _text(summary.get("finding_count"))],
                ["Highest observed severity", _text(summary.get("highest_observed_severity"))],
                ["Severity counts", display(summary.get("severity_counts"))],
                ["Provenance chain validity", _text(summary.get("provenance_chain_valid"))],
                ["Audit chain validity", _text(summary.get("audit_chain_valid"))],
                ["Distribution shift recorded", _text(summary.get("distribution_shift_detected"))],
            ]))
        else:
            summary_card.content.addWidget(QLabel("Executive summary unavailable in the persisted C5 report."))
        layout.addWidget(summary_card)

        coverage = self.report.get("asset_coverage") if isinstance(self.report.get("asset_coverage"), dict) else {}
        coverage_rows = []
        for key in ("dataset_integrity", "model_integrity", "inference_provenance", "distribution_shift", "findings_and_evidence", "audit_trail"):
            item = coverage.get(key)
            section_missing = key not in self.report
            if isinstance(item, dict):
                coverage_rows.append([key.replace("_", " ").title(), _text(item.get("status")), _text(item.get("finding_count")),
                                      "Section unavailable in C5 report" if section_missing else _text(item.get("assessed")), "Unavailable"])
            else:
                coverage_rows.append([key.replace("_", " ").title(), "Unavailable", UNAVAILABLE, UNAVAILABLE, UNAVAILABLE])
        for row in coverage_rows:
            prefix = {"Dataset Integrity": "A", "Model Integrity": "B", "Inference Provenance": "C1", "Distribution Shift": "C2", "Findings And Evidence": "C3", "Audit Trail": "C4"}.get(row[0])
            records = [(name, record) for name, record in engine_map.items() if prefix and name.startswith(prefix) and isinstance(record, dict)]
            states = [str(record.get("status")) for _, record in records]
            if states:
                row[2] = ", ".join(dict.fromkeys(states))
            digests = []
            for name, record in records:
                evidence = record.get("evidence")
                digest = evidence.get("sha256") if isinstance(evidence, dict) else record.get("result_digest")
                if isinstance(digest, str) and digest:
                    short = digest if len(digest) <= 28 else f"{digest[:12]}…{digest[-8:]}"
                    digests.append(f"{name}: {short}")
            if digests:
                row[4] = "; ".join(digests[:3]) + ("; …" if len(digests) > 3 else "")
        coverage_card = SectionCard("Assessment & Asset Coverage")
        self.coverage_table = AnalystTable(["Area", "C5 coverage", "Persisted engine status", "Assessed / section state", "Persisted result digest"], coverage_rows)
        coverage_card.content.addWidget(self.coverage_table); layout.addWidget(coverage_card)

        for title_text, key, engines in (
            ("Dataset Integrity", "dataset_integrity", tuple(f"A{i}" for i in range(1, 9))),
            ("Model Integrity", "model_integrity", tuple(f"B{i}" for i in range(1, 5))),
            ("Inference Provenance", "inference_provenance", ("C1",)),
            ("Distribution Shift", "distribution_shift", ("C2",)),
            ("Audit Trail", "audit_trail", ("C4",)),
        ):
            section = self.report.get(key)
            card = SectionCard(title_text)
            card.content.addWidget(AnalystTable(["Persisted coverage / engine", "Recorded status"], _engine_summary(section, engines, self.assessment)))
            card.content.addWidget(QLabel(self._section_summary(key, section)))
            details_button = QPushButton(f"{title_text} · Technical Details")
            details_button.clicked.connect(lambda checked=False, label=title_text, value=section: self._open_technical(label, value))
            card.content.addWidget(details_button)
            layout.addWidget(card)

        findings_card = SectionCard("Findings & Evidence")
        if self.findings:
            rows = [[_text(f.get("severity")).upper(), _text(f.get("confidence")), _text(f.get("finding_id")),
                     _text(f.get("title")), _text(f.get("affected_asset")), _text(f.get("source_engine"))]
                    for f in self.findings]
            self.findings_table = AnalystTable(["Severity", "Confidence", "Finding ID", "Finding", "Affected asset", "Source engine"], rows)
            self.findings_table.cellDoubleClicked.connect(self.open_finding_row)
            findings_card.content.addWidget(self.findings_table)
            findings_card.content.addWidget(QLabel("Double-click a finding for its persisted explanation, evidence, recommended action, and limitations."))
        else:
            self.findings_table = AnalystTable(["Severity", "Confidence", "Finding ID", "Finding", "Affected asset", "Source engine"], [])
            findings_card.content.addWidget(QLabel("No findings recorded in this persisted C5 report." if isinstance(self.report.get("findings_and_evidence"), dict) else "Findings section unavailable in the persisted C5 report."))
            findings_card.content.addWidget(self.findings_table)
        layout.addWidget(findings_card)

        actions = self.report.get("recommended_actions")
        actions_card = SectionCard("Recommended Actions")
        if isinstance(actions, list) and actions:
            for item in actions:
                label = QLabel("• " + _text(item)); label.setWordWrap(True); actions_card.content.addWidget(label)
        else:
            actions_card.content.addWidget(QLabel("No recommendations recorded." if "recommended_actions" in self.report else "Recommendations unavailable in the persisted C5 report."))
        layout.addWidget(actions_card)

        limitations = self.report.get("limitations")
        limitation_card = SectionCard("Limitations & Coverage")
        if isinstance(limitations, list) and limitations:
            for item in limitations:
                label = QLabel("• " + _text(item)); label.setWordWrap(True); limitation_card.content.addWidget(label)
        else:
            limitation_card.content.addWidget(QLabel("Limitations unavailable in the persisted C5 report."))
        layout.addWidget(limitation_card)

        product_scope = SectionCard("Current Product Coverage · Not an Assessment Finding")
        product_scope.content.addWidget(QLabel("The statements below describe TRACER-CV product scope. They are separate from the persisted C5 assessment and do not alter or supplement its findings."))
        for engine, values in PRODUCT_LIMITATIONS.items():
            for value in values:
                line = QLabel(f"{engine}: {value}"); line.setWordWrap(True); product_scope.content.addWidget(line)
        layout.addWidget(product_scope)

        technical = SectionCard("Technical Details · C5")
        technical.content.addWidget(QLabel(f"Engine status: {_text(engine_map.get('C5_assurance_report', {}).get('status') if isinstance(engine_map.get('C5_assurance_report'), dict) else None)}"))
        technical.content.addWidget(QLabel(f"C5 task: {_text(self.report.get('task'))} · method: {_text(self.report.get('method'))}"))
        self.json_button = QPushButton("View C5 JSON (technical)" if self.report else "C5 JSON unavailable")
        self.json_button.setEnabled(bool(self.report)); self.json_button.clicked.connect(self.open_json_viewer); technical.content.addWidget(self.json_button)
        layout.addWidget(technical)

        controls = QHBoxLayout()
        self.export_pdf_button = QPushButton("Export Full Report PDF")
        self.export_pdf_button.setObjectName("primary")
        self.export_pdf_button.setEnabled(bool(self.report) and self.status not in {"MALFORMED", "UNAVAILABLE"})
        self.export_pdf_button.clicked.connect(self.choose_pdf_path); controls.addWidget(self.export_pdf_button)
        self.export_json_button = QPushButton("Export JSON"); self.export_json_button.setEnabled(bool(self.report)); self.export_json_button.clicked.connect(self.choose_json_path); controls.addWidget(self.export_json_button)
        self.export_text_button = QPushButton("Export Text"); self.export_text_button.setEnabled(bool(self.text_report_path and self.text_report_path.is_file())); self.export_text_button.clicked.connect(self.choose_text_path); controls.addWidget(self.export_text_button)
        self.export_status = QLabel(""); self.export_status.setWordWrap(True); controls.addWidget(self.export_status, 1)
        layout.addLayout(controls)

        navigation = QHBoxLayout()
        for label, route in (("Open Findings", "findings"), ("Open Evidence Explorer", "evidence"), ("Open Audit Trail", "audit"), ("View Product Coverage", "coverage")):
            button = QPushButton(label); button.clicked.connect(lambda checked=False, target=route: self.on_navigate(target) if self.on_navigate else None); navigation.addWidget(button)
        layout.addLayout(navigation)
        layout.addWidget(QLabel("This report describes persisted observations and their recorded limits. It does not independently establish safety, malicious intent, attacker identity, or absence of attacks."))
        layout.addStretch()

    def _section_summary(self, key: str, section: Any) -> str:
        if not isinstance(section, dict):
            return "Section unavailable in the persisted C5 report."
        if section.get("message"):
            return str(section["message"])
        engine = section.get("engine_result")
        if not isinstance(engine, dict):
            return f"Persisted section status: {_text(section.get('status'))}."
        salient = []
        if key == "dataset_integrity":
            for engine_id, data in engine.items():
                if isinstance(data, dict):
                    status = _text(data.get("status"))
                    metrics = [(name, data[name]) for name in ("file_count", "duplicate_group_count", "near_duplicate_pair_count", "potential_ood_count", "finding_count", "image_finding_count", "candidate_trigger_count") if data.get(name) is not None]
                    salient.append(f"{engine_id}: {status}" + (" · " + ", ".join(f"{n.replace('_',' ')} {v}" for n,v in metrics) if metrics else ""))
        elif key == "model_integrity":
            for engine_id, data in engine.items():
                if isinstance(data, dict):
                    detail = data.get("status", UNAVAILABLE)
                    if engine_id == "B1_identity": detail = f"{detail}; format {_text(data.get('format'))}; digest {_text(data.get('sha256'))}"
                    elif engine_id == "B3_model_statistics": detail = f"{detail}; reason {_text(data.get('reason'))}; parameters {_text(data.get('total_parameters'))}; activation status {_text(data.get('activation_status'))}; limitations {_text(data.get('limitations'))}"
                    elif engine_id == "B4_trigger_search": detail = f"{detail}; candidate trigger-like results {_text(data.get('candidate_trigger_count'))}"
                    salient.append(f"{engine_id}: {detail}")
        elif key == "inference_provenance":
            salient.extend(f"{name.replace('_',' ').title()}: {_text(engine.get(name))}" for name in ("valid", "record_count", "model_id", "signature_status", "replay_status") if name in engine)
            verification = engine.get("verification") if isinstance(engine.get("verification"), dict) else {}
            for name in ("signature_status", "signature_valid", "replay_status", "replay_detected", "replay_findings"):
                if name in verification:
                    salient.append(f"Persisted {name.replace('_',' ').title()}: {_text(verification.get(name))}")
            records = engine.get("records")
            if isinstance(records, list):
                record_dicts = [record for record in records if isinstance(record, dict)]
                if record_dicts:
                    signed = sum(bool(record.get("signature")) for record in record_dicts)
                    salient.append(f"Signature evidence: {signed} of {len(record_dicts)} records contain a signature field")
                else:
                    salient.append("Signature evidence: no valid record detail stored")
            if not any("replay" in item.lower() for item in salient):
                salient.append("Replay evidence: unavailable (not recorded in the C5 result)")
        elif key == "distribution_shift":
            salient.extend(f"{name.replace('_',' ').title()}: {_text(engine.get(name))}" for name in ("reference_image_count", "candidate_image_count", "overall_shift", "severity", "shift_detected") if name in engine)
            if engine.get("overall_shift") is not None:
                salient.append("Calibration status: NOT CALIBRATED; the persisted shift magnitude is not an attack or maliciousness probability.")
            shifted = engine.get("shifted_features")
            if isinstance(shifted, list):
                salient.append("Shifted features: " + (", ".join(str(item.get("feature", item.get("name", UNAVAILABLE))) for item in shifted if isinstance(item, dict) and item.get("shifted") is True) or "None recorded as shifted"))
        elif key == "audit_trail":
            salient.extend(f"{name.replace('_',' ').title()}: {_text(engine.get(name))}" for name in ("valid", "entry_count", "finding_count") if name in engine)
        return "\n".join(salient[:12]) or f"Persisted section status: {_text(section.get('status'))}; detailed metrics are available under Technical Details."

    def open_finding_row(self, row: int, _column: int) -> None:
        if 0 <= row < len(self.findings):
            finding = self.findings[row]
            dialog = ReportFindingDialog(finding, self)
            if self.on_open_finding:
                open_button = QPushButton("Open in Findings workspace")
                open_button.clicked.connect(lambda: (dialog.accept(), self.on_open_finding(_text(finding.get("finding_id")))) )
                dialog.layout().addWidget(open_button)
            dialog.exec()

    def _open_technical(self, title: str, section: Any) -> None:
        EvidenceViewerDialog(f"{title} · persisted C5 section", self._section_summary(title.lower().replace(" ", "_"), section),
                             "Technical details and source section are shown as stored.", section, self).exec()

    def open_json_viewer(self) -> None:
        if self.report:
            EvidenceViewerDialog("Persisted C5 Assurance Report", "This is the stored C5 report. The analyst view is presented in the Report Center.",
                                 f"Report digest: {self.report.get('report_digest') or UNAVAILABLE}", self.report, self).exec()

    def _check_export_target(self, target: str | Path) -> Path:
        path = Path(target).expanduser().resolve()
        if path in self.protected_paths:
            raise ValueError("Export target matches an authoritative assessment artifact; choose a separate export path.")
        return path

    def export_json(self, target: str | Path) -> Path:
        path = self._check_export_target(target)
        if self.report_path and self.report_path.is_file():
            payload = self.report_path.read_bytes()
        else:
            payload = json.dumps(self.report, ensure_ascii=False, indent=2, default=str).encode("utf-8")
        path.write_bytes(payload)
        self.export_status.setText(f"JSON export written: {path}")
        return path

    def export_text(self, target: str | Path) -> Path:
        if not self.text_report_path or not self.text_report_path.is_file():
            raise FileNotFoundError("Persisted C5 text report is unavailable.")
        path = self._check_export_target(target)
        path.write_bytes(self.text_report_path.read_bytes())
        self.export_status.setText(f"Text export written: {path}")
        return path

    def export_pdf(self, target: str | Path) -> dict[str, str]:
        path = self._check_export_target(target)
        result = write_assurance_pdf(self.report, self.assessment, path)
        self.export_status.setText(f"PDF export written: {result['path']} · SHA-256 {result['sha256']} · document export time {result['exported_at']}")
        return result

    def choose_pdf_path(self) -> None:
        identity = self.report.get("assessment_id") or self.assessment.get("assessment_id") or "assessment"
        target, _ = QFileDialog.getSaveFileName(self, "Export Assurance Report PDF", f"TRACER-CV-{identity}-assurance-report.pdf", "PDF (*.pdf)")
        if target:
            try: self.export_pdf(target)
            except (OSError, ValueError, RuntimeError) as exc: QMessageBox.warning(self, "PDF export failed", str(exc))

    def choose_json_path(self) -> None:
        identity = self.report.get("assessment_id") or "assessment"
        target, _ = QFileDialog.getSaveFileName(self, "Export persisted C5 JSON", f"TRACER-CV-{identity}-C5.json", "JSON (*.json)")
        if target:
            try: self.export_json(target)
            except (OSError, ValueError) as exc: QMessageBox.warning(self, "JSON export failed", str(exc))

    def choose_text_path(self) -> None:
        identity = self.report.get("assessment_id") or "assessment"
        target, _ = QFileDialog.getSaveFileName(self, "Export persisted C5 text report", f"TRACER-CV-{identity}-assurance-report.txt", "Text (*.txt)")
        if target:
            try: self.export_text(target)
            except (OSError, ValueError) as exc: QMessageBox.warning(self, "Text export failed", str(exc))
