"""Assessment-backed A1–A8 analyst workspace. Reads persisted local evidence only."""
from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any, Callable

from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QComboBox, QDialog, QFileDialog, QGridLayout, QHBoxLayout, QLabel,
    QMessageBox, QPushButton, QScrollArea, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from desktop.widgets.components import (
    AnalystTable, EvidenceViewerDialog, MetricCard, SectionCard, SeverityBadge,
)


ENGINE_SPECS = (
    ("A1_manifest", "A1", "Manifest Integrity"),
    ("A2_exact_duplicates", "A2", "Exact Duplicates"),
    ("A3_near_duplicates", "A3", "Near Duplicates"),
    ("A4_ood", "A4", "Reference / OOD Analysis"),
    ("A5_label_consistency", "A5", "Label Consistency"),
    ("A6_contributor_risk", "A6", "Contributor / Source Risk"),
    ("A7_metadata_consistency", "A7", "Metadata / Acquisition Consistency"),
    ("A8_poison_trigger_forensics", "A8", "Trigger-Like Pattern Forensics"),
)

SEVERITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
SAMPLE_KEYS = {
    "files", "file", "file_a", "file_b", "image", "image_path", "path",
    "sample", "sample_path", "affected_file", "candidate_file", "reference_file",
}


def _text(value: Any, empty: str = "Not recorded") -> str:
    if value is None or value == "":
        return empty
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, float):
        return f"{value:.5g}"
    if isinstance(value, (dict, list, tuple)):
        return ", ".join(_text(item) for item in value[:10]) if isinstance(value, (list, tuple)) else "Structured evidence available"
    return str(value)


def _humanize(key: str) -> str:
    return key.replace("_", " ").replace("-", " ").strip().capitalize()


def _walk_samples(value: Any, key: str = "") -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for child_key, child in value.items():
            normalized = child_key.lower()
            if normalized in SAMPLE_KEYS:
                values = child if isinstance(child, list) else [child]
                found.extend(str(item) for item in values if isinstance(item, (str, Path)))
            else:
                found.extend(_walk_samples(child, normalized))
    elif isinstance(value, list):
        for child in value:
            found.extend(_walk_samples(child, key))
    return list(dict.fromkeys(item for item in found if item and item not in {"UNKNOWN", "None"}))


def engine_finding_count(engine_id: str, result: dict[str, Any]) -> int | None:
    count_fields = {
        "A1_manifest": (),
        "A2_exact_duplicates": ("duplicate_group_count",),
        "A3_near_duplicates": ("near_duplicate_pair_count",),
        "A4_ood": ("potential_ood_count",),
        "A5_label_consistency": ("finding_count",),
        "A6_contributor_risk": ("finding_count",),
        "A7_metadata_consistency": ("image_finding_count",),
        "A8_poison_trigger_forensics": ("candidate_trigger_count",),
    }
    fields = count_fields.get(engine_id, ())
    for key in fields:
        value = result.get(key)
        if isinstance(value, (int, float)):
            return int(value)
    if engine_id == "A1_manifest" and result.get("dataset_sha256"):
        return 0
    return None


def engine_status(engine_id: str, result: dict[str, Any], engine_records: dict[str, Any]) -> str:
    record = engine_records.get(engine_id, {})
    raw = str(record.get("status", result.get("status", "unavailable"))).strip().lower()
    if raw in {"completed", "completed_with_warnings", "completed_with_errors"} and not result:
        return "UNAVAILABLE"
    return {
        "completed": "COMPLETED",
        "completed_with_errors": "COMPLETED WITH WARNINGS",
        "completed_with_warnings": "COMPLETED WITH WARNINGS",
        "running": "RUNNING",
        "queued": "QUEUED",
        "created": "QUEUED",
        "not_assessed": "NOT ASSESSED",
        "unavailable": "UNAVAILABLE",
        "error": "FAILED",
        "failed": "FAILED",
        "cancelled": "CANCELLED",
    }.get(raw, raw.upper() if raw else "UNAVAILABLE")


def engine_severity(engine_id: str, result: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    explicit = result.get("severity")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.upper()
    engine_code = next((code for key, code, _ in ENGINE_SPECS if key == engine_id), engine_id)
    linked = [item for item in findings if item.get("source_engine") in {engine_id, engine_code}]
    if linked:
        return max((str(item.get("severity", "INFO")).upper() for item in linked),
                   key=lambda item: SEVERITY_ORDER.get(item, 0))
    if engine_id == "A6_contributor_risk":
        if result.get("high_risk_contributors"):
            return "HIGH"
        if result.get("medium_risk_contributors"):
            return "MEDIUM"
    severity_counts = result.get("image_findings_by_severity")
    if isinstance(severity_counts, dict):
        present = [str(level).upper() for level, count in severity_counts.items() if count]
        if present:
            return max(present, key=lambda item: SEVERITY_ORDER.get(item, 0))
    count = engine_finding_count(engine_id, result)
    if count == 0:
        return "NONE REPORTED"
    return "NOT ASSIGNED" if count is not None else "NOT AVAILABLE"


def engine_explanation(engine_id: str, result: dict[str, Any], status: str, count: int | None) -> str:
    if status != "COMPLETED":
        return str(result.get("reason") or "No completed result is available for this engine.")
    explanations = {
        "A1_manifest": f"Manifest records {result.get('file_count', 'an unrecorded number of')} files and the dataset digest.",
        "A2_exact_duplicates": f"The engine reported {count if count is not None else 'no recorded'} exact duplicate group(s) by matching file content digests.",
        "A3_near_duplicates": f"The {result.get('method', 'configured')} appearance comparison reported {count if count is not None else 'no recorded'} pair(s). It does not establish semantic similarity.",
        "A4_ood": f"Reference appearance analysis reported {count if count is not None else 'no recorded'} potential outlier sample(s); appearance shift does not establish semantic OOD.",
        "A5_label_consistency": f"Label checks recorded {count if count is not None else 'no recorded'} finding(s) or conflicting pairs.",
        "A6_contributor_risk": f"Contributor profiling recorded {count if count is not None else 'no recorded'} risk indicator(s); this heuristic does not establish malicious intent.",
        "A7_metadata_consistency": f"Metadata checks recorded {count if count is not None else 'no recorded'} image-level finding(s); anomalies do not prove manipulation.",
        "A8_poison_trigger_forensics": f"Forensics recorded {count if count is not None else 'no recorded'} trigger-like candidate(s); this does not prove poisoning or a backdoor.",
    }
    return explanations.get(engine_id, "Completed engine result is available for inspection.")


def sort_engine_rows(rows: list[dict[str, Any]], sort_by: str, descending: bool = False) -> list[dict[str, Any]]:
    status_order = {"FAILED": 0, "UNAVAILABLE": 1, "NOT ASSESSED": 2, "RUNNING": 3,
                    "QUEUED": 4, "COMPLETED WITH WARNINGS": 5, "COMPLETED": 6}
    def key(row):
        if sort_by == "Severity": return SEVERITY_ORDER.get(row["severity"], 0)
        if sort_by == "Finding count": return row["count"] if row["count"] is not None else -1
        if sort_by == "Affected samples": return len(row["samples"])
        if sort_by == "Status": return status_order.get(row["status"], 7)
        return row["spec"][1]
    return sorted(rows, key=key, reverse=descending)


def _evidence_pairs(value: Any, prefix: str = "") -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            label = f"{prefix} · {_humanize(str(key))}" if prefix else _humanize(str(key))
            if isinstance(child, dict):
                rows.extend(_evidence_pairs(child, label))
            elif isinstance(child, list):
                if child and all(not isinstance(item, (dict, list)) for item in child):
                    rows.append((label, _text(child)))
                else:
                    for index, item in enumerate(child[:20], 1):
                        rows.extend(_evidence_pairs(item, f"{label} {index}"))
            elif child is not None:
                rows.append((label, _text(child)))
    elif isinstance(value, list):
        for index, child in enumerate(value[:20], 1):
            rows.extend(_evidence_pairs(child, f"{prefix} {index}"))
    return rows[:80]


class DatasetSampleDialog(QDialog):
    """On-demand local image inspection with root containment and pixel checks."""
    def __init__(self, sample_path: Path | None, label: str, root: Path | None, parent=None,
                 compare_path: Path | None = None):
        super().__init__(parent)
        self.setWindowTitle(f"Sample inspection · {label}")
        self.resize(720, 560)
        layout = QVBoxLayout(self)
        title = QLabel(label); title.setObjectName("pageTitle"); layout.addWidget(title)
        previews = QHBoxLayout(); layout.addLayout(previews)
        metadata = []
        def inspect(path_value, preview_label):
            preview = QLabel("Image preview unavailable"); preview.setAlignment(Qt.AlignCenter); preview.setMinimumSize(300, 250); previews.addWidget(preview)
            if path_value is None or root is None or not root.is_dir():
                metadata.append(f"{preview_label}: sample path or selected dataset unavailable."); return
            try:
                path = path_value.resolve(strict=True)
                dataset_root = root.resolve(strict=True)
                if not path.is_relative_to(dataset_root) or not path.is_file():
                    raise ValueError("Sample path is outside the selected dataset.")
                from PIL import Image
                with Image.open(path) as image:
                    image.verify()
                with Image.open(path) as image:
                    dimensions = f"{image.width} × {image.height}"
                    image_format = image.format or path.suffix.lstrip(".").upper()
                    if image.width * image.height > 40_000_000:
                        preview.setText("Image exceeds the configured preview pixel limit.")
                    else:
                        pixmap = QPixmap(str(path))
                        if not pixmap.isNull():
                            preview.setPixmap(pixmap.scaled(660, 300, Qt.KeepAspectRatio, Qt.SmoothTransformation))
                        else:
                            preview.setText("Image preview unavailable: decoder returned no image.")
                with path.open("rb") as stream:
                    digest = hashlib.file_digest(stream, "sha256").hexdigest()
                metadata.append(f"{preview_label}: {path.name}\nPath: {path}\nDimensions: {dimensions}\nFormat: {image_format}\nSHA-256: {digest}")
            except Exception as exc:
                metadata.append(f"{preview_label}: image cannot be inspected: {type(exc).__name__}: {exc}")
        inspect(sample_path, "Left sample" if compare_path else "Affected sample")
        if compare_path:
            inspect(compare_path, "Right sample")
            layout.addWidget(QLabel("Side-by-side view of recorded samples. Similarity claims are limited to the source engine's measured evidence."))
        for line in metadata:
            info = QLabel(line); info.setWordWrap(True); layout.addWidget(info)
        close = QPushButton("Close"); close.clicked.connect(self.accept); layout.addWidget(close)


class DatasetDetailDialog(QDialog):
    def __init__(self, spec, result, engine_record, related_findings, root, parent=None):
        self.engine_id, self.code, self.title = spec
        self.result = result
        self.root = root
        super().__init__(parent)
        self.setWindowTitle(f"{self.code} · {self.title}")
        self.resize(900, 720)
        outer = QVBoxLayout(self)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); outer.addWidget(scroll)
        body = QWidget(); layout = QVBoxLayout(body); layout.setSpacing(12); scroll.setWidget(body)
        heading = QLabel(f"{self.code} — {self.title}"); heading.setObjectName("pageTitle"); layout.addWidget(heading)
        state = engine_status(self.engine_id, result, {self.engine_id: engine_record})
        layout.addWidget(SeverityBadge(f"STATUS · {state}"))
        reason = engine_record.get("reason") or result.get("reason")
        if reason:
            layout.addWidget(QLabel(f"Reason: {reason}"))
        count = engine_finding_count(self.engine_id, result)
        summary = SectionCard("Situation")
        summary.content.addWidget(QLabel(engine_explanation(self.engine_id, result, state, count)))
        layout.addWidget(summary)
        metrics = [(key, value) for key, value in result.items()
                   if key not in {"files", "results", "pairs", "groups", "findings", "profiles", "image_findings", "contributor_profiles", "contributor_findings", "pattern_evidence", "class_conditional_evidence", "status", "limitations", "parameters", "dataset_profile", "contributor_evidence"}
                   and not isinstance(value, (dict, list))]
        if metrics:
            card = SectionCard("Key metrics")
            table = AnalystTable(["Metric", "Recorded value"], [[_humanize(str(key)), _text(value)] for key, value in metrics[:40]])
            card.content.addWidget(table); layout.addWidget(card)
        findings = SectionCard("Related C3 findings")
        if related_findings:
            for finding in related_findings:
                line = QPushButton(f"{finding.get('severity', 'INFO')} · {finding.get('title', 'Finding')} · {finding.get('finding_id', '')}")
                line.clicked.connect(lambda checked=False, item=finding: DatasetFindingDialog(item, self.root, self).exec())
                findings.content.addWidget(line)
        else:
            findings.content.addWidget(QLabel("No C3 findings are linked to this engine result."))
        layout.addWidget(findings)
        sample_refs = _walk_samples(result)
        assets = SectionCard(f"Affected assets / samples · {len(sample_refs)} reference(s)")
        if sample_refs:
            rows = [[value, "Available" if _resolve_sample(root, value) else "Not found in selected dataset"] for value in sample_refs[:300]]
            sample_table=AnalystTable(["Sample", "Local status"], rows)
            sample_table.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)
            assets.content.addWidget(sample_table)
            sample_actions=QHBoxLayout()
            inspect=QPushButton("Inspect Sample"); inspect.clicked.connect(lambda:self._inspect_samples(sample_table,root,False)); sample_actions.addWidget(inspect)
            compare=QPushButton("Compare Samples"); compare.clicked.connect(lambda:self._inspect_samples(sample_table,root,True)); sample_actions.addWidget(compare)
            assets.content.addLayout(sample_actions)
        else:
            assets.content.addWidget(QLabel("This result contains no explicit affected-sample reference."))
        layout.addWidget(assets)
        limitations = result.get("limitations", [])
        if isinstance(limitations, str):
            limitations = [limitations]
        limit_card = SectionCard("Limitations")
        limit_card.content.addWidget(QLabel("\n".join(f"• {item}" for item in limitations) if limitations else "The engine returned no explicit limitations."))
        layout.addWidget(limit_card)
        evidence = _evidence_pairs(result)
        tech = QPushButton("Technical Details")
        tech.clicked.connect(lambda: EvidenceViewerDialog(
            f"{self.code} technical details", engine_explanation(self.engine_id, result, state, count),
            "\n".join(f"{name}: {value}" for name, value in evidence) or "No structured evidence fields were returned.",
            result, self).exec())
        layout.addWidget(tech)
        close = QPushButton("Close"); close.clicked.connect(self.accept); outer.addWidget(close)

    def _inspect_samples(self, table, root, compare):
        rows=sorted({item.row() for item in table.selectedItems()})
        if not rows and table.currentRow() >= 0: rows=[table.currentRow()]
        if not rows:
            QMessageBox.information(self, "Sample inspection", "Select an affected sample row first."); return
        if compare and len(rows) < 2:
            QMessageBox.information(self, "Sample comparison", "Select two affected sample rows to compare."); return
        first=table.item(rows[0],0).text(); first_path=_resolve_sample(root,first)
        second_path=_resolve_sample(root,table.item(rows[1],0).text()) if compare else None
        DatasetSampleDialog(first_path, Path(first).name, root, self, compare_path=second_path).exec()


def _resolve_sample(root: Path | None, reference: str) -> Path | None:
    if root is None:
        return None
    candidate = Path(reference)
    paths = [candidate] if candidate.is_absolute() else [root / candidate]
    if not candidate.is_absolute() and (root / "candidate").is_dir():
        paths.append(root / "candidate" / candidate)
    for path in paths:
        try:
            resolved = path.resolve(strict=True)
            if resolved.is_file() and resolved.is_relative_to(root.resolve()):
                return resolved
        except (OSError, RuntimeError):
            continue
    return None


class DatasetFindingDialog(QDialog):
    def __init__(self, finding, root: Path | None, parent=None):
        super().__init__(parent)
        self.finding = finding
        self.setWindowTitle(f"Finding investigation · {finding.get('finding_id', 'Finding')}")
        self.resize(840, 700)
        outer = QVBoxLayout(self)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); outer.addWidget(scroll)
        body = QWidget(); layout = QVBoxLayout(body); scroll.setWidget(body)
        heading = QLabel(str(finding.get("title", "Dataset finding"))); heading.setObjectName("pageTitle"); layout.addWidget(heading)
        layout.addWidget(SeverityBadge(str(finding.get("severity", "INFO"))))
        identity = SectionCard("Finding")
        for label, key in (("Finding ID", "finding_id"), ("Category", "category"), ("Confidence", "confidence"), ("Affected asset", "affected_asset"), ("Source engine", "source_engine")):
            identity.content.addWidget(QLabel(f"{label}: {_text(finding.get(key))}"))
        layout.addWidget(identity)
        explanation = SectionCard("Why this was flagged")
        explanation.content.addWidget(QLabel(str(finding.get("explanation", "No explanation was recorded."))))
        layout.addWidget(explanation)
        evidence_card = SectionCard("Structured evidence")
        evidence = finding.get("evidence", [])
        pairs = _evidence_pairs(evidence)
        evidence_card.content.addWidget(AnalystTable(["Evidence item", "Recorded value"], pairs or [["Evidence", "No structured evidence was recorded."]]))
        layout.addWidget(evidence_card)
        limitation_card = SectionCard("Limitations and recommended investigation")
        limitation_card.content.addWidget(QLabel("Limitations: " + _text(finding.get("limitations", []))))
        limitation_card.content.addWidget(QLabel("Recommended action: " + _text(finding.get("recommended_action"))))
        layout.addWidget(limitation_card)
        refs = list(dict.fromkeys([str(finding.get("affected_asset", "")), *_walk_samples(evidence)]))
        refs = [ref for ref in refs if ref and ref != "Not recorded"]
        sample_card = SectionCard("Affected samples")
        sample_rows = [[ref, str(_resolve_sample(root, ref) or "Not found in selected dataset")] for ref in refs]
        table = AnalystTable(["Sample / asset", "Local path"], sample_rows or [["No sample path recorded", "Unavailable"]])
        table.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)
        sample_card.content.addWidget(table); layout.addWidget(sample_card)
        actions = QHBoxLayout()
        inspect = QPushButton("Inspect Selected Image")
        inspect.clicked.connect(lambda: self._inspect(table, root, False))
        compare = QPushButton("Compare Selected Samples")
        compare.clicked.connect(lambda: self._inspect(table, root, True))
        actions.addWidget(inspect); actions.addWidget(compare); layout.addLayout(actions)
        self.decision_notice = QLabel("Analyst dispositions are not persisted or auditable in this version. No Review, Accept, or Quarantine action has been recorded.")
        self.decision_notice.setWordWrap(True); self.decision_notice.setObjectName("muted"); layout.addWidget(self.decision_notice)
        tech = QPushButton("Technical Details")
        tech.clicked.connect(lambda: EvidenceViewerDialog(
            "Finding technical details", str(finding.get("explanation", "Finding generated from recorded engine observations.")),
            "\n".join(f"{key}: {value}" for key, value in pairs) or "No structured evidence was recorded.", finding, self).exec())
        layout.addWidget(tech)
        close = QPushButton("Close"); close.clicked.connect(self.accept); outer.addWidget(close)

    def _inspect(self, table, root, compare):
        rows=sorted({item.row() for item in table.selectedItems()})
        if not rows and table.currentRow() >= 0: rows=[table.currentRow()]
        if not rows:
            QMessageBox.information(self, "Sample inspection", "Select an affected sample row first."); return
        if compare and len(rows) < 2:
            QMessageBox.information(self, "Sample comparison", "Select two affected sample rows to compare."); return
        first=table.item(rows[0],0).text(); first_path=_resolve_sample(root,first)
        second_path=None
        if compare:
            second=table.item(rows[1],0).text(); second_path=_resolve_sample(root,second)
        DatasetSampleDialog(first_path, Path(first).name, root, self, compare_path=second_path).exec()


class DatasetIntegrityWorkspace(QWidget):
    def __init__(self, assessment: dict[str, Any] | None, results: dict[str, Any] | None,
                 findings: list[dict[str, Any]] | None, *, results_root: Path | None = None,
                 on_rerun: Callable[[], None] | None = None, parent=None):
        super().__init__(parent)
        self.assessment = assessment if isinstance(assessment, dict) else {}
        self.results = results if isinstance(results, dict) else {}
        self.findings = [item for item in (findings or []) if isinstance(item, dict)
                         and (item.get("source_engine") == "dataset" or str(item.get("source_engine", "")).startswith("A"))]
        self.results_root = results_root
        self.engine_records = dict(self.assessment.get("engines", {})) if isinstance(self.assessment.get("engines"), dict) else {}
        self.dataset = self.assessment.get("dataset", {}) if isinstance(self.assessment.get("dataset"), dict) else {}
        self.dataset_root = Path(str(self.dataset.get("path"))).resolve() if self.dataset.get("path") else None
        self.engine_rows: list[dict[str, Any]] = []
        self.finding_rows: list[dict[str, Any]] = []
        self._build(on_rerun)

    def _build(self, on_rerun):
        outer = QVBoxLayout(self); outer.setContentsMargins(24, 20, 24, 24); outer.setSpacing(12)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); outer.addWidget(scroll)
        body = QWidget(); layout = QVBoxLayout(body); layout.setSpacing(12); scroll.setWidget(body)
        title = QLabel("Dataset Integrity"); title.setObjectName("pageTitle"); layout.addWidget(title)
        if not self.assessment:
            empty = SectionCard("No assessment selected")
            empty.content.addWidget(QLabel("Open a saved assessment from Assessments or run a New Assessment to view persisted A1–A8 results."))
            layout.addWidget(empty); return
        status = str(self.assessment.get("status", "UNKNOWN")).replace("_", " ").upper()
        dataset_name = Path(str(self.dataset.get("path", "Dataset unavailable"))).name if self.dataset.get("path") else "Dataset unavailable"
        header = SectionCard("Assessment context")
        header.content.addWidget(QLabel(f"{self.assessment.get('name') or 'Unnamed assessment'}\nDataset: {dataset_name}\nAssessment ID: {self.assessment.get('assessment_id', 'Not recorded')}"))
        row = QHBoxLayout(); row.addWidget(SeverityBadge(status))
        manifest_result = self.results.get("A1_manifest")
        digest = manifest_result.get("dataset_sha256") if isinstance(manifest_result, dict) else None
        row.addWidget(QLabel(f"Dataset digest: {digest or self.dataset.get('sha256') or 'Not available'}")); row.addStretch()
        header.content.addLayout(row)
        actions = QHBoxLayout()
        rerun = QPushButton("Re-run Assessment"); rerun.setEnabled(on_rerun is not None)
        if on_rerun: rerun.clicked.connect(on_rerun)
        export = QPushButton("Export Evidence"); export.clicked.connect(self.export_evidence)
        export_pdf = QPushButton("Export Dataset PDF"); export_pdf.clicked.connect(self.export_section_pdf)
        actions.addWidget(rerun); actions.addWidget(export); actions.addWidget(export_pdf); header.content.addLayout(actions)
        layout.addWidget(header)
        assessment_state = str(self.assessment.get("status", "")).strip().upper()
        if assessment_state in {"RUNNING", "QUEUED", "CREATED"}:
            notice = SectionCard("Assessment in progress")
            notice.content.addWidget(QLabel("A1–A8 results may be incomplete while this assessment is running. Open the page again after it finishes to review persisted results."))
            layout.addWidget(notice)
        elif assessment_state == "FAILED":
            notice = SectionCard("Assessment failed")
            notice.content.addWidget(QLabel("The assessment did not complete. Any persisted engine results remain available below; missing results are shown with their recorded status and reason."))
            layout.addWidget(notice)
        elif assessment_state in {"COMPLETED_WITH_WARNINGS", "COMPLETED_WITH_ERRORS"}:
            notice = SectionCard("Completed with warnings")
            notice.content.addWidget(QLabel("The assessment completed with one or more unavailable, skipped, or failed checks. Review each A1–A8 status and its recorded reason."))
            layout.addWidget(notice)
        if not self.dataset_root or not self.dataset_root.is_dir():
            missing = SectionCard("Dataset unavailable")
            missing.content.addWidget(QLabel("The selected dataset path is missing or unavailable. Persisted results remain inspectable; sample previews cannot be opened."))
            layout.addWidget(missing)
        elif not self.results:
            missing = SectionCard("Dataset results unavailable")
            missing.content.addWidget(QLabel("No persisted A1–A8 result document was found for this assessment.")); layout.addWidget(missing)

        engine_results = {}
        for key, _, _ in ENGINE_SPECS:
            raw_result = self.results.get(key)
            if raw_result is None:
                engine_results[key] = {}
            elif isinstance(raw_result, dict):
                engine_results[key] = raw_result
            else:
                engine_results[key] = {
                    "status": "error",
                    "reason": "Persisted engine result is malformed; an object was expected.",
                    "technical_error": f"Received {type(raw_result).__name__} instead of an object.",
                }
                self.engine_records[key] = {**self.engine_records.get(key, {}), "status": "error",
                                            "reason": engine_results[key]["reason"]}
        completed = sum(engine_status(key, engine_results[key], self.engine_records) == "COMPLETED" for key, _, _ in ENGINE_SPECS)
        manifest = engine_results.get("A1_manifest", {})
        manifest_state = self._manifest_state(manifest)
        contributor_data = engine_results.get("A6_contributor_risk", {})
        contributor_count = None
        if isinstance(contributor_data.get("high_risk_contributors"), int) and isinstance(contributor_data.get("medium_risk_contributors"), int):
            contributor_count = contributor_data["high_risk_contributors"] + contributor_data["medium_risk_contributors"]
        if contributor_count is None: contributor_count = "Not available"
        affected_samples = set()
        for finding in self.findings:
            affected_samples.update(_walk_samples(finding.get("evidence", [])))
            asset = finding.get("affected_asset")
            if asset:
                affected_samples.add(str(asset))
        for result in engine_results.values():
            affected_samples.update(_walk_samples(result))
        ref_available = engine_status("A4_ood", engine_results["A4_ood"], self.engine_records) in {
            "COMPLETED", "COMPLETED WITH WARNINGS"
        }
        high = [item for item in self.findings if str(item.get("severity", "")).lower() in {"high", "critical"}]
        highest = max((str(item.get("severity", "INFO")).upper() for item in self.findings),
                      key=lambda value: SEVERITY_ORDER.get(value, 0), default="NONE REPORTED")
        summary = QGridLayout()
        cards = [
            ("Files", manifest.get("file_count", self.dataset.get("file_count", "Not available")), "Recorded in A1 manifest", "normal"),
            ("Integrity checks", f"{completed} / 8", "Engine execution status", "info"),
            ("Findings", len(self.findings), "C3 dataset findings stored with assessment", "review" if self.findings else "normal"),
            ("Highest severity", highest, "From persisted C3 findings", "high" if highest in {"HIGH", "CRITICAL"} else "review" if highest in {"MEDIUM", "LOW"} else "normal"),
            ("Affected samples", len(affected_samples), "Unique recorded paths / assets", "info"),
            ("Contributors", contributor_count, "Contributor count returned by A6", "info"),
            ("Reference comparison", "Available" if ref_available else "Not available", "Assessment configuration", "info" if ref_available else "unavailable"),
            ("Manifest identity", manifest_state, "Compared only when a reviewed digest exists", "verified" if manifest_state == "Verified" else "review" if manifest_state == "Failed" else "unavailable"),
        ]
        for index, (label, value, detail, tone) in enumerate(cards):
            summary.addWidget(MetricCard(label, str(value), detail, tone), index // 4, index % 4)
        layout.addLayout(summary)
        interpretation = SectionCard("Analyst interpretation")
        if self.findings:
            interpretation.content.addWidget(QLabel("Recorded dataset findings require review. They describe engine observations and do not, by themselves, establish malicious activity."))
        elif completed < 8:
            interpretation.content.addWidget(QLabel("No persisted dataset findings are available to interpret, and one or more checks did not complete. Review engine status and reasons below."))
        else:
            interpretation.content.addWidget(QLabel("No C3 dataset findings were recorded. This does not establish that the dataset is safe or benign."))
        layout.addWidget(interpretation)

        coverage = SectionCard("A1–A8 engine coverage")
        filter_row = QHBoxLayout()
        self.search = QComboBox(); self.search.setEditable(True); self.search.lineEdit().setPlaceholderText("Search filename, contributor, ID, category…")
        self.search.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.engine_filter = QComboBox(); self.engine_filter.addItems(["All engines", *[f"{code} {name}" for _, code, name in ENGINE_SPECS]])
        self.category_filter = QComboBox(); self.category_filter.addItems(["All categories", *sorted({str(item.get("category", "Not recorded")) for item in self.findings})])
        self.status_filter = QComboBox(); self.status_filter.addItems(["All statuses", "COMPLETED", "COMPLETED WITH WARNINGS", "NOT ASSESSED", "UNAVAILABLE", "FAILED", "RUNNING", "QUEUED"])
        self.severity_filter = QComboBox(); self.severity_filter.addItems(["All severities", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NONE REPORTED", "NOT ASSIGNED", "NOT AVAILABLE"])
        self.contributor_filter = QComboBox(); self.contributor_filter.addItems(["All contributors", *self._contributors(engine_results)])
        self.class_filter = QComboBox(); self.class_filter.addItems(["All classes", *self._classes(engine_results)])
        self.sample_filter = QComboBox(); self.sample_filter.addItems(["All samples", *sorted(affected_samples)[:500]])
        self.finding_state_filter = QComboBox(); self.finding_state_filter.addItems(["Disposition persistence unavailable"])
        self.sort_by = QComboBox(); self.sort_by.addItems(["Engine", "Status", "Severity", "Finding count", "Affected samples"])
        self.sort_order = QComboBox(); self.sort_order.addItems(["Ascending", "Descending"])
        for control in (self.search, self.engine_filter, self.status_filter, self.severity_filter, self.category_filter, self.contributor_filter, self.class_filter, self.sample_filter, self.finding_state_filter, self.sort_by, self.sort_order):
            filter_row.addWidget(control)
        coverage.content.addLayout(filter_row)
        rows = []
        for spec in ENGINE_SPECS:
            key, code, name = spec; result = engine_results[key]
            status_value = engine_status(key, result, self.engine_records)
            count = engine_finding_count(key, result)
            severity = engine_severity(key, result, self.findings)
            samples = _walk_samples(result)
            reason = self.engine_records.get(key, {}).get("reason") or result.get("reason")
            explanation = str(reason) if status_value != "COMPLETED" and reason else engine_explanation(key, result, status_value, count)
            row = {"spec": spec, "result": result, "status": status_value, "count": count,
                   "severity": severity, "samples": samples, "explanation": explanation}
            self.engine_rows.append(row)
            rows.append([f"{code} · {name}", status_value, "Not recorded" if count is None else count,
                         severity, len(samples), explanation, "Open"])
        self.engine_table = None
        self.engine_table_host = QWidget(); self.engine_table_layout = QVBoxLayout(self.engine_table_host); self.engine_table_layout.setContentsMargins(0,0,0,0)
        coverage.content.addWidget(self.engine_table_host); layout.addWidget(coverage)

        finding_card = SectionCard("Dataset findings")
        finding_card.content.addWidget(QLabel("Disposition state is not persisted by the current backend; this view does not record analyst decisions."))
        finding_rows = [[str(item.get("source_engine", "dataset")), str(item.get("category", "Not recorded")),
                         str(item.get("severity", "INFO")).upper(), str(item.get("finding_id", "Not recorded")),
                         Path(str(item.get("affected_asset", ""))).name or "Not recorded", str(item.get("title", "Finding"))]
                        for item in self.findings]
        self.finding_table = AnalystTable(["Engine", "Category", "Severity", "Finding ID", "Affected asset", "Finding"], finding_rows)
        self.finding_table.setSortingEnabled(True)
        for row, finding in enumerate(self.findings):
            self.finding_table.item(row, 3).setData(Qt.ItemDataRole.UserRole, row)
        self.finding_table.cellDoubleClicked.connect(self.open_finding_row)
        finding_card.content.addWidget(self.finding_table)
        layout.addWidget(finding_card)
        self.filter_controls = (self.search, self.engine_filter, self.status_filter, self.severity_filter, self.category_filter,
                                self.contributor_filter, self.class_filter, self.sample_filter, self.finding_state_filter,
                                self.sort_by, self.sort_order)
        self.search.lineEdit().textChanged.connect(self.apply_filters)
        for control in self.filter_controls[1:]: control.currentTextChanged.connect(self.apply_filters)
        self._render_engine_table()
        layout.addStretch()
        self.apply_filters()

    def _manifest_state(self, manifest):
        state = engine_status("A1_manifest", manifest, self.engine_records)
        expected = self.dataset.get("selection_sha256")
        actual = manifest.get("dataset_sha256") if isinstance(manifest, dict) else None
        if state == "FAILED": return "Failed"
        if state != "COMPLETED" or not expected or not actual: return "Not assessed"
        return "Verified" if expected == actual else "Failed"

    def _contributors(self, results):
        values = set()
        for profile in results.get("A6_contributor_risk", {}).get("profiles", []):
            if isinstance(profile, dict) and profile.get("contributor"):
                values.add(str(profile["contributor"]))
        return sorted(values)[:500]

    def _classes(self, results):
        values = set()
        for row in results.get("A6_contributor_risk", {}).get("profiles", []):
            if isinstance(row, dict):
                distribution = row.get("class_distribution", {})
                if isinstance(distribution, dict): values.update(str(key) for key in distribution)
        return sorted(values)[:500]

    def apply_filters(self, *_):
        if not hasattr(self, "engine_table"):
            return
        needle = self.search.currentText().casefold().strip()
        engine_pick = self.engine_filter.currentText()
        status_pick = self.status_filter.currentText()
        severity_pick = self.severity_filter.currentText()
        category_pick = self.category_filter.currentText()
        contributor_pick = self.contributor_filter.currentText()
        class_pick = self.class_filter.currentText()
        sample_pick = self.sample_filter.currentText()
        for row_index, item in enumerate(self.visible_engine_rows):
            spec, result = item["spec"], item["result"]
            code_name = f"{spec[1]} {spec[2]}"
            document = json.dumps({"engine": code_name, "result": result}, ensure_ascii=False, default=str).casefold()
            visible = ((engine_pick == "All engines" or engine_pick == code_name)
                       and (status_pick == "All statuses" or item["status"] == status_pick)
                       and (severity_pick == "All severities" or item["severity"] == severity_pick)
                       and (category_pick == "All categories" or any(
                           finding.get("source_engine") in {spec[0], spec[1]}
                           and str(finding.get("category", "Not recorded")) == category_pick
                           for finding in self.findings))
                       and (contributor_pick == "All contributors" or contributor_pick.casefold() in document)
                       and (class_pick == "All classes" or class_pick.casefold() in document)
                       and (sample_pick == "All samples" or sample_pick.casefold() in document)
                       and (not needle or needle in document or needle in code_name.casefold()))
            self.engine_table.setRowHidden(row_index, not visible)
        for row_index, finding in enumerate(self.findings):
            text = json.dumps(finding, ensure_ascii=False, default=str).casefold()
            visible = ((engine_pick == "All engines" or finding.get("source_engine") in engine_pick)
                       and (severity_pick == "All severities" or str(finding.get("severity", "")).upper() == severity_pick)
                       and (category_pick == "All categories" or str(finding.get("category", "Not recorded")) == category_pick)
                       and (contributor_pick == "All contributors" or contributor_pick.casefold() in text)
                       and (class_pick == "All classes" or class_pick.casefold() in text)
                       and (sample_pick == "All samples" or sample_pick.casefold() in text)
                       and (not needle or needle in text))
            self.finding_table.setRowHidden(row_index, not visible)

    def _render_engine_table(self):
        if self.engine_table is not None:
            self.engine_table_layout.removeWidget(self.engine_table)
            self.engine_table.deleteLater()
        self.visible_engine_rows=sort_engine_rows(self.engine_rows,self.sort_by.currentText(),self.sort_order.currentText()=="Descending")
        headers=["Engine","Status","Finding count","Severity","Affected samples","Short explanation","Action"]
        table=QTableWidget(len(self.visible_engine_rows),len(headers)); table.setHorizontalHeaderLabels(headers)
        table.setAlternatingRowColors(True); table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers); table.verticalHeader().setVisible(False)
        for row,item in enumerate(self.visible_engine_rows):
            spec=item["spec"]; key=spec[0]
            name_item=QTableWidgetItem(f"{spec[1]} · {spec[2]}"); name_item.setData(Qt.ItemDataRole.UserRole,key); table.setItem(row,0,name_item)
            table.setCellWidget(row,1,SeverityBadge(item["status"]))
            table.setItem(row,2,QTableWidgetItem("Not recorded" if item["count"] is None else str(item["count"])))
            table.setCellWidget(row,3,SeverityBadge(item["severity"]))
            table.setItem(row,4,QTableWidgetItem(str(len(item["samples"]))))
            table.setItem(row,5,QTableWidgetItem(item["explanation"]))
            action=QPushButton("Investigate"); action.clicked.connect(lambda checked=False, engine_id=key:self.open_engine_key(engine_id)); table.setCellWidget(row,6,action)
        table.cellDoubleClicked.connect(lambda row,col:self.open_engine_key(table.item(row,0).data(Qt.ItemDataRole.UserRole)))
        table.setMinimumHeight(320); table.resizeColumnsToContents(); table.horizontalHeader().setStretchLastSection(True)
        self.engine_table=table; self.engine_table_layout.addWidget(table)
        self.apply_filters()

    def open_engine_row(self, row):
        if row is None or not isinstance(row, int) or row < 0 or row >= len(self.engine_rows): return
        self.open_engine_key(self.engine_rows[row]["spec"][0])

    def open_engine_key(self, engine_id):
        item = next((entry for entry in self.engine_rows if entry["spec"][0] == engine_id), None)
        if item is None: return
        linked = [finding for finding in self.findings if finding.get("source_engine") in {item["spec"][0], item["spec"][1]}]
        record = self.engine_records.get(item["spec"][0], {})
        DatasetDetailDialog(item["spec"], item["result"], record, linked, self.dataset_root, self).exec()

    def open_finding_row(self, row, _column):
        if row < 0: return
        item = self.finding_table.item(row, 3)
        index = item.data(Qt.ItemDataRole.UserRole) if item else row
        if isinstance(index, int) and 0 <= index < len(self.findings):
            DatasetFindingDialog(self.findings[index], self.dataset_root, self).exec()

    def export_evidence(self):
        if not self.results_root or not self.results_root.is_dir():
            QMessageBox.information(self, "Evidence export unavailable", "Persisted assessment result files are not available for export."); return
        target, _ = QFileDialog.getSaveFileName(self, "Export dataset evidence", "dataset-evidence.zip", "ZIP archive (*.zip)")
        if not target: return
        if not target.lower().endswith(".zip"): target += ".zip"
        root = self.results_root.resolve()
        paths = [root / "dataset_integrity.json", root / "findings.json"]
        paths.extend(root / f"{engine_id}.json" for engine_id, _, _ in ENGINE_SPECS)
        try:
            with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for path in paths:
                    resolved = path.resolve(strict=True)
                    if resolved.is_relative_to(root) and resolved.is_file():
                        archive.write(resolved, resolved.name)
        except (OSError, zipfile.BadZipFile) as exc:
            QMessageBox.warning(self, "Evidence export failed", f"Could not export persisted dataset evidence: {exc}")

    def export_section_pdf(self):
        from desktop.reporting import write_section_pdf
        target, _ = QFileDialog.getSaveFileName(
            self, "Export Dataset Integrity PDF", "dataset_integrity_report.pdf", "PDF (*.pdf)"
        )
        if not target:
            return
        try:
            rows = []
            if isinstance(self.results, dict):
                for key, value in self.results.items():
                    if isinstance(value, dict):
                        status = value.get("status", "—")
                        rows.append((key.replace("_", " ").upper(), str(status)))
                    elif isinstance(value, (str, int, float)):
                        rows.append((key.replace("_", " ").title(), str(value)))
            assessment_id = str(self.assessment.get("assessment_id", "")) if self.assessment else ""
            result = write_section_pdf(
                "Dataset Integrity Report",
                {"description": "A1–A8 dataset integrity analysis results.",
                 "rows": rows[:40]},
                target,
                assessment_id=assessment_id,
            )
            QMessageBox.information(
                self, "Export complete",
                f"PDF saved: {Path(result['path']).name}\nSHA-256: {result['sha256'][:32]}…",
            )
        except Exception as exc:
            QMessageBox.warning(self, "PDF export failed", str(exc))
