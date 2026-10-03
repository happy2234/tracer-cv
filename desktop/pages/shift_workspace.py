"""Assessment-backed C2 distribution shift analyst workspace."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox, QDialog, QHBoxLayout, QLabel, QPushButton, QScrollArea,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from desktop.pages.dataset_workspace import DatasetSampleDialog, _resolve_sample
from desktop.widgets.components import (
    AnalystTable, EvidenceViewerDialog, MetricBarChart, MetricCard,
    SectionCard, SeverityBadge,
)


def shift_status(result: Any, engine_records: Any = None) -> str:
    """Return a display state from persisted result/assessment metadata."""
    engines = engine_records if isinstance(engine_records, dict) else {}
    record = engines.get("C2_distribution_shift", {}) if isinstance(engines.get("C2_distribution_shift"), dict) else {}
    raw_record = str(record.get("status", "")).strip().lower()
    if result is not None and not isinstance(result, dict):
        return "PARTIAL"
    data = result if isinstance(result, dict) else {}
    result_missing = not data or data.get("status") == "unavailable"
    if result_missing:
        if raw_record in {"not_assessed", "unavailable", "error", "failed", "running", "queued", "created", "cancelled"}:
            raw = raw_record
        else:
            return "UNAVAILABLE"
    else:
        raw = raw_record or str(data.get("status", "unavailable")).strip().lower()
    if raw in {"completed", "completed_with_warnings", "completed_with_errors"}:
        if data.get("status") == "unavailable":
            return "UNAVAILABLE"
        required = ("reference", "candidate", "shifted_features", "distances", "overall_shift")
        if not all(key in data for key in required):
            return "PARTIAL"
        if not isinstance(data.get("reference"), dict) or not isinstance(data.get("candidate"), dict):
            return "PARTIAL"
        if (not isinstance(data.get("reference", {}).get("summary"), dict)
                or not isinstance(data.get("candidate", {}).get("summary"), dict)
                or not isinstance(data.get("shifted_features"), list)
                or not data.get("shifted_features")
                or not isinstance(data.get("distances"), dict)):
            return "PARTIAL"
    return {
        "completed": "COMPLETED",
        "completed_with_warnings": "COMPLETED WITH WARNINGS",
        "completed_with_errors": "COMPLETED WITH WARNINGS",
        "not_assessed": "NOT ASSESSED",
        "unavailable": "UNAVAILABLE",
        "error": "FAILED",
        "failed": "FAILED",
        "running": "RUNNING",
        "queued": "QUEUED",
        "created": "QUEUED",
        "cancelled": "CANCELLED",
    }.get(raw, raw.upper() or "UNAVAILABLE")


def _display(value: Any, fallback: str = "Not recorded") -> str:
    if value is None or value == "":
        return fallback
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, float):
        return f"{value:.6g}"
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, ensure_ascii=False, default=str)
    return str(value)


def _humanize(value: Any) -> str:
    return str(value).replace("_", " ").replace("-", " ").strip().capitalize()


def _c2_findings(findings: Any) -> list[dict[str, Any]]:
    if not isinstance(findings, list):
        return []
    return [item for item in findings if isinstance(item, dict)
            and (str(item.get("source_engine", "")).upper() == "C2"
                 or item.get("category") == "distribution_shift")]


def _population(result: dict[str, Any], population: str) -> dict[str, Any]:
    value = result.get(population)
    return value if isinstance(value, dict) else {}


def _summary(result: dict[str, Any], population: str) -> dict[str, Any]:
    value = _population(result, population).get("summary")
    return value if isinstance(value, dict) else {}


def _feature_rows(result: dict[str, Any]) -> list[list[Any]]:
    reference = _summary(result, "reference")
    candidate = _summary(result, "candidate")
    distances = result.get("distances") if isinstance(result.get("distances"), dict) else {}
    scalar = distances.get("scalar") if isinstance(distances.get("scalar"), dict) else {}
    thresholds = {str(item.get("feature")): item for item in result.get("shifted_features", [])
                  if isinstance(item, dict) and item.get("feature") is not None}
    rows = []
    for feature in ("brightness", "contrast", "saturation", "edge_density"):
        ref = reference.get(feature) if isinstance(reference.get(feature), dict) else {}
        cand = candidate.get(feature) if isinstance(candidate.get(feature), dict) else {}
        observation = thresholds.get(feature, {})
        if not ref and not cand and feature not in scalar and not observation:
            continue
        rows.append([
            _humanize(feature), ref.get("mean", "Not recorded"), cand.get("mean", "Not recorded"),
            scalar.get(feature, observation.get("distance", "Not recorded")),
            observation.get("threshold", "Not recorded"),
            "SHIFTED" if observation.get("shifted") is True else "NOT SHIFTED" if observation.get("shifted") is False else "NOT RECORDED",
        ])
    return rows


def _histogram_rows(result: dict[str, Any]) -> list[list[Any]]:
    distances = result.get("distances") if isinstance(result.get("distances"), dict) else {}
    histogram = distances.get("histogram") if isinstance(distances.get("histogram"), dict) else {}
    return [[_humanize(name), value] for name, value in histogram.items()]


def _anomaly_feature(anomaly: dict[str, Any]) -> str:
    values = anomaly.get("features")
    if isinstance(values, dict) and values:
        numeric = [(key, value) for key, value in values.items() if isinstance(value, (int, float))]
        if numeric:
            return _humanize(max(numeric, key=lambda pair: abs(float(pair[1])))[0])
    return "Not recorded"


def _evidence_rows(evidence: Any) -> list[list[str]]:
    if not isinstance(evidence, list):
        return []
    rows: list[list[str]] = []
    def flatten(name: str, value: Any):
        if isinstance(value, dict):
            for key, child in value.items():
                flatten(f"{name} · {_humanize(key)}", child)
        elif isinstance(value, list) and value and all(isinstance(child, dict) for child in value):
            for index, child in enumerate(value, 1):
                flatten(f"{name} {index}", child)
        elif isinstance(value, list):
            rows.append([name, ", ".join(str(child) for child in value)])
        else:
            rows.append([name, _display(value)])
    for item in evidence:
        if isinstance(item, dict):
            name = item.get("type") or item.get("feature") or item.get("metric") or "Recorded evidence"
            value = item.get("value", {key: val for key, val in item.items() if key not in {"type", "feature", "metric"}})
            flatten(_humanize(name), value)
        else:
            rows.append(["Recorded evidence", _display(item)])
    return rows


class ShiftFindingDialog(QDialog):
    def __init__(self, finding: dict[str, Any], parent=None):
        super().__init__(parent)
        self.finding = finding
        self.setWindowTitle(f"Distribution finding · {finding.get('finding_id', 'Finding')}")
        self.resize(820, 680)
        outer = QVBoxLayout(self)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); outer.addWidget(scroll)
        body = QWidget(); layout = QVBoxLayout(body); scroll.setWidget(body)
        heading = QLabel(str(finding.get("title", "Distribution shift finding"))); heading.setObjectName("pageTitle"); layout.addWidget(heading)
        layout.addWidget(SeverityBadge(str(finding.get("severity", "NOT ASSIGNED"))))
        identity = SectionCard("Finding")
        for label, key in (("Finding ID", "finding_id"), ("Category", "category"), ("Confidence", "confidence"),
                           ("Affected asset", "affected_asset"), ("Source engine", "source_engine")):
            identity.content.addWidget(QLabel(f"{label}: {_display(finding.get(key))}"))
        layout.addWidget(identity)
        situation = SectionCard("Why this was flagged")
        situation.content.addWidget(QLabel(str(finding.get("explanation", "No explanation was recorded."))))
        layout.addWidget(situation)
        evidence = SectionCard("Evidence")
        evidence.content.addWidget(AnalystTable(["Evidence item", "Recorded value"],
            _evidence_rows(finding.get("evidence")) or [["Evidence", "No structured evidence was recorded."]]))
        layout.addWidget(evidence)
        action = SectionCard("Recommended action and limitations")
        action.content.addWidget(QLabel("Recommended action: " + _display(finding.get("recommended_action"))))
        limitations = finding.get("limitations")
        action.content.addWidget(QLabel("Limitations: " + _display(limitations)))
        layout.addWidget(action)
        self.evidence_button = QPushButton("Technical Details")
        self.evidence_button.clicked.connect(lambda: EvidenceViewerDialog(
            "Distribution finding evidence", str(finding.get("explanation", "Recorded C2 evidence.")),
            "\n".join(f"{row[0]}: {row[1]}" for row in _evidence_rows(finding.get("evidence"))) or "No structured evidence recorded.",
            finding, self).exec())
        layout.addWidget(self.evidence_button)
        close = QPushButton("Close"); close.clicked.connect(self.accept); outer.addWidget(close)


class ShiftAnomalyDialog(QDialog):
    def __init__(self, anomaly: dict[str, Any], dataset_root: Path | None, parent=None):
        super().__init__(parent)
        self.anomaly = anomaly
        self.dataset_root = dataset_root
        self.sample_path = _resolve_sample(dataset_root, str(anomaly.get("path") or anomaly.get("file") or ""))
        self.setWindowTitle(f"Candidate image anomaly · {anomaly.get('file', 'sample')}")
        self.resize(720, 560)
        layout = QVBoxLayout(self)
        heading = QLabel(str(anomaly.get("file", "Candidate image"))); heading.setObjectName("pageTitle"); layout.addWidget(heading)
        summary = SectionCard("Situation")
        summary.content.addWidget(QLabel(
            f"Feature with largest recorded anomaly z-score: {_anomaly_feature(anomaly)}\n"
            f"Maximum z-score: {_display(anomaly.get('max_z_score'))}\n"
            "This is a statistical outlier observation relative to the persisted reference feature distribution; it does not establish cause."
        ))
        layout.addWidget(summary)
        evidence = SectionCard("Evidence")
        values = anomaly.get("features") if isinstance(anomaly.get("features"), dict) else {}
        evidence.content.addWidget(AnalystTable(["Feature", "Recorded z-score"], [
            [_humanize(key), value] for key, value in values.items()
        ] or [["Feature", "Not recorded"]]))
        evidence.content.addWidget(QLabel(f"Local image inspection: {'Available on request' if self.sample_path else 'Unavailable; no valid in-dataset image path was recorded.'}"))
        layout.addWidget(evidence)
        actions = QHBoxLayout()
        inspect = QPushButton("Inspect Image"); inspect.setEnabled(self.sample_path is not None)
        inspect.clicked.connect(self.inspect_image); actions.addWidget(inspect)
        viewer = QPushButton("Open Evidence"); viewer.clicked.connect(lambda: EvidenceViewerDialog(
            "Candidate image anomaly", "The selected candidate image was identified as a statistical outlier against the reference feature distribution.",
            f"Sample: {anomaly.get('file', 'Not recorded')}; feature: {_anomaly_feature(anomaly)}; max z-score: {_display(anomaly.get('max_z_score'))}.",
            anomaly, self).exec()); actions.addWidget(viewer)
        layout.addLayout(actions)
        limitation = QLabel("Anomalies may reflect legitimate acquisition, sensor, illumination, format, or processing differences. C2 does not establish malicious intent.")
        limitation.setWordWrap(True); layout.addWidget(limitation)
        close = QPushButton("Close"); close.clicked.connect(self.accept); layout.addWidget(close)

    def inspect_image(self):
        if self.sample_path is not None:
            DatasetSampleDialog(self.sample_path, str(self.anomaly.get("file", self.sample_path.name)),
                                self.dataset_root, self).exec()


class ShiftWorkspace(QWidget):
    """Read-only C2 analyst view over persisted assessment results."""
    def __init__(self, assessment: dict[str, Any] | None, result: Any,
                 findings: list[dict[str, Any]] | None, parent=None):
        super().__init__(parent)
        self.assessment = assessment if isinstance(assessment, dict) else {}
        self.result = result if isinstance(result, dict) else {}
        self.malformed_result = result is not None and not isinstance(result, dict)
        self.findings_available = isinstance(findings, list)
        self.findings = _c2_findings(findings)
        self.state = ("PARTIAL" if self.malformed_result else
                      shift_status(self.result, self.assessment.get("engines")))
        raw_anomalies = self.result.get("anomalous_images")
        self.anomalies = ([item for item in raw_anomalies if isinstance(item, dict)]
                          if isinstance(raw_anomalies, list) and self.state in {"COMPLETED", "COMPLETED WITH WARNINGS", "PARTIAL"} else [])
        self.dataset_root = self._dataset_root()
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
        title = QLabel("Distribution Shift"); title.setObjectName("pageTitle"); layout.addWidget(title)
        if not self.assessment:
            card = SectionCard("No assessment selected")
            card.content.addWidget(QLabel("Open a saved assessment to inspect its persisted C2 distribution analysis."))
            layout.addWidget(card)
            return

        state = self.state
        overview = SectionCard("Distribution comparison overview")
        overview.content.addWidget(QLabel(
            f"Assessment: {self.assessment.get('name', 'Unnamed assessment')}\n"
            f"Assessment ID: {self.assessment.get('assessment_id', 'Not recorded')}\n"
            f"Assessment status: {str(self.assessment.get('status', 'Not recorded')).replace('_', ' ').upper()}\n"
            f"C2 status: {state}"
        ))
        overview.content.addWidget(SeverityBadge(state))
        if state == "PARTIAL" or self.malformed_result:
            overview.content.addWidget(QLabel("Stored distribution shift evidence could not be interpreted completely. Available fields are shown without filling gaps."))
        elif state == "UNAVAILABLE":
            message = self.result.get("reason") or self.result.get("message") or "Distribution shift assessment not available for this assessment."
            overview.content.addWidget(QLabel(str(message)))
        elif state == "FAILED":
            overview.content.addWidget(QLabel(str(self.result.get("reason") or self.assessment.get("engines", {}).get("C2_distribution_shift", {}).get("reason") or "C2 failed; no completed metrics are presented.")))

        display_metrics = state in {"COMPLETED", "COMPLETED WITH WARNINGS", "PARTIAL"}
        reference = _population(self.result, "reference") if display_metrics else {}
        candidate = _population(self.result, "candidate") if display_metrics else {}
        shifted = self.result.get("shifted_features") if display_metrics and isinstance(self.result.get("shifted_features"), list) else []
        shifted_count = sum(1 for item in shifted if isinstance(item, dict) and item.get("shifted") is True)
        overall = self.result.get("overall_shift") if display_metrics else None
        severity = self.result.get("severity") if display_metrics else None
        digest = self.result.get("result_digest") if display_metrics else None
        self.finding_count = len(self.findings) if self.findings_available else None
        summary_grid = QHBoxLayout()
        for card in (
            MetricCard("Reference images", _display(reference.get("image_count")) if reference else "Not recorded", "Persisted C2 reference population count"),
            MetricCard("Candidate images", _display(candidate.get("image_count")) if candidate else "Not recorded", "Persisted C2 candidate population count"),
            MetricCard("Overall shift", _display(overall), "Distribution metric only; not a security or maliciousness score", str(severity or "info").lower()),
            MetricCard("Shifted features", str(shifted_count) if isinstance(self.result.get("shifted_features"), list) else "Not recorded", "Feature flags returned by C2"),
            MetricCard("Image anomalies", str(len(self.anomalies)) if isinstance(self.result.get("anomalous_images"), list) else "Not recorded", "Persisted candidate outlier records"),
            MetricCard("C3 findings", str(self.finding_count) if self.finding_count is not None else "Not available", "Persisted distribution-shift findings"),
        ):
            summary_grid.addWidget(card)
        overview.content.addLayout(summary_grid)
        if overall is not None:
            severity_label = _display(severity, "Not recorded").upper()
            overview.content.addWidget(QLabel(
                f"Overall distribution shift: {overall} · persisted severity: {severity_label}. "
                "C2 classifies measured population differences using configured heuristic thresholds; this is not an attack probability."
            ))
        if digest:
            overview.content.addWidget(QLabel(f"Result digest: {digest}"))
        if state == "COMPLETED":
            overview.content.addWidget(QLabel("Candidate distribution differs from the reference population only where the recorded C2 metrics indicate it. Legitimate acquisition and operating-condition changes may explain the difference."))
        layout.addWidget(overview)

        comparison = SectionCard("Reference vs candidate statistics")
        rows = _feature_rows(self.result) if display_metrics else []
        comparison.content.addWidget(AnalystTable(
            ["Feature", "Reference mean", "Candidate mean", "Distance", "Persisted threshold", "C2 status"],
            rows or [["No comparable scalar feature statistics were persisted", "", "", "", "", "Unavailable"]]))
        chart_rows = [[row[0], row[1], row[2], "normal"] for row in rows
                      if isinstance(row[1], (int, float)) and isinstance(row[2], (int, float))]
        if chart_rows:
            comparison.content.addWidget(MetricBarChart("Reference and candidate feature means", chart_rows))
        histogram_rows = _histogram_rows(self.result) if display_metrics else []
        if histogram_rows:
            comparison.content.addWidget(AnalystTable(["Histogram comparison", "Total variation distance"], histogram_rows))
        layout.addWidget(comparison)

        shifted_card = SectionCard("Shifted features")
        if isinstance(self.result.get("shifted_features"), list) and shifted and shifted_count == 0:
            shifted_card.content.addWidget(QLabel("No configured distribution features exceeded their persisted thresholds. This does not establish that the dataset is clean or free of manipulation."))
        elif isinstance(self.result.get("shifted_features"), list) and not shifted:
            shifted_card.content.addWidget(QLabel("No shifted-feature records were persisted; no feature-level shift conclusion is drawn."))
        shifted_rows = []
        for item in shifted:
            if isinstance(item, dict):
                feature = item.get("feature", "Not recorded")
                selected = next((row for row in rows if row[0].casefold() == _humanize(feature).casefold()), None)
                ref_value = selected[1] if selected else "Not recorded"
                candidate_value = selected[2] if selected else "Not recorded"
                shifted_rows.append([_humanize(feature), ref_value, candidate_value,
                                     item.get("distance", "Not recorded"), item.get("threshold", "Not recorded"),
                                     "SHIFTED" if item.get("shifted") is True else "NOT SHIFTED" if item.get("shifted") is False else "Not recorded",
                                     f"{_humanize(feature)} differs between the reference and candidate populations." if item.get("shifted") is True else "This feature did not cross the persisted threshold." if item.get("shifted") is False else "No persisted interpretation is available."])
        shifted_card.content.addWidget(AnalystTable(["Feature", "Reference mean", "Candidate mean", "Difference", "Threshold", "Status", "Interpretation"],
            shifted_rows or [["No shifted-feature records were persisted.", "", "", "", "", "", "No feature-level conclusion is drawn."]]))
        layout.addWidget(shifted_card)

        anomaly_card = SectionCard("Candidate image anomalies")
        controls = QHBoxLayout()
        self.anomaly_search = QComboBox(); self.anomaly_search.setEditable(True); self.anomaly_search.setInsertPolicy(QComboBox.InsertPolicy.NoInsert); self.anomaly_search.lineEdit().setPlaceholderText("Search candidate image or feature…")
        self.anomaly_feature = QComboBox(); self.anomaly_feature.addItems(["All features", *sorted({_anomaly_feature(item) for item in self.anomalies if _anomaly_feature(item) != "Not recorded"})])
        self.anomaly_sort = QComboBox(); self.anomaly_sort.addItems(["Maximum z-score", "Sample name"])
        controls.addWidget(self.anomaly_search); controls.addWidget(self.anomaly_feature); controls.addWidget(self.anomaly_sort); anomaly_card.content.addLayout(controls)
        self.anomaly_table = AnalystTable(["Candidate image", "Feature", "Maximum z-score", "Observation"], [])
        anomaly_card.content.addWidget(self.anomaly_table)
        if not isinstance(self.result.get("anomalous_images"), list):
            anomaly_card.content.addWidget(QLabel("Per-image anomaly evidence is unavailable in the stored result."))
        elif not self.anomalies:
            anomaly_card.content.addWidget(QLabel("No candidate image anomalies were recorded by C2."))
        else:
            anomaly_card.content.addWidget(QLabel("Select or double-click an anomaly for its recorded metrics and optional on-demand local image inspection."))
        self.anomaly_table.cellDoubleClicked.connect(self.open_anomaly_row)
        self.anomaly_search.lineEdit().textChanged.connect(self.apply_anomaly_filters)
        self.anomaly_feature.currentTextChanged.connect(self.apply_anomaly_filters)
        self.anomaly_sort.currentTextChanged.connect(self.apply_anomaly_filters)
        select_anomaly = QPushButton("Investigate Selected Anomaly")
        select_anomaly.clicked.connect(lambda: self.open_anomaly_row(self.anomaly_table.currentRow(), 0))
        anomaly_card.content.addWidget(select_anomaly)
        layout.addWidget(anomaly_card)
        self._render_anomalies()

        finding_card = SectionCard("C3 distribution-shift findings")
        controls = QHBoxLayout()
        self.finding_search = QComboBox(); self.finding_search.setEditable(True); self.finding_search.setInsertPolicy(QComboBox.InsertPolicy.NoInsert); self.finding_search.lineEdit().setPlaceholderText("Search finding ID, category, title…")
        self.finding_severity = QComboBox(); self.finding_severity.addItems(["All severities", *sorted({str(item.get("severity", "NOT ASSIGNED")).upper() for item in self.findings})])
        self.finding_sort = QComboBox(); self.finding_sort.addItems(["Severity", "Finding", "Confidence"])
        controls.addWidget(self.finding_search); controls.addWidget(self.finding_severity); controls.addWidget(self.finding_sort); finding_card.content.addLayout(controls)
        self.finding_table = AnalystTable(["Severity", "Category", "Confidence", "Finding ID", "Finding"], [])
        finding_card.content.addWidget(self.finding_table)
        if not self.findings:
            text = "No persisted distribution-shift findings were recorded." if self.findings_available else "No persisted findings available."
            finding_card.content.addWidget(QLabel(text))
        self.finding_table.cellDoubleClicked.connect(self.open_finding_row)
        self.finding_search.lineEdit().textChanged.connect(self.apply_finding_filters)
        self.finding_severity.currentTextChanged.connect(self.apply_finding_filters)
        self.finding_sort.currentTextChanged.connect(self._render_findings)
        layout.addWidget(finding_card)
        self._render_findings()

        limitation_card = SectionCard("Interpretation and limitations")
        limitations = self.result.get("limitations")
        if isinstance(limitations, str):
            limitations = [limitations]
        if isinstance(limitations, list) and limitations:
            limitation_card.content.addWidget(QLabel("\n".join(f"• {item}" for item in limitations)))
        else:
            limitations = []
        guidance = QLabel(
            "Analyst interpretation: distribution shift does not establish malicious manipulation or identify who or what caused a shift. "
            "Appearance statistics do not establish semantic correctness. No detected shift does not prove absence of manipulation. "
            "Thresholds are heuristic and configuration dependent; reference/candidate differences may have legitimate operational causes."
        )
        guidance.setWordWrap(True)
        limitation_card.content.addWidget(guidance)
        layout.addWidget(limitation_card)

        technical = SectionCard("Technical details")
        engine_record = self.assessment.get("engines", {}).get("C2_distribution_shift", {}) if isinstance(self.assessment.get("engines"), dict) else {}
        technical.content.addWidget(QLabel(
            f"Engine status: {engine_record.get('status', self.result.get('status', 'Not recorded'))}\n"
            f"Engine version: {_display(self.result.get('engine_version'))}\n"
            f"Method: {_display(self.result.get('method'))}\n"
            f"Configuration: {_display(self.result.get('config'))}\n"
            f"Reference errors: {_display(reference.get('error_count'))}\n"
            f"Candidate errors: {_display(candidate.get('error_count'))}\n"
            f"Result digest: {_display(digest)}\n"
            f"Load detail: {_display(self.result.get('message', self.result.get('technical_error')))}"
        ))
        evidence = QPushButton("Open C2 Evidence")
        evidence.clicked.connect(lambda: EvidenceViewerDialog(
            "C2 distribution evidence",
            "C2 compares persisted reference and candidate image-population statistics. A measured distribution difference does not establish cause, intent, or semantic correctness.",
            self._evidence_summary(), self.result, self).exec())
        technical.content.addWidget(evidence)
        layout.addWidget(technical)
        layout.addStretch()

    def _evidence_summary(self) -> str:
        return (f"C2 status: {self.state}; reference images: {_display(_population(self.result, 'reference').get('image_count'))}; "
                f"candidate images: {_display(_population(self.result, 'candidate').get('image_count'))}; "
                f"overall shift: {_display(self.result.get('overall_shift'))}; severity: {_display(self.result.get('severity'))}; "
                f"shifted features: {sum(1 for item in self.result.get('shifted_features', []) if isinstance(item, dict) and item.get('shifted') is True)}; "
                f"candidate anomalies: {len(self.anomalies)}.")

    def _render_anomalies(self):
        self.apply_anomaly_filters()

    def apply_anomaly_filters(self, *_):
        if not hasattr(self, "anomaly_table"):
            return
        needle = self.anomaly_search.currentText().casefold().strip()
        feature = self.anomaly_feature.currentText()
        indices = list(range(len(self.anomalies)))
        if self.anomaly_sort.currentText() == "Maximum z-score":
            indices.sort(key=lambda i: float(self.anomalies[i].get("max_z_score", -1))
                         if isinstance(self.anomalies[i].get("max_z_score"), (int, float)) else -1, reverse=True)
        else:
            indices.sort(key=lambda i: str(self.anomalies[i].get("file", "")).casefold())
        self.visible_anomaly_indices = indices
        self.anomaly_table.setRowCount(len(indices))
        for row, index in enumerate(indices):
            item = self.anomalies[index]
            filename = str(item.get("file") or Path(str(item.get("path", ""))).name or "Not recorded")
            values = [filename, _anomaly_feature(item), _display(item.get("max_z_score")), "Statistical outlier"]
            for column, value in enumerate(values):
                self.anomaly_table.setItem(row, column, QTableWidgetItem(value))
            self.anomaly_table.item(row, 0).setData(Qt.ItemDataRole.UserRole, index)
            blob = json.dumps(item, ensure_ascii=False, default=str).casefold()
            visible = (not needle or needle in blob) and (feature == "All features" or feature.casefold() == _anomaly_feature(item).casefold())
            self.anomaly_table.setRowHidden(row, not visible)

    def open_anomaly_row(self, row: int, _column: int):
        if not 0 <= row < self.anomaly_table.rowCount():
            return
        cell = self.anomaly_table.item(row, 0)
        index = cell.data(Qt.ItemDataRole.UserRole) if cell else None
        if isinstance(index, int) and 0 <= index < len(self.anomalies):
            ShiftAnomalyDialog(self.anomalies[index], self.dataset_root, self).exec()

    def _render_findings(self):
        if hasattr(self, "finding_table") and self.finding_table.rowCount():
            self.finding_table.setRowCount(0)
        indices = list(range(len(self.findings)))
        if self.finding_sort.currentText() == "Severity":
            order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
            indices.sort(key=lambda i: order.get(str(self.findings[i].get("severity", "")).upper(), 0), reverse=True)
        elif self.finding_sort.currentText() == "Confidence":
            indices.sort(key=lambda i: float(self.findings[i].get("confidence"))
                         if isinstance(self.findings[i].get("confidence"), (int, float)) else -1, reverse=True)
        else:
            indices.sort(key=lambda i: str(self.findings[i].get("title", "")).casefold())
        self.visible_finding_indices = indices
        self.finding_table.setRowCount(len(indices))
        for row, index in enumerate(indices):
            finding = self.findings[index]
            values = [str(finding.get("severity", "NOT ASSIGNED")).upper(), finding.get("category", "Not recorded"),
                      _display(finding.get("confidence")), finding.get("finding_id", "Not recorded"),
                      finding.get("title", "Finding")]
            for column, value in enumerate(values):
                self.finding_table.setItem(row, column, QTableWidgetItem(str(value)))
            self.finding_table.item(row, 3).setData(Qt.ItemDataRole.UserRole, index)
        self.finding_table.resizeColumnsToContents()
        self.apply_finding_filters()

    def apply_finding_filters(self, *_):
        if not hasattr(self, "finding_table"):
            return
        needle = self.finding_search.currentText().casefold().strip()
        severity = self.finding_severity.currentText()
        for row in range(self.finding_table.rowCount()):
            cell = self.finding_table.item(row, 3)
            index = cell.data(Qt.ItemDataRole.UserRole) if cell else -1
            if not isinstance(index, int) or not 0 <= index < len(self.findings):
                self.finding_table.setRowHidden(row, True)
                continue
            finding = self.findings[index]
            blob = json.dumps(finding, ensure_ascii=False, default=str).casefold()
            visible = (severity == "All severities" or str(finding.get("severity", "")).upper() == severity) and (not needle or needle in blob)
            self.finding_table.setRowHidden(row, not visible)

    def open_finding_row(self, row: int, _column: int):
        if not 0 <= row < self.finding_table.rowCount():
            return
        cell = self.finding_table.item(row, 3)
        index = cell.data(Qt.ItemDataRole.UserRole) if cell else None
        if isinstance(index, int) and 0 <= index < len(self.findings):
            ShiftFindingDialog(self.findings[index], self).exec()
