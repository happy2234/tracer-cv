"""Assessment-backed B1–B4 model integrity analyst workspace."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox, QDialog, QHBoxLayout, QLabel, QPushButton, QScrollArea,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from desktop.widgets.components import (
    AnalystTable, EvidenceViewerDialog, MetricBarChart, MetricCard,
    SectionCard, SeverityBadge,
)


ENGINE_SPECS = (
    ("B1_identity", "B1", "Model Identity"),
    ("B2_behavioral_fingerprint", "B2", "Behavioral Fingerprint"),
    ("B3_model_statistics", "B3", "Parameter & Activation Statistics"),
    ("B4_trigger_search", "B4", "Trigger Search / Reconstruction"),
)
SEVERITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


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


def model_engine_status(engine_id: str, result: dict[str, Any], records: dict[str, Any]) -> str:
    record = records.get(engine_id, {}) if isinstance(records.get(engine_id, {}), dict) else {}
    raw = str(record.get("status", result.get("status", "unavailable"))).strip().lower()
    if raw in {"completed", "completed_with_warnings", "completed_with_errors"} and not result:
        return "UNAVAILABLE"
    return {
        "completed": "COMPLETED", "completed_with_warnings": "COMPLETED WITH WARNINGS",
        "completed_with_errors": "COMPLETED WITH WARNINGS", "not_assessed": "NOT ASSESSED",
        "unavailable": "UNAVAILABLE", "error": "ERROR", "failed": "ERROR",
        "running": "RUNNING", "queued": "QUEUED", "created": "QUEUED", "cancelled": "CANCELLED",
    }.get(raw, raw.upper() or "UNAVAILABLE")


def _finding_engine(finding: dict[str, Any]) -> str:
    value = str(finding.get("source_engine", "")).upper()
    return value if value in {"B1", "B2", "B3", "B4"} else "MODEL" if value == "MODEL" else ""


def engine_finding_count(engine_id: str, findings: list[dict[str, Any]], findings_available: bool) -> int | None:
    code = next((code for key, code, _ in ENGINE_SPECS if key == engine_id), "")
    exact = sum(1 for item in findings if _finding_engine(item) == code)
    if exact:
        return exact
    # C3's general `model` source is not attributable to a specific B engine.
    if code in {"B2", "B3"} and any(_finding_engine(item) == "MODEL" for item in findings):
        return None
    return 0 if findings_available else None


def engine_severity(engine_id: str, result: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    explicit = result.get("severity")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.upper()
    code = next((code for key, code, _ in ENGINE_SPECS if key == engine_id), "")
    linked = [item for item in findings if _finding_engine(item) == code]
    if linked:
        return max((str(item.get("severity", "INFO")).upper() for item in linked),
                   key=lambda value: SEVERITY_ORDER.get(value, 0))
    return "NONE REPORTED" if not result or result.get("status") == "completed" else "NOT ASSIGNED"


def sort_engine_rows(rows: list[dict[str, Any]], sort_by: str, descending: bool = False) -> list[dict[str, Any]]:
    def key(row):
        if sort_by == "Severity":
            return SEVERITY_ORDER.get(row["severity"], 0)
        if sort_by == "Finding count":
            return row["finding_count"] if row["finding_count"] is not None else -1
        if sort_by == "Status":
            return row["status"]
        return row["spec"][1]
    return sorted(rows, key=key, reverse=descending)


def _flatten_scalars(value: Any, prefix: str = "") -> list[tuple[str, Any]]:
    pairs: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            label = f"{prefix} · {_humanize(key)}" if prefix else _humanize(key)
            if isinstance(child, dict):
                pairs.extend(_flatten_scalars(child, label))
            elif isinstance(child, list):
                if child and all(not isinstance(item, (dict, list)) for item in child):
                    pairs.append((label, _display(child)))
            elif child is not None:
                pairs.append((label, child))
    return pairs


def _class_distribution_tv(reference: Any, assessed: Any) -> float | None:
    if not isinstance(reference, dict) or not isinstance(assessed, dict):
        return None
    try:
        ref_total = sum(float(value) for value in reference.values())
        ass_total = sum(float(value) for value in assessed.values())
        if ref_total <= 0 or ass_total <= 0:
            return None
        classes = set(reference) | set(assessed)
        return 0.5 * sum(abs(float(reference.get(label, 0)) / ref_total - float(assessed.get(label, 0)) / ass_total)
                         for label in classes)
    except (TypeError, ValueError):
        return None


def _status_explanation(code: str, result: dict[str, Any], status: str) -> str:
    if status != "COMPLETED":
        return str(result.get("reason") or {
            "NOT ASSESSED": "This engine was not run for the selected assessment.",
            "UNAVAILABLE": "No persisted result is available for this engine.",
            "ERROR": "The engine recorded an error. Open technical details for its recorded context.",
        }.get(status, "No completed result is available."))
    if code == "B1":
        return "B1 recorded the model file's byte identity and format indicators. A digest establishes identity, not trustworthiness."
    if code == "B2":
        return "B2 recorded responses to its deterministic probe battery. Behavioral differences may have legitimate causes and do not establish malicious modification."
    if code == "B3":
        return "B3 recorded parameter, structure, and available activation statistics. Statistical deviations do not establish malicious modification."
    return "B4 tested configured localized perturbations. Candidate trigger-like evidence requires review and does not prove a backdoor."


class ModelFindingDialog(QDialog):
    def __init__(self, finding: dict[str, Any], model_name: str, parent=None):
        super().__init__(parent)
        self.finding = finding
        self.setWindowTitle(f"Model finding · {finding.get('finding_id', 'Finding')}")
        self.resize(820, 680)
        outer = QVBoxLayout(self)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); outer.addWidget(scroll)
        body = QWidget(); layout = QVBoxLayout(body); scroll.setWidget(body)
        heading = QLabel(str(finding.get("title", "Model finding"))); heading.setObjectName("pageTitle"); layout.addWidget(heading)
        layout.addWidget(SeverityBadge(str(finding.get("severity", "NOT ASSIGNED"))))
        identity = SectionCard("Finding")
        affected_model = finding.get("affected_asset") or model_name
        if isinstance(affected_model, str):
            affected_model = Path(affected_model).name or model_name
        for label, key, fallback in (
            ("Finding ID", "finding_id", "Not recorded"), ("Category", "category", "Not recorded"),
            ("Confidence", "confidence", "Not recorded"), ("Affected model", "affected_asset", model_name),
            ("Source engine", "source_engine", "Not recorded"),
        ):
            value = affected_model if key == "affected_asset" else finding.get(key)
            identity.content.addWidget(QLabel(f"{label}: {_display(value, fallback)}"))
        layout.addWidget(identity)
        explanation = SectionCard("Why this was flagged")
        explanation.content.addWidget(QLabel(str(finding.get("explanation", "No explanation was recorded."))))
        layout.addWidget(explanation)
        evidence = finding.get("evidence") if isinstance(finding.get("evidence"), list) else []
        evidence_card = SectionCard("Evidence")
        rows = []
        for entry in evidence:
            if isinstance(entry, dict):
                name = str(entry.get("type") or entry.get("metric") or entry.get("name") or "Recorded evidence")
                value = entry.get("value", {k: v for k, v in entry.items() if k not in {"type", "metric", "name"}})
                interpretation = _interpret_evidence(name, value)
                rows.append([_humanize(name), _display(value), interpretation, str(finding.get("source_engine", "C3"))])
            else:
                rows.append(["Evidence", _display(entry), "Recorded by the source engine.", str(finding.get("source_engine", "C3"))])
        evidence_card.content.addWidget(AnalystTable(["Evidence item", "Value", "Interpretation", "Source"],
                                                     rows or [["Evidence", "Not recorded", "No structured evidence is available.", "C3"]]))
        layout.addWidget(evidence_card)
        limitations = SectionCard("Limitations and recommendation")
        limitations.content.addWidget(QLabel("Limitations: " + _display(finding.get("limitations", []))))
        if finding.get("recommended_action"):
            limitations.content.addWidget(QLabel("Recommended investigation: " + str(finding["recommended_action"])))
        layout.addWidget(limitations)
        self.evidence_button = QPushButton("Technical Details")
        self.evidence_button.clicked.connect(lambda: EvidenceViewerDialog(
            "Model finding evidence", str(finding.get("explanation", "Recorded model evidence.")),
            "\n".join(f"{row[0]}: {row[1]} — {row[2]}" for row in rows) or "No structured evidence was recorded.",
            finding, self).exec())
        layout.addWidget(self.evidence_button)
        close = QPushButton("Close"); close.clicked.connect(self.accept); outer.addWidget(close)


def _interpret_evidence(name: str, value: Any) -> str:
    key = name.casefold()
    if "sha256" in key or "digest" in key or "model_id" in key:
        return "Cryptographic or configuration identifier recorded by the source engine."
    if "class_change_rate" in key or "target_hit_rate" in key:
        return "Observed fraction of assessed samples meeting the recorded class-change condition."
    if "confidence_gain" in key:
        return "Measured confidence difference under the recorded probe; not evidence of intent."
    if "patch" in key or "location" in key:
        return "Configured perturbation details; candidate behavior does not prove a backdoor."
    if "difference" in key or "deviation" in key or "distance" in key:
        return "Measured difference from the stated comparison basis; interpretation depends on compatibility and thresholds."
    return "Value retained from the source engine for analyst review."


class ModelEngineDialog(QDialog):
    def __init__(self, spec, result: dict[str, Any], record: dict[str, Any], findings: list[dict[str, Any]], parent=None):
        self.engine_id, self.code, self.name = spec
        self.result, self.record = result, record
        super().__init__(parent)
        self.setWindowTitle(f"{self.code} · {self.name}"); self.resize(920, 740)
        outer = QVBoxLayout(self); scroll = QScrollArea(); scroll.setWidgetResizable(True); outer.addWidget(scroll)
        body = QWidget(); layout = QVBoxLayout(body); layout.setSpacing(12); scroll.setWidget(body)
        heading = QLabel(f"{self.code} — {self.name}"); heading.setObjectName("pageTitle"); layout.addWidget(heading)
        status = model_engine_status(self.engine_id, result, {self.engine_id: record})
        layout.addWidget(SeverityBadge(f"STATUS · {status}"))
        reason = record.get("reason") or result.get("reason")
        if reason:
            reason_card = SectionCard("Availability / execution detail"); reason_card.content.addWidget(QLabel(str(reason))); layout.addWidget(reason_card)
        situation = SectionCard("Situation"); situation.content.addWidget(QLabel(_status_explanation(self.code, result, status))); layout.addWidget(situation)
        self._render_engine_detail(layout)
        linked = [item for item in findings if _finding_engine(item) in {self.code, "MODEL"}]
        related = SectionCard("Related findings")
        if linked:
            for finding in linked:
                button = QPushButton(f"{str(finding.get('severity', 'NOT ASSIGNED')).upper()} · {finding.get('title', 'Finding')} · {finding.get('finding_id', '')}")
                button.clicked.connect(lambda checked=False, item=finding: ModelFindingDialog(item, "assessed model", self).exec())
                related.content.addWidget(button)
        else:
            related.content.addWidget(QLabel("No C3 model finding is linked to this engine result."))
        layout.addWidget(related)
        limitations = result.get("limitations", [])
        if isinstance(limitations, str): limitations = [limitations]
        limit_card = SectionCard("Engine limitations")
        limit_card.content.addWidget(QLabel("\n".join(f"• {value}" for value in limitations) if limitations else "No engine-specific limitation list was recorded."))
        layout.addWidget(limit_card)
        tech = QPushButton("Technical Details"); tech.clicked.connect(lambda: EvidenceViewerDialog(
            f"{self.code} technical details", _status_explanation(self.code, result, status),
            "Persisted engine fields are available below on request.", result, self).exec())
        layout.addWidget(tech)
        close = QPushButton("Close"); close.clicked.connect(self.accept); outer.addWidget(close)

    def _render_engine_detail(self, layout):
        data = self.result
        if self.code == "B1":
            verification = data.get("verification") if isinstance(data.get("verification"), dict) else {}
            verified = "VERIFIED" if verification.get("match") is True else "FAILED" if verification.get("match") is False else "NOT ASSESSED"
            card = SectionCard("Model identity")
            values = [("Model ID", data.get("model_id")), ("SHA-256", data.get("sha256")),
                      ("Format", data.get("format")), ("File size (bytes)", data.get("file_size_bytes")),
                      ("Content signature", data.get("content_signature")), ("Verification", verified)]
            card.content.addWidget(AnalystTable(["Identity field", "Recorded value"], [[name, _display(value)] for name, value in values]))
            card.content.addWidget(QLabel("The assessed model is identified by its recorded SHA-256 digest. Identity does not establish trustworthiness."))
            layout.addWidget(card)
            return
        if self.code == "B2":
            fingerprint = data.get("fingerprint") if isinstance(data.get("fingerprint"), dict) else {}
            model = data.get("model") if isinstance(data.get("model"), dict) else {}
            card = SectionCard("Behavioral fingerprint")
            card.content.addWidget(QLabel(f"Assessed fingerprint: {_display(fingerprint.get('digest'))}\nProbe dataset digest: {_display(fingerprint.get('dataset_digest'))}\nReference fingerprint: {_display(data.get('reference_fingerprint'), 'Behavioral comparison unavailable — no compatible reference fingerprint was provided.') }"))
            probes = data.get("probes") if isinstance(data.get("probes"), list) else []
            baseline = data.get("baseline") if isinstance(data.get("baseline"), dict) else (probes[0] if probes and isinstance(probes[0], dict) else {})
            rows = [[p.get("probe", "Probe"), p.get("transform", "Not recorded"), p.get("images", "Not recorded"),
                     p.get("prediction_agreement", "Not available"), p.get("mean_confidence", "Not available"),
                     p.get("mean_entropy", "Not available"), _class_distribution_tv(baseline.get("prediction_distribution"), p.get("prediction_distribution")),
                     p.get("prediction_distribution", "Not recorded")]
                    for p in probes if isinstance(p, dict)]
            card.content.addWidget(AnalystTable(["Probe", "Transform", "Samples", "Agreement with clean", "Mean confidence", "Mean entropy", "Class-distribution TV from clean", "Observed class distribution"], rows or [["No probe details were persisted"] + [""] * 7]))
            if rows:
                chart_rows = [[row[0], row[3], "normal"] for row in rows if isinstance(row[3], (int, float))]
                if chart_rows:
                    card.content.addWidget(MetricBarChart("Prediction agreement with clean probe", chart_rows))
            dataset = data.get("dataset") if isinstance(data.get("dataset"), dict) else {}
            config = data.get("config") if isinstance(data.get("config"), dict) else {}
            card.content.addWidget(QLabel(f"Adapter: {_display(model.get('adapter'))}; class count: {_display(model.get('class_count'))}; probabilities: {_display(model.get('probabilities_available'))}; input shape: {_display(dataset.get('image_shape'))}; probe seed: {_display(config.get('seed'))}. These are within-model probe responses, not a comparison against another model."))
            layout.addWidget(card)
            return
        if self.code == "B3":
            parameters = data.get("parameters") if isinstance(data.get("parameters"), dict) else {}
            totals = parameters.get("totals") if isinstance(parameters.get("totals"), dict) else {}
            structure = data.get("structure") if isinstance(data.get("structure"), dict) else {}
            activations = data.get("activations") if isinstance(data.get("activations"), dict) else {}
            card = SectionCard("Parameters and structure")
            metric_rows = [[_humanize(key), value] for key, value in totals.items() if not isinstance(value, (dict, list))]
            for key in ("mean", "std", "min", "max", "nan_count", "posinf_count", "neginf_count"):
                if key in parameters:
                    metric_rows.append([_humanize(key), parameters[key]])
            card.content.addWidget(AnalystTable(["Metric", "Recorded value"], metric_rows or [["Parameter metrics", "Not available in this result"]]))
            card.content.addWidget(QLabel(f"Structure: {_display(structure.get('module_count'), 'Not available')} module(s); leaf modules: {_display(structure.get('leaf_module_count'))}; access: {_display(data.get('model', {}).get('access') if isinstance(data.get('model'), dict) else None)}"))
            module_types = structure.get("module_type_counts") if isinstance(structure.get("module_type_counts"), dict) else {}
            if module_types:
                card.content.addWidget(AnalystTable(["Module type", "Count"], [[name, count] for name, count in module_types.items()]))
            modules = structure.get("modules") if isinstance(structure.get("modules"), list) else []
            if modules:
                card.content.addWidget(AnalystTable(["Module", "Type"], [[item.get("name", "Module"), item.get("type", "Not recorded")]
                                                                           for item in modules if isinstance(item, dict)][:100]))
            tensor_rows = []
            for tensor in parameters.get("tensors", []) if isinstance(parameters.get("tensors"), list) else []:
                if not isinstance(tensor, dict): continue
                stats = tensor.get("statistics") if isinstance(tensor.get("statistics"), dict) else {}
                tensor_rows.append([tensor.get("name", "Tensor"), tensor.get("kind", "Not recorded"), tensor.get("num_elements", "Not recorded"),
                                    stats.get("mean", "Not available"), stats.get("std", "Not available"), stats.get("min", "Not available"), stats.get("max", "Not available"),
                                    stats.get("nan_count", "Not available"), stats.get("posinf_count", "Not available"), stats.get("neginf_count", "Not available")])
                if len(tensor_rows) >= 200: break
            card.content.addWidget(AnalystTable(["Tensor", "Kind", "Elements", "Mean", "Std", "Min", "Max", "NaN", "+Inf", "−Inf"], tensor_rows or [["Per-tensor statistics unavailable"] + [""] * 9]))
            layout.addWidget(card)
            activation = SectionCard("Activation statistics")
            if activations.get("status") in {"completed", "available"}:
                activation.content.addWidget(QLabel(f"Available for {len(activations.get('layers', []))} recorded layer(s) and the stated probe set."))
                activation.content.addWidget(AnalystTable(["Layer", "Statistics"], [[item.get("name", "Layer"), _display(item.get("statistics", item))] for item in activations.get("layers", []) if isinstance(item, dict)][:100] or [["Activation layers", "No layer records were returned"]]))
            else:
                activation.content.addWidget(QLabel(f"Activation statistics unavailable for this model representation. {_display(activations.get('reason'), '')}"))
            layout.addWidget(activation)
            comparison = data.get("comparison") or data.get("reference_comparison")
            compare_card = SectionCard("Reference comparison")
            if isinstance(comparison, dict):
                pairs = _flatten_scalars(comparison)
                compare_card.content.addWidget(AnalystTable(["Metric", "Recorded comparison"], [[key, _display(value)] for key, value in pairs[:100]] or [["Comparison", "No comparable metrics recorded"]]))
            else:
                compare_card.content.addWidget(QLabel("No compatible reference statistics were recorded."))
            layout.addWidget(compare_card)
            return
        search = data.get("search") if isinstance(data.get("search"), dict) else {}
        configuration = search.get("configuration") if isinstance(search.get("configuration"), dict) else {}
        assessment = data.get("assessment") if isinstance(data.get("assessment"), dict) else {}
        card = SectionCard("Trigger search evidence")
        card.content.addWidget(QLabel(f"Candidate status: {_display(assessment.get('interpretation'), 'No candidate interpretation was recorded.')}\nImages assessed: {_display(search.get('images_assessed'))} / {_display(search.get('images_requested'))}\nPatch sizes: {_display(configuration.get('patch_sizes'))}\nPositions: {_display(configuration.get('grid_fractions'))}\nPatterns: {_display(configuration.get('patterns'))}\nCandidate trigger-like count: {_display(data.get('candidate_trigger_count'))}"))
        candidates = data.get("candidate_evidence") if isinstance(data.get("candidate_evidence"), list) else []
        all_candidates = data.get("all_candidates") if isinstance(data.get("all_candidates"), list) else []
        if model_engine_status(self.engine_id, data, {self.engine_id: self.record}) != "COMPLETED":
            card.content.addWidget(QLabel("Trigger search was not assessed for this model result. No trigger-search conclusion is available."))
        elif candidates:
            rows = []
            for item in candidates[:200]:
                if not isinstance(item, dict): continue
                candidate = item.get("candidate") if isinstance(item.get("candidate"), dict) else {}
                changed = item.get("class_change_count")
                sample_count = item.get("sample_count")
                repeatability = f"{changed}/{sample_count} samples changed" if isinstance(changed, int) and isinstance(sample_count, int) else "Not recorded"
                rows.append([candidate.get("patch_size", "Not recorded"), candidate.get("x_fraction", "Not recorded"), candidate.get("y_fraction", "Not recorded"), candidate.get("pattern", "Not recorded"),
                             item.get("target_class", "Not recorded"), item.get("class_change_rate", "Not recorded"), repeatability,
                             item.get("target_hit_rate", "Not recorded"), item.get("mean_clean_confidence", "Not recorded"),
                             item.get("mean_patched_confidence", "Not recorded"), item.get("mean_confidence_gain", "Not recorded"),
                             item.get("mean_probability_l1_change", "Not recorded"), "CANDIDATE TRIGGER-LIKE" if item.get("candidate_trigger_like") else "Candidate evidence"])
            card.content.addWidget(AnalystTable(["Patch", "X", "Y", "Pattern", "Target class", "Class change rate", "Repeatability", "Target-hit rate", "Clean confidence", "Patched confidence", "Confidence gain", "Probability L1 change", "Status"], rows or [["No structured candidate details"] + [""] * 12]))
        elif data.get("candidate_trigger_count") == 0:
            card.content.addWidget(QLabel("No tested localized perturbation met the configured candidate criteria. Absence of candidate evidence does not prove absence of a backdoor."))
            if all_candidates:
                tested = sorted((item for item in all_candidates if isinstance(item, dict)),
                                key=lambda item: item.get("class_change_rate") if isinstance(item.get("class_change_rate"), (int, float)) else 0, reverse=True)[:20]
                tested_rows = []
                for item in tested:
                    candidate = item.get("candidate") if isinstance(item.get("candidate"), dict) else {}
                    tested_rows.append([candidate.get("patch_size", "Not recorded"), candidate.get("x_fraction", "Not recorded"),
                                        candidate.get("y_fraction", "Not recorded"), candidate.get("pattern", "Not recorded"),
                                        item.get("class_change_rate", "Not recorded"), item.get("mean_confidence_gain", "Not recorded"),
                                        "Below configured candidate criteria" if item.get("candidate_trigger_like") is False else "Recorded candidate result"])
                card.content.addWidget(QLabel(f"Showing {len(tested_rows)} tested perturbation(s) with the highest recorded class-change rates; these did not meet the engine's candidate criteria."))
                card.content.addWidget(AnalystTable(["Patch", "X", "Y", "Pattern", "Class change rate", "Mean confidence gain", "Recorded status"], tested_rows))
                chart_rows = [[str(row[3]), row[4], "normal"] for row in tested_rows[:8] if isinstance(row[4], (int, float))]
                if chart_rows:
                    card.content.addWidget(MetricBarChart("Class-change rate among leading tested perturbations", chart_rows))
        else:
            card.content.addWidget(QLabel("Candidate summary records exist, but no detailed candidate evidence was persisted."))
        card.content.addWidget(QLabel("Candidate trigger-like behavior requires analyst review. It does not prove a backdoor or poisoning, and results depend on the configured search space and supplied images."))
        layout.addWidget(card)


class ModelIntegrityWorkspace(QWidget):
    def __init__(self, assessment: dict[str, Any] | None, results: dict[str, Any] | None,
                 findings: list[dict[str, Any]] | None, *, on_rerun: Callable[[], None] | None = None, parent=None):
        super().__init__(parent)
        self.assessment = assessment if isinstance(assessment, dict) else {}
        self.results = results if isinstance(results, dict) else {}
        self.findings_available = isinstance(findings, list)
        self.findings = [item for item in (findings or []) if isinstance(item, dict)
                         and (_finding_engine(item) or item.get("category") == "model_integrity")]
        self.records = dict(self.assessment.get("engines", {})) if isinstance(self.assessment.get("engines"), dict) else {}
        self.model_record = self.assessment.get("model", {}) if isinstance(self.assessment.get("model"), dict) else {}
        self.engine_rows: list[dict[str, Any]] = []
        self._build(on_rerun)

    def _build(self, on_rerun):
        outer = QVBoxLayout(self); outer.setContentsMargins(24, 20, 24, 24); outer.setSpacing(12)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); outer.addWidget(scroll)
        body = QWidget(); layout = QVBoxLayout(body); layout.setSpacing(12); scroll.setWidget(body)
        title = QLabel("Model Integrity"); title.setObjectName("pageTitle"); layout.addWidget(title)
        if not self.assessment:
            empty = SectionCard("No assessment selected")
            empty.content.addWidget(QLabel("Open a saved assessment or run a new local assessment to inspect persisted B1–B4 model evidence."))
            layout.addWidget(empty); return

        status = str(self.assessment.get("status", "UNKNOWN")).replace("_", " ").upper()
        model_path = Path(str(self.model_record.get("path", ""))).name if self.model_record.get("path") else "Model unavailable"
        b1 = self.results.get("B1_identity") if isinstance(self.results.get("B1_identity"), dict) else {}
        model_id = b1.get("model_id") or self.model_record.get("model_id") or "Not available"
        model_hash = b1.get("sha256") or self.model_record.get("sha256") or "Not available"
        model_format = b1.get("format") or Path(str(self.model_record.get("path", ""))).suffix or "Not recorded"
        header = SectionCard("Assessment and model")
        header.content.addWidget(QLabel(f"Assessment: {self.assessment.get('name') or 'Unnamed assessment'}\nModel: {model_path}\nModel ID: {model_id}"))
        state_row = QHBoxLayout(); state_row.addWidget(SeverityBadge(status)); state_row.addWidget(QLabel(f"SHA-256: {model_hash}")); state_row.addStretch(); header.content.addLayout(state_row)
        actions = QHBoxLayout()
        evidence = QPushButton("Open Model Evidence")
        evidence.clicked.connect(lambda: EvidenceViewerDialog("Model assurance evidence", "Persisted B1–B4 results for the selected assessment.", "Model identity, behavioral, statistical, and trigger-search sections are listed below.", self.results, self).exec())
        rerun = QPushButton("Re-run Assessment"); rerun.setEnabled(on_rerun is not None)
        if on_rerun: rerun.clicked.connect(on_rerun)
        actions.addWidget(evidence); actions.addWidget(rerun); header.content.addLayout(actions); layout.addWidget(header)
        if status in {"RUNNING", "QUEUED", "CREATED"}:
            notice = SectionCard("Assessment in progress"); notice.content.addWidget(QLabel("B1–B4 results may be incomplete while the selected assessment is running.")); layout.addWidget(notice)
        elif status == "FAILED":
            notice = SectionCard("Assessment failed"); notice.content.addWidget(QLabel("The assessment did not complete. Persisted engine results, if any, remain inspectable below.")); layout.addWidget(notice)
        elif status in {"COMPLETED WITH WARNINGS", "COMPLETED WITH ERRORS"}:
            notice = SectionCard("Completed with warnings"); notice.content.addWidget(QLabel("One or more engines were skipped, unavailable, or failed. Review each B1–B4 status and its recorded reason.")); layout.addWidget(notice)

        verification = b1.get("verification") if isinstance(b1.get("verification"), dict) else {}
        verified = "VERIFIED" if verification.get("match") is True else "FAILED" if verification.get("match") is False else "NOT ASSESSED"
        summary = QHBoxLayout()
        for index, card in enumerate((
            MetricCard("Model ID", str(model_id), "B1 identity identifier", "info"),
            MetricCard("SHA-256", str(model_hash), "Recorded model byte digest", "info"),
            MetricCard("Format", str(model_format), str(b1.get("format_confidence", "Format confidence not recorded")), "normal"),
            MetricCard("B1 verification", verified, "Compared only when an expected digest was supplied", "verified" if verified == "VERIFIED" else "unavailable" if verified == "NOT ASSESSED" else "critical"),
        )):
            summary.addWidget(card)
        layout.addLayout(summary)
        if not self.results:
            missing = SectionCard("Model results unavailable"); missing.content.addWidget(QLabel("No persisted B1–B4 result document is available for this assessment.")); layout.addWidget(missing)

        for key, _, _ in ENGINE_SPECS:
            raw = self.results.get(key)
            if raw is None:
                self.results[key] = {}
            elif isinstance(raw, dict):
                if raw.get("status") in {"error", "failed"}:
                    self.records[key] = {**self.records.get(key, {}), "status": raw.get("status"),
                                          "reason": raw.get("reason") or raw.get("error") or "Engine result recorded an error."}
                continue
            else:
                self.results[key] = {"status": "error", "reason": "Persisted model result is malformed; an object was expected.",
                                     "technical_error": f"Received {type(raw).__name__} instead of an object."}
                self.records[key] = {**self.records.get(key, {}), "status": "error", "reason": self.results[key]["reason"]}

        coverage = SectionCard("B1–B4 engine coverage")
        controls = QHBoxLayout()
        self.search = QComboBox(); self.search.setEditable(True); self.search.setInsertPolicy(QComboBox.InsertPolicy.NoInsert); self.search.lineEdit().setPlaceholderText("Search finding ID, model, title, category…")
        self.engine_filter = QComboBox(); self.engine_filter.addItems(["All engines", *[f"{code} {name}" for _, code, name in ENGINE_SPECS]])
        model_name = model_path if model_path != "Model unavailable" else "Not available"
        self.model_filter = QComboBox(); self.model_filter.addItems(["All models", model_name])
        self.status_filter = QComboBox(); self.status_filter.addItems(["All statuses", "COMPLETED", "COMPLETED WITH WARNINGS", "NOT ASSESSED", "UNAVAILABLE", "ERROR"])
        self.severity_filter = QComboBox(); self.severity_filter.addItems(["All severities", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NONE REPORTED", "NOT ASSIGNED"])
        categories = sorted({str(item.get("category", "Not recorded")) for item in self.findings})
        self.category_filter = QComboBox(); self.category_filter.addItems(["All categories", *categories])
        self.sort_by = QComboBox(); self.sort_by.addItems(["Engine", "Status", "Severity", "Finding count"])
        self.sort_order = QComboBox(); self.sort_order.addItems(["Ascending", "Descending"])
        for control in (self.search, self.engine_filter, self.model_filter, self.status_filter, self.severity_filter, self.category_filter, self.sort_by, self.sort_order): controls.addWidget(control)
        coverage.content.addLayout(controls)
        for spec in ENGINE_SPECS:
            key, code, name = spec; result = self.results[key]
            state = model_engine_status(key, result, self.records)
            linked = [item for item in self.findings if _finding_engine(item) == code]
            count = engine_finding_count(key, self.findings, self.findings_available)
            if state not in {"COMPLETED", "COMPLETED WITH WARNINGS"}:
                count = None
            severity = engine_severity(key, result, self.findings)
            explanation = _status_explanation(code, result, state)
            self.engine_rows.append({"spec": spec, "result": result, "status": state, "finding_count": count,
                                     "severity": severity, "findings": linked, "explanation": explanation})
        self.table_host = QWidget(); self.table_layout = QVBoxLayout(self.table_host); self.table_layout.setContentsMargins(0, 0, 0, 0)
        coverage.content.addWidget(self.table_host); layout.addWidget(coverage)
        self._render_engine_table()

        finding_card = SectionCard("Model findings")
        finding_sort = QHBoxLayout()
        self.finding_sort_by = QComboBox(); self.finding_sort_by.addItems(["Severity", "Engine", "Confidence"])
        self.finding_sort_order = QComboBox(); self.finding_sort_order.addItems(["Descending", "Ascending"])
        finding_sort.addWidget(QLabel("Sort findings")); finding_sort.addWidget(self.finding_sort_by); finding_sort.addWidget(self.finding_sort_order); finding_sort.addStretch()
        finding_card.content.addLayout(finding_sort)
        self.finding_table_host = QWidget(); self.finding_table_layout = QVBoxLayout(self.finding_table_host); self.finding_table_layout.setContentsMargins(0, 0, 0, 0)
        finding_card.content.addWidget(self.finding_table_host)
        finding_card.content.addWidget(QLabel("Candidate anomalies describe measured evidence and require analyst interpretation; they do not by themselves establish model safety, maliciousness, or a backdoor."))
        if not self.findings:
            if not self.findings_available:
                finding_card.content.addWidget(QLabel("Persisted C3 model findings are unavailable for this assessment."))
            else:
                finding_card.content.addWidget(QLabel("No persisted C3 model findings are recorded for this assessment."))
        layout.addWidget(finding_card)
        capabilities = SectionCard("Access and compute")
        b3 = self.results["B3_model_statistics"]
        model = b3.get("model") if isinstance(b3.get("model"), dict) else {}
        access = model.get("access") or ("WHITE-BOX" if b3.get("status") == "completed" and isinstance(b3.get("parameters"), dict) else "UNAVAILABLE")
        b3_status = model_engine_status("B3_model_statistics", b3, self.records)
        capability_note = ("Parameter/activation analysis was not assessed for this model representation." if b3_status == "NOT ASSESSED"
                           else "Parameter/activation analysis unavailable for the supplied model representation." if b3_status in {"UNAVAILABLE", "ERROR"}
                           else "B3 access and activation availability are reported from the stored result.")
        capabilities.content.addWidget(QLabel(f"B3 access: {str(access).replace('_', ' ').upper()}\n{capability_note}\nExecution device: {self.assessment.get('compute', {}).get('device', 'Not recorded') if isinstance(self.assessment.get('compute'), dict) else 'Not recorded'}\nOpening this page reads persisted results only; it does not load the model or rerun B2–B4."))
        layout.addWidget(capabilities)

        self.filter_controls = (self.search, self.engine_filter, self.model_filter, self.status_filter, self.severity_filter, self.category_filter, self.sort_by, self.sort_order)
        self.search.lineEdit().textChanged.connect(self.apply_filters)
        for control in self.filter_controls[1:]: control.currentTextChanged.connect(self.apply_filters)
        self.finding_sort_by.currentTextChanged.connect(self._render_finding_table)
        self.finding_sort_order.currentTextChanged.connect(self._render_finding_table)
        self._render_finding_table()
        self.apply_filters(); layout.addStretch()

    def _render_finding_table(self, *_):
        if hasattr(self, "finding_table"):
            self.finding_table_layout.removeWidget(self.finding_table); self.finding_table.deleteLater()
        indices = list(range(len(self.findings)))
        descending = self.finding_sort_order.currentText() == "Descending"
        mode = self.finding_sort_by.currentText()
        if mode == "Severity":
            indices.sort(key=lambda index: SEVERITY_ORDER.get(str(self.findings[index].get("severity", "")).upper(), 0), reverse=descending)
        elif mode == "Confidence":
            indices.sort(key=lambda index: float(self.findings[index].get("confidence"))
                         if isinstance(self.findings[index].get("confidence"), (int, float)) else -1, reverse=descending)
        else:
            indices.sort(key=lambda index: _finding_engine(self.findings[index]), reverse=descending)
        self.visible_finding_indices = indices
        self.finding_table = AnalystTable(["Engine", "Category", "Severity", "Finding ID", "Confidence", "Finding"], [
            [_finding_engine(self.findings[index]) or "MODEL", self.findings[index].get("category", "Not recorded"),
             str(self.findings[index].get("severity", "NOT ASSIGNED")).upper(), self.findings[index].get("finding_id", "Not recorded"),
             self.findings[index].get("confidence", "Not recorded"), self.findings[index].get("title", "Finding")]
            for index in indices])
        for row, index in enumerate(indices):
            self.finding_table.item(row, 3).setData(Qt.ItemDataRole.UserRole, index)
        self.finding_table.cellDoubleClicked.connect(self.open_finding_row)
        self.finding_table_layout.addWidget(self.finding_table)
        self.apply_filters()

    def _render_engine_table(self):
        if hasattr(self, "engine_table"):
            self.table_layout.removeWidget(self.engine_table); self.engine_table.deleteLater()
        self.visible_engine_rows = sort_engine_rows(self.engine_rows, self.sort_by.currentText(), self.sort_order.currentText() == "Descending")
        headers = ["Engine", "Status", "Finding Count", "Severity", "Key Evidence", "Action"]
        table = QTableWidget(len(self.visible_engine_rows), len(headers)); table.setHorizontalHeaderLabels(headers)
        table.setAlternatingRowColors(True); table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows); table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers); table.verticalHeader().setVisible(False)
        for row, item in enumerate(self.visible_engine_rows):
            key, code, name = item["spec"]
            title = QTableWidgetItem(f"{code} · {name}"); title.setData(Qt.ItemDataRole.UserRole, key); table.setItem(row, 0, title)
            table.setCellWidget(row, 1, SeverityBadge(item["status"]))
            table.setItem(row, 2, QTableWidgetItem("Not recorded" if item["finding_count"] is None else str(item["finding_count"])))
            table.setCellWidget(row, 3, SeverityBadge(item["severity"]))
            detail = self._key_evidence(code, item["result"])
            table.setItem(row, 4, QTableWidgetItem(detail))
            button = QPushButton("Investigate"); button.clicked.connect(lambda checked=False, engine=key: self.open_engine(engine)); table.setCellWidget(row, 5, button)
        table.cellDoubleClicked.connect(lambda row, col: self.open_engine(table.item(row, 0).data(Qt.ItemDataRole.UserRole)))
        table.resizeColumnsToContents(); table.horizontalHeader().setStretchLastSection(True); table.setMinimumHeight(230)
        self.engine_table = table; self.table_layout.addWidget(table)

    def _key_evidence(self, code: str, result: dict[str, Any]) -> str:
        if code == "B1": return f"SHA-256 {_display(result.get('sha256'))}; {_display(result.get('format'))}; {_display(result.get('file_size_bytes'))} bytes"
        if code == "B2": return f"{_display(result.get('probe_count'), 'Probe count not recorded')} probe(s); fingerprint {_display(result.get('fingerprint', {}).get('digest') if isinstance(result.get('fingerprint'), dict) else None)}"
        if code == "B3":
            params = result.get("parameters") if isinstance(result.get("parameters"), dict) else {}
            totals = params.get("totals") if isinstance(params.get("totals"), dict) else {}
            return f"{_display(totals.get('total_parameter_count'))} parameters; activations {_display(result.get('activations', {}).get('status') if isinstance(result.get('activations'), dict) else None)}"
        return f"{_display(result.get('candidate_trigger_count'))} candidate(s); {_display(result.get('assessment', {}).get('interpretation') if isinstance(result.get('assessment'), dict) else None)}"

    def apply_filters(self, *_):
        needle = self.search.currentText().casefold().strip()
        engine = self.engine_filter.currentText(); model = self.model_filter.currentText(); status = self.status_filter.currentText(); severity = self.severity_filter.currentText(); category = self.category_filter.currentText()
        for row, item in enumerate(self.visible_engine_rows):
            code_name = f"{item['spec'][1]} {item['spec'][2]}"
            text = json.dumps({"result": item["result"], "findings": item["findings"], "model": self.model_record}, ensure_ascii=False, default=str).casefold()
            visible = ((engine == "All engines" or engine == code_name) and (status == "All statuses" or item["status"] == status)
                       and (severity == "All severities" or item["severity"] == severity)
                       and (category == "All categories" or any(x.get("category") == category for x in item["findings"]))
                       and (model == "All models" or model.casefold() == Path(str(self.model_record.get("path", ""))).name.casefold())
                       and (not needle or needle in text or needle in code_name.casefold() or needle in str(self.results.get("B1_identity", {}).get("model_id", "")).casefold()))
            self.engine_table.setRowHidden(row, not visible)
        for row in range(self.finding_table.rowCount()):
            original_index = self.finding_table.item(row, 3).data(Qt.ItemDataRole.UserRole)
            finding = self.findings[original_index]
            text = json.dumps(finding, ensure_ascii=False, default=str).casefold()
            code = _finding_engine(finding)
            engine_code = engine.split(" ", 1)[0] if engine != "All engines" else ""
            visible = ((not engine_code or code == engine_code or (code == "MODEL" and engine_code in {"B2", "B3"}))
                       and (severity == "All severities" or str(finding.get("severity", "")).upper() == severity)
                       and (category == "All categories" or str(finding.get("category", "Not recorded")) == category)
                       and (model == "All models" or model.casefold() == Path(str(self.model_record.get("path", ""))).name.casefold())
                       and (not needle or needle in text or needle in str(self.model_record.get("path", "")).casefold()
                            or needle in str(self.model_record.get("model_id", "")).casefold()
                            or needle in str(self.results.get("B1_identity", {}).get("model_id", "")).casefold()))
            self.finding_table.setRowHidden(row, not visible)

    def open_engine(self, engine_id: str):
        item = next((row for row in self.engine_rows if row["spec"][0] == engine_id), None)
        if item:
            record = self.records.get(engine_id, {})
            ModelEngineDialog(item["spec"], item["result"], record, self.findings, self).exec()

    def open_finding_row(self, row: int, _column: int):
        if not 0 <= row < self.finding_table.rowCount(): return
        item = self.finding_table.item(row, 3); index = item.data(Qt.ItemDataRole.UserRole) if item else row
        if isinstance(index, int) and 0 <= index < len(self.findings):
            ModelFindingDialog(self.findings[index], Path(str(self.model_record.get("path", "assessed model"))).name, self).exec()
