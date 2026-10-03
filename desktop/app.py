"""TRACER-CV local analyst desktop. Engine result files remain authoritative."""
from __future__ import annotations

import copy
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QPixmap, QFontDatabase
from PySide6.QtWidgets import (
    QApplication, QComboBox, QFileDialog, QFrame, QGridLayout, QHBoxLayout,
    QLabel, QListWidget, QListWidgetItem, QMainWindow, QMessageBox, QLineEdit,
    QPushButton, QScrollArea, QStackedWidget, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget, QDialog, QStyle,
    QTreeWidget, QTreeWidgetItem, QToolButton, QFormLayout, QCheckBox,
)
from backend.core.compute import DeviceUnavailableError, resolve_compute
from backend.core.local_config import LocalConfig
from backend.core.local_logging import configure_local_logging
from backend.core.local_resources import load_stylesheet
from backend.core.local_storage import ReportStore, import_demo_outputs, initialize_local_storage
from backend.application.assessment_manager import AssessmentManager
from backend.core.offline_status import offline_capability_check
from desktop.widgets.components import AnalystTable, EvidenceViewerDialog, MetricBarChart, MetricCard, NavigationSidebar, SectionCard, SeverityBadge, StatusBadge
from desktop.pages.new_assessment import NewAssessmentWizard
from desktop.pages.dataset_workspace import DatasetIntegrityWorkspace
from desktop.pages.model_workspace import ModelIntegrityWorkspace
from desktop.pages.provenance_workspace import ProvenanceWorkspace
from desktop.pages.shift_workspace import ShiftWorkspace
from desktop.pages.findings_workspace import FindingsWorkspace
from desktop.pages.audit_workspace import AuditWorkspace
from desktop.pages.evidence_workspace import EvidenceWorkspace, load_engine_evidence
from desktop.pages.settings_workspace import SettingsWorkspace
from desktop.pages.report_workspace import ReportWorkspace

CONFIG = LocalConfig.load()
APP_VERSION = "0.1.0"
REPORTS = CONFIG.reports_dir
RESULTS = REPORTS / "engine_results"
SERVICES = None
COMPUTE_ERROR = None
try:
    ACTIVE_COMPUTE = resolve_compute(CONFIG.device)
except DeviceUnavailableError as exc:
    ACTIVE_COMPUTE = resolve_compute("cpu")
    COMPUTE_ERROR = str(exc)
ACTIVE_REQUESTED = CONFIG.device

ROOT = Path(__file__).resolve().parents[1]
NAMES = ["Dashboard", "Dataset Integrity", "Model Integrity", "Inference Provenance",
         "Distribution Shift", "Findings & Evidence", "Audit Trail", "Assurance Report"]
FILES = [None, "dataset_integrity.json", "model_assurance.json", "provenance.json",
         "distribution_shift.json", "findings.json", "../evidence/audit_chain.json",
         "../tracer_cv_assurance_report.json"]
ASSESSMENT_FILES = {0:"tracer_cv_assurance_report.json",1:"dataset_integrity.json",2:"model_assurance.json",
                    3:"C1_provenance.json",4:"C2_distribution_shift.json",5:"findings.json",6:"audit_chain.json",
                    7:"tracer_cv_assurance_report.json"}
REVIEWED_FINDINGS: set[str] = set()
SESSION_ACTIVITY: list[dict] = []
NAV_PAGES = {
    "MISSION CONTROL": ("utility", "mission"), "ASSESSMENTS": ("utility", "assessments"),
    "CURRENT ASSESSMENT": ("utility", "overview"),
    "ASSETS": ("utility", "assets"), "Dataset": ("engine", 1),
    "Model": ("engine", 2), "Inference Provenance": ("engine", 3),
    "Distribution": ("engine", 4), "FINDINGS": ("engine", 5),
    "EVIDENCE": ("utility", "evidence"), "AUDIT TRAIL": ("engine", 6),
    "REPORTS": ("engine", 7), "SETTINGS": ("utility", "settings"),
}


def read_result(index):
    path = None
    try:
        pointer=json.loads((REPORTS/"active_assessment.json").read_text(encoding="utf-8"))
        assessment_id=str(pointer.get("assessment_id",""))
        if assessment_id and Path(assessment_id).name==assessment_id and index in ASSESSMENT_FILES:
            candidate=(REPORTS/"assessments"/assessment_id/ASSESSMENT_FILES[index]).resolve()
            if candidate.is_relative_to((REPORTS/"assessments").resolve()): path=candidate
    except (OSError,ValueError,AttributeError):
        pass
    if path is None:
        path = ((REPORTS / "tracer_cv_assurance_report.json") if index == 0
                else (RESULTS / FILES[index]).resolve() if FILES[index] else None)
    try:
        if path is None:
            return {}
        if not path.is_relative_to(REPORTS.resolve()):
            return {"status": "unavailable", "message": "Evidence path is outside reports."}
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {"status": "unavailable", "message": str(exc)}


def read_current_assessment():
    try:
        pointer=json.loads((REPORTS/"active_assessment.json").read_text(encoding="utf-8"))
        assessment_id=str(pointer.get("assessment_id",""))
        if not assessment_id or Path(assessment_id).name!=assessment_id: return {}
        # The manager performs the final lifecycle transition after the runner
        # writes assessment.json. Prefer its persisted record so warning/failure
        # status from orchestration is not hidden by the runner's earlier copy.
        if SERVICES and "assessment_store" in SERVICES:
            current=SERVICES["assessment_store"].load(assessment_id)
            if current:
                return current
        path=(REPORTS/"assessments"/assessment_id/"assessment.json").resolve()
        if not path.is_relative_to((REPORTS/"assessments").resolve()): return {}
        if path.is_file(): return json.loads(path.read_text(encoding="utf-8"))
        return {}
    except (OSError,ValueError,AttributeError):
        return {}


def pretty(value):
    return json.dumps(value, indent=2, ensure_ascii=False, default=str)


def field(obj, *keys, default="—"):
    for key in keys:
        if isinstance(obj, dict) and key in obj and obj[key] is not None:
            return obj[key]
    return default


def human_value(value):
    if isinstance(value, dict):
        return "; ".join(f"{humanize(k)}: {human_value(v)}" for k,v in list(value.items())[:8])
    if isinstance(value, (list, tuple, set)):
        return ", ".join(human_value(item) for item in list(value)[:12]) or "None reported"
    if isinstance(value, float): return f"{value:.4g}"
    return str(value)


def humanize(value):
    return str(value).replace("_", " ").replace("-", " ").strip().capitalize()


def samples_from(items, keys):
    found=[]
    for item in items if isinstance(items,list) else []:
        if isinstance(item,str): found.append(item)
        elif isinstance(item,list): found.extend(str(v) for v in item if isinstance(v,str))
        elif isinstance(item,dict):
            for key in keys:
                value=item.get(key)
                if isinstance(value,str): found.append(Path(value).name)
                elif isinstance(value,list): found.extend(Path(str(v)).name for v in value if isinstance(v,(str,Path)))
    return list(dict.fromkeys(found))


def searchable_fields(value,prefix=""):
    if isinstance(value,dict):
        for key,child in value.items():yield from searchable_fields(child,f"{prefix}.{key}" if prefix else str(key))
    elif isinstance(value,list):
        for index,child in enumerate(value):yield from searchable_fields(child,f"{prefix}[{index}]")
    elif value is not None:yield prefix,str(value)


def dataset_finding_count(index,value):
    keys={1:(),2:("duplicate_group_count",),3:("near_duplicate_pair_count",),4:("potential_ood_count",),5:("finding_count","conflicting_pair_count"),6:("finding_count",),7:("image_finding_count",),8:("candidate_trigger_count",)}
    return next((value[k] for k in keys[index] if isinstance(value.get(k),(int,float))),0)


def dataset_severity(index,value,count):
    if field(value,"status",default="unavailable") in {"unavailable","not_assessed","failed"}: return "UNAVAILABLE"
    if not count:return "VERIFIED"
    if index==6:
        levels=[str(item.get("risk_level","" )).upper() for item in value.get("profiles",[]) if isinstance(item,dict)]
        return "HIGH" if "HIGH" in levels else "REVIEW"
    return "REVIEW"


def report_section_summary(label,data):
    result=data.get("engine_result",{}) if isinstance(data.get("engine_result"),dict) else data
    if label=="Dataset Integrity":
        manifest=result.get("A1_manifest",{})
        return f"{len(result)} recorded check sections; {field(manifest,'file_count',default='Unavailable')} files in the manifest; digest {field(manifest,'dataset_sha256',default='Unavailable')}."
    if label=="Model Integrity":
        identity=result.get("B1_identity",{})
        return f"Model {field(identity,'file_name',default='Unavailable')} · {field(identity,'format',default='format unavailable')} · SHA-256 {field(identity,'sha256',default='Unavailable')}; B1–B4 coverage is available in Model."
    if label=="Provenance":
        return f"{len(result.get('records',[]))} inference record(s); chain valid: {field(data,'valid',default=field(result,'valid',default='Unavailable'))}. A valid chain does not establish artifact safety."
    if label=="Distribution Shift":
        shifted=sum(1 for item in result.get("shifted_features",[]) if isinstance(item,dict) and item.get("shifted") is True)
        return f"Overall measured shift: {field(result,'overall_shift',default='Unavailable')}; {shifted} feature(s) crossed their configured threshold. Shift does not establish malicious manipulation."
    return f"{field(data,'entry_count',default=len(result.get('entries',[])))} audit record(s); chain valid: {field(data,'valid',default=field(result,'valid',default='Unavailable'))}. Chain validity concerns record integrity, not whether activity was benign."


def verification_summary(result):
    if not isinstance(result,dict):return "Verification completed; see Technical Details for the recorded result."
    parts=[]
    for key,label in (("valid","Chain valid"),("verified","Verified"),("entry_count","Entries"),("record_count","Records"),("error","Error"),("message","Message")):
        value=result.get(key)
        if value is not None and not isinstance(value,(dict,list)):parts.append(f"{label}: {value}")
    return "; ".join(parts) or "Verification completed; see Technical Details for the recorded result."


class TechnicalDetailsDialog(EvidenceViewerDialog):
    """Compatibility wrapper retaining the existing evidence drill-down API."""
    def __init__(self,title,data,parent=None):
        super().__init__(title,"Technical evidence is available for detailed review.","Source engine evidence is retained with the local assessment.",data,parent)


class ImageDialog(QDialog):
    def __init__(self, finding, parent=None, compare_path=None):
        super().__init__(parent)
        self.setWindowTitle("Image evidence investigation")
        self.resize(760, 600)
        layout = QVBoxLayout(self)
        images=QHBoxLayout()
        for sample_path,label_text in ((field(finding,"path",default=""),"Affected sample"),(compare_path,"Comparison sample")):
            if not sample_path:continue
            path=Path(str(sample_path)).resolve(); panel=QVBoxLayout(); panel.addWidget(QLabel(f"{label_text}: {path.name}"))
            image=QLabel("Image preview unavailable"); image.setAlignment(Qt.AlignCenter); image.setMinimumSize(280,180)
            # Only render local images within the project; malformed paths are not opened.
            if path.is_relative_to(ROOT.resolve()) and path.is_file() and path.suffix.lower() in {".png", ".jpg", ".jpeg", ".bmp", ".webp"}:
                try:
                    from PIL import Image
                    with Image.open(path) as source:
                        if source.width * source.height <= CONFIG.max_image_pixels:
                            pixmap=QPixmap(str(path))
                            if not pixmap.isNull():image.setPixmap(pixmap.scaled(420,300,Qt.KeepAspectRatio,Qt.SmoothTransformation))
                        else:image.setText("Image exceeds configured preview pixel limit")
                except Exception:image.setText("Image preview unavailable: decode validation failed")
            panel.addWidget(image); images.addLayout(panel)
        layout.addLayout(images)
        card=SectionCard(str(field(finding,"title",default="Image evidence investigation")))
        for label,key in (("Severity","severity"),("Why it was flagged","reason"),("Affected metrics","features"),("Reference comparison","reference_comparison"),("Possible explanations","possible_explanations"),("Recommended investigation","recommended_action"),("Limitations","limitations")):
            value=finding.get(key)
            if value is not None:
                if label=="Severity":card.content.addWidget(SeverityBadge(str(value)))
                else:
                    line=QLabel(f"{label}: {human_value(value)}"); line.setWordWrap(True); card.content.addWidget(line)
        layout.addWidget(card)
        self.feedback = QLabel(""); layout.addWidget(self.feedback)
        row = QHBoxLayout()
        for text in ("Add to Review", "Mark Reviewed", "Back"):
            button = QPushButton(text); row.addWidget(button)
            if text == "Add to Review": button.clicked.connect(lambda: self.feedback.setText("Added to this session’s review queue."))
            elif text == "Mark Reviewed": button.clicked.connect(lambda: self.feedback.setText("Marked reviewed for this session."))
            else: button.clicked.connect(self.accept)
        layout.addLayout(row)
        technical=QPushButton("Technical Details")
        technical.clicked.connect(lambda: EvidenceViewerDialog("Image finding",finding.get("reason","Candidate outlier flagged by configured image metrics."),"Image path and measured feature values are available in the source engine record.",finding,self).exec())
        layout.addWidget(technical)


class FindingDialog(QDialog):
    def __init__(self, finding, parent=None):
        super().__init__(parent); self.finding=finding; self.setWindowTitle(finding.get("finding_id","Finding")); self.resize(720,560)
        layout=QVBoxLayout(self)
        for label, key in (("Title", "title"), ("Severity", "severity"), ("Category", "category"), ("Affected asset", "affected_asset"), ("Confidence", "confidence"), ("Explanation", "explanation"), ("Recommended action", "recommended_action"), ("Limitations", "limitations")):
            value = finding.get(key)
            if value is not None:
                if label=="Severity": layout.addWidget(SeverityBadge(str(value)))
                else:
                    row = QLabel(f"{label}:  {human_value(value)}"); row.setWordWrap(True); layout.addWidget(row)
        tech=QPushButton("Technical Details"); tech.clicked.connect(lambda: EvidenceViewerDialog("Finding evidence",finding.get("explanation","Finding produced from recorded engine observations."),human_value(finding.get("evidence",[])),finding,self).exec()); layout.addWidget(tech)
        self.status=QLabel("Reviewed in this session" if finding.get("finding_id") in REVIEWED_FINDINGS else "Unreviewed"); layout.addWidget(self.status)
        row=QHBoxLayout(); mark=QPushButton("Mark Reviewed"); mark.clicked.connect(self.mark_reviewed); back=QPushButton("Back"); back.clicked.connect(self.accept); row.addWidget(mark); row.addWidget(back); layout.addLayout(row)
    def mark_reviewed(self):
        finding_id=str(self.finding.get("finding_id"))
        if finding_id not in REVIEWED_FINDINGS:
            SESSION_ACTIVITY.append({"timestamp":datetime.now().astimezone().isoformat(timespec="seconds"),"event_type":"Analyst decision recorded · session review","source_engine":"Analyst UI","affected_asset":field(self.finding,"affected_asset"),"event_id":finding_id,"route":"FINDING"})
        REVIEWED_FINDINGS.add(finding_id); self.status.setText("Reviewed in this session")


class Page(QWidget):
    def __init__(self, title, data, on_navigate, index):
        super().__init__(); self.data = data; self.title = title; self.navigate = on_navigate; self.index = index
        outer = QVBoxLayout(self); outer.setContentsMargins(30, 24, 30, 24)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); outer.addWidget(scroll)
        body = QWidget(); self.layout = QVBoxLayout(body); self.layout.setSpacing(14); scroll.setWidget(body)
        heading = QLabel(title); heading.setStyleSheet("font-size:26px;font-weight:700")
        self.layout.addWidget(heading)
        self.layout.addWidget(QLabel("Trustworthy Computer Vision Integrity Assurance · Local evidence view"))
        actions = QHBoxLayout()
        raw = QPushButton("Technical Details"); raw.clicked.connect(lambda: EvidenceViewerDialog(title,"Structured engine results for this assessment.",f"Source: {title}; technical evidence remains available through the drill-down.",self.data,self).exec())
        actions.addWidget(raw)
        if index == 1:
            browse = QPushButton("Browse Dataset"); browse.clicked.connect(self.browse); actions.addWidget(browse)
            run = QPushButton("Run Demo Assessment (bundled assets)"); run.clicked.connect(lambda: self.run_demo()); actions.addWidget(run)
        if index == 0:
            run = QPushButton("Run Full Assessment"); run.clicked.connect(self.run_demo); actions.addWidget(run)
        if index in (2, 3, 4):
            run = QPushButton({2:"Rerun Full Assessment",3:"Verify Record / Chain",4:"Rerun Full Assessment"}[index])
            run.clicked.connect(self.verify_or_run); actions.addWidget(run)
        if index == 6:
            verify = QPushButton("Verify Audit Chain"); verify.clicked.connect(self.verify_or_run); actions.addWidget(verify)
            tamper = QPushButton("Simulate Audit Tampering"); tamper.clicked.connect(lambda: self.tamper(True)); actions.addWidget(tamper)
        if index == 3:
            tamper = QPushButton("Simulate Tampering"); tamper.clicked.connect(lambda: self.tamper(False)); actions.addWidget(tamper)
        self.layout.addLayout(actions)
        self.status = QLabel(""); self.layout.addWidget(self.status)
        self.render()

    def card(self, heading, value, parent_layout=None):
        box = SectionCard(str(heading)); b=QLabel(str(value)); b.setWordWrap(True); box.content.addWidget(b)
        (parent_layout or self.layout).addWidget(box)

    def table(self, headers, rows, activate=None):
        table = AnalystTable(headers, rows); table.setMinimumHeight(min(430, 70+len(rows)*32)); self.layout.addWidget(table)
        if activate:
            def selected_row(row,col):
                values=[]
                for column in range(table.columnCount()):
                    item=table.item(row,column); widget=table.cellWidget(row,column)
                    values.append(item.text() if item else widget.text() if widget and hasattr(widget,"text") else "")
                activate(values)
            table.cellDoubleClicked.connect(selected_row)
        return table

    def render(self):
        d = self.data if isinstance(self.data,dict) else {}
        if self.index == 0:
            summary=d.get("executive_summary",{}); coverage=d.get("asset_coverage",{})
            prov=d.get("inference_provenance",{}); shift=d.get("distribution_shift",{}); audit=d.get("audit_trail",{})
            self.card("Assessment", field(d,"assessment_id",default="TRACER-FULL-DEMO-001"))
            grid=QGridLayout(); cards=[("DATASET INTEGRITY","A1–A8",field(coverage.get("dataset_integrity",{}),"status",default="Unavailable")), ("MODEL INTEGRITY","B1–B4",field(coverage.get("model_integrity",{}),"status",default="Unavailable")), ("INFERENCE PROVENANCE","C1",field(prov,"valid",default="Unavailable")), ("DISTRIBUTION SHIFT","C2",field(shift,"shift_detected",default="Unavailable")), ("FINDINGS & EVIDENCE","C3",field(d.get("findings",{}),"count",default=field(coverage.get("findings_and_evidence",{}),"finding_count",default="Available"))), ("AUDIT TRAIL","C4",field(audit,"valid",default="Unavailable")), ("ASSURANCE REPORT","C5",field(d,"status",default="Generated"))]
            for n,(title,engine,state) in enumerate(cards):
                b=QPushButton(f"{title}\n{engine}   ·   {state}"); b.setMinimumHeight(78); b.clicked.connect(lambda checked=False, ix=min(n+1,7): self.navigate(ix)); grid.addWidget(b,n//2,n%2)
            self.layout.addLayout(grid)
            count_row=QHBoxLayout(); count_box=section("FINDING SEVERITY")
            for name,severity in (("Total",None),("High","high"),("Medium","medium"),("Low","low"),("Informational","informational")):
                value=len(findings) if severity is None else severity_count(severity)
                badge=SeverityBadge(f"{name}: {value}",severity or "info"); count_row.addWidget(badge)
            count_box.content.addLayout(count_row)
            self.layout.addWidget(MetricBarChart("Finding severity distribution",[[name,severity_count(level),level] for name,level in (("High","high"),("Medium","medium"),("Low","low"),("Informational","informational"))]))
            self.card("Operating mode / compute", f"OFFLINE / AIR-GAPPED · network probes not performed · {ACTIVE_COMPUTE.device.upper()} ({ACTIVE_COMPUTE.device_name})")
            self.card("Pipeline", "A1–A8  →  B1–B4  →  C1  →  C2  →  C3  →  C4  →  C5")
        elif self.index == 1:
            self.dataset_view(d)
        elif self.index == 2:
            self.model_view(d)
        elif self.index == 3:
            records=d.get("records",[]); record=records[0] if records and isinstance(records[0],dict) else {}
            self.layout.addWidget(SeverityBadge("VALID" if d.get("valid") is True else ("INVALID" if d.get("valid") is False else "UNAVAILABLE")))
            self.table(["Stage","Identifier / digest","Status"], [["Input",field(record,"input_digest"),"Bound"],["Model",field(record,"model_id"),"Bound"],["Preprocessing",field(record,"preprocessing_digest"),"Bound"],["Output",field(record,"output_digest"),"Bound"]])
            self.table(["Sequence","Nonce","Timestamp","Previous hash","Record hash","Signature"], [[field(record,"sequence"),field(record,"nonce"),field(record,"timestamp"),field(record,"previous_record_hash"),field(record,"record_hash"),"Absent" if not record.get("signature") else "Present"]])
        elif self.index == 4:
            self.shift_view(d)
        elif self.index == 5:
            filters=QHBoxLayout(); self.severity_filter=QComboBox(); self.severity_filter.addItems(["All","critical","high","medium","low","none"])
            self.category_filter=QComboBox(); self.category_filter.addItems(["All","dataset_integrity","model_integrity","provenance","distribution_shift"])
            self.review_filter=QComboBox(); self.review_filter.addItems(["All","Unreviewed","Reviewed"])
            for control in (self.severity_filter,self.category_filter,self.review_filter): filters.addWidget(control)
            apply=QPushButton("Apply Filters"); apply.clicked.connect(self.apply_finding_filters); filters.addWidget(apply); self.layout.addLayout(filters)
            findings=d.get("findings",[]); self._finding_table=self.table(["Severity","Category","Finding ID","Title","Asset","Confidence"], [[field(x,"severity"),field(x,"category"),field(x,"finding_id"),field(x,"title"),field(x,"affected_asset"),field(x,"confidence")] for x in findings], lambda row:self.show_finding(row[2]))
            self.findings=findings
            self.card("Analyst note", "Findings describe measured evidence and do not establish malicious intent.")
        elif self.index == 6:
            entries=d.get("entries",[]); self.layout.addWidget(SeverityBadge("VALID" if field(d,"valid") is True or (isinstance(d.get("valid"),dict) and d["valid"].get("valid") is True) else "Review required"))
            self.table(["#","Event ID","Timestamp","Event Type","Source","Affected Asset","Payload Digest","Previous Hash","Entry Hash"], [[field(x,"sequence"),field(x,"event_id"),field(x,"timestamp"),field(x,"event_type"),field(x,"source_engine"),field(x,"affected_asset"),field(x,"payload_digest"),field(x,"previous_entry_hash"),field(x,"entry_hash")] for x in entries])
        elif self.index == 7:
            self.report_view(d)
            return
        self.layout.addStretch()

    def dataset_view(self,d):
        a1=d.get("A1_manifest",{}); self.card("Dataset",field(a1,"root",default="Dataset identity from stored A1 result"))
        explanations={1:"Cryptographic manifest identifies the files and aggregate dataset digest.",2:"Finds files with matching content digests; duplicates are observations for review.",3:"Compares image similarity using the configured near-duplicate method.",4:"Compares candidate appearance with the reference; this does not establish semantic OOD or intent.",5:"Checks supported annotation records for possible conflicts and format issues.",6:"Profiles contributor metadata; risk indicators do not establish malicious activity.",7:"Checks image and contributor metadata for unusual differences.",8:"Searches for repeated localized visual patterns; candidates do not prove poisoning."}
        names={1:"manifest",2:"exact_duplicates",3:"near_duplicates",4:"ood",5:"label_consistency",6:"contributor_risk",7:"metadata_consistency",8:"poison_trigger_forensics"}
        rows=[]; samples=[]
        for i,name in names.items():
            key=f"A{i}_{name}"; value=d.get(key,{}) if isinstance(d.get(key),dict) else {}
            count=dataset_finding_count(i,value); severity=("VERIFIED" if value.get("dataset_sha256") else "UNAVAILABLE") if i==1 else dataset_severity(i,value,count)
            related=samples_from(value.get("groups",value.get("pairs",value.get("results",value.get("conflicting_pairs",value.get("image_findings",value.get("findings",[])))))),("files","file_a","file_b","file","path","image"))
            status=field(value,"status",default="Recorded" if value else "Unavailable")
            if i==1:explanations[i]=f"{explanations[i]} Files recorded: {field(value,'file_count',default='Unavailable')}; digest: {field(value,'dataset_sha256',default='Unavailable')}"
            rows.append([key.replace("_"," ").upper(),status,count,severity,explanations[i],", ".join(related[:4]) or "No affected sample listed"])
            for filename in related: samples.append([filename,key])
        filter_row=QHBoxLayout(); check_search=QLineEdit(); check_search.setPlaceholderText("Filter checks, samples, or explanation…"); severity_filter=QComboBox(); severity_filter.addItems(["All severities","Verified","Information","Review","High","Critical","Unavailable"]); filter_row.addWidget(check_search); filter_row.addWidget(severity_filter); self.layout.addLayout(filter_row)
        table=self.table(["Check","Status","Finding count","Severity","Explanation","Affected samples / assets"],rows,lambda row:self.open_check(row[0].lower().replace(" ","_")))
        table.setSortingEnabled(True)
        def filter_checks(*_):
            text=check_search.text().casefold(); severity=severity_filter.currentText().upper()
            for row_index,row in enumerate(rows):
                text_match=not text or any(text in str(value).casefold() for value in row)
                severity_match=severity=="ALL SEVERITIES" or str(row[3]).upper()==severity
                table.setRowHidden(row_index,not(text_match and severity_match))
        check_search.textChanged.connect(filter_checks); severity_filter.currentTextChanged.connect(filter_checks)
        selected_assessment=read_current_assessment()
        root_value=field(a1,"root",default=field(selected_assessment.get("dataset",{}),"path",default=""))
        root=Path(str(root_value)).resolve() if root_value else None
        if root and root.is_dir() and samples:
            unique=[]
            for filename,key in samples:
                path=(root/filename).resolve()
                if path.is_relative_to(root.resolve()) and path.is_file() and [filename,str(path),key] not in unique:unique.append([filename,str(path),key])
            if unique:
                self.layout.addWidget(QLabel("Affected samples — select multiple rows to compare; double-click a row to inspect."))
                sample_table=AnalystTable(["Sample","Local image","Check"],unique); sample_table.setSelectionMode(QTableWidget.ExtendedSelection); sample_table.setMinimumHeight(min(320,70+len(unique)*28))
                sample_table.cellDoubleClicked.connect(lambda row,col:self.inspect_path(unique[row][1],unique[row][0]))
                inspect=QPushButton("Inspect Selected Sample"); inspect.clicked.connect(lambda:self.inspect_sample(sample_table))
                compare=QPushButton("Compare Selected Samples"); compare.clicked.connect(lambda:self.compare_samples(sample_table))
                actions=QHBoxLayout(); actions.addWidget(inspect); actions.addWidget(compare); self.layout.addLayout(actions); self.layout.addWidget(sample_table)
        self.card("Interpretation", "Automated checks identify measurable patterns for analyst review. Cryptographic identity confirms the bound files and digest; it does not establish that the dataset is safe or benign.")

    def inspect_sample(self,table):
        selected=table.selectedItems()
        if selected:self.inspect_path(table.item(selected[0].row(),1).text(),table.item(selected[0].row(),0).text())

    def compare_samples(self,table):
        selected=sorted({item.row() for item in table.selectedItems()})
        if len(selected)<2:
            QMessageBox.information(self,"Compare samples","Select at least two affected samples."); return
        self.inspect_path(table.item(selected[0],1).text(),table.item(selected[0],0).text(),table.item(selected[1],1).text())

    def inspect_path(self,path,label,compare=None):
        detail={"path":path,"title":label,"severity":"Review","reason":"This sample was included in an engine result and is available for visual inspection.","features":f"Comparison sample: {Path(compare).name}" if compare else "See the associated check for measured values.","recommended_action":"Review the image and compare it with trusted examples.","limitations":"A flagged sample is not, by itself, evidence of malicious activity."}
        ImageDialog(detail,self,compare_path=compare).exec()

    def open_check(self, key):
        if isinstance(self.data,dict) and key in self.data:
            TechnicalDetailsDialog(key, self.data[key], self).exec()

    def model_view(self,d):
        identity=d.get("B1_identity",{}); self.card("B1 — Model Identity",f"Model ID: {field(identity,'model_id')}\nFile: {field(identity,'file_name')}\nSHA-256: {field(identity,'sha256')}\nFormat: {field(identity,'format')}\nSize: {field(identity,'file_size_bytes')} bytes\nVerification: {field(identity,'verification',default=field(identity,'status',default='Unavailable'))}\nLimitations: {human_value(identity.get('limitations',[]))}")
        b2=d.get("B2_behavioral_fingerprint",{}); probes=b2.get("probes",[]) if isinstance(b2.get("probes"),list) else []; probe_names=[str(field(x,"name",default="Probe")) for x in probes if isinstance(x,dict)]
        if not probe_names:probe_names=[str(field(x,"name",default="Probe")) for x in b2.get("config",{}).get("probes",[]) if isinstance(x,dict)]
        self.card("B2 — Behavioral Fingerprint",f"Status: {field(b2,'status',default='Unavailable')}\nProbe count: {field(b2,'probe_count',default=len(probes))}\nProbe names: {', '.join(probe_names) or 'Not recorded'}\nReference comparison: No trusted model baseline was supplied.\nObserved: {human_value(b2.get('notes',[])) or 'No specific behavioral difference was recorded.'}\nInterpretation: Fingerprint differences do not prove malicious modification.\nLimitations: {human_value(b2.get('limitations',[]))}")
        b3=d.get("B3_model_statistics",{}); params=b3.get("parameters",{}); structure=b3.get("structure",{}); activations=b3.get("activations",{}); totals=params.get("totals",{}) if isinstance(params,dict) else {}
        activation_state=field(activations,"status",default=field(activations,"reason",default="Unavailable"))
        self.card("B3 — Parameter / Activation Statistics",f"Status: {field(b3,'status',default='Unavailable')}\nParameter count: {human_value(totals.get('total_parameter_count',totals.get('total_parameters',totals.get('parameter_count','Unavailable'))))}\nModule structure: {human_value(structure)}\nStatistics: {human_value(b3.get('statistics',{}))}\nActivation availability: {activation_state}\nReference comparison: No trusted model baseline was supplied.\nLimitations: {human_value(b3.get('limitations',[]))}")
        b4=d.get("B4_trigger_search",{}); search=b4.get("search",{}); assessment=b4.get("assessment",{}); configuration=search.get("configuration",{}) if isinstance(search,dict) else {}; candidates=b4.get("all_candidates",[]) if isinstance(b4.get("all_candidates"),list) else []
        changes=[float(x.get("class_change_rate",0)) for x in candidates if isinstance(x,dict) and isinstance(x.get("class_change_rate"),(int,float))]
        confidence=[float(x.get("mean_confidence_gain",0)) for x in candidates if isinstance(x,dict) and isinstance(x.get("mean_confidence_gain"),(int,float))]
        change_range=f"{min(changes):.3g}–{max(changes):.3g}" if changes else "Unavailable"; confidence_range=f"{min(confidence):.3g}–{max(confidence):.3g}" if confidence else "Unavailable"
        self.card("B4 — Trigger Search",f"Status: {field(b4,'status',default='Unavailable')}\nProbe images assessed: {field(search,'images_assessed',default='Unavailable')} of {field(search,'images_requested',default='Unavailable')}\nPatch sizes: {human_value(configuration.get('patch_sizes',[]))}\nTested positions: {human_value(configuration.get('grid_fractions',[]))}\nPrediction-change rate across candidates: {change_range}\nMean confidence gain range: {confidence_range}\nCandidate trigger-like results: {field(b4,'candidate_trigger_count',default=0)}\nAssessment: {field(assessment,'interpretation',default='No interpretation available.')}\nLimitations: {human_value(b4.get('limitations',[]))}\nA trigger-like result is an investigation lead; it does not prove a backdoor.")
        for key, value in (("B1",identity),("B2",b2),("B3",b3),("B4",b4)):
            self.layout.addWidget(SeverityBadge(f"{key}: {field(value,'status',default='Unavailable')}"))
            button=QPushButton(f"{key} Technical Details"); button.clicked.connect(lambda checked=False,k=key,v=value: EvidenceViewerDialog(f"{k} Model Evidence",f"{k} measured model identity or behavior evidence.","Observed model evidence and its limitations are available above.",v,self).exec()); self.layout.addWidget(button)

    def report_view(self,d):
        summary=d.get("executive_summary",{}) if isinstance(d.get("executive_summary"),dict) else {}
        coverage=d.get("asset_coverage",{}) if isinstance(d.get("asset_coverage"),dict) else {}
        self.card("Executive Summary",field(summary,"interpretation",default="No executive interpretation is available."))
        self.card("Assessment Scope",field(summary,"assessment_scope",default=field(d,"task",default="Not recorded")))
        rows=[[humanize(name),field(value,"status",default="Unavailable"),field(value,"finding_count",default="—")] for name,value in coverage.items() if isinstance(value,dict)]
        self.table(["Coverage Area","Status","Findings"],rows)
        for label,key in (("Dataset Integrity","dataset_integrity"),("Model Integrity","model_integrity"),("Provenance","inference_provenance"),("Distribution Shift","distribution_shift"),("Audit","audit_trail")):
            item=d.get(key,{}) if isinstance(d.get(key),dict) else {}
            status=field(item,"status",default=field(coverage.get(key,{}),"status",default="Unavailable"))
            self.card(label,f"Status: {status}\n{report_section_summary(label,item)}")
        finding_block=d.get("findings_and_evidence",{}) if isinstance(d.get("findings_and_evidence"),dict) else {}
        findings=finding_block.get("findings",[]) if isinstance(finding_block.get("findings"),list) else []
        self.table(["Severity","Finding","Affected Asset","Recommended Investigation"],[[field(x,"severity"),field(x,"title"),field(x,"affected_asset"),field(x,"recommended_action")] for x in findings],lambda row:self.show_finding(row[1]))
        limitations=d.get("limitations",[])
        self.card("Limitations","\n".join(f"• {x}" for x in limitations) if isinstance(limitations,list) else human_value(limitations))
        row=QHBoxLayout()
        for text,callback in (("Assessment Overview",lambda:self.navigate(0)),("Export Text",lambda:self.export("text")),("Open Findings",lambda:self.navigate(5)),("Open Audit Trail",lambda:self.navigate(6))):
            button=QPushButton(text); button.clicked.connect(callback); row.addWidget(button)
        self.layout.addLayout(row)

    def shift_view(self,d):
        self.layout.addWidget(SeverityBadge(f"Distribution shift: {field(d,'severity',default=field(d,'status',default='Unavailable'))}"))
        self.card("Population comparison",f"Reference images: {field(d.get('reference',{}),'image_count')}  ·  Candidate images: {field(d.get('candidate',{}),'image_count')}  ·  Overall shift: {field(d,'overall_shift')}  ·  Severity: {field(d,'severity')}\nObserved: measured feature distributions differ from the selected reference.\nNot established: distribution shift alone does not show malicious manipulation.\nLimitations: {human_value(d.get('limitations',[]))}")
        rows=[]; refs=d.get("reference",{}).get("summary",{}); cands=d.get("candidate",{}).get("summary",{})
        for x in d.get("shifted_features",[]):
            name=x.get("feature"); rows.append([name,field(refs.get(name,{}),"mean"),field(cands.get(name,{}),"mean"),field(x,"distance"),field(x,"threshold"),field(x,"shifted")])
        self.table(["Feature","Reference mean","Candidate mean","Distance","Threshold","Shifted"],rows)
        chart_rows=[[name,field(refs.get(name,{}),"mean",default=0),field(cands.get(name,{}),"mean",default=0)] for name in sorted(set(refs)|set(cands)) if name in refs and name in cands]
        if chart_rows:self.layout.addWidget(MetricBarChart("Reference vs candidate feature means (paired bars)",chart_rows))
        rows=[[field(x,"file"),field(x,"max_z_score"),human_value(x.get("features",{})),"Review"] for x in d.get("anomalous_images",[])]
        self.table(["Image","Max Z-score","Affected Metrics","Action"],rows,lambda row:self.inspect(row[0]))
        self.card("Interpretation", "Distribution shift does not by itself establish malicious manipulation.")

    def show_finding(self, finding_id):
        for finding in getattr(self,"findings",[]):
            if finding.get("finding_id")==finding_id: FindingDialog(finding,self).exec(); break

    def apply_finding_filters(self):
        severity=self.severity_filter.currentText(); category=self.category_filter.currentText(); reviewed=self.review_filter.currentText()
        rows=[]
        for item in getattr(self,"findings",[]):
            fid=str(item.get("finding_id")); seen=fid in REVIEWED_FINDINGS
            if severity!="All" and str(item.get("severity","none")).lower()!=severity: continue
            if category!="All" and str(item.get("category",""))!=category: continue
            if reviewed=="Reviewed" and not seen or reviewed=="Unreviewed" and seen: continue
            rows.append([field(item,"severity"),field(item,"category"),fid,field(item,"title"),field(item,"affected_asset"),field(item,"confidence")])
        # Replace the existing result table with the filtered local view.
        old=self._finding_table
        self.layout.removeWidget(old); old.deleteLater()
        self._finding_table=self.table(["Severity","Category","Finding ID","Title","Asset","Confidence"],rows,lambda row:self.show_finding(row[2]))

    def inspect(self, filename):
        for item in self.data.get("anomalous_images",[]):
            if item.get("file")==filename:
                candidate = next((x for x in self.data.get("findings",[]) if x.get("type")=="candidate_image_anomalies"),{})
                detail=dict(item)
                detail.update({
                    "title": "Candidate image statistical outlier",
                    "reason": candidate.get("message","C2 reported this sample as a statistical candidate outlier."),
                    "severity": candidate.get("severity","unavailable"),
                    "reference_comparison": "Candidate features are compared with the configured reference population.",
                    "possible_explanations": "Acquisition, sensor, environment, preprocessing, or population differences may produce this observation.",
                    "recommended_action": "Compare the affected sample with trusted reference images and review acquisition conditions.",
                    "severity_scope": "C2 candidate-image group; not an individual maliciousness rating",
                    "source_engine": "C2 Distribution Shift",
                    "evidence_note": "Feature values shown here are reference-relative absolute z-scores.",
                    "limitations": self.data.get("limitations",[]),
                })
                ImageDialog(detail,self).exec(); break

    def browse(self):
        path=QFileDialog.getExistingDirectory(self,"Select dataset")
        if path:
            try:
                registered=SERVICES["asset_registry"].register(Path(path),"dataset",hash_file=False)
                self.card("Selected local dataset asset",f"{registered['display_name']} · asset ID {registered['asset_id']} · registered locally; full demo runner still uses bundled assets")
            except Exception as exc:
                QMessageBox.warning(self,"Dataset registration failed",str(exc))

    def verify_or_run(self):
        if self.index == 3:
            try:
                from backend.engines.provenance.inference_provenance import ProvenanceRecord, verify_chain
                records=[ProvenanceRecord(**x) for x in self.data.get("records",[]) if isinstance(x,dict)]
                result=verify_chain(records); self.status.setText("C1 verification: "+verification_summary(result))
            except Exception as exc: self.status.setText(f"C1 verification unavailable: {exc}")
        elif self.index == 6: self.verify_audit(self.data)
        else: self.run_demo()

    def tamper(self,audit):
        duplicate=copy.deepcopy(self.data)
        field_name="entry_hash" if audit else "output_digest"
        records=duplicate.get("entries" if audit else "records",[])
        if not records or not isinstance(records[0],dict):
            QMessageBox.information(self,"Tamper demonstration","JSON-native evidence records are unavailable. Run the full demo first."); return
        original=records[0].get(field_name,""); records[0][field_name]="0"*64 if original!="0"*64 else "f"*64
        if audit: self.verify_audit(duplicate)
        else:
            try:
                from backend.engines.provenance.inference_provenance import ProvenanceRecord,verify_chain
                result=verify_chain([ProvenanceRecord(**x) for x in records]); self.status.setText("In-memory tamper check: "+verification_summary(result)+"\nOriginal report file was not changed.")
            except Exception as exc: self.status.setText(str(exc))

    def verify_audit(self,data):
        try:
            from backend.engines.provenance.audit_trail import AuditEntry,verify_audit_chain
            entries=[AuditEntry(**x) for x in data.get("entries",[]) if isinstance(x,dict)]
            self.status.setText("Audit verification: "+verification_summary(verify_audit_chain(entries)))
        except Exception as exc: self.status.setText(f"Audit verification unavailable: {exc}")

    def run_demo(self):
        self.status.setText("Running existing local assurance demo…"); QApplication.processEvents()
        try:
            from demos.run_full_assurance_demo import run
            logging.getLogger("tracer_cv").info("operation=full_assessment status=started device=%s",ACTIVE_COMPUTE.device)
            run(device=ACTIVE_COMPUTE.device, fallback_on_error=(ACTIVE_REQUESTED == "auto"))
            import_demo_outputs(ROOT / "reports", CONFIG, overwrite=True)
            logging.getLogger("tracer_cv").info("operation=full_assessment status=completed device=%s",ACTIVE_COMPUTE.device)
            self.data=read_result(self.index); self.status.setText(f"Assessment finished locally on {ACTIVE_COMPUTE.device.upper()}. Results saved under {REPORTS}.")
            # Reload the visible page to consume newly generated evidence.
            self.navigate(self.index)
        except Exception as exc:
            logging.getLogger("tracer_cv").error("operation=full_assessment status=failed error_category=%s",type(exc).__name__)
            self.status.setText(f"Assessment failed: {type(exc).__name__}: {exc}")

    def export(self, kind):
        filters="JSON (*.json)" if kind=="json" else "Text (*.txt)"
        target,_=QFileDialog.getSaveFileName(self,"Export local report",str(ROOT / ("assurance-export."+kind)),filters)
        if not target:return
        try:
            if kind=="json": Path(target).write_text(pretty(self.data),encoding="utf-8")
            else:
                current=read_current_assessment()
                assessment_id=str(current.get("assessment_id",""))
                text_path=(REPORTS/"assessments"/assessment_id/"tracer_cv_assurance_report.txt") if assessment_id and Path(assessment_id).name==assessment_id else REPORTS/"tracer_cv_assurance_report.txt"
                if not text_path.is_file(): raise FileNotFoundError("Text report is not available for the current assessment.")
                Path(target).write_text(text_path.read_text(encoding="utf-8"),encoding="utf-8")
        except OSError as exc: QMessageBox.critical(self,"Export failed",str(exc))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__(); self.setWindowTitle("TRACER-CV — Computer Vision Integrity Assurance Workbench"); self.resize(1500,940)
        central=QWidget(); self.setCentralWidget(central); base=QHBoxLayout(central); base.setContentsMargins(0,0,0,0); base.setSpacing(0)
        self.offline_badge=StatusBadge("AIR-GAPPED · LOCAL ONLY", "verified"); self.offline_badge.setToolTip(offline_capability_check(CONFIG).get("network_probe_note", "No network probe performed"))
        self.sidebar=NavigationSidebar(self.offline_badge); self.tree=self.sidebar.tree; self.nav_items=self.sidebar.nav_items
        base.addWidget(self.sidebar)
        main=QWidget(); main_layout=QVBoxLayout(main); main_layout.setContentsMargins(0,0,0,0); main_layout.setSpacing(0); base.addWidget(main,1)
        header=QFrame(); header.setObjectName("appHeader"); head=QHBoxLayout(header); head.setContentsMargins(20,12,20,12)
        self.page_context=QLabel("MISSION CONTROL"); self.page_context.setObjectName("pageContext"); head.addWidget(self.page_context)
        head.addStretch()
        report=read_result(0); self.assessment_label=QLabel(f"Assessment  ·  {field(report,'assessment_id',default='No assessment loaded')}"); self.assessment_label.setObjectName("contextChip"); head.addWidget(self.assessment_label)
        self.search=QLineEdit(); self.search.setPlaceholderText("Search local evidence…"); self.search.setClearButtonEnabled(True); self.search.setMaximumWidth(240); self.search.returnPressed.connect(self.search_local); head.addWidget(self.search)
        self.activity=QToolButton(); self.activity.setText("Activity · 0"); self.activity.clicked.connect(self.show_activity); head.addWidget(self.activity)
        self.system_badge=StatusBadge(f"{ACTIVE_COMPUTE.device.upper()} · READY", "info"); head.addWidget(self.system_badge)
        self.theme_button=QPushButton("Dark theme" if CONFIG.theme=="light" else "Light theme"); self.theme_button.clicked.connect(self.toggle_theme); head.addWidget(self.theme_button)
        main_layout.addWidget(header)
        self.stack=QStackedWidget(); main_layout.addWidget(self.stack,1)
        self.tree.currentItemChanged.connect(self.navigate_item)
        self.device_selector=QComboBox(); self.device_selector.addItems(["Automatic","CPU","CUDA"]); self.device_selector.setCurrentIndex(1 if COMPUTE_ERROR else {"auto":0,"cpu":1,"cuda":2}[CONFIG.device]); self.device_selector.currentIndexChanged.connect(self.set_device)
        self.navigate(0)
        QTimer.singleShot(0, self.review_interrupted_assessments)

    def review_interrupted_assessments(self):
        manager=SERVICES.get("assessment_manager") if SERVICES else None
        if not manager:return
        for record in manager.recoverable():
            dialog=QMessageBox(self); dialog.setWindowTitle("Assessment interrupted")
            dialog.setText(f"Assessment {record.get('name') or record.get('assessment_id')} was interrupted. Existing results remain available.")
            resume=dialog.addButton("Resume if safe",QMessageBox.ButtonRole.AcceptRole)
            mark=dialog.addButton("Mark Interrupted",QMessageBox.ButtonRole.DestructiveRole)
            inspect=dialog.addButton("Inspect Results",QMessageBox.ButtonRole.ActionRole)
            dialog.addButton(QMessageBox.StandardButton.Close); dialog.exec()
            if dialog.clickedButton() is resume:
                future=manager.resume_if_safe(record["assessment_id"])
                if future is None:
                    QMessageBox.information(self,"Cannot safely resume","This assessment has started engines or lacks a safe checkpoint. Inspect results or mark it interrupted.")
                else:
                    QMessageBox.information(self,"Assessment queued","The untouched queued assessment was safely resumed.")
            elif dialog.clickedButton() is mark:
                manager.mark_interrupted(record["assessment_id"])
            elif dialog.clickedButton() is inspect:
                self.open_assessment_by_id(record["assessment_id"])

    def set_device(self, index, persist=True):
        global ACTIVE_COMPUTE, ACTIVE_REQUESTED, CONFIG
        requested=("auto","cpu","cuda")[index]
        try:
            context=resolve_compute(requested)
        except DeviceUnavailableError as exc:
            QMessageBox.warning(self,"CUDA unavailable",str(exc))
            from PySide6.QtCore import QSignalBlocker
            blocker=QSignalBlocker(self.device_selector)
            self.device_selector.setCurrentIndex({"auto":0,"cpu":1,"cuda":2}[ACTIVE_COMPUTE.device])
            del blocker
            return
        ACTIVE_COMPUTE=context; ACTIVE_REQUESTED=requested
        CONFIG=__import__("dataclasses").replace(CONFIG,device=requested)
        if persist:
            try: CONFIG.save()
            except OSError as exc: QMessageBox.warning(self,"Configuration not saved",str(exc))
        self.system_badge.setText(f"{context.device.upper()} · READY")

    def navigate_item(self, current, previous=None):
        if current is None: return
        key=current.data(0,Qt.UserRole)
        route=NAV_PAGES.get(key)
        if route:
            self.page_context.setText(key.upper())
            if route[0]=="engine": self.show_engine(route[1])
            else: self.show_utility(route[1])

    def navigate(self,index):
        if index<0:return
        key=next((name for name, route in NAV_PAGES.items() if route==("engine",index)),"MISSION CONTROL")
        self.page_context.setText(key.upper())
        self.show_engine(index)
        item=self.nav_items.get(key)
        if item and self.tree.currentItem()!=item: self.tree.setCurrentItem(item)

    def _replace_view(self, widget):
        while self.stack.count():
            old=self.stack.widget(0); self.stack.removeWidget(old); old.deleteLater()
        self.stack.addWidget(widget); self.stack.setCurrentWidget(widget)

    def show_engine(self,index):
        if index == 0:
            self.show_utility("mission")
            return
        if index == 8:
            self.show_utility("overview")
            return
        if index == 1:
            assessment=read_current_assessment()
            results=read_result(1) if assessment else {}
            findings_result=read_result(5) if assessment else {}
            findings=findings_result.get("findings", []) if isinstance(findings_result,dict) else []
            results_root=None
            if assessment.get("results_path"):
                candidate=Path(str(assessment["results_path"])).resolve()
                if candidate.is_relative_to(REPORTS.resolve()): results_root=candidate
            workspace=DatasetIntegrityWorkspace(
                assessment if assessment else None,
                results if isinstance(results,dict) and results.get("status")!="unavailable" else {},
                findings if isinstance(findings,list) else [],
                results_root=results_root,
                on_rerun=(lambda record=assessment:self.run_assessment_from_shell(record)) if assessment else None,
                parent=self,
            )
            self._replace_view(workspace)
            self.assessment_label.setText(f"Assessment  ·  {field(assessment,'assessment_id',default='No assessment loaded')}")
            self.activity.setText(f"Activity · {self._activity_count()}")
            return
        if index == 2:
            assessment = read_current_assessment()
            results = read_result(2) if assessment else {}
            findings_result = read_result(5) if assessment else {}
            findings = findings_result.get("findings") if isinstance(findings_result, dict) else None
            if isinstance(findings_result, dict) and findings_result.get("status") == "unavailable":
                findings = None
            workspace = ModelIntegrityWorkspace(
                assessment if assessment else None,
                results if isinstance(results, dict) and results.get("status") != "unavailable" else {},
                findings if isinstance(findings, list) else None,
                on_rerun=(lambda record=assessment: self.run_assessment_from_shell(record)) if assessment else None,
                parent=self,
            )
            self._replace_view(workspace)
            self.assessment_label.setText(f"Assessment  ·  {field(assessment,'assessment_id',default='No assessment loaded')}")
            self.activity.setText(f"Activity · {self._activity_count()}")
            return
        if index == 3:
            assessment = read_current_assessment()
            result = read_result(3) if assessment else {}
            findings_result = read_result(5) if assessment else {}
            findings = findings_result.get("findings") if isinstance(findings_result, dict) else None
            if isinstance(findings_result, dict) and findings_result.get("status") == "unavailable":
                findings = None
            workspace = ProvenanceWorkspace(
                assessment if assessment else None,
                result if isinstance(result, dict) else {},
                findings if isinstance(findings, list) else None,
                parent=self,
            )
            self._replace_view(workspace)
            self.assessment_label.setText(f"Assessment  ·  {field(assessment,'assessment_id',default='No assessment loaded')}")
            self.activity.setText(f"Activity · {self._activity_count()}")
            return
        if index == 4:
            assessment = read_current_assessment()
            result = read_result(4) if assessment else {}
            findings_result = read_result(5) if assessment else {}
            findings = findings_result.get("findings") if isinstance(findings_result, dict) else None
            if isinstance(findings_result, dict) and findings_result.get("status") == "unavailable":
                findings = None
            workspace = ShiftWorkspace(
                assessment if assessment else None,
                result,
                findings if isinstance(findings, list) else None,
                parent=self,
            )
            self._replace_view(workspace)
            self.assessment_label.setText(f"Assessment  ·  {field(assessment,'assessment_id',default='No assessment loaded')}")
            self.activity.setText(f"Activity · {self._activity_count()}")
            return
        if index == 5:
            assessment = read_current_assessment()
            result = read_result(5) if assessment else {}
            def review_in_session(finding):
                finding_id = str(finding.get("finding_id", ""))
                before = finding_id in REVIEWED_FINDINGS
                FindingDialog(finding, self).exec()
                return finding_id in REVIEWED_FINDINGS and not before
            workspace = FindingsWorkspace(
                assessment if assessment else None,
                result,
                on_navigate=self.navigate,
                on_review=review_in_session,
                parent=self,
            )
            self._replace_view(workspace)
            self.assessment_label.setText(f"Assessment  ·  {field(assessment,'assessment_id',default='No assessment loaded')}")
            self.activity.setText(f"Activity · {self._activity_count()}")
            return
        if index == 6:
            assessment = read_current_assessment()
            result = read_result(6) if assessment else {}
            findings_result = read_result(5) if assessment else {}
            findings = findings_result.get("findings") if isinstance(findings_result, dict) else None
            workspace = AuditWorkspace(
                assessment if assessment else None,
                result,
                findings if isinstance(findings, list) else None,
                on_navigate=self.navigate,
                parent=self,
            )
            self._replace_view(workspace)
            self.assessment_label.setText(f"Assessment  ·  {field(assessment,'assessment_id',default='No assessment loaded')}")
            self.activity.setText(f"Activity · {self._activity_count()}")
            return
        if index == 7:
            assessment = read_current_assessment()
            report = read_result(7)
            assessment_id = str(assessment.get("assessment_id") or "")
            if assessment_id and Path(assessment_id).name == assessment_id:
                assessment_root = (REPORTS / "assessments" / assessment_id).resolve()
                report_path = (assessment_root / "tracer_cv_assurance_report.json").resolve()
                text_report_path = (assessment_root / "tracer_cv_assurance_report.txt").resolve()
                if not report_path.is_relative_to((REPORTS / "assessments").resolve()):
                    report_path = None
                if not text_report_path.is_relative_to((REPORTS / "assessments").resolve()):
                    text_report_path = None
                protected = [assessment_root / "assessment.json", report_path, text_report_path, REPORTS / "active_assessment.json"]
                engine_records = assessment.get("engines", {})
                if isinstance(engine_records, dict):
                    for record in engine_records.values():
                        if not isinstance(record, dict) or not record.get("result_path"):
                            continue
                        try:
                            candidate = Path(str(record["result_path"])).resolve()
                            if candidate.is_relative_to(assessment_root):
                                protected.append(candidate)
                        except (OSError, RuntimeError, ValueError):
                            pass
            else:
                report_path = (REPORTS / "tracer_cv_assurance_report.json").resolve()
                text_report_path = (REPORTS / "tracer_cv_assurance_report.txt").resolve()
                protected = [report_path, text_report_path, REPORTS / "active_assessment.json"]
            workspace = ReportWorkspace(
                assessment if assessment else None,
                report,
                report_path=report_path,
                text_report_path=text_report_path,
                protected_paths=protected,
                on_navigate=self.open_report_related,
                on_open_finding=self.open_report_finding,
                parent=self,
            )
            self._replace_view(workspace)
            self.assessment_label.setText(f"Assessment  ·  {field(assessment, 'assessment_id', default=field(report, 'assessment_id', default='No assessment loaded'))}")
            self.activity.setText(f"Activity · {self._activity_count()}")
            return
        self._replace_view(Page(NAMES[index],read_result(index),self.navigate,index))
        self.assessment_label.setText(f"Assessment  ·  {field(read_result(0),'assessment_id',default='No assessment loaded')}")
        self.activity.setText(f"Activity · {self._activity_count()}")

    def _utility_page(self,title):
        page=QWidget(); outer=QVBoxLayout(page); outer.setContentsMargins(28,24,28,24); outer.setSpacing(14)
        scroll=QScrollArea(); scroll.setWidgetResizable(True); outer.addWidget(scroll)
        body=QWidget(); layout=QVBoxLayout(body); layout.setSpacing(14); scroll.setWidget(body)
        h=QLabel(title); h.setObjectName("pageTitle"); layout.addWidget(h)
        return page,layout

    def show_utility(self, key):
        title={"mission":"Mission Control","overview":"Assessment Overview","assessments":"Assessments","assets":"Assets","evidence":"Evidence","settings":"Settings"}[key]
        self.page_context.setText(title.upper())
        current_report=read_result(0)
        self.assessment_label.setText(f"Assessment  ·  {field(current_report,'assessment_id',default='No assessment loaded')}")
        self.activity.setText(f"Activity · {self._activity_count()}")
        if key == "settings":
            assessment_store = SERVICES.get("assessment_store") if SERVICES else None
            workspace = SettingsWorkspace(
                CONFIG, ACTIVE_COMPUTE,
                device_selector=self.device_selector,
                theme_button=self.theme_button,
                on_navigate=self.open_settings_related,
                assessment_store_path=getattr(assessment_store, "database", None),
                parent=self,
            )
            self._replace_view(workspace)
            return
        page,layout=self._utility_page(title)
        if key in ("mission", "overview"):
            self.build_assessment_view(key, layout)
        elif key=="assessments":
            result=read_result(0); coverage=result.get("asset_coverage",{})
            current=read_current_assessment()
            layout.addWidget(MetricCard("Current assessment",field(current,"assessment_id",default=field(result,"assessment_id",default="No completed assessment")),field(current,"name",default="Loaded from local C5 report")))
            layout.addWidget(MetricCard("Assessment status",field(current,"status",default=field(result,"status",default="Unavailable")),"Persisted local assessment status"))
            layout.addWidget(MetricCard("Covered assets",len([k for k,v in coverage.items() if isinstance(v,dict) and field(v,"status",default="unavailable") not in ("unavailable","not_assessed")]),"Counts reflect the loaded report"))
            run=QPushButton("New Assessment"); run.clicked.connect(lambda:self.run_assessment_from_shell()); layout.addWidget(run)
            open_current=QPushButton("Open Assessment Overview"); open_current.clicked.connect(lambda:self.show_utility("overview")); layout.addWidget(open_current)
            details=QPushButton("Open Mission Control"); details.clicked.connect(lambda:self.navigate(0)); layout.addWidget(details)
            saved=SERVICES["assessment_store"].list_assessments() if SERVICES and "assessment_store" in SERVICES else []
            layout.addWidget(QLabel("Saved local assessments"))
            table=AnalystTable(["Name","Assessment ID","Status","Created","Updated"],[[a.get("name","—"),a.get("assessment_id","—"),a.get("status","—"),a.get("created_at","—"),a.get("updated_at","—")] for a in saved])
            if saved:
                table.cellDoubleClicked.connect(lambda row,col:self.open_assessment_by_id(saved[row].get("assessment_id")))
            layout.addWidget(table)
            if not saved: layout.addWidget(QLabel("No wizard assessments have been saved yet."))
        elif key=="assets":
            layout.addWidget(QLabel("Local asset registry. Registration records identity metadata; it does not execute selected files."))
            add=QPushButton("Register Dataset or Model"); add.clicked.connect(self.register_asset_dialog); layout.addWidget(add)
            assets=SERVICES["asset_registry"].list_assets() if SERVICES else []
            table=AnalystTable(["Type","Name","Trust state","Size","SHA-256","Registered"],[[a["kind"],a["display_name"],a["trust_state"],a["size_bytes"] or "—",a["sha256"] or "Not hashed",a["registered_at"]] for a in assets]); layout.addWidget(table)
            if not assets: layout.addWidget(QLabel("No assets are registered in the local registry yet."))
        elif key=="evidence":
            assessment = read_current_assessment()
            engine_results = load_engine_evidence(assessment, REPORTS, CONFIG.evidence_dir)
            findings_result = read_result(5) if assessment else None
            findings = findings_result.get("findings") if isinstance(findings_result, dict) else None
            def open_related_finding(finding_id):
                self.navigate(5)
                findings_page = self.stack.currentWidget()
                if isinstance(findings_page, FindingsWorkspace):
                    findings_page.search.setEditText(str(finding_id))
                    for row in range(findings_page.finding_table.rowCount()):
                        if not findings_page.finding_table.isRowHidden(row):
                            findings_page.open_finding_row(row, 0)
                            break
            workspace = EvidenceWorkspace(
                assessment if assessment else None,
                engine_results,
                findings if isinstance(findings, list) else None,
                on_navigate=self.navigate,
                on_open_finding=open_related_finding,
                parent=self,
            )
            self._replace_view(workspace)
            self.assessment_label.setText(f"Assessment  ·  {field(assessment,'assessment_id',default='No assessment loaded')}")
            self.activity.setText(f"Activity · {self._activity_count()}")
            return
        else:
            layout.addWidget(QLabel("Local runtime and display preferences."))
            form=QFormLayout(); form.addRow("Execution device",self.device_selector); form.addRow("Active execution",QLabel(f"{ACTIVE_COMPUTE.device.upper()} · {ACTIVE_COMPUTE.device_name}")); form.addRow("Network mode",StatusBadge("AIR-GAPPED · NO SERVICE DEPENDENCIES","verified")); layout.addLayout(form)
            check=offline_capability_check(CONFIG)
            layout.addWidget(MetricCard("Offline self-check",check.get("status","unknown").upper(),check.get("network_probe_note","Network connectivity was not probed.")))
            layout.addWidget(MetricCard("Theme",CONFIG.theme.title(),"Use the header control to switch themes."))
            layout.addWidget(QLabel("Settings are stored locally in the configured TRACER-CV TOML file."))
        layout.addStretch(); self._replace_view(page)

    def open_settings_related(self, route):
        if route == "evidence":
            self.show_utility("evidence")
        elif route == "findings":
            self.navigate(5)
        elif route == "audit":
            self.navigate(6)
        elif route == "reports":
            self.navigate(7)

    def open_report_related(self, route):
        routes = {"findings": 5, "evidence": "evidence", "audit": 6}
        target = routes.get(route)
        if target == "evidence":
            self.show_utility("evidence")
        elif isinstance(target, int):
            self.navigate(target)

    def open_report_finding(self, finding_id):
        self.navigate(5)
        workspace = self.stack.currentWidget()
        if not isinstance(workspace, FindingsWorkspace):
            return
        workspace.search.setEditText(str(finding_id))
        for row in range(workspace.finding_table.rowCount()):
            if not workspace.finding_table.isRowHidden(row):
                workspace.open_finding_row(row, 0)
                break

    def build_assessment_view(self, key, layout):
        """Show an operator summary based on the local report and engine files."""
        report=read_result(0); dataset=read_result(1); model=read_result(2)
        current_assessment=read_current_assessment()
        prov=read_result(3); shift=read_result(4); findings_data=read_result(5); audit=read_result(6)
        findings=findings_data.get("findings",[]) if isinstance(findings_data,dict) else []
        findings=findings if isinstance(findings,list) else []
        summary=report.get("executive_summary",{}) if isinstance(report,dict) else {}
        coverage=report.get("asset_coverage",{}) if isinstance(report,dict) else {}
        audit_entries=audit.get("entries",[]) if isinstance(audit,dict) else []
        def section(title):
            box=SectionCard(title); layout.addWidget(box); return box
        def metric(parent,title,value,detail=""):
            parent.content.addWidget(MetricCard(title,str(value),detail))
        def button(parent,label,callback):
            item=QPushButton(label); item.clicked.connect(callback); parent.content.addWidget(item)
        def severity_count(severity):
            if severity == "informational":
                return sum(1 for item in findings if str(item.get("severity", "")).lower() in {"informational", "none"})
            levels={"high":{"critical","high"},"medium":{"medium"},"low":{"low"}}
            return sum(1 for item in findings if str(item.get("severity", "")).lower() in levels[severity])
        shifted=any(isinstance(item,dict) and item.get("shifted") is True for item in shift.get("shifted_features",[])) if isinstance(shift,dict) else False
        audit_valid=audit.get("valid") is True or (isinstance(audit.get("valid"),dict) and audit["valid"].get("valid") is True)
        audit_invalid=audit.get("valid") is False or (isinstance(audit.get("valid"),dict) and audit["valid"].get("valid") is False)
        if key=="mission":
            box=section("SYSTEM")
            metric(box,"TRACER-CV version",APP_VERSION,"Local desktop workbench")
            metric(box,"AIR-GAPPED","ENABLED" if CONFIG.offline_mode else "DISABLED","Network probes are not performed.")
            metric(box,"Compute backend",f"{ACTIVE_COMPUTE.device.upper()} · {ACTIVE_COMPUTE.device_name}")
            runtime_ready=SERVICES is not None
            readiness="READY · CPU FALLBACK" if runtime_ready and COMPUTE_ERROR else "READY" if runtime_ready else "NOT READY"
            box.content.addWidget(SeverityBadge(readiness,"verified" if runtime_ready and not COMPUTE_ERROR else "review" if runtime_ready else "unavailable"))
            metric(box,"Readiness detail",COMPUTE_ERROR or ("Local storage and compute initialized" if runtime_ready else "Local services are not initialized"))
            box=section("CURRENT ASSESSMENT")
            ds=field(current_assessment.get("dataset",{}),"path",default=field(dataset.get("A1_manifest",{}),"root",default="—"))
            mo=field(current_assessment.get("model",{}),"path",default=field(model.get("B1_identity",{}),"file_name",default="—"))
            started=field(current_assessment,"started_at",default=field(report,"assessment_started_at",default="Not recorded"))
            completed=field(current_assessment,"completed_at",default=field(report,"assessment_completed_at",default="Not recorded"))
            metric(box,"Assessment ID",field(current_assessment,"assessment_id",default=field(report,"assessment_id",default="No assessment loaded")))
            if current_assessment.get("name"): metric(box,"Assessment name",current_assessment["name"])
            if current_assessment.get("analyst"): metric(box,"Analyst / operator",current_assessment["analyst"])
            if current_assessment.get("reference_id"): metric(box,"Mission / reference ID",current_assessment["reference_id"])
            metric(box,"Dataset",Path(str(ds)).name if ds!="—" else "—",str(ds))
            metric(box,"Model",mo)
            box.content.addWidget(SeverityBadge(str(field(current_assessment,"status",default="ASSESSED" if report.get("report_digest") else "UNAVAILABLE"))))
            metric(box,"Start / completion",f"{started}  →  {completed}")
            box=section("ASSURANCE SUMMARY")
            for name,keyname in (("Dataset","dataset_integrity"),("Model","model_integrity"),("Provenance","inference_provenance"),("Distribution","distribution_shift"),("Audit","audit_trail")):
                value=coverage.get(keyname,{})
                if name=="Provenance": state="Valid" if prov.get("valid") is True else "Review required" if prov.get("valid") is False else "Unavailable"
                elif name=="Distribution": state="Shift detected" if shifted else field(shift,"status",default=field(value,"status",default="Unavailable"))
                elif name=="Audit": state="Valid" if audit_valid else "Invalid" if audit_invalid else field(value,"status",default="Unavailable")
                else: state=field(value,"status",default="Unavailable")
                box.content.addWidget(SeverityBadge(f"{name}: {state}"))
            box=section("FINDINGS")
            row=QHBoxLayout(); box.content.addLayout(row)
            for name,sev in (("Total",None),("High","high"),("Medium","medium"),("Low","low"),("Informational","informational")):
                value=len(findings) if sev is None else severity_count(sev)
                row.addWidget(SeverityBadge(f"{name}: {value}",sev or "info"))
            layout.addWidget(MetricBarChart("Finding severity distribution",[[name,severity_count(level),level] for name,level in (("High","high"),("Medium","medium"),("Low","low"),("Informational","informational"))]))
            box=section("KEY FINDINGS")
            for finding in findings[:5]:
                box.content.addWidget(SeverityBadge(str(finding.get("severity","UNAVAILABLE"))))
                b=QPushButton(f"{str(finding.get('severity','')).upper()} · {finding.get('title','Finding')}\n{finding.get('recommended_action','Open finding details')}")
                b.setMinimumHeight(58); b.clicked.connect(lambda checked=False,fid=finding.get("finding_id"): self.open_finding(fid)); box.content.addWidget(b)
            if not findings: box.content.addWidget(QLabel("No findings are present in the current local results."))
            box=section("RECENT ACTIVITY")
            events=sorted((x for x in audit_entries if isinstance(x,dict)),key=lambda x:str(x.get("timestamp","")),reverse=True)[:6]
            for event in events:
                b=QPushButton(f"{event.get('timestamp','—')} · {event.get('event_type','Activity')} · {event.get('source_engine','')}")
                b.clicked.connect(lambda checked=False:self.navigate(6)); box.content.addWidget(b)
            if not events: box.content.addWidget(QLabel("No audit activity is recorded for this assessment."))
            box=section("QUICK ACTIONS")
            grid=QGridLayout(); box.content.addLayout(grid)
            choices=(("New Assessment",self.run_assessment_from_shell),("Open Assessment",lambda:self.show_utility("overview")),("Import Dataset",self.import_dataset),("Import Model",self.import_model),("View Findings",lambda:self.navigate(5)),("Generate Report",lambda:self.navigate(7)))
            for i,(label,callback) in enumerate(choices):
                b=QPushButton(label); b.clicked.connect(callback); grid.addWidget(b,i//3,i%3)
            self.activity.setText(f"Activity · {self._activity_count()}")
            return
        controls=QHBoxLayout(); layout.addLayout(controls)
        for label,callback in (("Mission Control",lambda:self.show_utility("mission")),("Findings",lambda:self.navigate(5)),("Technical Evidence",lambda:self.navigate(1)),("Generate Report",lambda:self.navigate(7))):
            b=QPushButton(label); b.clicked.connect(callback); controls.addWidget(b)
        note=QLabel("Assessment results are summarized here. Open a section to inspect its technical evidence."); note.setWordWrap(True); layout.addWidget(note)
        box=section("ASSESSMENT SUMMARY")
        metric(box,"Assessment ID",field(report,"assessment_id",default="—"))
        metric(box,"Status",field(current_assessment,"status",default="ASSESSED" if report.get("report_digest") else "UNAVAILABLE"))
        ds=field(current_assessment.get("dataset",{}),"path",default=field(dataset.get("A1_manifest",{}),"root",default="—"))
        mo=field(current_assessment.get("model",{}),"path",default=field(model.get("B1_identity",{}),"file_name",default="—"))
        started=field(current_assessment,"started_at",default=field(report,"assessment_started_at",default="Not recorded"))
        completed=field(current_assessment,"completed_at",default=field(report,"assessment_completed_at",default="Not recorded"))
        metric(box,"Dataset",Path(str(ds)).name if ds!="—" else "—",str(ds))
        metric(box,"Model",mo)
        if current_assessment.get("name"): metric(box,"Assessment name",current_assessment["name"])
        if current_assessment.get("analyst"): metric(box,"Analyst / operator",current_assessment["analyst"])
        if current_assessment.get("reference_id"): metric(box,"Mission / reference ID",current_assessment["reference_id"])
        metric(box,"Start / completion",f"{started}  →  {completed}")
        metric(box,"Interpretation",field(summary,"interpretation",default="No assessment report is available."))
        box.content.addWidget(SeverityBadge(str(field(summary,"highest_observed_severity",default="INFORMATION"))))
        counts=QHBoxLayout(); box.content.addLayout(counts)
        for label,severity in (("Total",None),("High", "high"),("Medium","medium"),("Low","low"),("Informational","informational")):
            counts.addWidget(SeverityBadge(f"{label}: {len(findings) if severity is None else severity_count(severity)}",severity or "info"))
        for title,index,coverage_key in (("Dataset",1,"dataset_integrity"),("Model",2,"model_integrity"),("Provenance",3,"inference_provenance"),("Distribution",4,"distribution_shift"),("Audit",6,"audit_trail")):
            box=section(title.upper())
            if title=="Provenance": state="Valid" if prov.get("valid") is True else "Review required" if prov.get("valid") is False else "Unavailable"
            elif title=="Distribution": state="Shift detected" if shifted else field(shift,"status",default=field(coverage.get(coverage_key,{}),"status",default="Unavailable"))
            elif title=="Audit": state="Valid" if audit_valid else "Review required" if audit_invalid else field(coverage.get(coverage_key,{}),"status",default="Unavailable")
            else: state=field(coverage.get(coverage_key,{}),"status",default="Unavailable")
            box.content.addWidget(SeverityBadge(f"Status: {state}"))
            button(box,f"Open {title} evidence",lambda checked=False,i=index:self.navigate(i))
        box=section("FINDINGS")
        metric(box,"Total findings",len(findings))
        for finding in findings:
            box.content.addWidget(SeverityBadge(str(finding.get("severity","UNAVAILABLE"))))
            b=QPushButton(f"{str(finding.get('severity','')).upper()} · {finding.get('title','Finding')}")
            b.clicked.connect(lambda checked=False,fid=finding.get("finding_id"): self.open_finding(fid)); box.content.addWidget(b)
        if not findings: box.content.addWidget(QLabel("No findings are present in the current local results."))

    def open_finding(self, finding_id):
        data=read_result(5); findings=data.get("findings",[]) if isinstance(data,dict) else []
        for finding in findings if isinstance(findings,list) else []:
            if finding.get("finding_id")==finding_id:
                FindingDialog(finding,self).exec(); return

    def import_dataset(self):
        path=QFileDialog.getExistingDirectory(self,"Import local dataset")
        if not path: return
        try:
            SERVICES["asset_registry"].register(Path(path),"dataset",hash_file=False)
            self.show_utility("assets")
        except Exception as exc:
            QMessageBox.warning(self,"Dataset import failed",str(exc))

    def open_assessment_by_id(self, assessment_id):
        store=SERVICES.get("assessment_store") if SERVICES else None
        data=store.load(assessment_id) if store else None
        if not data: return
        ReportStore(REPORTS).save("active_assessment.json",json.dumps({"assessment_id":assessment_id}).encode(),overwrite=True)
        self.show_utility("overview")

    def open_assessment(self, assessment):
        self.assessment_label.setText(f"Assessment  ·  {assessment.assessment_id}")
        self.show_utility("overview")

    def import_model(self):
        path,_=QFileDialog.getOpenFileName(self,"Import local model",str(ROOT),"Model files (*.pt *.pth *.onnx *.torchscript);;All files (*)")
        if not path: return
        try:
            SERVICES["asset_registry"].register(Path(path),"model",hash_file=True)
            self.show_utility("assets")
        except Exception as exc:
            QMessageBox.warning(self,"Model import failed",str(exc))

    def run_assessment_from_shell(self, prefill=None):
        wizard=NewAssessmentWizard(config=CONFIG,services=SERVICES,parent=self)
        if isinstance(prefill,dict):
            try: wizard.prefill_from_assessment(prefill)
            except (OSError,ValueError,KeyError,TypeError) as exc:
                QMessageBox.warning(self,"Assessment inputs unavailable",f"The prior inputs could not all be staged. Review the wizard selections before running.\n{exc}")
        wizard.exec()

    def register_asset_dialog(self):
        path,_=QFileDialog.getOpenFileName(self,"Register local asset",str(ROOT),"All files (*)")
        if not path:return
        kind="model" if Path(path).suffix.lower() in {".pt",".pth",".onnx",".torchscript"} else "dataset"
        try:
            SERVICES["asset_registry"].register(Path(path),kind,hash_file=True)
            self.show_utility("assets")
        except Exception as exc: QMessageBox.warning(self,"Asset registration failed",str(exc))

    def _finding_count(self):
        findings=read_result(5).get("findings",[])
        return len(findings) if isinstance(findings,list) else 0

    def _activity_count(self):
        events=read_result(6).get("entries",[])
        assessment=read_current_assessment()
        return (len(events) if isinstance(events,list) else 0)+sum(1 for key in ("created_at","started_at","completed_at") if assessment.get(key))+len(SESSION_ACTIVITY)

    def show_activity(self):
        dialog=QDialog(self); dialog.setWindowTitle("Activity Center"); dialog.resize(900,560); layout=QVBoxLayout(dialog)
        layout.addWidget(QLabel("Recent recorded assessment and audit events. No inferred progress is shown."))
        events=[]; audit=read_result(6); entries=audit.get("entries",[]) if isinstance(audit,dict) else []
        for event in entries if isinstance(entries,list) else []:
            if not isinstance(event,dict):continue
            events.append([field(event,"timestamp"),humanize(field(event,"event_type",default="Audit event")),field(event,"source_engine"),field(event,"affected_asset"),field(event,"event_id"),"AUDIT"])
        for event in SESSION_ACTIVITY:
            events.append([event.get("timestamp"),event.get("event_type"),event.get("source_engine"),event.get("affected_asset"),event.get("event_id"),event.get("route")])
        current=read_current_assessment()
        for label,key in (("Assessment created","created_at"),("Assessment started","started_at"),("Assessment completed","completed_at")):
            if current.get(key):events.append([current[key],label,"Assessment",field(current,"name"),field(current,"assessment_id"),"ASSESSMENT"])
        events.sort(key=lambda row:str(row[0]),reverse=True)
        table=AnalystTable(["Time","Event","Source","Affected Asset","Event / Assessment ID","Route"],events[:100]); layout.addWidget(table)
        def open_event(row,col):
            kind=events[row][5]
            if kind=="ASSESSMENT":self.show_utility("overview")
            elif kind=="FINDING":self.open_finding(events[row][4])
            else:self.navigate(6)
            dialog.accept()
        table.cellDoubleClicked.connect(open_event)
        close=QPushButton("Close"); close.clicked.connect(dialog.accept); layout.addWidget(close); dialog.exec()

    def search_local(self):
        query=self.search.text().strip().casefold()
        if not query:return
        candidates=[]
        current=read_current_assessment()
        if current:candidates.append(["Assessment",f"{field(current,'name')} · {field(current,'assessment_id')}","ASSESSMENT",current])
        for asset in SERVICES["asset_registry"].list_assets() if SERVICES and SERVICES.get("asset_registry") else []:
            candidates.append(["Asset",f"{asset.get('display_name')} · {asset.get('sha256') or 'digest unavailable'}","ASSET",asset])
        findings=read_result(5).get("findings",[])
        for finding in findings if isinstance(findings,list) else []:
            candidates.append(["Finding",f"{field(finding,'finding_id')} · {field(finding,'title')} · {field(finding,'affected_asset')}","FINDING",finding])
            for path,value in searchable_fields(finding):
                candidates.append([f"Finding · {path}",f"{path}: {value}","FINDING",finding])
        audit=read_result(6); entries=audit.get("entries",[]) if isinstance(audit,dict) else []
        for event in entries if isinstance(entries,list) else []:
            candidates.append(["Audit event",f"{field(event,'event_id')} · {field(event,'event_type')} · {field(event,'affected_asset')} · {field(event,'payload_digest')}","AUDIT",event])
        provenance=read_result(3).get("records",[])
        for record in provenance if isinstance(provenance,list) else []:
            candidates.append(["Provenance",f"{field(record,'record_id')} · {field(record,'model_id')} · {field(record,'input_digest')} · {field(record,'output_digest')}","PROVENANCE",record])
        for i,name in enumerate(NAMES):
            data=read_result(i)
            if data:
                candidates.extend([[f"{name} · {path}",f"{path}: {value}",f"ENGINE:{i}",data] for path,value in searchable_fields(data)])
        matches=[item for item in candidates if query in item[1].casefold()][:500]
        dialog=QDialog(self); dialog.setWindowTitle("Local Search Results"); dialog.resize(920,560); layout=QVBoxLayout(dialog)
        layout.addWidget(QLabel(f"{len(matches)} matching local result(s). Double-click to open."))
        table=AnalystTable(["Type","Result"],[[item[0],item[1]] for item in matches]); layout.addWidget(table)
        def open_match(row,col):
            item=matches[row]; kind=item[2]
            if kind=="ASSESSMENT":self.show_utility("overview")
            elif kind=="ASSET":self.show_utility("assets")
            elif kind=="FINDING":self.open_finding(field(item[3],"finding_id"))
            elif kind=="AUDIT":self.navigate(6)
            elif kind=="PROVENANCE":self.navigate(3)
            elif kind.startswith("ENGINE:"):self.navigate(int(kind.split(":")[1]))
            dialog.accept()
        table.cellDoubleClicked.connect(open_match)
        close=QPushButton("Close"); close.clicked.connect(dialog.accept); layout.addWidget(close); dialog.exec()

    def toggle_theme(self):
        global CONFIG
        theme="dark" if CONFIG.theme=="light" else "light"
        CONFIG=__import__("dataclasses").replace(CONFIG,theme=theme)
        try: CONFIG.save()
        except OSError as exc: QMessageBox.warning(self,"Theme not saved",str(exc))
        self.theme_button.setText("Light theme" if theme=="dark" else "Dark theme")
        try: QApplication.instance().setStyleSheet(load_stylesheet(CONFIG.resources_dir, "tracer_dark.qss" if theme=="dark" else "tracer.qss"))
        except (OSError,ValueError,UnicodeError): pass


def main():
    global SERVICES
    CONFIG.ensure_local_directories()
    SERVICES=initialize_local_storage(CONFIG)
    SERVICES["assessment_manager"]=AssessmentManager(config=CONFIG,assessment_store=SERVICES["assessment_store"],evidence_store=SERVICES["evidence_store"])
    configure_local_logging(CONFIG.logs_dir,CONFIG.logging_level)
    import_demo_outputs(ROOT / "reports",CONFIG,overwrite=False)
    app=QApplication(sys.argv); app.setApplicationName("TRACER-CV"); app.setApplicationVersion(APP_VERSION)
    try: app.setStyleSheet(load_stylesheet(CONFIG.resources_dir, "tracer_dark.qss" if CONFIG.theme=="dark" else "tracer.qss"))
    except (OSError,ValueError,UnicodeError): app.setStyleSheet("")
    app.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.GeneralFont))
    app.setWindowIcon(app.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon))
    window=MainWindow(); window.show()
    app.aboutToQuit.connect(lambda: SERVICES["assessment_manager"].close(wait=True))
    sys.exit(app.exec())

if __name__=="__main__": main()
