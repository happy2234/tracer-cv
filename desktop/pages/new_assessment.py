"""Eight-step local-only TRACER-CV assessment wizard."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QFileDialog, QFormLayout, QGroupBox, QLabel,
    QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QSpinBox, QVBoxLayout,
    QWizard, QWizardPage, QComboBox, QTableWidget, QTableWidgetItem,
)

from backend.core.assessment import Assessment
from backend.core.compute import DeviceUnavailableError, resolve_compute
from backend.engines.dataset.manifest import build_manifest
from backend.engines.model.identity import inspect_model

IMAGE_SUFFIXES={".jpg", ".jpeg", ".png", ".bmp", ".webp", ".tif", ".tiff"}


def detect_dataset_format(root: Path) -> tuple[str,int]:
    files=[p for p in root.rglob("*") if p.is_file()]
    images=[p for p in files if p.suffix.lower() in IMAGE_SUFFIXES]
    if (root/"candidate").is_dir() and (root/"reference").is_dir():
        label="Image dataset with reference/candidate partitions"
    elif (root/"labels").is_dir() or any(p.suffix.lower()==".txt" for p in files):
        label="Image dataset with YOLO-style labels" if images else "YOLO-style labeled dataset"
    elif images:
        label="Image folder dataset"
    elif any(p.suffix.lower() in {".json",".jsonl"} for p in files):
        label="JSON dataset (image checks may be limited)"
    else:
        label="Generic local file collection"
    return label,len(images)


def reference_compatibility(dataset: Path, reference: Path) -> str:
    candidate=dataset/"candidate" if (dataset/"candidate").is_dir() else dataset
    _,dataset_count=detect_dataset_format(candidate)
    _,reference_count=detect_dataset_format(reference)
    if dataset_count and reference_count:
        return f"Compatible for image comparisons ({dataset_count} assessment images; {reference_count} reference images)."
    return "Limited: one or both folders contain no supported image files."


class _Step(QWizardPage):
    def __init__(self, title: str, explanation: str = ""):
        super().__init__(); self.setTitle(title)
        layout=QVBoxLayout(self)
        if explanation:
            text=QLabel(explanation); text.setWordWrap(True); layout.addWidget(text)
        self.body=QVBoxLayout(); layout.addLayout(self.body); layout.addStretch()


class _RunStep(_Step):
    def __init__(self, wizard: "NewAssessmentWizard"):
        super().__init__("Run Assessment", "The pipeline runs locally. Stage updates appear only when an engine starts or returns.")
        self.wizard=wizard; self.finished=False; self.future=None; self.event_cursor=0
        self.state=QLabel("Ready to run the configured assessment."); self.state.setWordWrap(True); self.body.addWidget(self.state)
        self.stage_names=["A1_manifest","A2_exact_duplicates","A3_near_duplicates","A4_ood","A5_label_consistency","A6_contributor_risk","A7_metadata_consistency","A8_poison_trigger_forensics","B1_identity","B2_behavioral_fingerprint","B3_model_statistics","B4_trigger_search","C1_provenance","C2_distribution_shift","C3_findings","C4_audit_trail","C5_assurance_report"]
        self.stage_table=QTableWidget(len(self.stage_names),3); self.stage_table.setHorizontalHeaderLabels(["Engine","Status","Reason"]); self.stage_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.stage_rows={}
        for row,name in enumerate(self.stage_names):
            self.stage_rows[name]=row; self.stage_table.setItem(row,0,QTableWidgetItem(name)); self.stage_table.setItem(row,1,QTableWidgetItem("NOT STARTED")); self.stage_table.setItem(row,2,QTableWidgetItem(""))
        self.stage_table.horizontalHeader().setStretchLastSection(True); self.body.addWidget(self.stage_table)
        self.log=QPlainTextEdit(); self.log.setReadOnly(True); self.log.setMaximumBlockCount(300); self.body.addWidget(self.log)
        self.run_button=QPushButton("START ASSESSMENT"); self.run_button.clicked.connect(self.execute); self.body.addWidget(self.run_button)
        self.cancel_button=QPushButton("Cancel Assessment"); self.cancel_button.setEnabled(False); self.cancel_button.clicked.connect(self.cancel); self.body.addWidget(self.cancel_button)
        self.poll=QTimer(self); self.poll.setInterval(200); self.poll.timeout.connect(self.refresh_execution)

    def isComplete(self) -> bool:
        return self.finished

    def execute(self):
        if self.finished: return
        if not self.wizard.collect_inputs(show_errors=True): return
        assessment=self.wizard.make_assessment()
        self.run_button.setEnabled(False)
        self.state.setText("Creating assessment…")
        self.log.clear(); self.event_cursor=0
        for row in range(len(self.stage_names)):
            self.stage_table.item(row,1).setText("QUEUED")
            self.stage_table.item(row,2).setText("")
        manager=self.wizard.services.get("assessment_manager") if self.wizard.services else None
        try:
            if manager is None: raise RuntimeError("Local assessment manager is unavailable.")
            self.wizard.assessment=manager.create(assessment)
            self.future=manager.queue(assessment)
            self.run_button.setEnabled(False); self.cancel_button.setEnabled(True)
            self.state.setText(f"Assessment QUEUED: {assessment.assessment_id}. Execution updates reflect engine events.")
            self.poll.start()
        except Exception as exc:
            assessment.status="FAILED"; assessment.error=f"Assessment could not start: {type(exc).__name__}: {exc}"
            assessment.completed_at=datetime.now(timezone.utc).isoformat()
            self.wizard.assessment=assessment
            store=self.wizard.services.get("assessment_store") if self.wizard.services else None
            if store: store.save(assessment.to_dict())
            self.state.setText(f"Assessment failed: {assessment.error}")
            self.log.appendPlainText("Orchestration failed; the failure is recorded in the local assessment object.")
            self.run_button.setEnabled(True)
        self.completeChanged.emit()

    def refresh_execution(self):
        manager=self.wizard.services.get("assessment_manager") if self.wizard.services else None
        if manager and self.wizard.assessment:
            events=manager.events(self.wizard.assessment.assessment_id)
            for event in events[self.event_cursor:]:
                engine=event["engine"]; state=event["state"]; result=event.get("result") or {}
                detail=result.get("reason","") if isinstance(result,dict) else ""
                self.log.appendPlainText(f"{state.upper():<22} {engine}" + (f"  ·  {detail}" if detail else ""))
                self.state.setText(f"{engine}: {state.replace('_',' ').upper()}")
                if engine in self.stage_rows:
                    row=self.stage_rows[engine]
                    self.stage_table.item(row,1).setText("RUNNING" if state=="started" else state.replace("_"," ").upper())
                    self.stage_table.item(row,2).setText(detail)
            self.event_cursor=len(events)
        if self.future and self.future.done():
            self.poll.stop(); self.cancel_button.setEnabled(False)
            try: self.wizard.assessment=self.future.result()
            except Exception as exc: self.state.setText(f"Assessment failed: {type(exc).__name__}: {exc}")
            status=self.wizard.assessment.status if self.wizard.assessment else "FAILED"
            self.state.setText(f"Assessment {status}: {self.wizard.assessment.assessment_id}")
            self.finished=status in {"COMPLETED","COMPLETED_WITH_WARNINGS","CANCELLED","FAILED"}
            self.completeChanged.emit()

    def cancel(self):
        assessment=self.wizard.assessment
        manager=self.wizard.services.get("assessment_manager") if self.wizard.services else None
        if assessment and manager and manager.cancel(assessment.assessment_id):
            self.state.setText("Cancellation requested. The current engine operation will finish before later stages are skipped.")
            self.cancel_button.setEnabled(False)


class NewAssessmentWizard(QWizard):
    def __init__(self, *, config, services, parent=None):
        super().__init__(parent)
        self.config=config; self.services=services; self.assessment: Assessment | None=None
        try: self.detected_hardware=resolve_compute("auto")
        except DeviceUnavailableError: self.detected_hardware=None
        self.setWindowTitle("New TRACER-CV Assessment"); self.resize(760,620)
        self.setWizardStyle(QWizard.WizardStyle.ModernStyle)
        self.setButtonText(QWizard.FinishButton,"Open Assessment Overview")
        self._build_information()
        self._build_dataset()
        self._build_reference()
        self._build_model()
        self._build_analysis()
        self._build_compute()
        self._build_review()
        self.run_page=_RunStep(self); self.addPage(self.run_page)
        self.currentIdChanged.connect(self.page_changed)
        self.accepted.connect(self.open_result)

    def _build_information(self):
        self.info_page=_Step("Assessment Information","Add identifying information for the local assessment record.")
        form=QFormLayout(); self.info_page.body.addLayout(form)
        self.name=QLineEdit(); self.name.setPlaceholderText("e.g. Q3 production model review")
        self.description=QPlainTextEdit(); self.description.setMaximumHeight(90)
        self.analyst=QLineEdit(); self.analyst.setPlaceholderText("Analyst or operator")
        self.reference_id=QLineEdit(); self.reference_id.setPlaceholderText("Optional")
        form.addRow("Assessment name *",self.name); form.addRow("Description",self.description)
        form.addRow("Analyst / operator *",self.analyst); form.addRow("Mission / reference ID",self.reference_id)
        self.addPage(self.info_page)

    def _build_dataset(self):
        page=_Step("Dataset","Select a local dataset directory. TRACER-CV calculates a manifest identity and registers the folder locally.")
        self.dataset_page=page
        self.dataset_path=QLineEdit(); self.dataset_path.setReadOnly(True)
        choose=QPushButton("Select Dataset"); choose.clicked.connect(self.choose_dataset)
        row=QVBoxLayout(); row.addWidget(self.dataset_path); row.addWidget(choose); page.body.addLayout(row)
        self.dataset_summary=QLabel("No dataset selected."); self.dataset_summary.setWordWrap(True); page.body.addWidget(self.dataset_summary)
        self.dataset_asset=None; self.dataset_manifest=None; self.dataset_format=""
        self.dataset_image_count=0
        self.addPage(page)

    def _build_reference(self):
        page=_Step("Reference Dataset","Optionally choose a trusted reference folder for OOD and distribution comparison.")
        self.reference_path=QLineEdit(); self.reference_path.setReadOnly(True)
        choose=QPushButton("Select Reference Dataset"); choose.clicked.connect(self.choose_reference)
        clear=QPushButton("Clear"); clear.clicked.connect(self.clear_reference)
        page.body.addWidget(self.reference_path); page.body.addWidget(choose); page.body.addWidget(clear)
        self.reference_summary=QLabel("No reference selected; reference based checks will be limited."); self.reference_summary.setWordWrap(True); page.body.addWidget(self.reference_summary)
        self.reference_asset=None; self.reference_format=""
        self.addPage(page)

    def _build_model(self):
        page=_Step("Model","Select a local model. TRACER-CV records its file digest and identifies available assurance methods.")
        self.model_path=QLineEdit(); self.model_path.setReadOnly(True)
        choose=QPushButton("Select Model"); choose.clicked.connect(self.choose_model)
        page.body.addWidget(self.model_path); page.body.addWidget(choose)
        self.model_summary=QLabel("No model selected."); self.model_summary.setWordWrap(True); page.body.addWidget(self.model_summary)
        self.model_asset=None; self.model_identity=None
        self.addPage(page)

    def _build_analysis(self):
        page=_Step("Analysis Configuration","Choose the assessment areas in analyst language. Advanced settings are optional.")
        self.dataset_checks=QCheckBox("Dataset integrity checks (A1 identity is always recorded; other checks can be disabled)"); self.dataset_checks.setChecked(True)
        self.model_checks=QCheckBox("Model identity and behavior checks"); self.model_checks.setChecked(True)
        self.shift_checks=QCheckBox("Compare against the trusted reference when selected"); self.shift_checks.setChecked(True)
        page.body.addWidget(self.dataset_checks); page.body.addWidget(self.model_checks); page.body.addWidget(self.shift_checks)
        self.advanced_toggle=QCheckBox("Show Advanced Settings")
        advanced=QGroupBox("Advanced Settings"); advanced.setVisible(False)
        form=QFormLayout(advanced)
        self.max_images=QSpinBox(); self.max_images.setRange(1,512); self.max_images.setValue(16)
        self.trigger_search=QCheckBox("Run trigger search when supported"); self.trigger_search.setChecked(True)
        form.addRow("Maximum model probe images",self.max_images); form.addRow(self.trigger_search)
        page.body.addWidget(self.advanced_toggle); page.body.addWidget(advanced); self.advanced=advanced
        self.advanced_toggle.toggled.connect(advanced.setVisible)
        self.addPage(page)

    def _build_compute(self):
        page=_Step("Compute","Choose the local execution device. Automatic selects an available local backend.")
        self.compute_choice=QComboBox(); self.compute_choice.addItems(["Automatic","CPU","CUDA"])
        self.hardware=QLabel(); self.hardware.setWordWrap(True)
        page.body.addWidget(self.compute_choice); page.body.addWidget(self.hardware)
        self.compute_choice.currentIndexChanged.connect(self.update_hardware)
        self.addPage(page); self.update_hardware()

    def _build_review(self):
        page=_Step("Review","Confirm the assets and engine scope before starting the assessment.")
        self.review_text=QPlainTextEdit(); self.review_text.setReadOnly(True); page.body.addWidget(self.review_text)
        self.addPage(page)

    def page_changed(self, page_id: int):
        if page_id==6: self.refresh_review()

    def update_hardware(self, *_):
        requested=("auto","cpu","cuda")[self.compute_choice.currentIndex()]
        try:
            self.compute_context=self.detected_hardware if requested=="auto" and self.detected_hardware else resolve_compute(requested)
            context=self.compute_context
            detected=self.detected_hardware
            if context.cuda_available is True: gpu=f"CUDA detected: {context.device_name}"
            elif context.cuda_available is False: gpu="CUDA unavailable"
            elif detected and detected.cuda_available: gpu=f"CUDA detected: {detected.device_name}"
            elif detected and detected.cuda_available is False: gpu="CUDA unavailable"
            else: gpu="CUDA availability not detected"
            self.hardware.setText(f"Active backend: {context.device.upper()} · {context.device_name}\n{gpu}"+(f"\n{context.fallback_reason}" if context.fallback_reason else ""))
        except DeviceUnavailableError as exc:
            self.compute_context=None; self.hardware.setText(f"CUDA cannot be selected: {exc}")

    def choose_dataset(self):
        selected=QFileDialog.getExistingDirectory(self,"Select local dataset",str(self.config.project_root))
        if not selected: return
        path=Path(selected)
        try:
            manifest=build_manifest(path); fmt,image_count=detect_dataset_format(path)
            asset=self.services["asset_registry"].register(path,"dataset",hash_file=False)
            self.dataset_asset=asset; self.dataset_manifest=manifest; self.dataset_format=fmt; self.dataset_image_count=image_count
            self.dataset_path.setText(str(path))
            self.dataset_summary.setText(f"Registered locally · {fmt}\nFiles: {manifest['file_count']} · Image files: {image_count}\nDataset SHA-256: {manifest['dataset_sha256']}")
            if self.reference_path.text():
                self.reference_summary.setText(f"Registered locally · {self.reference_format}\n{reference_compatibility(path,Path(self.reference_path.text()))}")
            self.dataset_page.completeChanged.emit()
        except Exception as exc:
            QMessageBox.warning(self,"Dataset identity failed",f"Could not identify/register this dataset: {exc}")

    def choose_reference(self):
        selected=QFileDialog.getExistingDirectory(self,"Select trusted reference dataset",str(self.config.project_root))
        if not selected:return
        path=Path(selected)
        try:
            fmt,_=detect_dataset_format(path)
            asset=self.services["asset_registry"].register(path,"dataset",hash_file=False)
            self.reference_asset=asset; self.reference_format=fmt; self.reference_path.setText(str(path))
            self.reference_summary.setText(f"Selected as trusted reference by the analyst · registered locally · {fmt}\n{reference_compatibility(Path(self.dataset_path.text()),path) if self.dataset_path.text() else 'Select the assessment dataset to evaluate compatibility.'}")
        except Exception as exc: QMessageBox.warning(self,"Reference registration failed",str(exc))

    def clear_reference(self):
        self.reference_asset=None; self.reference_format=""; self.reference_path.clear()
        self.reference_summary.setText("No reference selected; reference based checks will be limited.")

    def choose_model(self):
        selected,_=QFileDialog.getOpenFileName(self,"Select local model",str(self.config.project_root),"Models (*.pt *.pth *.torchscript *.onnx *.h5 *.keras);;All files (*)")
        if not selected:return
        path=Path(selected)
        try:
            identity=inspect_model(path)
            asset=self.services["asset_registry"].register(path,"model",hash_file=True)
            suffix=path.suffix.lower()
            capabilities=("B1 identity supported; B2–B4 can be attempted for a loadable TorchScript image-classification model. Other tasks or architectures may be limited." if suffix in {".pt",".pth",".torchscript"} else "B1 identity supported; behavior and white-box checks are limited for this format.")
            self.model_asset=asset; self.model_identity=identity; self.model_path.setText(str(path))
            self.model_summary.setText(f"Format: {identity.get('format',suffix.lstrip('.').upper())}\nSHA-256: {identity.get('sha256',asset.get('sha256','Unavailable'))}\n{capabilities}")
        except Exception as exc: QMessageBox.warning(self,"Model identity failed",f"Could not identify/register this model: {exc}")

    def collect_inputs(self, show_errors=False) -> bool:
        error=None
        if not self.name.text().strip(): error="Enter an assessment name."
        elif not self.analyst.text().strip(): error="Enter the analyst or operator."
        elif not self.dataset_path.text() or not self.dataset_manifest: error="Select and identify a dataset."
        elif not self.model_path.text() or not self.model_identity: error="Select and identify a model."
        elif self.compute_context is None: error="Select an available compute backend."
        if error and show_errors: QMessageBox.information(self,"Assessment details required",error)
        return error is None

    def validatePage(self):
        current=self.currentId()
        if current==0 and (not self.name.text().strip() or not self.analyst.text().strip()):
            QMessageBox.information(self,"Assessment details required","Assessment name and analyst/operator are required."); return False
        if current==1 and not self.dataset_manifest:
            QMessageBox.information(self,"Dataset required","Select and identify a dataset."); return False
        if current==3 and not self.model_identity:
            QMessageBox.information(self,"Model required","Select and identify a model."); return False
        if current==5 and self.compute_context is None:
            QMessageBox.information(self,"Compute unavailable","Choose a compute backend that is available on this system."); return False
        return super().validatePage()

    def refresh_review(self):
        planned=[]
        planned.append("A1 manifest identity (always recorded and rechecked against the reviewed digest)")
        if self.dataset_checks.isChecked():
            planned.extend(["A2 exact duplicates", "A3 near duplicates", "A7 metadata consistency", "A8 trigger-like dataset forensics"])
            if self.reference_path.text(): planned.append("A4 reference/OOD comparison")
            root=Path(self.dataset_path.text()) if self.dataset_path.text() else None
            candidate=root/"candidate" if root and (root/"candidate").is_dir() else root
            if root and ((root/"labels").is_dir() or (candidate and (candidate/"labels").is_dir())): planned.append("A5 label consistency")
            if root and (root/"contributor_manifest.csv").is_file(): planned.append("A6 contributor risk")
        else: planned.append("A2–A8 dataset checks disabled")
        model_suffix=Path(self.model_path.text()).suffix.lower() if self.model_path.text() else ""
        behavior_supported=model_suffix in {".pt",".pth",".torchscript"} and self.dataset_image_count>0
        if self.model_checks.isChecked():
            planned.append("B1 model identity")
            if behavior_supported:
                planned.extend(["B2 behavioral fingerprint (if local adapter loads)", "B3 model statistics (if model loads)", "B4 trigger search (if enabled and model loads)" if self.trigger_search.isChecked() else "B4 trigger search disabled"])
            else: planned.append("B2–B4 limited: selected model is not a supported TorchScript model or no readable images are present")
        else: planned.append("Model checks disabled")
        planned.append("C1 provenance unavailable: no actual inference records are supplied by this workflow")
        if self.reference_path.text() and self.shift_checks.isChecked(): planned.append("C2 distribution comparison against selected reference")
        else: planned.append("C2 distribution comparison not assessed: no reference selected or comparison disabled")
        planned.extend(["C3 findings aggregation", "C4 audit chain", "C5 assurance report"])
        dataset_path=self.dataset_path.text() or "Not selected"
        reference_path=self.reference_path.text() or "Not selected"
        model_path=self.model_path.text() or "Not selected"
        text=(f"Assessment: {self.name.text().strip() or '—'}\nDescription: {self.description.toPlainText().strip() or '—'}\nAnalyst: {self.analyst.text().strip() or '—'}\nMission/reference ID: {self.reference_id.text().strip() or '—'}\n\n"
              f"Dataset: {dataset_path}\nFormat: {self.dataset_format or '—'}\nFile count: {self.dataset_manifest.get('file_count','—') if self.dataset_manifest else '—'}\nDigest: {self.dataset_manifest.get('dataset_sha256','—') if self.dataset_manifest else '—'}\n\n"
              f"Reference: {reference_path}\nCompatibility: {self.reference_summary.text()}\n\nModel: {model_path}\nFormat: {self.model_identity.get('format','—') if self.model_identity else '—'}\nSHA-256: {self.model_identity.get('sha256','—') if self.model_identity else '—'}\n"
              f"\nCompute: {self.compute_context.device.upper()+' · '+self.compute_context.device_name if self.compute_context else 'Unavailable'}\nModel execution: selected local model may be loaded for B2–B4 when adapter, task, and image inputs are supported.\nAdvanced settings: {'custom' if self.advanced_toggle.isChecked() else 'defaults'}; max images {self.max_images.value() if self.advanced_toggle.isChecked() else 16}\n\nEngines/actions:\n- " + "\n- ".join(planned))
        self.review_text.setPlainText(text)

    def make_assessment(self) -> Assessment:
        ref={**self.reference_asset,"path":self.reference_asset["local_path"],"format":self.reference_format,"trusted_by_operator":True} if self.reference_asset else None
        model={**self.model_asset,"path":self.model_asset["local_path"],"format":self.model_identity.get("format"),"selection_sha256":self.model_identity.get("sha256")}
        dataset={**self.dataset_asset,"path":self.dataset_asset["local_path"],"format":self.dataset_format,"file_count":self.dataset_manifest["file_count"],"sha256":self.dataset_manifest["dataset_sha256"],"dataset_id":self.dataset_manifest["dataset_id"],"selection_sha256":self.dataset_manifest["dataset_sha256"]}
        return Assessment(name=self.name.text().strip(),description=self.description.toPlainText().strip(),analyst=self.analyst.text().strip(),reference_id=self.reference_id.text().strip() or None,dataset=dataset,reference_dataset=ref,model=model,
            configuration={"dataset_checks":self.dataset_checks.isChecked(),"model_checks":self.model_checks.isChecked(),"distribution_check":self.shift_checks.isChecked(),"trigger_search":self.trigger_search.isChecked(),"max_images":self.max_images.value() if self.advanced_toggle.isChecked() else 16,"advanced_settings":self.advanced_toggle.isChecked()},
            compute={"requested":self.compute_context.requested,"device":self.compute_context.device,"device_name":self.compute_context.device_name,"cuda_available":self.compute_context.cuda_available,"torch_version":self.compute_context.torch_version,"fallback_reason":self.compute_context.fallback_reason})

    def prefill_from_assessment(self, record: dict) -> None:
        """Re-stage persisted local inputs for a fresh, explicitly reviewed run."""
        self.name.setText(f"{record.get('name', 'Assessment')} · repeat")
        self.description.setPlainText(record.get("description", ""))
        self.analyst.setText(record.get("analyst", ""))
        self.reference_id.setText(record.get("reference_id") or "")
        dataset_path=Path(str(record.get("dataset", {}).get("path", "")))
        if dataset_path.is_dir():
            manifest=build_manifest(dataset_path); fmt,image_count=detect_dataset_format(dataset_path)
            self.dataset_asset=self.services["asset_registry"].register(dataset_path,"dataset",hash_file=False)
            self.dataset_manifest=manifest; self.dataset_format=fmt; self.dataset_image_count=image_count
            self.dataset_path.setText(str(dataset_path))
            self.dataset_summary.setText(f"Re-identified locally · {fmt}\nFiles: {manifest['file_count']} · Image files: {image_count}\nDataset SHA-256: {manifest['dataset_sha256']}")
        model_path=Path(str(record.get("model", {}).get("path", "")))
        if model_path.is_file():
            identity=inspect_model(model_path)
            self.model_asset=self.services["asset_registry"].register(model_path,"model",hash_file=True)
            self.model_identity=identity; self.model_path.setText(str(model_path))
            self.model_summary.setText(f"Re-identified locally · {identity.get('format',model_path.suffix)}\nSHA-256: {identity.get('sha256','Unavailable')}")
        reference=record.get("reference_dataset")
        reference_path=Path(str(reference.get("path", ""))) if isinstance(reference,dict) and reference.get("path") else None
        if reference_path and reference_path.is_dir():
            fmt,_=detect_dataset_format(reference_path)
            self.reference_asset=self.services["asset_registry"].register(reference_path,"dataset",hash_file=False)
            self.reference_format=fmt; self.reference_path.setText(str(reference_path))
            self.reference_summary.setText(f"Previously selected reference · re-registered locally · {fmt}\n{reference_compatibility(dataset_path,reference_path)}")
        configuration=record.get("configuration", {})
        self.dataset_checks.setChecked(bool(configuration.get("dataset_checks",True)))
        self.model_checks.setChecked(bool(configuration.get("model_checks",True)))
        self.shift_checks.setChecked(bool(configuration.get("distribution_check",True)))
        self.trigger_search.setChecked(bool(configuration.get("trigger_search",True)))
        self.max_images.setValue(max(1,min(512,int(configuration.get("max_images",16)))))
        self.advanced_toggle.setChecked(bool(configuration.get("advanced_settings",False)))
        requested=str(record.get("compute",{}).get("requested", "auto")).lower()
        self.compute_choice.setCurrentIndex({"auto":0,"cpu":1,"cuda":2}.get(requested,0))
        self.refresh_review()

    def open_result(self):
        if self.assessment and self.assessment.status in {"completed","completed_with_errors","COMPLETED","COMPLETED_WITH_WARNINGS","CANCELLED","FAILED"} and self.parent():
            callback=getattr(self.parent(),"open_assessment",None)
            if callback: callback(self.assessment)
