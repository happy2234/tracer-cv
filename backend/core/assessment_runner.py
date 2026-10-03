"""Offline orchestration of the supported TRACER-CV assessment engines."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from time import monotonic

from backend.core.assessment import Assessment, utc_now
from backend.core.local_config import LocalConfig
from backend.core.local_storage import ReportStore


def _images(root: Path, limit: int) -> list[Any]:
    try:
        import numpy as np
        from PIL import Image
    except ImportError:
        return []
    extensions={".jpg", ".jpeg", ".png", ".bmp", ".webp", ".tif", ".tiff"}
    paths=[p for p in sorted(root.rglob("*")) if p.is_file() and p.suffix.lower() in extensions][:limit]
    output=[]
    for path in paths:
        try:
            with Image.open(path) as image:
                output.append(np.asarray(image.convert("RGB").resize((32,32)),dtype=np.uint8))
        except (OSError, ValueError):
            continue
    return output


def _image_sources(root: Path, limit: int) -> list[tuple[bytes, Any]]:
    """Return exact local input bytes paired with the runner's decoded 32px RGB tensor."""
    try:
        import numpy as np
        from PIL import Image
    except ImportError:
        return []
    extensions={".jpg", ".jpeg", ".png", ".bmp", ".webp", ".tif", ".tiff"}
    paths=[p for p in sorted(root.rglob("*")) if p.is_file() and p.suffix.lower() in extensions][:limit]
    output=[]
    for path in paths:
        try:
            raw=path.read_bytes()
            with Image.open(path) as image:
                pixels=np.asarray(image.convert("RGB").resize((32,32)),dtype=np.uint8)
            output.append((raw,pixels))
        except (OSError, ValueError):
            continue
    return output


def _serialize(value: Any) -> Any:
    if value is None or isinstance(value,(str,int,float,bool)):
        return value
    if isinstance(value,dict):
        return {str(k):_serialize(v) for k,v in value.items()}
    if isinstance(value,(list,tuple)):
        return [_serialize(x) for x in value]
    if hasattr(value,"tolist"):
        try: return _serialize(value.tolist())
        except Exception: pass
    if hasattr(value,"item"):
        try: return _serialize(value.item())
        except Exception: pass
    if hasattr(value,"as_dict"):
        return _serialize(value.as_dict())
    if hasattr(value,"to_dict"):
        return _serialize(value.to_dict())
    if hasattr(value,"__dataclass_fields__"):
        from dataclasses import asdict
        return _serialize(asdict(value))
    if hasattr(value,"__dict__"):
        return _serialize(vars(value))
    return str(value)


def _save_json(store: ReportStore, base: str, name: str, data: Any) -> None:
    payload=json.dumps(_serialize(data),indent=2,sort_keys=True,ensure_ascii=False,default=str).encode("utf-8")
    store.save(f"{base}/{name}" if base else name,payload,overwrite=True)


def run_assessment(
    assessment: Assessment,
    *,
    config: LocalConfig,
    assessment_store: Any,
    on_event: Callable[[str,str,dict[str,Any] | None],None] | None = None,
    evidence_store: Any = None,
    execution_context: Any = None,
) -> Assessment:
    """Run real engines and persist each result as it completes.

    ``on_event`` receives only stage-start and stage-completion events. No
    estimated percentage or synthetic engine progress is emitted.
    """
    emit=on_event or (lambda _engine,_state,_result: None)
    base=f"assessments/{assessment.assessment_id}"
    reports=ReportStore(config.reports_dir)
    assessment.results_path=str((config.reports_dir/base).resolve())
    dataset_root=Path(assessment.dataset["path"]).resolve()
    reference=Path(assessment.reference_dataset["path"]).resolve() if assessment.reference_dataset else None
    model_path=Path(assessment.model["path"]).resolve()
    max_images=int(assessment.configuration.get("max_images",64))
    enabled=assessment.configuration
    assessment.status="running"; assessment.started_at=utc_now(); assessment.error=None
    if assessment_store: assessment_store.save(assessment.to_dict())
    outputs: dict[str,Any]={}
    event_history=[{"event_type":item.get("event_type","ASSESSMENT_EVENT"),"source_engine":"assessment","affected_asset":assessment.assessment_id,"status":"recorded","timestamp":item.get("timestamp",assessment.created_at)} for item in assessment.lifecycle_events]
    event_history.append({"event_type":"ASSESSMENT_STARTED","source_engine":"assessment","affected_asset":assessment.assessment_id,"status":"started","timestamp":assessment.started_at})
    def stage(name: str, operation: Callable[[],Any], *, enabled_stage: bool=True,
              dependency: dict[str, Any] | None = None) -> Any:
        if execution_context is not None and execution_context.cancellation_requested and not name.startswith(("C3", "C4", "C5")):
            result={"status":"cancelled","reason":"Assessment cancellation was requested before this engine started."}
            outputs[name]=result; assessment.engines[name]={"status":"cancelled","reason":result["reason"]}
            _save_json(reports,base,f"{name}.json",result)
            if assessment_store: assessment_store.save(assessment.to_dict())
            emit(name,"cancelled",result)
            return result
        dependency_status=dependency.get("status","completed") if dependency is not None else None
        if dependency is not None and dependency_status not in {"completed", "completed_with_warnings"}:
            result={"status":"unavailable","reason":f"Required dependency did not complete (status: {dependency_status})."}
            enabled_stage=False
        else:
            result=None
        if not enabled_stage:
            result=result or {"status":"not_assessed","reason":"Disabled in assessment configuration."}
            outputs[name]=result; assessment.engines[name]={"status":result["status"],"reason":result.get("reason")}
            _save_json(reports,base,f"{name}.json",result)
            if assessment_store: assessment_store.save(assessment.to_dict())
            event_history.append({"event_type":"ENGINE_UNAVAILABLE" if result["status"]=="unavailable" else "ENGINE_SKIPPED","source_engine":name,"affected_asset":assessment.assessment_id,"status":result["status"],"timestamp":utc_now()})
            emit(name,result["status"],result)
            return result
        started=utc_now(); timer=monotonic()
        assessment.engines[name]={"status":"running","started_at":started}
        if assessment_store: assessment_store.save(assessment.to_dict())
        affected=str(dataset_root) if name.startswith("A") else str(model_path) if name.startswith("B") else str(reference or candidate) if name.startswith("C2") else assessment.assessment_id
        event_history.append({"event_type":"ENGINE_STARTED","source_engine":name,"affected_asset":affected,"status":"started","timestamp":started})
        emit(name,"started",None)
        try:
            result=operation()
            if not isinstance(result,dict): result={"status":"completed","result":result}
        except Exception as exc:
            result={"status":"error","reason":f"{name} could not complete.",
                    "error":f"{type(exc).__name__}: {exc}","technical_error":repr(exc)}
        outputs[name]=_serialize(result)
        result_status=result.get("status","completed")
        if result_status in {"error", "failed"}:
            result.setdefault("reason",f"{name} reported an engine failure. See Technical Details for the recorded engine error.")
            outputs[name]=_serialize(result)
        ended=utc_now(); duration=monotonic()-timer
        result_digest=None
        if evidence_store is not None:
            try: result_digest=evidence_store.put_json(outputs[name])
            except Exception: result_digest=None
        engine_record={"status":result_status,"started_at":started,"completed_at":ended,
                       "duration_seconds":round(duration,3),"result_path":str((config.reports_dir/base/f"{name}.json").resolve()),
                       "warnings":result.get("warnings",[]),"errors":result.get("errors",[]),
                       "limitations":result.get("limitations",[]),"reason":result.get("reason") or result.get("error"),
                       "technical_error":result.get("technical_error")}
        if result_digest: engine_record["evidence"] = result_digest
        assessment.engines[name]=engine_record
        _save_json(reports,base,f"{name}.json",result)
        if assessment_store: assessment_store.save(assessment.to_dict())
        event_kind="ENGINE_FAILED" if result_status in {"error","failed"} else "ENGINE_UNAVAILABLE" if result_status=="unavailable" else "ENGINE_COMPLETED"
        event_history.append({"event_type":event_kind,"source_engine":name,"affected_asset":affected,"status":result_status,"timestamp":ended})
        emit(name,result_status,result)
        return result

    # A1-A8 dataset checks. Directory roles are discovered from local structure.
    candidate=dataset_root / "candidate" if (dataset_root/"candidate").is_dir() else dataset_root
    reference_dir=reference
    labels_dir=dataset_root/"labels" if (dataset_root/"labels").is_dir() else None
    if candidate!=dataset_root and labels_dir is None and (dataset_root/"candidate"/"labels").is_dir(): labels_dir=dataset_root/"candidate"/"labels"
    contributor=dataset_root/"contributor_manifest.csv"
    from backend.engines.dataset.manifest import build_manifest
    from backend.engines.dataset.duplicates import find_exact_duplicates
    from backend.engines.dataset.near_duplicates import find_near_duplicates
    from backend.engines.dataset.ood import assess_ood
    from backend.engines.dataset.label_consistency import assess_label_consistency
    from backend.engines.dataset.contributor_risk import assess_contributor_risk
    from backend.engines.dataset.metadata_consistency import assess_metadata_consistency
    from backend.engines.dataset.poison_trigger import analyze_poison_trigger

    a1=stage("A1_manifest",lambda:build_manifest(dataset_root))
    selected_dataset_digest=assessment.dataset.get("selection_sha256")
    assessed_dataset_digest=a1.get("dataset_sha256")
    dataset_identity_valid=not (selected_dataset_digest and assessed_dataset_digest and selected_dataset_digest!=assessed_dataset_digest)
    if not dataset_identity_valid:
        a1.update({"status":"error","reason":"Dataset contents changed after review. Re-select and review the new identity.","technical_error":"selected and assessed dataset digests differ"})
        outputs["A1_manifest"]=a1
        assessment.engines["A1_manifest"].update({"status":"error","reason":a1["reason"]})
        _save_json(reports,base,"A1_manifest.json",a1)
        event_history.append({"event_type":"ENGINE_FAILED","source_engine":"A1_manifest","affected_asset":str(dataset_root),"status":"error","timestamp":utc_now()})
        emit("A1_manifest","error",a1)
    if assessed_dataset_digest:
        assessment.dataset.update({"sha256":assessed_dataset_digest,"dataset_id":a1.get("dataset_id"),"file_count":a1.get("file_count")})
    a2=stage("A2_exact_duplicates",lambda:find_exact_duplicates(a1.get("files",[])),enabled_stage=enabled.get("dataset_checks",True) and dataset_identity_valid,dependency=a1)
    a3=stage("A3_near_duplicates",lambda:find_near_duplicates(candidate),enabled_stage=enabled.get("dataset_checks",True) and dataset_identity_valid,dependency=a1)
    a4=stage("A4_ood",lambda:assess_ood(reference_dir,candidate),enabled_stage=enabled.get("dataset_checks",True) and reference_dir is not None and dataset_identity_valid,dependency=a1)
    a5=stage("A5_label_consistency",lambda:assess_label_consistency(candidate,labels_dir),enabled_stage=enabled.get("dataset_checks",True) and labels_dir is not None and dataset_identity_valid,dependency=a1)
    a6=stage("A6_contributor_risk",lambda:assess_contributor_risk(contributor,dataset_root,a4,a5),enabled_stage=enabled.get("dataset_checks",True) and contributor.is_file() and dataset_identity_valid,dependency=a1)
    a7=stage("A7_metadata_consistency",lambda:assess_metadata_consistency(candidate),enabled_stage=enabled.get("dataset_checks",True) and dataset_identity_valid,dependency=a1)
    a8=stage("A8_poison_trigger_forensics",lambda:analyze_poison_trigger(candidate),enabled_stage=enabled.get("dataset_checks",True) and dataset_identity_valid,dependency=a1)
    dataset_result={"A1_manifest":a1,"A2_exact_duplicates":a2,"A3_near_duplicates":a3,"A4_ood":a4,"A5_label_consistency":a5,"A6_contributor_risk":a6,"A7_metadata_consistency":a7,"A8_poison_trigger_forensics":a8}
    _save_json(reports,base,"dataset_integrity.json",dataset_result)

    # B1 always hashes the chosen model; B2-B4 need a usable local TorchScript adapter.
    from backend.engines.model.identity import inspect_model
    b1=stage("B1_identity",lambda:inspect_model(model_path),enabled_stage=True)
    selected_model_digest=assessment.model.get("selection_sha256")
    assessed_model_digest=b1.get("sha256")
    model_identity_valid=not (selected_model_digest and assessed_model_digest and selected_model_digest!=assessed_model_digest)
    if not model_identity_valid:
        b1.update({"status":"error","reason":"Model contents changed after review. Re-select and review the new identity.","technical_error":"selected and assessed model digests differ"})
        outputs["B1_identity"]=b1
        assessment.engines["B1_identity"].update({"status":"error","reason":b1["reason"]})
        _save_json(reports,base,"B1_identity.json",b1)
        event_history.append({"event_type":"ENGINE_FAILED","source_engine":"B1_identity","affected_asset":str(model_path),"status":"error","timestamp":utc_now()})
        emit("B1_identity","error",b1)
    if assessed_model_digest: assessment.model["sha256"]=assessed_model_digest
    from backend.engines.model.behavioral_fingerprint import try_load_torchscript_adapter,compute_behavioral_fingerprint
    from backend.engines.model.model_statistics import load_torchscript_model,analyze_model
    from backend.engines.model.trigger_search import TorchClassificationAdapter,TriggerSearchConfig,search_triggers
    sample_images=_images(candidate,max_images)
    model_enabled=enabled.get("model_checks",True)
    torchscript=model_path.suffix.lower() in {".pt",".pth",".torchscript"}
    def b2_run():
        adapter=try_load_torchscript_adapter(str(model_path),output_type="logits",input_size=(32,32),mean=(0,0,0),std=(1,1,1),device=assessment.compute.get("device","cpu"))
        if adapter.get("status")!="loaded": return {"status":adapter.get("status","unavailable"),"reason":"Local TorchScript adapter could not load the selected model.","adapter":adapter}
        if not sample_images: return {"status":"unavailable","reason":"No readable images were found in the selected dataset."}
        return compute_behavioral_fingerprint(sample_images,adapter["adapter"],model_identity=b1,model_id=b1.get("model_id"))
    def b3_run():
        loaded=load_torchscript_model(model_path,trusted=True,device=assessment.compute.get("device","cpu"))
        return analyze_model(model=loaded,images=sample_images,model_id=b1.get("model_id"),access="white_box",probe_set_id=assessment.assessment_id)
    def b4_run():
        loaded=load_torchscript_model(model_path,trusted=True,device=assessment.compute.get("device","cpu"))
        adapter=TorchClassificationAdapter(loaded,device=assessment.compute.get("device","cpu"),output_type="logits",scale_inputs=True,mean=(0,0,0),std=(1,1,1))
        return search_triggers(sample_images,adapter,config=TriggerSearchConfig(max_images=max_images),model_id=b1.get("model_id"))
    b2=stage("B2_behavioral_fingerprint",b2_run,enabled_stage=model_enabled and model_identity_valid and torchscript and bool(sample_images),dependency=b1)
    b3=stage("B3_model_statistics",b3_run,enabled_stage=model_enabled and model_identity_valid and torchscript and bool(sample_images),dependency=b1)
    b4=stage("B4_trigger_search",b4_run,enabled_stage=model_enabled and model_identity_valid and torchscript and bool(sample_images) and enabled.get("trigger_search",True),dependency=b1)
    model_result={"B1_identity":b1,"B2_behavioral_fingerprint":b2,"B3_model_statistics":b3,"B4_trigger_search":b4}
    _save_json(reports,base,"model_assurance.json",model_result)

    from backend.engines.provenance.inference_provenance import create_inference_record,verify_chain
    provenance_inputs=_image_sources(candidate,max_images)
    def c1_run():
        if not torchscript or not provenance_inputs:
            return {"status":"unavailable","reason":"C1 requires readable local images and a supported TorchScript classification adapter."}
        model_id=b1.get("model_id") or b1.get("sha256")
        if not model_id:
            return {"status":"unavailable","reason":"B1 did not provide a model identity to bind to inference records."}
        loaded=try_load_torchscript_adapter(str(model_path),output_type="logits",input_size=(32,32),mean=(0,0,0),std=(1,1,1),device=assessment.compute.get("device","cpu"))
        if loaded.get("status")!="loaded":
            return {"status":"unavailable","reason":loaded.get("reason","Local inference adapter is unavailable."),"limitations":["No inference provenance record was created because the model could not be run safely by the supported adapter."]}
        adapter=loaded["adapter"]
        preprocess={"decoder":"Pillow RGB","decoded_resize":[32,32],"adapter":"TorchScriptClassificationAdapter","input_size":[32,32],"input_range":"uint8 0-255 scaled to 0-1","normalization_mean":[0,0,0],"normalization_std":[1,1,1],"output_type":"logits interpreted as probabilities by the existing adapter"}
        records=[]; previous="0"*64
        for sequence,(input_bytes,pixels) in enumerate(provenance_inputs,start=1):
            prediction=adapter.predict(pixels[None,...])
            output={"predicted_classes":prediction.predicted_classes.tolist(),
                    "probabilities":prediction.probabilities.tolist() if prediction.probabilities is not None else None,
                    "confidence":prediction.confidence.tolist() if prediction.confidence is not None else None,
                    "entropy":prediction.entropy.tolist() if prediction.entropy is not None else None,
                    "notes":prediction.notes}
            output_bytes=json.dumps(output,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")
            record=create_inference_record(sequence=sequence,input_bytes=input_bytes,model_id=str(model_id),preprocessing_config=preprocess,output_bytes=output_bytes,previous_record_hash=previous)
            records.append(record); previous=record.record_hash
        verification=verify_chain(records)
        return {"status":"completed" if verification.get("valid") else "error","model_id":str(model_id),"record_count":len(records),"records":[_serialize(item) for item in records],"verification":verification,"adapter_warnings":loaded.get("warnings",[]),"limitations":["Provenance binds the selected source image bytes and this local inference output; it does not establish that the model is safe or benign."]}
    c1=stage("C1_provenance",c1_run,enabled_stage=model_identity_valid,dependency=b1)
    from backend.engines.shift.distribution_shift import analyze_image_directories
    c2=stage("C2_distribution_shift",lambda:analyze_image_directories(reference_dir,candidate),enabled_stage=reference_dir is not None and enabled.get("distribution_check",True),dependency=a1)

    from backend.engines.risk.findings import findings_from_dataset,findings_from_model,findings_from_provenance,findings_from_shift
    def collect_findings():
        found=[]; errors=[]
        for maker,result,asset in ((findings_from_dataset,dataset_result,str(dataset_root)),(findings_from_model,model_result,str(model_path)),(findings_from_provenance,c1,str(dataset_root)),(findings_from_shift,c2,str(candidate))):
            try: found.extend(maker(result,affected_asset=asset))
            except Exception as exc: errors.append(f"{maker.__name__}: {type(exc).__name__}: {exc}")
        return {"status":"completed_with_errors" if errors else "completed","findings":[_serialize(x) for x in found],"errors":errors}
    finding_result=stage("C3_findings",collect_findings)
    findings=finding_result.get("findings",[])
    assessment.findings=findings
    for finding in findings:
        event_history.append({"event_type":"FINDING_CREATED","source_engine":"C3","affected_asset":finding.get("affected_asset",assessment.assessment_id),"status":finding.get("severity","recorded"),"timestamp":utc_now()})
    _save_json(reports,base,"findings.json",{"status":"completed","finding_count":len(findings),"findings":findings})

    from backend.engines.provenance.audit_trail import create_audit_entry,verify_audit_chain
    emit("C4_audit_trail","started",None)
    if execution_context is not None and execution_context.cancellation_requested:
        event_history.append({"event_type":"ASSESSMENT_CANCELLED","source_engine":"assessment","affected_asset":assessment.assessment_id,"status":"cancelled","timestamp":utc_now()})
    event_history.append({"event_type":"ENGINE_STARTED","source_engine":"C4","affected_asset":assessment.assessment_id,"status":"started","timestamp":utc_now()})
    events=[]; previous="0"*64
    for seq,event in enumerate(event_history,start=1):
        entry=create_audit_entry(sequence=seq,event_type=event["event_type"],source_engine=event["source_engine"],affected_asset=event["affected_asset"],payload={"assessment_id":assessment.assessment_id,"stage_status":event["status"]},previous_entry_hash=previous,timestamp=event["timestamp"])
        events.append(entry); previous=entry.entry_hash
    audit_valid=verify_audit_chain(events)
    audit_ok=audit_valid.get("valid",False) if isinstance(audit_valid,dict) else bool(audit_valid)
    audit={"status":"completed" if audit_ok else "error","valid":audit_ok,"reason":None if audit_ok else "C4 could not verify the generated audit chain.","entries":[_serialize(x) for x in events],"entry_count":len(events)}
    if evidence_store is not None:
        try: audit["evidence"] = evidence_store.put_json(audit)
        except Exception: pass
    outputs["audit_trail"]=audit; assessment.engines["C4_audit_trail"]={"status":audit["status"],"reason":audit.get("reason"),"result_path":str((config.reports_dir/base/"audit_chain.json").resolve())}
    _save_json(reports,base,"audit_chain.json",audit)
    emit("C4_audit_trail","completed",audit)

    from backend.engines.risk.assurance_report import build_assurance_report
    def make_report():
        return build_assurance_report(assessment_id=assessment.assessment_id,dataset=dataset_result,model=model_result,provenance=c1,shift=c2,findings=findings,audit=audit)
    report_result=stage("C5_assurance_report",make_report)
    report=report_result
    assessment.completed_at=utc_now()
    report_path=(config.reports_dir/base/"tracer_cv_assurance_report.json").resolve()
    assessment.report={"status":report_result.get("status","completed"),"path":str(report_path)}
    has_engine_errors=any(item.get("status") in {"error","completed_with_errors"} for item in assessment.engines.values() if isinstance(item,dict))
    assessment.status="completed_with_errors" if has_engine_errors else "completed"
    _save_json(reports,base,"tracer_cv_assurance_report.json",report)
    from backend.engines.risk.assurance_report import render_text_report
    try: text_report=render_text_report(report)
    except Exception as exc: text_report=f"TRACER-CV assessment report\nAssessment ID: {assessment.assessment_id}\nReport rendering failed: {type(exc).__name__}: {exc}\n"
    reports.save(f"{base}/tracer_cv_assurance_report.txt",text_report.encode("utf-8"),overwrite=True)
    outputs.update({"dataset_integrity":dataset_result,"model_assurance":model_result,"provenance":c1,"distribution_shift":c2,"findings":{"status":"completed","finding_count":len(findings),"findings":findings},"audit_chain":audit})
    assessment.completed_at=utc_now()
    if assessment_store: assessment_store.save(assessment.to_dict())
    _save_json(reports,base,"assessment.json",assessment.to_dict())
    _save_json(reports,"","active_assessment.json",{"assessment_id":assessment.assessment_id})
    return assessment
