"""Run deterministic local demonstration scenarios; results are not findings."""
from __future__ import annotations

import hashlib
import json
import tempfile
import sys
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.core.provenance_demo import run_provenance_demonstration
from backend.engines.dataset.duplicates import find_exact_duplicates
from backend.engines.dataset.near_duplicates import find_near_duplicates
from backend.engines.dataset.metadata_consistency import assess_metadata_consistency
from backend.engines.dataset.poison_trigger import analyze_poison_trigger
from backend.engines.dataset.label_consistency import assess_label_consistency
from backend.engines.shift.distribution_shift import analyze_image_directories
from backend.engines.model.identity import inspect_model
from backend.engines.model.trigger_search import CallableClassificationAdapter, TriggerSearchConfig, search_triggers


def generate_scenarios(root: str | Path) -> list[dict]:
    root = Path(root); root.mkdir(parents=True, exist_ok=True)
    clean = root / "clean"; clean.mkdir(exist_ok=True)
    clean_reference = root / "clean_reference"; clean_reference.mkdir(exist_ok=True)
    rng = np.random.default_rng(26228)
    images=[]
    for index in range(6):
        array=np.zeros((48,48,3),dtype=np.uint8); array[:]=rng.integers(30,100,size=3,dtype=np.uint8)
        array[8+index:18+index, 8:38]=[180,180,180]
        path=clean/f"sample_{index}.png"; Image.fromarray(array).save(path); Image.fromarray(array).save(clean_reference/path.name); images.append(path)
    duplicates=[]
    for index in range(4):
        duplicate=clean/f"duplicate_{index}.png"; duplicate.write_bytes(images[0].read_bytes()); duplicates.append(duplicate)
    near=clean/"near.png"; arr=np.asarray(Image.open(images[1]).convert("RGB")).copy(); arr[0,0]=[255,0,0]; Image.fromarray(arr).save(near)
    labels=root/"labels"; labels.mkdir(exist_ok=True)
    (labels/f"{images[0].stem}.txt").write_text("0 0.5 0.5 0.5 0.5\n",encoding="utf-8")
    (labels/f"{duplicates[0].stem}.txt").write_text("1 0.5 0.5 0.5 0.5\n",encoding="utf-8")
    triggered=root/"triggered"; triggered.mkdir(exist_ok=True)
    for i,path in enumerate(images[:4]):
        arr=np.asarray(Image.open(path).convert("RGB")).copy()
        yy, xx=np.indices((16,16)); checker=((xx+yy)%2)*255
        arr[-16:,-16:]=np.repeat(checker[...,None],3,axis=2).astype(np.uint8)
        Image.fromarray(arr).save(triggered/f"trigger_{i}.png")
    metadata_dataset=root/"metadata_inconsistent"; metadata_dataset.mkdir(exist_ok=True)
    for index in range(21):
        source=images[index % len(images)]
        with Image.open(source) as image:
            if index == 0: image=image.resize((60,60))
            image.save(metadata_dataset/f"metadata_{index:02d}.png")
    files=[{"path":str(item),"sha256":hashlib.sha256(item.read_bytes()).hexdigest()} for item in [images[0],*duplicates]]
    duplicate_result=find_exact_duplicates(files)
    near_result=find_near_duplicates(clean,threshold=8)
    label_result=assess_label_consistency(clean,labels_dir=labels,num_classes=2,near_duplicate_threshold=8)
    metadata=assess_metadata_consistency(metadata_dataset)
    trigger=analyze_poison_trigger(triggered)
    shift=analyze_image_directories(clean_reference,triggered)
    model_a=root/"clean_model.weights"; model_b=root/"modified_model.weights"
    tensor=np.linspace(-1.0,1.0,128,dtype="<f4"); altered=tensor.copy(); altered[17]+=0.125
    model_a.write_bytes(tensor.tobytes()); model_b.write_bytes(altered.tobytes())
    identity_a=inspect_model(model_a); identity_b=inspect_model(model_b)
    def trigger_predict(batch):
        values=[]
        for image in batch:
            white=np.mean(np.asarray(image)[-8:,-8:]) > 245
            values.append([0.05, 0.95] if white else [0.95, 0.05])
        return np.asarray(values,dtype=np.float32)
    def clean_predict(batch):
        return np.tile(np.array([[0.95,0.05]],dtype=np.float32),(len(batch),1))
    benchmark_images=[np.asarray(Image.open(path).convert("RGB")) for path in images[:4]]
    trigger_config=TriggerSearchConfig(patch_sizes=(8,),grid_fractions=(0.8,1.0),patterns=("white",),min_samples=3,max_images=4)
    clean_model=search_triggers(benchmark_images,CallableClassificationAdapter(clean_predict,output_type="probabilities"),config=trigger_config)
    trigger_model=search_triggers([np.asarray(Image.open(path).convert("RGB")) for path in images[:4]],
        CallableClassificationAdapter(trigger_predict,output_type="probabilities"),
        config=trigger_config)
    provenance=run_provenance_demonstration()["cases"]
    rows=[
        ("DATA-CLEAN", "DATA", "A2 reports no byte-identical pair in the clean synthetic population", find_exact_duplicates([{"path":str(path.relative_to(clean_reference)),"sha256":hashlib.sha256(path.read_bytes()).hexdigest()} for path in sorted(clean_reference.iterdir())])["duplicate_group_count"]==0, {"image_count":len(images),"duplicate_group_count":0}),
        ("DATA-EXACT-DUPLICATE-FLOODING", "DATA", "Multiple exact copies form a digest-identical group", duplicate_result["duplicate_group_count"]>0 and duplicate_result["duplicate_file_count"]>=5, duplicate_result),
        ("DATA-NEAR-DUPLICATE", "DATA", "Appearance-based near-duplicate pair identified", near_result.get("near_duplicate_pair_count",0)>0, near_result),
        ("DATA-LABEL-CONFLICT", "DATA", "A5 reports near-duplicate images with conflicting supplied class labels", label_result.get("conflicting_pair_count",0)>0, label_result),
        ("DATA-OOD-INSERTION", "DATA", "C2 comparison report produced for changed reference/candidate populations", shift.get("status")=="completed", {"status":shift.get("status"),"shifted_features":shift.get("shifted_features"),"overall_shift":shift.get("overall_shift"),"limitations":shift.get("limitations")}),
        ("DATA-METADATA", "DATA", "A7 reports a rare-resolution acquisition observation in the synthetic 21-image population", metadata.get("status")=="completed" and any(item.get("code")=="rare_resolution" for item in metadata.get("image_findings",[]) if isinstance(item,dict)), {"status":metadata.get("status"),"image_count":metadata.get("image_count"),"image_findings":metadata.get("image_findings",[]),"limitations":metadata.get("limitations")}),
        ("DATA-REPEATED-PATTERN", "DATA", "A8 reports repeated-pattern evidence where threshold is met", bool(trigger.get("candidates") or trigger.get("findings")), trigger),
        ("MODEL-CLEAN", "MODEL", "No candidate response change under this configured synthetic B4 probe battery", clean_model.get("status")=="completed" and clean_model.get("candidate_trigger_count")==0, {"b1_model_id":identity_a.get("model_id"),"b4_result":clean_model,"limitations":"A negative configured search does not prove absence of a backdoor."}),
        ("MODEL-MODIFIED-WEIGHTS", "MODEL", "Changed synthetic tensor bytes produce a different B1 identity", identity_a.get("sha256")!=identity_b.get("sha256"), {"first_sha256":identity_a.get("sha256"),"second_sha256":identity_b.get("sha256"),"limitation":"B1 establishes byte identity only; these bytes are not loaded as an executable model."}),
        ("MODEL-TRIGGER-SENSITIVE-SYNTHETIC", "MODEL", "Configured B4 search reports candidate trigger-like behavior for a synthetic callable", trigger_model.get("candidate_trigger_count",0)>0, trigger_model),
    ]
    for case in provenance:
        rows.append((case["scenario_id"],"PROVENANCE",case["expected_behavior"],bool(case["detected"]),case["evidence"]))
    def normalize(value):
        if isinstance(value, dict): return {str(key): normalize(child) for key, child in value.items()}
        if isinstance(value, list): return [normalize(child) for child in value]
        if isinstance(value, tuple): return [normalize(child) for child in value]
        if isinstance(value, str): return value.replace(str(root), ".")
        return value
    limitations="Synthetic demonstration only; thresholds and supported adapters bound the observations. Results are not operational assessment findings or a detection-performance estimate."
    return [{"scenario_id":key,"category":category,"expected_behavior":expected,"observed_behavior":"Observed by local engine" if detected else "Not observed / scenario not established by this method","detected":bool(detected),"evidence":normalize(evidence),"limitations":limitations,"data_label":"DEMONSTRATION DATA"} for key,category,expected,detected,evidence in rows]


def run_benchmark(output: str | Path | None = None) -> dict:
    if output is None:
        with tempfile.TemporaryDirectory(prefix="tracer-benchmark-") as directory:
            scenarios=generate_scenarios(directory)
    else:
        scenarios=generate_scenarios(output)
    return {"label":"DEMONSTRATION DATA","seed":26228,"scenarios":scenarios}


def main(argv=None):
    import argparse
    parser=argparse.ArgumentParser(); parser.add_argument("--output",type=Path)
    args=parser.parse_args(argv)
    result=run_benchmark(args.output)
    rendered=json.dumps(result,indent=2,ensure_ascii=False,default=str)
    if args.output: (args.output/"benchmark_results.json").write_text(rendered,encoding="utf-8")
    print(rendered)


if __name__=="__main__": main()
