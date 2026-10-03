"""Product capability and limitation registry for TRACER-CV.

This registry describes implemented scope, not the state of an individual
assessment and not a security verdict.
"""
from __future__ import annotations

from typing import Any

STATES = {"SUPPORTED", "PARTIAL", "CONDITIONAL", "UNAVAILABLE", "NOT_APPLICABLE"}

_ENGINE_ROWS = [
    ("A1", "Manifest / Merkle Integrity", "Dataset Integrity", "SUPPORTED", "Hash dataset files and summarize identities with a Merkle root", "Image files and manifest metadata", "Files readable locally", False, True, "SHA-256 digests and manifest/Merkle evidence", "Hash identity does not establish content safety; a trusted expected digest is required for comparison."),
    ("A2", "Exact Duplicates", "Dataset Integrity", "SUPPORTED", "Identify byte-identical or digest-identical files", "Supported local image files", "Readable files", False, True, "Duplicate groups and digests", "Only exact identity is established; semantic equivalence is not."),
    ("A3", "Near Duplicates", "Dataset Integrity", "SUPPORTED", "Identify visually similar image pairs under configured comparisons", "Supported local images", "Readable image pixels", False, True, "Similarity/pair evidence", "Similarity is appearance-based and threshold-dependent."),
    ("A4", "OOD / Reference Distribution", "Dataset Integrity", "CONDITIONAL", "Compare appearance features to an available reference population", "Reference and candidate image collections", "Readable images and reference set", False, True, "Feature distance and candidate outlier evidence", "Distribution/appearance differences do not prove malicious manipulation or semantic OOD."),
    ("A5", "Label Consistency", "Dataset Integrity", "CONDITIONAL", "Check supplied labels/annotations for supported consistency conditions", "Image collections and supported label inputs, including limited YOLO label validation", "Images and labels", False, True, "Label consistency observations", "Input coverage and supported annotation conventions bound the result."),
    ("A6", "Contributor / Source Risk", "Dataset Integrity", "CONDITIONAL", "Assess contributor/source patterns in supplied metadata", "Images and contributor/source manifest", "Source metadata", False, True, "Contributor statistics and heuristic risk evidence", "Contributor/source risk is heuristic and does not establish malicious intent."),
    ("A7", "Metadata / Acquisition Consistency", "Dataset Integrity", "CONDITIONAL", "Identify metadata/acquisition inconsistencies in available fields", "Image metadata and acquisition information", "Metadata present in inputs", False, True, "Metadata mismatch observations", "Metadata anomalies do not prove manipulation."),
    ("A8", "Poison / Trigger-like Forensics", "Dataset Integrity", "CONDITIONAL", "Search for repeated localized image-pattern evidence", "Supported images; optional labels", "Readable image pixels", False, True, "Localized pattern candidates and supporting measurements", "Trigger-like evidence does not prove poisoning or a backdoor; thresholds and image scope are limited."),
    ("B1", "Model Identity", "Model Integrity", "SUPPORTED", "Stream and hash model bytes without loading the model", "A model file", "File access only; no model execution", False, True, "SHA-256 identity and format hints", "Format hints are not full validation; identity does not establish trustworthiness."),
    ("B2", "Behavioral Fingerprint", "Model Integrity", "CONDITIONAL", "Compare responses to deterministic input probes", "Supported callable image-classification adapter", "Callable inference; no generic checkpoint support", False, True, "Probe responses and behavioral distances", "Behavioral differences may have legitimate causes and do not establish maliciousness."),
    ("B3", "Parameter / Activation Statistics", "Model Integrity", "CONDITIONAL", "Measure accessible model parameters, structure and optional activations", "Supported PyTorch/TorchScript representations", "White-box model access; activation hooks depend on representation", True, False, "Parameter/module/activation summaries", "Parameter/activation deviations do not prove malicious modification; model execution is not sandboxed."),
    ("B4", "Trigger Search / Reconstruction", "Model Integrity", "CONDITIONAL", "Search configured localized perturbations for repeatable response changes", "Callable image-classification adapter and probe images", "Callable inference", False, True, "Candidate trigger-like behavior and perturbation evidence", "Trigger-like behavior does not confirm a backdoor; negative results do not prove absence."),
    ("C1", "Inference Provenance", "Provenance", "SUPPORTED", "Bind input/model/preprocessing/output digests in a local chain", "Inference metadata and digests", "Digest fields; optional Ed25519 key", False, True, "Hash-linked records and optional signatures", "Broken provenance does not identify an attacker or establish malicious intent; signatures depend on key custody."),
    ("C2", "Distribution Shift", "Provenance", "SUPPORTED", "Compare reference/candidate image feature distributions", "Reference and candidate image collections", "Readable images and reference set", False, True, "Statistical feature differences and image anomalies", "Distribution shift does not inherently indicate an attack or semantic error."),
    ("C3", "Findings & Evidence", "Provenance", "SUPPORTED", "Normalize persisted engine evidence into analyst findings", "Persisted A1–A8/B1–B4/C1–C2 results", "Existing persisted engine outputs", False, True, "Finding records with source references, evidence and limitations", "Findings inherit source-engine limitations; absence of findings does not prove absence of attacks."),
    ("C4", "Audit Trail", "Provenance", "SUPPORTED", "Create and verify a local tamper-evident audit chain", "Local audit event metadata", "Local storage; no external trust anchor", False, True, "Hash-linked audit records and verification observations", "Broken audit chain does not establish attacker identity or intent; local privileged users may alter files."),
    ("C5", "Assurance Report", "Provenance", "SUPPORTED", "Aggregate persisted assessment evidence into JSON/text/PDF report views", "Persisted assessment results and findings", "Local result access; PDF uses local Qt support", False, True, "Structured report and local PDF export", "Report faithfully summarizes available inputs; missing sections remain unavailable and do not imply a pass."),
]

_FORMAT_BY_ID = {
    "A1": "Local files of any format supported by the manifest file reader",
    "A2": "Supported local dataset files; exact digest comparison",
    "A3": "JPEG, PNG, BMP, TIFF and WebP image inputs",
    "A4": "JPEG, PNG, BMP, TIFF and WebP reference/candidate images",
    "A5": "Images plus supported labels/annotations (limited YOLO-style validation)",
    "A6": "Image manifest and contributor/source metadata",
    "A7": "Supported image files and available EXIF/acquisition metadata",
    "A8": "JPEG, PNG, BMP, TIFF and WebP image inputs; optional labels",
    "B1": "Arbitrary readable model file bytes; extension is only a format hint",
    "B2": "Selected TorchScript classification adapter or compatible callable interface",
    "B3": "Supported in-memory PyTorch module / trusted TorchScript path",
    "B4": "Compatible callable image-classification adapter",
    "C1": "Structured local provenance records; optional Ed25519 signatures",
    "C2": "JPEG, PNG, BMP, TIFF and WebP reference/candidate images",
    "C3": "Persisted structured A1–A8, B1–B4, C1 and C2 results",
    "C4": "Structured local audit events and hash-linked entries",
    "C5": "Persisted structured assessment data; local JSON, text and PDF outputs",
}
_DETERMINISTIC_BY_ID = {"B2": False, "B3": False, "C1": False, "C4": False}

CAPABILITIES: tuple[dict[str, Any], ...] = tuple(
    {"id": i, "name": name, "category": category, "status": status,
     "supported_task": task, "supported_data": data, "supported_formats": formats,
     "required_access": access, "white_box": white, "black_box": black,
     "deterministic": _DETERMINISTIC_BY_ID.get(i, True), "offline": True, "evidence_produced": evidence,
     "limitations": limitation, "method_identifier": "See engine result metadata"}
    for i, name, category, status, task, data, access, white, black, evidence, limitation in _ENGINE_ROWS
    for formats in [_FORMAT_BY_ID[i]]
)

MODEL_FORMATS = (
    {"format": "PyTorch model/checkpoint", "B1": "SUPPORTED", "B2": "CONDITIONAL", "B3": "CONDITIONAL", "B4": "CONDITIONAL", "reason": "B1 hashes without loading. General checkpoint execution is not established; pickle-based formats may execute code."},
    {"format": "TorchScript", "B1": "SUPPORTED", "B2": "CONDITIONAL", "B3": "CONDITIONAL", "B4": "CONDITIONAL", "reason": "Adapters exist for selected classification paths. B3 requires explicit trusted=True; loading/execution is not sandboxed."},
    {"format": "ONNX", "B1": "SUPPORTED", "B2": "UNAVAILABLE", "B3": "UNAVAILABLE", "B4": "UNAVAILABLE", "reason": "B1 can record an extension-based format hint; general ONNX inference is not established."},
    {"format": "Black-box / inference-only", "B1": "CONDITIONAL", "B2": "CONDITIONAL", "B3": "UNAVAILABLE", "B4": "CONDITIONAL", "reason": "B1 needs file access for hashing; B2/B4 need a compatible callable interface. Parameters and activations are unavailable."},
)

DATASET_FORMATS = (
    {"format": "Generic image directories", "status": "SUPPORTED", "scope": "Local image collections for image-level engines; labels/source data may be separate inputs."},
    {"format": "YOLO-style data", "status": "PARTIAL", "scope": "Some label validation is supported; this is not a complete dataset adapter or detection-model assurance."},
    {"format": "COCO-style data", "status": "PARTIAL", "scope": "Limited annotation/input handling only; no complete COCO adapter or full detection-model assurance."},
    {"format": "Reference/candidate image collections", "status": "SUPPORTED", "scope": "Used by reference-based appearance/distribution comparisons when both populations are available."},
    {"format": "Segmentation datasets/models", "status": "UNAVAILABLE", "scope": "Segmentation model assurance is outside the current implemented scope."},
)

ACCESS_MODES = (
    {"capability": "B1 Model Identity", "white_box": "Not required", "black_box": "Available with file access", "required_access": "Model bytes only; model is not loaded."},
    {"capability": "B2 Behavioral Fingerprint", "white_box": "Not required by probe interface", "black_box": "Conditional", "required_access": "Compatible callable inference adapter and image probes."},
    {"capability": "B3 Parameter statistics", "white_box": "Required", "black_box": "Unavailable", "required_access": "Accessible supported model representation."},
    {"capability": "B3 Activation statistics", "white_box": "Required", "black_box": "Unavailable", "required_access": "Forward execution and hook-compatible representation; may be unavailable for TorchScript."},
    {"capability": "B4 Trigger Search", "white_box": "Not required by probe interface", "black_box": "Conditional", "required_access": "Callable inference adapter and configured image probe battery."},
)

UNSUPPORTED_ATTACK_CLASSES = (
    "Arbitrary novel or semantic backdoors outside the configured trigger-search battery — not assessed exhaustively.",
    "Model supply-chain attacks that require external infrastructure or signing-key custody evidence — outside current artifact scope.",
    "Malicious training infrastructure, host/kernel compromise, and hardware-level attacks — not assessed.",
    "Adaptive adversarial behavior and input attacks outside configured deterministic probes — not established by current probe batteries.",
    "Cryptographic private-key compromise and trusted-anchor compromise — outside local artifact verification scope.",
    "Operational/classified telemetry-based attack analysis — unavailable in the offline public/synthetic-data scope.",
    "Attacks leaving no observable evidence in the supplied artifacts or configured tests — not assessable from absence of evidence.",
)

LIMITATIONS: dict[str, tuple[str, ...]] = {
    "A4": ("This is an appearance-space detector. It does not establish semantic OOD.",),
    "A6": ("Risk scores identify unusual contributor characteristics; they do not establish malicious intent.", "The current engine uses manifest metadata and class distributions rather than image-content embeddings.", "Source identity is assumed to be correctly represented in the manifest."),
    "A7": ("Metadata is trivially editable or strippable; consistent metadata does not establish authenticity.", "Missing EXIF is common and benign; it is reported as divergence, not tampering.", "Contributor divergence is a statistical heuristic; legitimate sensor or campaign differences can also be flagged.", "Small contributors below min_contributor_images are not profiled.", "Timestamp checks rely on camera clocks, which may be wrong or unset.", "Findings are evidence for analyst review and do not establish malicious intent, poisoning, or confirmed integrity violation."),
    "A8": ("Cannot distinguish a trigger from legitimate repeated visual structure (watermarks, logos, borders, timestamps, sensor artefacts, repeated textures); such content can produce the same evidence.", "Only compact, high-frequency localized patches are detected. Blended, low-contrast, very small, very large, semantic or frequency-domain triggers may be missed.", "Repeat matching uses a 64-bit hash at reduced resolution; it is not robust to large shifts, rotation, scaling, inverted polarity or heavy recompression.", "Images are converted to grayscale and resized to 128x128 before analysis; colour-only triggers and fine detail are not visible to this engine.", "Class association is statistical association only and does not establish a backdoor.", "Thresholds are heuristic defaults and have not been calibrated on real datasets; JPEG block artefacts may occasionally resemble patches."),
    "B1": ("Cryptographic identity establishes byte identity, not trustworthiness or safety.",),
    "B2": ("Behavioral fingerprinting is model- and dataset-dependent.", "A difference between fingerprints does not prove malicious modification.", "Similar fingerprints do not prove model integrity.", "Probe coverage is limited to the listed transformations.", "Classification-only in this version (no detection or segmentation).", "Black-box models may expose only predictions/confidence.", "Some adapters may not expose full probability distributions; probability-based statistics are then reported as unavailable.", "Floating-point and backend differences can affect exact reproducibility.", "Probe parameters influence the observed behavior.", "This does not reconstruct hidden triggers.", "This does not prove the absence of backdoors."),
    "B3": ("B3 reports measurable structural and numerical statistics only; it produces no maliciousness score, no probability of compromise and no safe/unsafe verdict.", "Unusual parameter or activation statistics do not prove malicious modification or a backdoor, and a statistical deviation does not prove tampering.", "The absence of deviations does not prove the absence of backdoors; the model is not thereby shown to be safe or clean.", "Activation statistics depend entirely on the supplied probe images and describe only those probes.", "Only aggregate summaries are kept; localized or low-magnitude changes that leave aggregates unchanged cannot be seen.", "B3 does not sandbox model execution: activation capture runs the supplied model's forward code in the caller's process. Analyze only models from trusted artifacts.", "B3 does not establish model identity or provenance (see B1); a caller-supplied model_id is recorded as given and not verified."),
    "B4": ("B4 trigger-like candidate evidence does not prove a backdoor.", "B4 identifies trigger-like behavioural changes for analyst review; it does not prove malicious modification.", "Prediction changes may result from ordinary model sensitivity, distribution shift, preprocessing effects, or meaningful image features.", "The search covers only the configured patch sizes, positions and patterns.", "Results depend on the supplied input images and model preprocessing.", "B4 currently targets image classification and does not assess detection or segmentation models.", "Black-box models can be assessed only through their prediction interface; parameter and activation evidence requires separate white-box engines.", "No candidate trigger-like behaviour under the configured search does not prove absence of a backdoor."),
    "C1": ("A broken provenance chain does not identify an attacker or establish malicious intent.",),
    "C2": ("Distribution shift does not prove malicious manipulation.", "Appearance features do not establish semantic correctness.", "A stable distribution does not prove absence of attacks.", "Thresholds are configurable heuristics and require validation against representative reference data.", "This MVP analyzes image populations rather than proving causal source of a detected shift."),
    "C3": ("Findings inherit the methods, thresholds, assumptions and limitations of their source engines.", "Finding confidence is method-specific and is not automatically a calibrated probability of attack.", "A finding summarizes recorded evidence; it does not independently establish malicious intent or attribution."),
    "C4": ("A broken audit chain does not establish attacker identity or intent; a valid chain is consistency under implemented rules only.",),
    "C5": ("TRACER-CV reports evidence observed by configured checks; it does not prove absence of every possible attack.", "Distribution shift can have benign operational causes and does not by itself establish malicious manipulation.", "Behavioral and trigger-like model findings are indicators for analyst review, not proof of a backdoor.", "Parameter and activation anomalies can arise from legitimate model differences.", "Appearance-based dataset checks do not establish semantic correctness for every image.", "White-box model methods depend on access to the model structure and supported execution format.", "Unsupported attack classes are outside the evidence presented by this assessment."),
    "GLOBAL": ("The application is designed for offline use but does not verify physical network isolation.", "Absence of findings is not evidence of absence; results are bounded by supplied artifacts, configurations, thresholds and supported adapters.", "TRACER-CV does not provide a blanket safe/unsafe verdict or malicious-intent attribution."),
}

def capability_by_id(capability_id: str) -> dict[str, Any] | None:
    return next((item for item in CAPABILITIES if item["id"] == capability_id), None)

__all__ = ["STATES", "CAPABILITIES", "MODEL_FORMATS", "DATASET_FORMATS", "ACCESS_MODES", "UNSUPPORTED_ATTACK_CLASSES", "LIMITATIONS", "capability_by_id"]
