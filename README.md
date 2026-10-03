# TRACER-CV

**Trust, Reliability & Assurance for Computer Vision**

## Problem Statement

PS-26228

TRACER-CV addresses the technical challenge of examining integrity and reliability evidence across computer-vision datasets, models, inference records, distribution comparisons, findings, audit events, and reports.

## Overview

TRACER-CV is an offline computer-vision assurance platform. It consumes local artifacts, runs configured local assessment methods, persists their evidence, and presents results for analyst review. It reports observations and limitations; it does not produce a blanket safe/unsafe verdict.

The architecture is adapter-based and model-agnostic at the method boundary. Demonstrated analysis depth depends on task, model format, adapter availability, and access level. Current demonstrated model scope is image classification. Dataset-level image integrity methods can also inspect supported local image collections independently of the model task.

## Core Capabilities

### Dataset Integrity — A1–A8

- **A1** Manifest and cryptographic identity / Merkle integrity
- **A2** Exact duplicate detection
- **A3** Appearance-based near-duplicate detection
- **A4** Reference distribution / OOD-style appearance analysis
- **A5** Label consistency checks
- **A6** Contributor/source pattern analysis
- **A7** Metadata/acquisition consistency
- **A8** Repeated localized trigger-like pattern forensics

### Model Integrity — B1–B4

- **B1** Model file identity without loading the model
- **B2** Deterministic behavioral fingerprint probes
- **B3** Accessible parameter and conditional activation statistics
- **B4** Configured trigger-like behavior search

### Provenance and Assurance — C1–C5

- **C1** Hash-bound inference provenance and optional Ed25519 signatures
- **C2** Reference/candidate distribution-shift analysis
- **C3** Structured findings and evidence
- **C4** Local hash-chained audit events
- **C5** Persisted JSON, text, and local PDF assurance reports

```text
Dataset ──→ A1–A8 ──┐
                    ├──→ C3 Findings ──→ C4 Audit ──→ C5 Report
Model ─────→ B1–B4 ─┤
Inference ─→ C1 ────┤
Distribution → C2 ──┘
```

## Supported Formats and Scope

### Datasets

- Generic local image directories are supported by image-level engines.
- Reference/candidate image collections support appearance/distribution comparison.
- YOLO-style label validation is partial.
- COCO-style annotation handling is limited and is not a complete ingestion adapter.
- Dataset ingestion does not imply complete object-detection model assurance. Segmentation assurance is outside the current implemented scope.

### Models

- PyTorch/TorchScript support is conditional on the selected adapter and access mode. TorchScript execution is not sandboxed and must be treated as trusted code.
- ONNX support is optional and conditional. The local CPU adapter targets single-input RGB image-classification graphs with a rank-four image tensor and rank-two output, embedded weights, and supported standard operators. It does not establish arbitrary ONNX task compatibility.
- B1 can hash model bytes without executing them. An extension-derived format label is only a hint.
- Black-box behavioral methods require a compatible callable inference adapter. B3 internal statistics are unavailable in black-box mode.
- ONNX B3 initializer summaries describe stored graph constants; trainability is not established and activation statistics are unavailable through the current adapter.

Optional ONNX dependency declarations are in [`requirements-onnx.txt`](requirements-onnx.txt). Provision matching packages from a locally approved wheelhouse before an offline deployment. The application never installs dependencies dynamically.

## Security and Assurance Model

SHA-256 identifies bytes relative to a known digest. A1 can organize file digests into a Merkle structure. C1 binds input, model, preprocessing, output, sequence, nonce, and predecessor metadata; Ed25519 signatures are optional and require trusted public-key handling. C4 provides local chained audit evidence. C3 findings retain source-engine evidence and limitations. Evidence and results use local persistence.

Cryptographic consistency does not by itself establish semantic correctness, trustworthiness, or absence of compromise. Local files remain subject to host access controls.

## Offline / Air-Gapped Operation

Core assessment and analyst workflows use local files and local computation. They do not require cloud services, external APIs, telemetry, online model downloads, or remote report services. Evidence, assessment records, and reports are local. The software does not test or prove physical network isolation; operating-system isolation remains an external deployment control.

## Coverage and Limitations

- Trigger-like evidence is not proof of a backdoor or poisoning.
- A negative configured trigger search does not prove absence of a backdoor.
- Distribution shift is not proof of manipulation, semantic error, or malicious intent.
- Contributor/source risk is heuristic and is not maliciousness probability.
- Metadata anomalies do not prove tampering.
- Behavioral and parameter differences can have legitimate causes.
- Model analysis depends on format, task, adapter, and access level.
- Absence of findings does not prove absence of attacks.
- Adaptive/semantic attacks, compromised runtime or hardware, malicious training infrastructure, key compromise, and attacks without observable evidence in supplied artifacts are outside or incompletely addressed by current methods.
- C2 shift magnitude is heuristic and **not probabilistically calibrated**. It is not an attack probability.

See [`docs/COVERAGE_AND_READINESS.md`](docs/COVERAGE_AND_READINESS.md) and [`docs/PS26228_TRACEABILITY.md`](docs/PS26228_TRACEABILITY.md) for capability coverage and detailed boundaries.

## Demonstration / Benchmark

`demos/benchmark/` generates deterministic local synthetic scenarios. Results are explicitly labeled **DEMONSTRATION DATA** and are not operational findings, benchmark accuracy estimates, or proof that an attack class is generally detected.

```bash
.venv/bin/python demos/benchmark/run_benchmark.py
```

## Project Structure

```text
backend/                 Assessment orchestration, engines, stores and registries
desktop/                 PySide6 application and analyst workspaces
configs/                 Local application configuration
demos/assets/            Existing local synthetic/demo assets
demos/benchmark/         Reproducible synthetic validation scenarios
datasets_store/          Local dataset storage
models_store/            Local model storage
evidence_store/          Local evidence and assessment registry
reports/                 Persisted assessments and report exports
tests/                   Offline unit and UI tests
docs/                    Architecture, coverage, deployment and threat-model docs
```

## Installation

Use the repository's existing Python virtual environment or provision dependencies from a local approved package source before disconnecting the host. The repository does not currently provide a complete pinned dependency lockfile. No package installation occurs when the application starts.

Optional ONNX inference requires the packages listed in `requirements-onnx.txt`; these are not required for the non-ONNX workflows.

## Running

From the repository root:

```bash
.venv/bin/python -m desktop.app
```

Run the existing synthetic full-assessment demonstration:

```bash
.venv/bin/python demos/create_demo_assets.py
.venv/bin/python demos/run_full_assurance_demo.py
```

The demo writes into repository-local demo/report locations; review current working-tree changes before preserving generated outputs.

## Testing

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m compileall -q backend desktop demos tests
git diff --check
```

The validated test result can change as tests evolve; consult the current project checkpoint rather than treating historical counts as guarantees.

## Reports

C5 is the authoritative persisted assurance report. Report Center presents its available summary, coverage, findings, evidence, and limitations. Local exports include JSON and text, with PDF generated using local Qt support. PDF export is a separate artifact and does not update assessment evidence or the C4 chain.

## License

Apache-2.0. See [`LICENSE`](LICENSE).

## Scope

TRACER-CV uses an adapter-based architecture that separates assurance methods from specific model implementations. Supported assurance depth depends on model format, task, and access level. Current demonstrated scope centers on image classification, dataset-level computer-vision integrity, selected model formats, and conditional black-box inference. COCO/YOLO ingestion does not constitute full detection-model assurance. Findings are evidence for review, not attribution or a universal security conclusion.
