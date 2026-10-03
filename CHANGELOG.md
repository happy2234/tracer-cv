# TRACER-CV Changelog

## [Phase 18] — 2026-10-03

### UI/UX Improvements
- Redesigned QSS themes (light and dark) with professional color system: primary action blue, semantic status cards, step cards, scope panel, accent buttons, improved scrollbars, splitters, tab widgets, group boxes
- Added `QPushButton#primary`, `QPushButton#danger`, `QPushButton#success` named styles
- Added `QFrame#statusCard` with semantic tone variants (verified/review/critical/info/unavailable) for dashboard status cards
- Added `QFrame#stepCard` with active/done/pending states for guided assessment
- Added `QFrame#scopePanel` for assurance scope panels
- Improved sidebar navigation grouping: OVERVIEW · ASSURANCE · INVESTIGATION · REPORTING · SYSTEM
- Sidebar width reduced to 230px; group header labels added
- `AnalystTable` improvements: word wrap enabled, 40px default row height, interactive column resize, 280px column cap, severity badge rendering
- Added `StatusCard` widget with semantic left-border color for dashboard cards
- `SectionCard` and `MetricCard` improved with minimum width constraints

### Guided Assessment Wizard
- Added 9-step guided assessment wizard (`desktop/pages/guided_assessment.py`)
- Steps: Select Dataset → Select Model → Configure → Run Assessment → Review Findings → Review Evidence → Verify Provenance → Review Audit → Generate Report
- Visual step indicator (pending/active/done states using `QFrame#stepCard`)
- Emits `navigate_to(str)` signal for page routing to existing workspaces
- Delegates execution to existing `AssessmentManager` — no engine logic duplicated
- All file path inputs validate locally; no network access

### PDF Reporting
- Redesigned `desktop/reporting/report_pdf.py` with professional cover page
- Cover page clearly distinguishes **Assessment Date** from **PDF Export Date**
- Assessment capability scope table (A1–A8, B1–B4, C1–C5 with status) on first content page
- Severity-colored finding blocks (CRITICAL/HIGH/MEDIUM/LOW left borders)
- Calibration disclaimer callout in Distribution Shift section
- Improved CSS: 9.5pt body, 28pt cover title, 13pt section headers, 9pt muted text
- Added `write_section_pdf()` shared function for workspace-specific PDF exports
- Updated `desktop/reporting/__init__.py` to export both functions
- Added PDF export buttons to:
  - Dataset Integrity workspace (`Export Dataset PDF`)
  - Findings workspace (`Export Findings PDF`)
  - Audit Trail workspace (`Export Audit Trail PDF`)
  - Report Center (`Export Full Report PDF` — primary styled)
- Report Center's main export button styled with `#primary` for visibility
- All exports: read-only, never rerun engines, never modify assessment state

### ONNX Validation
- Added `tests/test_onnx_real_inference.py` with 14 tests validating real `.onnx` file inference
- Validated: B1 identity, adapter loading, real ORT inference, batch size preservation, determinism, finite outputs, dtype rejection, B2 behavioral fingerprint, different-model identity
- Tested against: onnx==1.23.1, onnxruntime==1.30.0
- No downloads; all models built synthetically in memory

### Dependency Reproducibility
- Added `requirements.txt` with pinned core dependencies for offline wheelhouse provisioning
- Updated `requirements-onnx.txt` with tested version annotations (onnx==1.23.1, onnxruntime==1.30.0)

### Test Quality
- Fixed `PytestReturnNotNoneWarning` in `test_inference_provenance.py` (4 functions)
- Fixed `PytestReturnNotNoneWarning` in `test_assurance_report.py` (1 function)
- Fixed `PytestReturnNotNoneWarning` in `test_audit_trail.py` (1 function)
- Added `tests/test_pdf_generation.py`: 24 tests (full PDF, section PDF, mutation safety, engine isolation, stability, path creation)
- Added `tests/test_ui_layout.py`: 27 tests (sidebar keys, table properties, badge tones, cards, dialogs, wizard, chart)
- Added `tests/test_onnx_real_inference.py`: 14 tests (real ONNX file loading and inference)

### Architecture Preservation
- A1–A8 dataset integrity engines: **unchanged**
- B1–B4 model integrity engines: **unchanged**
- C1–C5 assurance engines: **unchanged**
- Assessment runner (`assessment_runner.py`): **unchanged**
- Audit trail schema: **unchanged**
- Finding schema: **unchanged**
- DispositionManager: **unchanged**
- Persisted assessment format: **unchanged**

---

## [Phase 17] — 2026-10-03

### Added
- Optional local ONNX Runtime image-classification adapter (B2/B4 conditional path)
- Deterministic synthetic C1 signed-provenance demonstration (7 scenarios: VALID-SIGNED, INVALID-SIGNATURE, OUTPUT-TAMPERING, INPUT-SUBSTITUTION, MODEL-SUBSTITUTION, PREVIOUS-HASH-TAMPERING, REPLAY)
- Persistent analyst dispositions (ACCEPT/REVIEW/QUARANTINE) with C4 audit chain binding
- Deterministic synthetic benchmark: 17 scenarios across DATA/MODEL/PROVENANCE categories, seed 26228
- PS-26228 compliance hardening: public documentation uses only TRACER-CV / PS-26228
- Apache-2.0 license

---

## [Phase 16] — 2026-10-03

### Added
- Machine-readable capability/limitation registry (A1–A8, B1–B4, C1–C5) in `backend/core/capabilities.py`
- Dataset format, model format, and access mode matrices
- Self-test with isolated synthetic checks (runtime, storage, SHA-256, Ed25519, Merkle, provenance, audit, report, Qt workspace construction)
- Deployment readiness assessment
- Coverage & Limitations workspace
- Self-Test & Readiness workspace

---

## [Phases 1–15] — 2026-09-29 to 2026-10-02

### Assessment engines
- A1: Manifest / Merkle integrity
- A2: Exact duplicate detection
- A3: Near-duplicate detection (dHash)
- A4: OOD / reference distribution analysis
- A5: Label consistency (YOLO partial)
- A6: Contributor / source risk (heuristic)
- A7: Metadata / acquisition consistency
- A8: Poison / trigger-like forensics
- B1: Model identity (SHA-256, format hints)
- B2: Behavioral fingerprint (deterministic probes)
- B3: Parameter / activation statistics
- B4: Trigger search / reconstruction
- C1: Inference provenance (Ed25519 optional)
- C2: Distribution shift analysis
- C3: Structured findings and evidence
- C4: Local tamper-evident audit chain
- C5: Assurance report (JSON / text / PDF)

### Desktop workspaces
- Dashboard / Mission Control, Assessments, Assets, Dataset Integrity, Model Integrity, Inference Provenance, Distribution Shift, Findings & Evidence, Evidence Explorer, Audit Trail, Assurance Report / Report Center, Settings / Security Center, Coverage & Limitations, Self-Test & Readiness, Provenance Demonstration

### Security
- Offline-only: no cloud APIs, telemetry, external services
- SHA-256 content addressing for all evidence
- Ed25519 optional inference provenance signatures
- Local tamper-evident C4 audit chain
- Path traversal prevention in all storage operations
- TorchScript loading requires explicit `trusted=True`
- ONNX adapter rejects external tensor data and custom operators

---

## Known Limitations

- ONNX support is conditional on local optional packages (see `requirements-onnx.txt`)
- Distribution shift magnitude is heuristic and **not probabilistically calibrated**; it must not be interpreted as an attack probability
- Trigger-like evidence does not prove poisoning or a backdoor; negative search does not prove absence
- Contributor risk is heuristic; not maliciousness probability
- Segmentation model assurance is not implemented
- COCO/YOLO ingestion is partial
- Absence of findings does not prove absence of attacks
- Behavioral/parameter differences may have legitimate causes
- Attribution of tampering to a specific actor is not established by this tool
