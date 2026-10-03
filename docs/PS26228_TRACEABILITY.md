# PS-26228 Capability Traceability

This document maps PS-26228's technical scope to implemented TRACER-CV components. Status describes repository capability, not guaranteed detection effectiveness.

| Area | Components | Evidence | State / boundary |
|---|---|---|---|
| Dataset integrity | A1–A8 | Manifests, duplicate groups, appearance metrics, label/source/metadata observations, localized pattern candidates | Implemented with per-engine input and threshold limitations |
| Model identity | B1 | Streaming SHA-256 and format hint | Supported; hashes bytes without loading or validating model behavior |
| Model behavior | B2, B4 | Deterministic probe responses and configured localized perturbation observations | Conditional on a compatible callable image-classification adapter |
| Model statistics | B3 | Accessible tensor/structure and conditional activation summaries | White-box and representation dependent; ONNX only has a bounded initializer summary, with trainability and activations unavailable |
| ONNX | Adapter | Local CPU ONNX Runtime execution for a constrained image-classification interface | Conditional on local optional dependencies, embedded weights, compatible graph/input/operators; no arbitrary task support |
| Inference provenance | C1 | Hash-bound input/model/preprocessing/output records, optional Ed25519 signatures, chain/replay checks | Supported locally; signature trust depends on public-key custody; integrity failure does not establish attribution |
| Distribution shift | C2 | Reference/candidate appearance statistics, distances and image anomalies | Heuristic, not probabilistically calibrated; not evidence of malicious cause or semantic correctness |
| Findings | C3 | Persisted structured findings with evidence, confidence and limitations | Derived from completed engine evidence; absence does not establish absence of issues |
| Audit | C4 | Local chained audit events and persisted verification | Tamper-evident local record; no external trust anchor or attribution |
| Reports | C5 | Persisted JSON/text and local PDF presentation/export | Reports reflect persisted availability; export does not rerun engines |
| Analyst dispositions | C3/C4 workspace integration | Separate ACCEPT/REVIEW/QUARANTINE decision history with finding digest and C4 event | Local governance record; original C3 finding remains unchanged |
| Synthetic validation | `demos/benchmark/` | Fixed-seed locally generated dataset/model/provenance scenarios | Demonstration data only; no operational accuracy estimate |

## Explicit scope boundaries

The architecture separates assurance methods from model implementations through adapters. Demonstrated model scope is image classification; capability depth depends on model format, task and access. Generic image directories and reference/candidate image collections are supported. YOLO label checks and COCO input handling are partial and do not provide full object-detection model assurance. Segmentation assurance is unavailable.

Arbitrary novel or semantic backdoors, adaptive attacks outside configured probes, malicious training infrastructure, compromised host/runtime/kernel or hardware, cryptographic key compromise, and causes requiring external operational telemetry are not exhaustively assessed. No negative result proves absence of an attack. Appearance shift, metadata anomalies, contributor heuristics and trigger-like observations retain their source-engine limitations.

TRACER-CV is designed for local offline use, but does not prove physical network isolation. Successful self-tests mean only that the tested local functions operated as expected; they do not assess dataset/model safety.
