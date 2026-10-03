# Coverage, limitations, and local readiness

TRACER-CV is an offline, local evidence-generation and analyst-review tool. Capability states describe implemented product scope, not the result or success of any one assessment. Readiness describes local functions exercised by the self-test; it is not a security verdict for an assessed model or dataset.

## Supported and conditional scope

The desktop Coverage & Limitations page is backed by `backend/core/capabilities.py`. It documents A1–A8 dataset checks, B1–B4 model checks, C1–C5 provenance/assurance functions, and product-level capabilities. Conditional support depends on actual local inputs, adapters, model access, configuration, and engine result status. B1 extension recognition is not format validation. Optional ONNX inference is limited to local CPU image-classification graphs meeting the adapter's fixed input/output, embedded-weight, and operator constraints; it is not general ONNX task support.

Generic image collections and reference/candidate image populations are supported within the engines' documented scope. COCO/YOLO support is partial input/label handling and does not mean full object-detection model assurance. Segmentation assurance is not implemented. Model behavior checks focus on supported image-classification paths.

## Limitations

Distribution and appearance differences do not prove malicious manipulation or semantic error. Contributor/source risk is heuristic. Metadata irregularities do not prove tampering. Trigger-like image/model evidence does not prove poisoning or a backdoor; a negative configured search does not prove absence. Parameter or behavioral differences have legitimate possible causes. Provenance/audit chain inconsistencies do not establish attribution or intent. Hashes establish identity relative to bytes/anchors, not safety. Findings inherit source-engine limits, and absence of findings is not evidence of absence.

Arbitrary semantic/adaptive backdoors, training infrastructure, host/kernel and hardware attacks, key compromise, and attacks without observable evidence in supplied artifacts are not exhaustively assessed. Operational/classified telemetry is outside scope. Local files remain mutable to a sufficiently privileged host user; the application does not provide a remote trust anchor or verify physical network isolation.

## Model loading

B1 hashes files without loading them. Selected TorchScript adapters exist, but TorchScript execution is not sandboxed; the B3 loader requires explicit `trusted=True`. Pickle-based checkpoint formats must not be loaded from untrusted sources. The ONNX adapter does not execute embedded Python or register custom operators, rejects external weight data, and requests ONNX Runtime's local CPU provider; ONNX Runtime native graph execution is not a general-purpose sandbox. The self-test checks the documented source-level loading gate and does not load any model.

## C2 calibration

C2's overall shift magnitude and threshold classification are heuristic and **not probabilistically calibrated**. The value is a measured distribution-deviation metric under the persisted method/configuration, not a probability of attack or maliciousness. The product currently has no validated calibration population or calibration curve.

## Analyst dispositions and synthetic validation

ACCEPT, REVIEW, and QUARANTINE decisions are stored separately from C3 findings and linked to a local C4 audit-chain event. This local chain is tamper-evident under its verifier, not an external trust anchor. `demos/benchmark/` and the C1 provenance demonstration contain synthetic validation inputs/results only; they are not operational assessment findings or measured general detection performance.

See [PS-26228 traceability](PS26228_TRACEABILITY.md) for the current capability map and boundaries.

## Self-test interpretation

Self-test uses small synthetic records, ephemeral cryptographic keys, and temporary files. It does not run A1–A8/B1–B4/C1–C4 on real assessment assets, inspect assessment evidence, load models, or probe network connectivity. `READY` means required local TRACER-CV functions exercised by the self-test passed. It does not mean that an assessed asset is safe, that every optional capability is available, or that the host is physically disconnected from a network.

TRACER-CV is designed for offline operation with local storage and public/synthetic inputs. Host network isolation remains an external deployment control.
