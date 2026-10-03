# TRACER-CV Security Model

## Security objective

Provide offline local integrity-assurance workflows and tamper-evident evidence for analysts. TRACER-CV does not certify that a dataset or model is safe, does not sandbox arbitrary models, and does not protect a compromised workstation.

## Assets and trust boundaries

| Boundary | Trust stance | Required handling |
|---|---|---|
| Analyst workstation and OS | Trusted deployment boundary | Apply OS hardening, account controls, patch review and physical controls outside the application |
| Imported dataset/annotations/manifest | Untrusted input | Validate format, size, dimensions and paths; never execute embedded code |
| Imported model | Untrusted until explicitly approved | B1 hash-only by default; only run model adapters on trusted artifacts |
| Existing engine code and Python packages | Trusted after local review/provisioning | Pin/provision software locally; verify package origin and integrity outside runtime |
| Asset registry | Local metadata, may contain sensitive paths | Restrict directory permissions; do not put secrets in asset names/metadata |
| Evidence/report store | Locally mutable files | Verify content digests and C1/C4 chains; protect backups and exported chain heads |
| Optional signing keys | High-value secrets | Keep private key outside repository, report/evidence paths and general logs |

## Model loading and execution

- `backend/engines/model/identity.py` hashes bytes without model deserialization.
- TorchScript loading requires explicit `trusted=True` in B3; TorchScript execution is not sandboxed.
- Pickle-based formats such as `.pt`, `.pth`, `.ckpt`, `.pkl` or `.joblib` can execute code when deserialized. Do not load untrusted checkpoints.
- The new compute selector chooses device; it does not increase model trust. CUDA and CPU execute the same trusted local model code under different runtimes.
- Optional ONNX Runtime execution is conditional and limited to the local CPU image-classification adapter described in the coverage registry; it is not a general-purpose sandbox or universal graph/task loader.

## Path, file and archive handling

The local asset registry rejects a selected symlink and enforces a maximum size for single-file assets before optional streaming hash. It stores the resolved local path and never executes it. It does not yet recursively inventory/reject every symlink inside a selected dataset directory, perform universal archive validation, or enforce image pixel bounds through every engine path. Treat directory inputs and engine decoding paths as a remaining hardening area. Report writes reject traversal and symlink destinations and are atomic. Evidence objects are content-addressed and written locally.

## Evidence and audit integrity

SHA-256 demonstrates byte identity relative to an expected digest. It does not prove source authenticity or model safety. C1 hashes canonical record fields and supports optional Ed25519 verification; signature authenticity depends on trusted key custody. C4 detects changes to the recorded chain relative to an expected chain head. A privileged local attacker who can rewrite all files and trusted local state can recompute hashes. Store protected audit checkpoints/backups separately if this threat matters.

## Offline and network posture

Normal desktop/engine operation has no remote service requirement and no configured telemetry, cloud API, online auth, CDN, remote font, remote data/model download or network database. `--offline-check` statically scans backend, desktop and demo source for common network clients and makes no network probe. It cannot prove that operating-system networking is physically disabled. The optional FastAPI module must not be started in an air-gapped desktop deployment unless separately required and locally bound/controlled by policy.

## Compute behavior

`auto` probes local PyTorch CUDA availability with a tiny allocation and synchronization. If CUDA is absent or the probe fails, it selects CPU. Explicit `cuda` fails visibly when unavailable or unsuitable. This runtime probe does not guarantee that a later model workload cannot fail (for example, memory exhaustion); the current integration does not transparently retry every failed model engine on CPU. The demo runner defaults to CPU when launched directly; the desktop passes its resolved selection to supported B2/B3/B4 adapters.

## Logging and secrets

Logs are local, rotating and bounded. Do not log private keys, secrets, full image contents or unnecessary personal data. No secrets are required for standard offline use. Environment variables/configuration should contain only local path and runtime options, not credentials.

## Known residual risks

- Model execution can run arbitrary behavior available to the current Python process; no sandbox is included.
- Engine decoders, annotation parsers and image libraries process untrusted inputs; universal parser hardening and resource bounds are incomplete.
- Local evidence/report storage is not an append-only filesystem and is not encrypted by the application.
- The asset registry records a selected directory path without recursively hashing it; A1 remains the dataset manifest source of truth.
- The GUI can block during the synchronous demo pipeline; no bounded background job manager is included yet.
- Static offline scan has a finite pattern list and can miss dynamically constructed network use in later dependencies/code.

## Supported deployment target

The current deployment target for this foundation is **Linux x86_64**, using a locally provisioned Python 3.11+ environment, PySide6 and the project’s installed engine dependencies. Linux is the only target exercised in this workspace. Windows and macOS are not yet validated or claimed portable. CUDA additionally requires a compatible local NVIDIA driver, CUDA-enabled PyTorch build and GPU; CPU operation does not require CUDA.
