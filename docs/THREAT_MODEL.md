# TRACER-CV Threat Model

## Purpose and assumptions

TRACER-CV measures integrity and statistical evidence in a local analyst workstation workflow. The analyst, operating system, Python environment, installed dependencies, and trusted reference digests/keys are assumed uncompromised. Imported datasets, labels, manifests and model files are untrusted.

## Assets

- Training data, labels, contributor and acquisition metadata.
- Model files and expected model digests.
- Preprocessing configuration, inference inputs and inference outputs.
- C1 provenance records and optional signing/verification keys.
- C4 audit records, C3 evidence and C5 generated reports.
- Local demo assets and configuration.

## Threats in scope for evidence generation

Data poisoning, label manipulation, duplicate flooding, OOD insertion, trigger-like contamination, model substitution/modification, measured anomalous model behavior, inference output modification, recorded inference replay/sequence issues, provenance record tampering, distribution shift and audit-chain changes. Implemented coverage varies; see [COVERAGE.md](COVERAGE.md).

## Trust boundaries

1. **Analyst workstation:** trusted execution boundary; compromise can falsify UI and evidence.
2. **Imported dataset:** untrusted bytes and metadata. Current GUI demo flow does not provide a complete hardened arbitrary-directory ingestion pipeline.
3. **Imported model:** untrusted. B1 hashes without loading. TorchScript or other executable inference adapters must only be used on trusted models. Pickle-based checkpoints can execute code when deserialized and must not be loaded from untrusted sources.
4. **Assurance engines:** trusted only to the degree their code/runtime and configuration are trusted; methods have documented limits.
5. **Evidence store/reports:** local mutable files. C1/C4 detect tampering relative to a trusted expected chain; they do not stop an administrator from rewriting all local evidence and recomputing hashes.
6. **Generated report:** derived evidence; it does not independently validate the correctness of source inputs.

## Existing security properties

- No network service is started by `python -m desktop.app`.
- Demo workflow uses local assets and local result files.
- B1 hashes content without deserializing model files.
- C1/C4 use canonicalized hash-bound fields; optional Ed25519 uses `cryptography` when available.
- UI tamper demonstrations deep-copy loaded evidence and only alter the copy.
- GUI reads fixed report filenames and image preview is limited to image files under the repository root.

## Known gaps / safeguards required for deployment

- The desktop does not yet expose a complete validated import workflow, central resource limits, symlink policy, or universal archive validation.
- The API helper accepts a local path and resolves it but does not enforce configured-root containment; do not expose that API to untrusted callers.
- The desktop has no unified configurable CPU/CUDA selector or device fallback UI.
- Model execution paths require trusted model artifacts. Do not deserialize untrusted pickle-based checkpoints.
- Local evidence should be copied to protected/append-only storage if protection against a local privileged attacker is required. Protect signing keys outside the evidence directory.

## Out of scope

TRACER-CV does not protect a compromised workstation, detect all adaptive or semantic attacks, establish model safety from a digest, prove benign intent, provide a remote trusted timestamp, protect private keys, or guarantee that no finding means no attack.
