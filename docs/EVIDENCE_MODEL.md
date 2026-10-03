# TRACER-CV Target Evidence Model

Evidence is the factual substrate of an assessment: engine measurements, input identities, verification outcomes and source artifacts. The target model adds traceability around the existing engine payloads; it does not reinterpret a measurement as a stronger claim or alter a detection algorithm.

## Evidence principles

- **Source-bound:** identify the producing engine/module, version, method, job and input asset digests.
- **Immutable:** preserve the exact original result. A normalized display projection is additional and versioned, never a replacement.
- **Digest-verifiable:** use SHA-256 for byte identity, and canonical JSON for structured evidence digests where deterministic serialization is defined.
- **Linked:** connect evidence to assessments, execution jobs, assets and findings through stable IDs.
- **Honest about gaps:** represent absent output as `not_assessed`, `unavailable`, `error`, or `partial`; never synthesize a value.
- **Local:** store evidence and artifacts on local configured storage. No evidence upload, telemetry, remote API, cloud bucket or network timestamp service.

## Target evidence record

The canonical shape corresponds to `Evidence` in [DATA_MODEL.md](DATA_MODEL.md):

```json
{
  "evidence_id": "local-random-id",
  "assessment_id": "assessment-id",
  "execution_job_id": "job-id",
  "source_engine": "A2",
  "engine_version": "engine-version-or-unknown",
  "evidence_type": "duplicate_group",
  "observed_at": "UTC ISO-8601 timestamp",
  "asset_ids": ["asset-id"],
  "payload_digest": "sha256-hex",
  "digest_algorithm": "SHA-256",
  "serialization": "canonical-json",
  "artifact_uri": "evidence/sha256/<digest>.json",
  "size_bytes": 0,
  "method": "engine-reported method",
  "limitations": [],
  "parent_evidence_ids": [],
  "sensitivity": "internal",
  "schema_version": 1
}
```

Example values above are schema examples, not TRACER-CV results.

## Evidence classes

| Evidence class | Current source | Examples to preserve | Notes |
|---|---|---|---|
| Asset identity | A1/B1 | File paths/relative names, sizes, SHA-256, Merkle root, format observation | B1 format detection may be heuristic; hash proves byte identity only |
| Dataset finding evidence | A2-A8 | Duplicate groups/pairs, OOD scores, label conflicts, contributor profiles, metadata observations, trigger-like candidates | Preserve thresholds, skipped/error files and engine limitations with outputs |
| Model assurance evidence | B2-B4 | Probe outputs/statistics, parameter/module counts, activation summaries, trigger candidates | Preserve access mode and explicit load/adapter errors; do not imply unsupported metrics |
| Provenance record | C1 | Input/model/preprocessing/output digests, sequence, nonce, timestamp, previous/current record hash, signature state | Signature authenticity depends on trust in the verification key |
| Shift evidence | C2 | Reference/candidate counts and summaries, feature distances, thresholds, anomalies, findings | Outlier feature values in current result may be z-scores rather than raw measurements; label units explicitly |
| Finding evidence | C3 | Evidence entries linked to source result and affected asset | Confidence is not calibrated probability unless separately validated |
| Audit evidence | C4 | Event ID, sequence, timestamp, source, target, payload digest, previous hash, event hash and verifier output | Local chain is tamper-evident relative to a retained expected head, not inherently immutable |
| Report evidence | C5 | Coverage, summary, finding references, limitations, digests, report version | A report is a derived snapshot, not a new primary observation |
| Analyst evidence | Target decision | Reviewer, action, rationale, time, cited finding/evidence, supersedes link | Human disposition is separate from engine evidence |

## Linking and evidence packages

An evidence package for an assessment should contain:

1. Assessment manifest: assessment ID, scope, asset digests, requested engine set, configuration digest and per-engine status.
2. One immutable source payload per completed job, plus normalized evidence-index rows and the source serializer/schema version.
3. Findings that reference evidence IDs and affected asset IDs; no copied prose should lose the source link.
4. C1/C4 record chains and verification results, including signature checked/not checked distinction.
5. Analyst decisions and corresponding C4 events, stored separately from engine findings.
6. C5 report snapshot with a manifest of included record IDs/digests and coverage/limitations.

Missing engine outputs should have a small status/error evidence record when possible, not an invented successful result. Failed jobs may still have useful partial evidence.

## Digest and serialization rules

- Raw asset bytes: streaming SHA-256; do not load a whole large file into memory solely to hash it.
- Structured records: deterministic canonical JSON (`sort_keys`, compact separators, UTF-8) before digesting. Keep canonicalization/version metadata because serialization is part of the digest contract.
- Existing C1/C4 hash algorithms and field sets remain authoritative. New wrappers must not silently alter their canonical payloads.
- A digest detects a change only relative to a trusted expected digest. A digest does not establish origin, safety or semantic correctness.
- Optional Ed25519 signatures authenticate only when the verification key’s trust and custody are established. Never put private signing keys into report/evidence storage.
- Store evidence content by digest under a local content-addressed path. Verify digest on read/export and refuse silent replacement when an object with the same digest path differs.

## Lifecycle and retention

```text
captured → schema-checked → hashed → persisted → referenced → verified/exported
                                       ↘ quarantined/error
```

Engine evidence is append-only at the logical level. Corrected/re-run evidence gets a new job/evidence ID and links to the prior assessment where useful. Retention/deletion is an explicit policy action recorded in audit evidence; storage garbage collection must not remove artifacts still referenced by a report or active assessment.

## Privacy and security handling

Evidence can include paths, contributor identifiers, image previews, metadata and model details. Store only fields needed for analysis, redact secrets and irrelevant personal data at ingestion, enforce local file permissions, avoid sensitive values in logs, and provide a controlled export preview. Images and models remain untrusted inputs. Previewing should use bounded image decoding; executing a model must require a trusted-execution decision. Evidence remains offline and local by default.

## Current repository correspondence

Current evidence is mostly JSON in `reports/engine_results/`, `reports/evidence/`, and the C5 report files. C1, C3 and C4 full-demo persistence currently serializes records into JSON-native dictionaries. These files are fixed-path demo artifacts and are not yet managed by the proposed typed immutable evidence store or database lifecycle. The target structure above is an additive design direction.
