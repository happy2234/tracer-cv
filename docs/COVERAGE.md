# TRACER-CV Coverage and Limits

Coverage describes implemented methods in this repository. It is not a guarantee that an attack will be detected. “Evidence” means the corresponding engine result fields, not a ground-truth label.

| Attack / risk class | Status | Detection method | Evidence | Assumptions | Limitations |
|---|---|---|---|---|---|
| Exact duplication | Implemented | A2 content hash grouping | Duplicate groups and hashes | Files are readable | Legitimate repeats occur |
| Near-duplicate flooding | Implemented | A3 similarity comparison | Candidate pairs/groups | Similarity representation is useful | Transformations may evade matching; thresholds are method-configured |
| OOD insertion | Implemented | A4 reference comparison | OOD scores/findings | Representative reference data | Reference bias and domain differences affect results |
| Label inconsistency | Implemented | A5 label consistency rules | Conflicts/findings | Labels can be parsed in supported input shape | Not a semantic ground-truth oracle |
| Contributor/source anomalies | Implemented | A6 contributor/source features | Contributor findings | Manifest fields are trustworthy enough to compare | Self-reported metadata may be false |
| Metadata/acquisition anomalies | Implemented | A7 metadata checks | Metadata findings | Relevant metadata exists | Missing or rewritten metadata limits evidence |
| Trigger-like/poison evidence | Implemented | A8 forensic pattern checks | Candidate regions/scores | Configured method fits observed pattern | A candidate does not prove a model backdoor or malicious intent |
| Model substitution via digest mismatch | Partial | B1 SHA-256 compared to supplied expected digest | Expected/observed digest and match | Expected digest is trusted | Hash equality establishes byte identity, not safety |
| Behavioral anomalies | Implemented where adapter works | B2 clean/probe response and distribution statistics | Confidence, entropy, histogram, deviations | Compatible inference adapter/model | Demo paths can error; not all model formats load |
| Parameter/activation anomalies | Partial | B3 parameter/module stats and supported activation hooks | Counts/statistics or explicit error | Adapter exposes model internals | Activation hooks unavailable for some formats |
| Trigger-search evidence | Implemented where adapter works | B4 configured patch/position/class search | Candidate count, patch/probe outcomes | Compatible, trusted model execution | Zero candidates do not prove absence; no thresholds are weakened |
| Inference record tampering | Implemented | C1 canonical record hash verification | Expected and actual hash | Record supplied in supported schema | No remote trust anchor by default |
| Inference replay/sequence issues | Implemented for recorded chain | C1 sequence, nonce and previous-hash checks | Chain findings | Complete ordered records supplied | Replay outside recorded state cannot be detected |
| Distribution shift | Implemented | C2 feature distances and reference-relative z-scores | Overall shift, feature distances, anomalies | Reference population is appropriate | Shift does not establish malicious manipulation |
| Audit-chain tampering | Implemented | C4 sequence/event/hash-chain verification | Chain validity and findings | Expected head/records protected | A rewritten entire local chain can be recomputed |
| Adaptive semantic poisoning | Unsupported / not proven | None comprehensive | None | — | No absence-of-attack guarantee |
| Arbitrary malicious model code | Unsupported | B1 hashes without loading; trusted adapters may execute code | Hash/adapter error | Model execution is trusted | No general static safety scanner |
| Compromised keys, host, dependencies or expected digests | Unsupported | Outside engine boundary | None | Workstation/key trust | Compromise invalidates downstream assurance |

An absent finding does not prove an attack is absent. Trigger-like evidence does not prove a model contains a malicious backdoor. Distribution shift does not by itself establish malicious manipulation. Model hash equality establishes byte identity relative to a trusted digest, not model safety.
