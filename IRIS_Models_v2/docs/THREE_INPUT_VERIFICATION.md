# Three-input integration verification

Executed 25 October 2026 using Python 3.12.14 and the pinned scikit-learn 1.8.0 environment.

## Actual end-to-end sample run

The three operational inputs were passed to `train-three`, with the separate synthetic label sidecar used only by its offline training stage. Both model components were fitted. A separate `predict-three --limit 5` run used the same three sources and trained artifacts, with **no label argument or label read**.

| Quantity | Observed result |
| --- | --- |
| Distinct assets / inventory snapshots | 60 / 120 |
| Distinct registered risks / risk snapshots | 120 / 240 |
| Incoming SIEM rows | 26,086 |
| Exact duplicate rows removed | 12 |
| Malformed timestamp rows quarantined | 1 |
| Unified deduplicated event records | 26,073 |
| Unified events with unresolved assets | 2, retained with visible unresolved status |
| Events available to matched-asset sessions | 26,071 |
| Final prepared sessions | 900 |
| Sessions per supported class | 300 benign, 300 credential access, 300 reconnaissance |
| Artificial campaign groups | 60 |
| Untouched test sessions | 135, 45 per class |
| Risk-driven multiplication of alert rows | None |
| Integration labels read at runtime | None |
| Core preparation elapsed time | Approximately 1.49 seconds in this environment |

Timing includes source parsing/validation, indexed point-in-time enrichment, sorting, session construction and source hashing. It excludes Python/library startup, model fitting and serialization of the large unified-event output. This single synthetic batch is not a production throughput or memory-capacity guarantee.

## Model results are software checks only

| Model result | Synthetic value |
| --- | --- |
| Selected scenario candidate | Random Forest |
| Model 1 macro-F1 | 0.9405 |
| Model 1 coverage | 1.0000 |
| Model 1 benign FPR | 7/45 = 15.56% |
| Model 2 micro-F1 | 0.9542 |
| Model 2 status | Trained, shadow-only |
| Advisory model release | Blocked |

The sample classifier fails the false-positive limit. Synthetic provenance also blocks release. The intentionally unreviewed integration exclusions require attention before any real release. Scores are not presented as evidence of actual SIEM detection quality, complete control coverage or control effectiveness.

## Test suite

**79 tests passed**, including the 46 original model checks plus new calibration/integration checks. The complete output is in `three_input_test_results.txt`.

New/extended coverage includes:

- Three-source joining with no event multiplication when two risks match an asset.
- Exact asset ID, destination-IP and agent-hostname resolution; no attacker-IP or null-key victim matching.
- Conflicting ID/IP clues and ambiguous IPs remain unresolved.
- Historical IP rotation, exclusive validity boundaries and context-version session splits.
- Future/backdated-but-recorded-later asset/risk snapshots cannot leak into earlier events.
- Overlapping histories, duplicate snapshot IDs, unknown risk foreign keys and missing criticality fail explicitly.
- Exact duplicate alerts collapse; conflicting duplicate IDs exclude all conflicting versions.
- Malformed alerts and unhealthy sensors remain visible or fail closed.
- Input order does not change session features/context.
- Rolling history excludes future and unfinished sessions.
- Likelihood and impact come from the same actual risk record, not independent maxima.
- Nested Indexer `_source` records preserve collector-provided metadata.
- Runtime integration never reads labels; synthetic generated labels cannot masquerade as real expert reviews.
- Complete three-input preparation, training and label-free prediction paths execute successfully.
- Calibration uses the frozen base model without refitting its preprocessing on calibration data, including small valid calibration splits.

## Included and reproducible outputs

The archive includes the three original sources, the offline label sidecar, the complete 900-session integrated model input, joined session reviews, integration report, trained shadow artifacts, evaluation/split reports and the five-session prediction preview.

The large raw `unified_events.jsonl` audit outputs and a duplicate prediction-preparation directory are omitted from the ZIP to avoid unnecessary repeated data. Run `prepare-three` to regenerate the complete unified-event audit. No training sessions or source rows are truncated in the supplied source/model-input files.

## What was not established

No real enterprise/cyber-range campaign evaluation, universal SIEM schema compatibility, delayed-arrival streaming correctness, million-row benchmark, live connector delivery, authenticated enterprise approval system or production model readiness has been established.
