# Expanded input agreement and analysis refinement — 14 November 2026

This change strengthens the analysis pipeline and specifies the next synthetic dataset. It does not fit new weights, change frozen confidence thresholds, or establish new accuracy, F1, or control-effectiveness results.

## Delivered behavior

- An executable agreement fixes exactly three runtime sources: asset inventory, risk register and SIEM observations. JSON schemas, cross-file references, point-in-time validity, endpoint roles, event membership and explicit readiness diagnostics are checked before inference. Missing observations are not replaced with target-derived defaults.
- Model 2 withholds scored recommendations unless a registered risk and the catalogue control share supporting observed technique evidence and the control applies to the asset. Accepted advice carries risk/event links in the audit. Unknown implementation state remains unknown. Business-facing responses continue to exclude raw telemetry and learned scores.
- The grounding-policy identity participates in analysis cache identity, preventing reuse of older advice under the changed rules.
- Coverage output includes class probabilities, normalized entropy, top-two margin, rule/model disagreements, source event IDs and withheld-candidate reasons. These diagnostics measure ambiguity and traceability, not correctness.
- The demo reads every accepted case up to its configured session limit before preparing reviews. Previously, a hardcoded 2,000-case read could omit downstream processing for later cases. An incomplete read now fails before demo working-record or proposal updates.
- A separate offline handoff prepares seven-class records with 23 observed features. Runtime inference never reads its annotation sidecar. Campaigns, reused templates and identical observed feature vectors stay together when experimental roles are assigned. Reviewed labels and adequate per-class support are required for fitting readiness. The preparation command does not fit or activate a model.

## Verification

The targeted Python regression run completed 238 tests: 223 passed, 15 existing TLS/LAN environment-dependent checks skipped, zero failures or errors. JavaScript controller checks also passed. New cases include a real 2,001-session integration/SQLite batch, incomplete-read rollback boundaries, unsupported inputs, label separation, historical knowledge, endpoint confusion, and unsupported or disconnected recommendation evidence.

| Isolated dataset | Prepared sessions checked | Model 1 assessed | Grounded Model 2 assessed | Explicit limitation |
| --- | ---: | ---: | ---: | --- |
| Expanded demo | 84 | 84 | 72 | 12 sessions lack observed technique |
| Legacy demo with matching profile | 132 | 131 | Separate legacy advisor | One unhealthy-sensor session |
| Older v2 JSON exports | 2,985 | 2,985 | 2,388 | 597 sessions lack observed technique |
| Included contract example | 7 | 7 | 6 | One routine session lacks observed technique |

The final v2 run withheld **951 individual control candidates** under the evidence gate and exposed nine rule/model disagreements. Candidate counts are not session counts or accuracy measurements. The source's 1,340 original session identifiers become 2,985 context/time fragments, not independent attack experiments. Its 6,764 raw event rows include 99 duplicate deliveries and 131 unresolved-asset events; the retained 6,534 events are accounted for. Unresolved asset events require corrected inventory evidence rather than fabricated context.

Source hashes were unchanged after the isolated runs. Saved demo databases and approvals were not used for these checks. The new agreement is stricter than the retained compatibility adapters: a clean generated bundle must account for every supplied event without duplicates or unresolved assets.

## Next dataset

Give the generating LLM [the full request](../contracts/expanded-v1/LLM_GENERATION_PROMPT.txt), [the schemas and pinned catalogue reference](../contracts/expanded-v1), and [the field agreement](INPUT_AGREEMENT.md). The requested dataset has 40 logical assets, 240 current logical risks with historical versions, and 1,260 sessions across seven classes. LLM annotations begin unreviewed. The included seven-session example demonstrates format and joins; it is not a sufficient training dataset.

After the actual data arrives, qualify it, inspect coverage and review the offline labels before a fresh versioned fit, calibration and held-out evaluation. Earlier learned-model metrics must not be reused as evidence for the changed recommendation postprocessor.
