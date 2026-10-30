# Model 2 repair protocol

The earlier 399-fragment test has already been inspected. It is diagnostic data,
not a fresh final evaluation for this repair. Do not tune a repair to that score.

Freeze this protocol before candidate fitting or reading new audit scores:

- Fit on the original train and selection groups, 1,867 fragments.
- Select between a balanced pairwise logistic classifier and a depth-limited
  pairwise decision tree using the original threshold groups, 418 fragments.
- Pick a validation threshold by macro-independent pooled F1 subject to at least
  0.80 micro precision; if none passes, retain the best F1 and report failure.
- Evaluate once on the original calibration groups, 301 fragments. Those control
  targets were not used by the previous control model. They are excluded from
  fitting and tuning of the repair. The repair does not use Model 1 predictions,
  so earlier scenario calibration on these rows cannot enter its features.
- Keep the original 399 diagnostic test fragments out of fitting and selection.
- Report the original telemetry-only baseline and a deterministic catalogue-link
  baseline on the same new audit set. Do not call deterministic matching AI.

The dataset's targets are synthetic risk-control associations, not expert-ranked
recommendations. Candidate operational context includes pre-existing GRC control
membership and observed SIEM technique annotations. It never reads alert
associations.control_ids, associations.risk_ids, offline scenario truth, control
held-out flags or global effectiveness scores. Candidate membership in a
technique-matched registered risk is closely related to the synthetic label
generator. High agreement is therefore reconstruction of that generator, NOT
independent evidence that AI chooses effective mitigations. The deterministic
baseline and this limitation must remain in the results.

Historical control-membership versions and knowledge timestamps are absent. This
synthetic replay assumes static membership for the applicable registered-risk
snapshot. Real deployment requires authoritative pre-decision control history or
prospective current-state evaluation. No production release, fabricated review
labels, automatic risk reduction or autonomous control execution is authorized.

The current demo and original model artifacts must remain unchanged. Publish the
repair as a separately versioned experimental component with a callable inference
path, tests, feature ablations and checksum-verified artifacts.
