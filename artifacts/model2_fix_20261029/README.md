# Model 2 context repair

The repair was fitted on 29 October 2026 and verified on 30 October 2026. The
original demo, Model 1 and original control-model weights are unchanged.

## What was wrong

The uploaded control targets are asset-specific links generated from SIEM
techniques and registered risks. The old model received telemetry, asset type and
a few risk numbers, but not the control-membership context needed to distinguish
those links. In its fitting pool, 108 identical-input groups contain conflicting
target sets, affecting 336 of 1,867 fragments. The old approach also cannot fit 87
of 120 controls with its minimum support requirement, and validation suppresses
19 more fitted controls. Its old-test recall is only 17.46%.

This is a task and data-contract mismatch, not a Python crash or something that
can be fixed responsibly by forcing a lower threshold.

## Implemented repair

The new module scores each candidate control using observed SIEM technique
annotations, the affected asset and its applicable registered-risk context. It
retains control memberships instead of reducing all GRC information to a single
likelihood and impact pair. The pairwise classifier shares evidence across
controls rather than requiring a separate learned classifier for every ID.

Alert associations.control_ids, associations.risk_ids, offline scenario truth,
held-out flags and global effectiveness values are not read as predictors. The
module returns named review recommendations, explicit support counts and separate
catalogue-policy matches. Unknown implementation state remains unknown. Missing
technique information requires review instead of fabricated advice. Cross-asset
context, wrong event membership, modified catalogues and artifact tampering are
rejected. Real-data release and automatic execution remain blocked.

## Evaluation

The old 399-fragment test was already inspected and was not reused as the new
final audit. The fixed protocol uses 1,867 fitting fragments and 418 development
fragments. The audit comprises the 301 original calibration fragments whose
control targets were not used in earlier Model 2 fitting or threshold selection.
Groups are disjoint; no Model 1 predictions enter the revised classifier. The
original comparator uses a recalibrated upstream Model 1 on development data so
its original scenario calibrator does not expose audit scenario labels.

| Method on the same 301 audit fragments | Micro precision | Micro recall | Micro F1 | Exact set accuracy |
| --- | ---: | ---: | ---: | ---: |
| Original control model | 0.6917 | 0.1930 | 0.3018 | 36.54% |
| Pairwise model without GRC membership | 0.1822 | 0.7186 | 0.2907 | 33.22% |
| Repaired context-aware model | 1.0000 | 1.0000 | 1.0000 | 100.00% |
| Deterministic catalogue-matching rule | 1.0000 | 1.0000 | 1.0000 | 100.00% |

The selected pairwise model is balanced Logistic Regression with a development-
selected threshold of approximately 0.95. Only 24 of the 120 catalogue controls
have positive audit support. All 301 audit responses are replayed through the
actual inference API, not just the offline scoring arrays.

## What these results do not prove

The deterministic rule is just as accurate on these targets. Pre-existing
control membership in a technique-matched risk closely reconstructs the synthetic
label generator, so 100% agreement is NOT 100% independently validated AI
recommendation accuracy. No added ML benefit over catalogue matching is shown.
The useful repair is grounding the advice in the correct operational context;
the rule baseline alone is sufficient for this synthetic association task.

The original targets identify existing or planned control associations. They do
not establish which new control should be installed, the best order of treatment,
or measured risk reduction. Independent expert action labels or prospective
outcomes are needed to validate those broader recommendation claims. Historical
control membership and knowledge timestamps are also absent, so this synthetic
replay assumes static control memberships. The new audit is an internal re-use
of the dataset, not independent external or production validation.

## Run the repaired recommendation component

From the IRIS repository root on Windows:

```powershell
.\.venv\Scripts\python.exe tools/recommend_grounded_controls.py
```

The example prints named controls such as MFA for remote access and impossible-
travel sign-in detection. It starts no server, changes no database and exits.
Use `--json` to obtain the structured response. Pass `--request` and `--model` for
other compatible synthetic requests and artifacts. Use the pinned environment
from the v2 training package; load joblib only from trusted artifacts.

This component is not silently wired into the old dashboard. That dashboard uses
a different 30-control catalogue; integrating the 120-control dataset is a
separate versioned deployment change, not replacing a file behind the user.

## Reproduce the repair

First recreate the base v2 preparation if the full local run is absent:

```bash
python tools/retrain_dataset_v2.py --dataset IRIS_dataset_v2.zip --out artifacts/v2_base_for_repair
python tools/fix_model2_grounding.py --source artifacts/v2_base_for_repair --out artifacts/my_new_model2_repair
python tools/verify_model2_repair.py --source artifacts/v2_base_for_repair --repair artifacts/my_new_model2_repair
```

Use new output directories. The fixed audit partition must not be used to tune
later revisions. See docs/MODEL2_FIX_PROTOCOL.md for the frozen protocol and the
artifact JSON files for all per-control scores and limitations.
