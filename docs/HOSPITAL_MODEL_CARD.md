# Hospital classifier: 14 November 2026

`iris_hospital_20261114` is a trained, experimental synthetic-data Model 1.
The supplied hospital inputs and annotations are preserved. Model 2 retains its
existing pinned grounded estimator and 120-control catalogue. The primary risk
policy and human approval requirements remain in force.

## Data review

The supplied IRIS General Hospital bundle has 500 logical assets, 1,860 current
risks, 15,000 observed events and 2,490 prepared sessions. Its 572 inventory and
2,169 risk snapshots preserve historical context. Independent checks completed
157,612 assertions with zero errors; seeded regeneration reproduced the original
generated sources. Official qualification accounts for all 15,000 events exactly
once. It warns that 593 sessions lack observed technique context for Model 2.

Annotations remain `unreviewed`, with `label_verified=false`, no reviewer, and
unreviewed control targets. No automated check is represented as expert review.

## Training protocol

The original five-role preparation has only 14 connected groups and misses
classes in several roles. Web exploitation occurs in just two groups; a
class-complete five-role experiment cannot be obtained by shuffling these rows.
The original preparation report still correctly says reviewed fitting is blocked.

The explicit `--experimental-synthetic` option permits a separate two-role
software experiment. Connected campaigns, reused templates, identical observed
feature vectors and their event memberships remain together. Pre-fit
stratification considers class counts only, with a fixed target of 25% of rows
for the holdout. It does not use predictions, errors or fitted scores.

| Role | Sessions | Connected groups |
| --- | ---: | ---: |
| Fit | 1,868 | 8 |
| Final synthetic holdout | 622 | 6 |

All seven classes occur in both roles. The 23-feature allowlist contains only
observations. Scenario labels, controls, risk values, asset/campaign IDs and
clinical criticality are not Model 1 features. Scaling and category encoding fit
only the fitting data.

The estimator is fixed logistic regression (`C=1`, balanced class weights,
`max_iter=1500`, seed `20261114`). The confidence threshold is fixed at 0.5.
There is no model search, probability calibration, or threshold tuning on this
holdout. Outputs are explicitly described as uncalibrated experimental scores.
The final model is not refitted on the test data after evaluation.

## Recorded holdout results

| Measurement | New hospital model | Previous expanded model | Primary rules |
| --- | ---: | ---: | ---: |
| Sessions | 622 | 622 | 622 |
| Macro-F1, including abstentions as missed classes | 0.9489 | 0.3210 | 0.7793 |
| All-session accuracy | 94.37% | 35.37% | 63.02% |
| Classification coverage | 99.36% | 85.21% | 63.18% |
| Benign false-positive rate | **16.67% (20/120)** | 0/120 | 0.83% (1/120) |

The previous model and primary rules are compared on the exact same held-out
rows. Scores describe agreement with unreviewed synthetic references. They do
not establish actual attack detection quality or hospital suitability. Row-level
confidence intervals would overstate the independent sample size, so none are
claimed. The benign false-positive rate exceeds the project's 5% review gate.

| Class | Test support | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: |
| Routine | 120 | 0.9000 | 0.8250 | 0.8609 |
| Credential access | 120 | 1.0000 | 1.0000 | 1.0000 |
| Reconnaissance | 51 | 0.9808 | 1.0000 | 0.9903 |
| Malicious execution | 70 | 0.8667 | 0.9286 | 0.8966 |
| Privilege escalation | 111 | 0.9369 | 0.9369 | 0.9369 |
| Web exploitation | 40 | 0.9744 | 0.9500 | 0.9620 |
| Exfiltration | 110 | 0.9910 | 1.0000 | 0.9955 |

## Runtime and verification

The model is pinned by metadata and weight hashes in
`backend/model_profile_hospital.json`. `python demo.py` now defaults to the
hospital dataset. Explicit `--dataset expanded` and `--dataset legacy` retain
earlier exercises. The automatic profile selector chooses the hospital model
only for its exact three source hashes; transformed/new files require an
explicit compatible profile.

Full replay assessed 2,477/2,490 sessions and explicitly abstained on 13. This
includes fitting rows and is **runtime coverage**, not another accuracy test.
Grounded Model 2 assessed 1,897 sessions; 593 had no observed technique.

The temporary HTTPS workflow checked all 15,000 alerts and 2,490 saved cases,
authenticated roles, approval isolation, idempotency, real risk/priority writes,
exports, persistence and reanalysis. It changed one synthetic risk and four
synthetic alert priorities under the proper approvals. Source inputs stayed
unchanged. No existing user's database, accounts or approvals were opened.

Recorded regressions: 112 backend tests passed; 128 demo tests passed and two
private-LAN tests skipped; 92 ML tests passed. JavaScript controller checks
passed. Browser visual inspection and an actual private-LAN rehearsal remain
unperformed in this run. The prepared FastAPI tests used the available runtime
versions recorded in the verification summary; the active demo uses the Python
standard-library server.

## Reproduction and evidence

Use Python 3.12 and `requirements-hospital.txt`. To make a new experimental
version, choose a new output directory:

```powershell
.\.venv\Scripts\python.exe tools/train_hospital.py --experimental-synthetic --out artifacts/model_versions/NEW_HOSPITAL_EXPERIMENT
```

The trainer writes the hospital profile pointer for the new version. Retain
and review that pointer with the artifacts; it never overwrites an existing
fitted output directory. Independent annotation review, broader template
support, a predeclared five-role experiment, calibration, acceptable false
positives and real-data validation remain prerequisites for a reviewed release.

- `datasets/iris_general_hospital_20261114/`: original supplied sources,
  generator, narratives, reference contract and original validation.
- `artifacts/model_versions/iris_hospital_20261114/`: fitted weights, metadata,
  source hashes, original preparation, final split and per-session holdout
  predictions, confusion matrix and comparisons in `RESULTS.json`.
- `artifacts/hospital_training_20261114/`: fresh validation, test logs and full
  runtime session outcomes. The original SGP2 report retains older results;
  this model card records the newer experiment without rewriting that evidence.
