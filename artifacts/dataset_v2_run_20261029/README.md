# IRIS retrained models from the uploaded dataset

Fresh training completed on 29 October 2026. All six dataset files match the
current uploaded attachments and the supplied manifest by SHA-256. The attachments
also match the prior dataset byte-for-byte; the fixed-seed rerun reproduces its
metrics. No model was installed into the demo and no old upload job was resumed.

## Evaluation results

The fixed seed is 42. The existing three-source integration and 60-second
sessionizer produced 2,985 matched session fragments from 1,280 supported labeled
source sessions. The additional 60 unknown-asset source sessions are not trained.
The held-out test has 399 fragments: 119 benign, 243 credential access and 37
reconnaissance. These are NOT 399 independent attack campaigns. All fragments of
an original session remain together; attack campaign IDs are respected and benign
activity uses recurring observed-source-set grouping proxies. There is no
independent organization, chronological or template-family external evaluation.

| Metric | Result |
| --- | ---: |
| Model 1 selected algorithm | Logistic Regression |
| Correct scenario predictions | 389 / 399 |
| Model 1 accuracy | 97.4937% |
| Model 1 macro F1 | 0.979556 |
| Prediction coverage | 100% |
| Benign false positives | 0 / 119 |
| Model 2 algorithm | Binary relevance Logistic Regression |
| Model 2 micro precision | 0.655629 |
| Model 2 micro recall | 0.174603 |
| Model 2 micro F1 | 0.275766 |
| Model 2 exact set accuracy | 37.5940% |
| Model 2 Hamming loss | 0.010860 |
| Model 2 macro F1 across 120 controls | 0.030481 |
| Controls with positive held-out support | 32 / 120 |

Confusion matrix rows are actual benign, credential access and reconnaissance;
columns are predicted benign, credential access, reconnaissance and abstention.

| Actual class | Benign | Credential | Reconnaissance | Abstain |
| --- | ---: | ---: | ---: | ---: |
| Benign | 119 | 0 | 0 | 0 |
| Credential access | 10 | 233 | 0 | 0 |
| Reconnaissance | 0 | 0 | 37 | 0 |

Logistic Regression and Random Forest tied on the selection partition. The fixed
selection order chose Logistic Regression; the model was not selected on the test
set. Ten credential-access fragments were missed. Zero observed benign false
alarms is not a guarantee of a zero real-world false-positive rate. The 95% Wilson
interval is approximately 0% to 3.13%, without campaign-cluster adjustment.

## Model 2 limitations

Control targets are unions of the supplied association control IDs, as approved
by the user. They are weak synthetic targets, not independent expert labels or
measurements of control effectiveness. Model 2 fails precision, F1 and support
checks and must not be deployed as trusted advice. Low Hamming loss is not high
recommendation accuracy: most of the 120 label decisions per fragment are negative.
Only 33 controls had sufficient positive and negative fitting support; 19 of those
were suppressed by validation thresholds. Check metadata for all per-control
scores and support rather than treating the catalogue as fully validated.

## Preparation assumptions and safety

There are 535 assets, 2,372 risks, 120 controls and 6,764 raw alerts. Full-content
deduplication excluding the delivery ID removes 99 redeliveries, leaving 6,665
events, including 131 unresolved events excluded from session training. There are
4,911 risk history snapshots. Risk history is used as supplied, rather than current
residual scores. Missing knowledge timestamps are assumed equal to validity starts
and sensor health is assumed for synthetic generation only. These assumptions are
not evidence of a production point-in-time or sensor-health guarantee. Criticality
maps Low=1, Medium=3, High=4, Critical=5. Global control implementation/effectiveness
fields are not asset-specific and are excluded.

Control IDs, risk IDs, attack labels, ATT&CK fields and held-out support flags do
not enter predictor features. Synthetic review flags identify the automatic
annotation adapter, NOT a human reviewer. The saved report records 2,238 repeated
feature vectors; short fragments make many observations similar, limiting
generalization claims. This experiment is not directly comparable to the old
135-session test. No thresholds were adjusted after the final test.

Both models remain unreleased experimental candidates. The 120-control catalogue
uses different IDs from the current demo. Do not simply replace demo weights or
edit its manifest. A separate integration and review is required.

## Contents and reproduction

The compact package contains both trained components in models/models.joblib,
metadata, the control catalogue, pinned requirements, split and threshold records,
test predictions, weak targets, verification records and adapter code. It omits
the bulky raw data and full prepared session file; the supplied datasets remain
unchanged. Original input hashes are in upload_verification.json.

Use these files with the IRIS repository's existing IRIS_Models_v2 package. Put
the original dataset ZIP in the repository root, then run in the pinned environment:

```bash
python tools/retrain_dataset_v2.py --dataset IRIS_dataset_v2.zip --out artifacts/my_new_v2_run
python -m unittest tools.test_retrain_dataset_v2 -q
PYTHONPATH=IRIS_Models_v2 python -m unittest discover -s IRIS_Models_v2/tests -q
```

Choose a new output directory; prior experiments are never overwritten. The adapter
test accepts the original ZIP in the repository root or IRIS_V2_DATASET. The training
adapter never executes the dataset generator or supplied scripts. Load joblib only
from this trusted training run; serialized model files can execute Python code.
