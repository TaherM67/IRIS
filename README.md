# IRIS

Integrated Risk Intelligence System: a research prototype joining SOC/SIEM
observations with asset and GRC risk context.

The current default demo is **IRIS General Hospital**: 500 assets, 1,860 risks,
15,000 alerts and 2,490 sessions. The supplied synthetic data, newly trained
Model 1, existing grounded Model 2, evaluation results and runnable Admin/SOC/GRC
application are included.

**Start with [the VS Code/Codex run guide](docs/VSCODE_HOSPITAL_DEMO.md).** It
contains a copyable Codex prompt, Windows commands, fresh-install setup and
instructions that preserve existing accounts, certificates and saved approvals.

## Start the hospital demo

Use Python 3.12 and an existing compatible virtual environment. For a fresh
checkout, create `.venv` first. Install:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-hospital.txt
.\.venv\Scripts\python.exe -m unittest backend.tests.test_hospital_training -v
.\.venv\Scripts\python.exe demo.py check --dataset hospital --model-profile iris_hospital_20261114
.\.venv\Scripts\python.exe demo.py --dataset hospital --model-profile iris_hospital_20261114
```

The server requires local HTTPS certificate files and individual accounts.
Reuse existing ones. The [run guide](docs/VSCODE_HOSPITAL_DEMO.md) explains the
one-time setup on a fresh machine. No passwords or private keys are shipped.

Open:

- Admin: <https://127.0.0.1:8010/admin>
- SOC: <https://127.0.0.1:8010/soc>
- GRC: <https://127.0.0.1:8010/grc>

Admin runs analysis. Each team reviews and approves its own proposals. GRC
approval changes the synthetic working register; SOC approval changes stored
alert priorities. SQLite retains revisions, audit records, chat and approvals.
Admin can monitor both teams but cannot approve for either team.

`python demo.py` also selects the hospital by default. Explicit commands above
avoid an old `IRIS_MODEL_PROFILE` environment override. Earlier demonstrations
remain available with `--dataset expanded --model-profile auto` or
`--dataset legacy --model-profile auto`. Dataset switches retain prior exercises.

## Training results and limits

[The model card](docs/HOSPITAL_MODEL_CARD.md) explains the review, split, features,
comparisons, limitations and reproduction commands.

| New Model 1 holdout measurement | Result |
| --- | ---: |
| Fit / held-out sessions | 1,868 / 622 |
| Macro-F1 | 0.9489 |
| All-session accuracy | 94.37% |
| Classification coverage | 99.36% |
| Benign false-positive rate | **16.67% (20/120)** |

These are synthetic-reference measurements. Annotations remain unreviewed.
Connected campaigns, templates and identical feature vectors never cross the
fit/test boundary. Too few independent template groups support the former
five-role protocol, so this explicit experiment uses a fixed logistic-regression
configuration and fixed 0.5 threshold, without probability calibration or test-set
tuning. The model exceeds the 5% benign false-positive review gate and remains
**unreleased, experimental and shadow-only**. Primary rules and authorized human
approvals remain responsible for demo changes.

Model 2 retains its pinned 120-control grounded estimator; it was not refitted on
unreviewed control targets. Missing technique context produces an explicit
unassessed outcome, not an invented benign result or control recommendation.

Full replay assessed 2,477 of 2,490 sessions with Model 1 and 1,897 sessions with
Model 2. Full replay includes fit rows; those numbers are runtime coverage only.
No real hospital data or production SIEM/GRC connector is included. LLM/RAG
explanations and live enterprise integration remain future work.

## Exactly three operational inputs

The hospital files are in `datasets/iris_general_hospital_20261114/data/`:

1. `asset_inventory.json`
2. `risk_register.json`
3. `siem_alerts.jsonl`

Historical validity and knowledge times are retained. The pipeline validates
sources, performs exact point-in-time joins, deduplicates/quarantines evidence,
and builds 60-second sessions. Model 1 receives 23 observed features.
`offline/training_labels.jsonl` is used only for the supervised experiment;
runtime inference never reads it. The supplied catalogue is a fixed reference.

## Recorded verification

- 112 backend tests passed.
- 128 demo tests passed; two private-LAN checks skipped.
- 92 ML tests passed; JavaScript controller checks passed.
- Independent hospital validation completed 157,612 assertions with zero errors.
- A separate HTTPS workflow checked all 15,000 events, all 2,490 cases, account
  sign-in, role isolation, approval writes/retries, exports, restart persistence
  and reanalysis using temporary state.

Existing user databases/accounts were not opened for those checks. Browser visual
inspection and actual private-LAN rehearsal remain local follow-up checks.
See `artifacts/hospital_training_20261114/` for logs and detailed outcomes.

## Repository map

| Path | Contents |
| --- | --- |
| `demo.py`, `demo_app/` | Active HTTPS application, accounts, approvals, chat and role dashboards |
| `backend/` | Shared integration, model adapters, rules, storage and separate FastAPI service |
| `datasets/iris_general_hospital_20261114/` | Supplied fictional hospital data, narratives, generator and original validation |
| `artifacts/model_versions/iris_hospital_20261114/` | Trained weights, pinned metadata, split, held-out predictions and results |
| `artifacts/hospital_training_20261114/` | Fresh qualification, full-system verification and test logs |
| `IRIS_Models_v2/` | Original model library, three-source integration, samples and tests |
| `notebooks/` | Earlier Colab training workflow |
| `report/SGP2/` | Existing PDF, Overleaf source and figures guide; older evidence is preserved |

The earlier passive FastAPI interface is documented in
[BACKEND_SETUP.md](docs/BACKEND_SETUP.md). The active hospital demo uses the
standard-library HTTPS server and does not require FastAPI, Node.js, Colab, an
LLM API key or training at startup. Node.js is used only for controller tests.

Keep `.local/` private and preserve it when updating. It holds local accounts,
certificates and saved demonstration state. Do not commit real organizational
telemetry or credentials. Load only model artifacts whose origin you trust;
serialized joblib/pickle files can execute code when loaded.
