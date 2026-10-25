# IRIS

Integrated Risk Intelligence System: a research prototype connecting SOC/SIEM evidence with asset and GRC risk context.

This repository contains the working **three-input advisory ML package**, linked synthetic samples, a Google Colab training notebook, and a simple engine/deployment guide. It is not a finished live SOC/GRC platform.

## Start here

1. Read [the simple Colab and deployment guide](docs/COLAB_AND_DEPLOYMENT.md).
2. Open [the Colab training notebook](notebooks/IRIS_Colab_Training.ipynb).
3. Read [the three-input schemas and joining rules](IRIS_Models_v2/docs/THREE_INPUTS_GUIDE.md).
4. Read [the full model explanation](IRIS_Models_v2/docs/MODEL_GUIDE.md).

The repository is private. To use Colab without putting a GitHub token in a notebook, download this repository with **Code > Download ZIP**, upload the notebook to Colab, and upload the repository ZIP when its first cell asks for it. The notebook also accepts the original `IRIS_Model_Code_v2.zip` package.

## Exactly three operational inputs

| Input | Supplied sample |
| --- | --- |
| Asset inventory | [asset_inventory.json](IRIS_Models_v2/samples/three_inputs/asset_inventory.json) |
| Risk register | [risk_register.json](IRIS_Models_v2/samples/three_inputs/risk_register.json) |
| SIEM alerts | [siem_alerts.jsonl](IRIS_Models_v2/samples/three_inputs/siem_alerts.jsonl) |

The samples contain 60 assets, 120 registered risks and 26,086 alert rows. They produce 900 synthetic labeled sessions: 300 benign, 300 credential-access and 300 reconnaissance sessions.

`training_labels.jsonl` is a separate **offline annotation sidecar**, not a fourth runtime input. Preparation and prediction never read it.

Validation and exact point-in-time enrichment produce one unified event dataset before session feature engineering. Both training and inference use the same preparation function. The models use tabular features, not raw JSON documents.

## Run locally

Use Python 3.12 and the pinned dependencies. From the repository root:

```bash
cd IRIS_Models_v2
python -m venv .venv
```

Activate the environment with `source .venv/bin/activate` on Linux/macOS, or `.\.venv\Scripts\Activate.ps1` in Windows PowerShell. Then:

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python -m iris_models train-three --assets samples/three_inputs/asset_inventory.json --risks samples/three_inputs/risk_register.json --alerts samples/three_inputs/siem_alerts.jsonl --labels samples/three_inputs/training_labels.jsonl --synthetic --out my_training
python -m iris_models predict-three --assets samples/three_inputs/asset_inventory.json --risks samples/three_inputs/risk_register.json --alerts samples/three_inputs/siem_alerts.jsonl --models my_training/models --mode shadow --out my_predictions
```

Use fresh output directories when repeating experiments. No GPU, cloud account or LLM key is required for local training.

## What is implemented

- Three-source validation, exact asset matching, historical asset/risk enrichment, deduplication, quarantine and session construction.
- Model 1: supervised scenario classification with candidate comparison, calibration and abstention.
- Model 2: multi-label control recommendations with policy and catalogue fallback.
- Campaign-grouped fitting, selection, calibration, threshold selection and held-out evaluation.
- Synthetic source generation, release safeguards and 79 model/integration tests.
- Complete sample training artifacts and a clearly limited five-session prediction preview.

## What is not implemented here

The older v0.3 FastAPI/SQLite/Streamlit engine was a separate bundle. Its backend and dashboard are **not included or wired to the new model by this upload**.

Remaining work includes the backend adapter, live SIEM/GRC connectors, authenticated SOC/GRC/Admin access, reliable external delivery, GRC-change-triggered re-evaluation and real-data validation. The [deployment guide](docs/COLAB_AND_DEPLOYMENT.md) explains that target architecture and build order.

## Validation and safety

All supplied training data is synthetic. It exercises the software; it does not establish real-world detection quality or control effectiveness.

In the recorded sample run, Model 1's benign false-positive rate was **7/45 = 15.56%**, above the configured 5% limit. Model release remains blocked. ML candidates must be shown as **shadow/test predictions**, separate from primary rules-based advice.

No security control is automatically executed. No official GRC risk value is changed by this model package. Any future operational change requires an authorized human review and an explicit connector workflow.

See [the verification report](IRIS_Models_v2/docs/THREE_INPUT_VERIFICATION.md) for actual counts, tests, metrics and limitations. Never load untrusted `joblib`/pickle files: loading them can execute code.

## Repository layout

```text
IRIS_Models_v2/     Model source, tests, schemas, samples and recorded examples
notebooks/          Google Colab training and shadow-prediction notebook
docs/               Simple training, engine and demonstration guide
```

Do not commit real SIEM logs, credentials, private organizational inventories, or unapproved risk registers. Store authorized real datasets outside this repository.
