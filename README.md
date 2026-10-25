# IRIS

Integrated Risk Intelligence System: a research prototype connecting SOC/SIEM evidence with asset and GRC risk context.

This repository contains the **three-input advisory ML package**, the user's Colab-trained artifact, linked synthetic samples, a training notebook, and a prepared FastAPI backend with a small HTML dashboard. It is not a finished live SOC/GRC platform.

**Verification boundary:** 79 ML tests and 33 backend-core tests passed, and a fresh batch persisted 900 shadow cases. The actual FastAPI/Uvicorn HTTP server and browser interactions were **not run here**, because PyPI downloads were denied. Run the target-computer HTTP tests before using that interface. See [the verification record](backend/VERIFICATION.md).

## Start here

1. Follow [the step-by-step backend setup guide](docs/BACKEND_SETUP.md) to use the already-trained models.
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

## Run the backend locally

Use Python 3.12. From the repository root, install `requirements-backend.txt`, run both backend test suites, generate local role keys, and start `python -m backend serve`. The same server serves the website at `http://127.0.0.1:8000`; Colab is not needed during inference.

See [the setup guide](docs/BACKEND_SETUP.md) for exact Windows and macOS/Linux commands, privacy notes, limitations and the examiner walkthrough. Use the generated Admin/SOC/GRC keys; no default deployment keys are shipped.

## Train or run the ML CLI locally

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
- Prepared FastAPI adapter using the user's pinned Colab bundle, SQLite cases/audit, local role-key guards and three-source batch submission.
- A small HTML SOC/GRC/Admin interface and local-only GRC follow-up reviews; HTTP/UI runtime verification remains pending on the target computer.

## What is not implemented here

The older v0.3 FastAPI/SQLite/Streamlit engine remains a separate bundle. The new `backend/` is a smaller adapter for this repository's exact three-source/session contract, not a drop-in merge of every legacy feature.

Remaining work includes target-computer HTTP/browser verification, live SIEM/GRC connectors, enterprise user authentication, reliable external delivery, GRC-change-triggered re-evaluation and real-data validation. Shared lab role keys are not enterprise SSO or individual user identity. The [setup guide](docs/BACKEND_SETUP.md) states the exact current boundary.

## Validation and safety

All supplied training data is synthetic. It exercises the software; it does not establish real-world detection quality or control effectiveness.

In the recorded sample run, Model 1's benign false-positive rate was **7/45 = 15.56%**, above the configured 5% limit. Model release remains blocked. ML candidates must be shown as **shadow/test predictions**, separate from primary rules-based advice.

Model 2 has positive held-out examples for only six catalogue controls. Its synthetic micro-F1 does not establish complete catalogue coverage or actual control effectiveness.

No security control is automatically executed. No official GRC risk value is changed by this model package. Any future operational change requires an authorized human review and an explicit connector workflow.

See [the verification report](IRIS_Models_v2/docs/THREE_INPUT_VERIFICATION.md) for actual counts, tests, metrics and limitations. Never load untrusted `joblib`/pickle files: loading them can execute code.

## Repository layout

```text
IRIS_Models_v2/     Model source, tests, schemas, samples and recorded examples
artifacts/          The user's pinned, synthetic Colab-trained model bundle
backend/            Batch model adapter, SQLite store, API source, HTML UI, tests
notebooks/          Google Colab training and shadow-prediction notebook
docs/               Simple training, engine and demonstration guide
```

Do not commit real SIEM logs, credentials, private organizational inventories, or unapproved risk registers. Store authorized real datasets outside this repository.
