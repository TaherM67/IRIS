# IRIS

Integrated Risk Intelligence System: a research prototype connecting SOC/SIEM evidence with asset and GRC risk context.

This repository contains the **three-input advisory ML package**, the user's Colab-trained artifact, linked synthetic samples, a training notebook, a prepared FastAPI backend, and an **active, approval-gated demonstration** with Admin/SOC/GRC dashboards. It is not a finished live SOC/GRC platform.

**For the examiner demonstration, start with [`demo.py`](demo.py) and [the active demo instructions](docs/ACTIVE_DEMO.md).** The original dark dashboard and direct key login are restored; only unrelated team content is removed. GRC approval actually changes the synthetic working risk register; SOC approval actually reprioritizes stored alerts. Changes persist, can be exported, and have before/after audit records. There are **54 passing demo tests including real HTTP/API approval, authentication, original-layout and role-isolation checks**, plus frontend controller regressions. No real organization or security controls are modified. Browser layout/click-through still needs a local rehearsal.

**Each workspace now shows only its own work:** SOC has alerts and priority reviews; GRC has the risk register and business/control reviews; Admin can monitor both working systems plus full analysis, model and audit details. This is enforced in server-rendered HTML and API response allowlists, not only hidden panels. See [the dashboard guide and update steps](docs/ROLE_DASHBOARDS.md).

**Use the original sign-in:** run `python demo.py keys` from the same project folder as the running server and copy only the matching role's token. The two redesigns, their build/session gates and new key commands are removed. See [the access guide](docs/ACCESS_HELP.md). Keep your existing `.local/` folder and credentials.

**Verification boundary:** 79 ML tests and 33 backend-core tests passed, and a fresh batch persisted 900 shadow cases. The actual FastAPI/Uvicorn HTTP server and browser interactions were **not run here**, because PyPI downloads were denied. Run the target-computer HTTP tests before using that interface. See [the verification record](backend/VERIFICATION.md).

## Start here

1. Follow [the active demo guide](docs/ACTIVE_DEMO.md): run `python demo.py`, open the three dashboards on port 8010, analyze, then approve and show real synthetic record changes.
2. For the older passive FastAPI prototype, follow [the backend setup guide](docs/BACKEND_SETUP.md).
3. Open [the Colab training notebook](notebooks/IRIS_Colab_Training.ipynb) if you want to train again; the saved models are already included.
4. Read [the three-input schemas and joining rules](IRIS_Models_v2/docs/THREE_INPUTS_GUIDE.md) and [the full model explanation](IRIS_Models_v2/docs/MODEL_GUIDE.md).

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

### Active demo (recommended for the examination)

From the project root with Python 3.12, install `IRIS_Models_v2/requirements.txt` and run:

```bash
python -m unittest demo_app.tests.test_demo -v
python demo.py
```

In a second private terminal run `python demo.py keys`. Open `http://127.0.0.1:8010/admin`, `/soc`, and `/grc` with their separate demo keys. Admin analyzes; each team reviews and applies its own proposed changes to **persisted synthetic records**. See [the complete steps](docs/ACTIVE_DEMO.md).

The new [three demo datasets](demo/data/) contain 30 assets, 60 risks and 2,367 alert rows. They produce 132 cases. Demo state and credentials stay in `.local/active_demo/`, excluded from Git. No FastAPI install, Colab runtime or Node.js is needed for this local demo.

### Earlier passive FastAPI interface

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
- A separate active synthetic-system demo: role-gated approval writes, persistent working risk register, reprioritized alert queue, before/after audit and current-state JSON exports. Its loopback HTTP/API workflow is tested; browser rehearsal remains necessary.

## What is not implemented here

The older v0.3 FastAPI/SQLite/Streamlit engine remains a separate bundle. The new `backend/` is a smaller adapter for this repository's exact three-source/session contract, not a drop-in merge of every legacy feature.

Remaining work includes target-computer HTTP/browser verification, live SIEM/GRC connectors, enterprise user authentication, reliable external delivery, GRC-change-triggered re-evaluation and real-data validation. Shared lab role keys are not enterprise SSO or individual user identity. The [setup guide](docs/BACKEND_SETUP.md) states the exact current boundary.

## Validation and safety

All supplied training data is synthetic. It exercises the software; it does not establish real-world detection quality or control effectiveness.

In the recorded sample run, Model 1's benign false-positive rate was **7/45 = 15.56%**, above the configured 5% limit. Model release remains blocked. ML candidates must be shown as **shadow/test predictions**, separate from primary rules-based advice.

Model 2 has positive held-out examples for only six catalogue controls. Its synthetic micro-F1 does not establish complete catalogue coverage or actual control effectiveness.

No security control is automatically executed. No official company GRC value is changed. **The active demo does change its own synthetic working risk records and alert priorities after the appropriate human approval**; this must not be confused with a live company connector or production release of the ML models.

See [the verification report](IRIS_Models_v2/docs/THREE_INPUT_VERIFICATION.md) for actual counts, tests, metrics and limitations. Never load untrusted `joblib`/pickle files: loading them can execute code.

## Repository layout

```text
IRIS_Models_v2/     Model source, tests, schemas, samples and recorded examples
artifacts/          The user's pinned, synthetic Colab-trained model bundle
backend/            Batch model adapter, SQLite store, API source, HTML UI, tests
demo.py             One-command active demonstration launcher
demo_app/           Local demo HTTP adapter, working records, approvals, UI, tests
demo/               Three new synthetic demo inputs and verification record
notebooks/          Google Colab training and shadow-prediction notebook
docs/               Simple training, engine and demonstration guide
```

Do not commit real SIEM logs, credentials, private organizational inventories, or unapproved risk registers. Store authorized real datasets outside this repository.
