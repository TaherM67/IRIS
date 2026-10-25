# IRIS model code - working advisory ML package

Version 1.1.0 | 25 October 2026

## New: exactly three operational input datasets

The engine can now start from `asset_inventory.json`, `risk_register.json` and `siem_alerts.jsonl` directly. It validates identifiers/timestamps first, performs exact point-in-time enrichment without multiplying alerts, builds one unified event dataset, then produces ML session inputs. Both training and inference use the same preparation function.

Read [the three-input guide](docs/THREE_INPUTS_GUIDE.md) for the source schemas, joining rules and examples. The included samples have 60 assets, 120 registered risks and 26,086 SIEM alert rows, supporting 900 labeled synthetic sessions across sixty artificial campaigns (300 sessions per class). They are software-development data, not evidence of real-world detection quality.

After installing the requirements, train directly from the three samples:

```bash
python -m iris_models train-three --assets samples/three_inputs/asset_inventory.json --risks samples/three_inputs/risk_register.json --alerts samples/three_inputs/siem_alerts.jsonl --labels samples/three_inputs/training_labels.jsonl --synthetic --out my_three_input_training
```

`training_labels.jsonl` is an offline annotation sidecar, not a fourth runtime input. Real data needs independently reviewed session labels. Generated event labels cannot be used to claim real expert review.

Runtime preparation/prediction uses only the three operational sources:

```bash
python -m iris_models predict-three --assets samples/three_inputs/asset_inventory.json --risks samples/three_inputs/risk_register.json --alerts samples/three_inputs/siem_alerts.jsonl --models my_three_input_training/models --out my_three_input_predictions
```

Use a fresh output directory. `examples/three_input_training` contains the executed training run. `examples/three_input_prediction` contains an explicitly limited five-session prediction preview. The earlier `examples/synthetic_demo` remains a legacy standalone model fixture; do not use its different aggregation contract for three-input inference.

This package implements the two ML components of the IRIS SOC-GRC-SIEM decision-support design. It builds on the v0.3 engine's contracts, without replacing its risk policy, audit, approval workflow, SIEM or GRC system.

**Start with [the full explanation](docs/MODEL_GUIDE.md).** It explains the architecture, every feature, the learning algorithms, training/evaluation, deployment guards, source files, integration and limitations.

## What works

- Model 1: supervised, session-level, three-class scenario assessment with calibrated scores and abstention.
- Candidate comparison: Logistic Regression, Random Forest, Histogram Gradient Boosting.
- Model 2: supervised multi-label control recommendation using separate logistic classifiers.
- Grouped out-of-fold scenario inputs for Model 2; no oracle scenario labels as its inputs.
- Five disjoint data roles, grouped by campaign/template (run grouping is development-only).
- A CyberRangeV1 adapter for the existing GNS3 export layout, including Wazuh and Suricata alert normalization, exact topology mapping, deduplication, integrity checks and sensor-health checks.
- Separate observed telemetry and reviewed labels, with quarantine and a strict feature allowlist.
- Matching normalization/sessionization contracts at training and inference.
- Conservative rules/catalogue fallback; sensor gaps and unsupported categories do not become benign verdicts.
- Model release gate, named model reviewer, implemented-control checks and active-exception checks.
- A synthetic, end-to-end demo and a standard-library unittest suite.

**Not complete:** real campaign validation, live connector delivery, organization-specific control labels, unknown-attack detection, production hardening, LLM/RAG explanations and automated GRC-change triggers. No control is executed and no official risk is written.

## Quick start - Linux/macOS

Unzip the package, open a terminal inside `IRIS_Models_v2`, then:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m iris_models demo --out my_first_demo
.venv/bin/python -m unittest discover -s tests -v
```

## Quick start - Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m iris_models demo --out my_first_demo
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Tested using Python 3.12.14 and scikit-learn 1.8.0. Training and inference must use the same pinned scikit-learn version. No GPU, cloud account or LLM key is needed. The demo is deterministic under the pinned environment, but exact floating-point results may differ across operating systems/BLAS implementations.

The included `examples/synthetic_demo` directory is a completed **software test only**, not real cyber-range evidence. Run your own demo into a fresh directory. Existing model experiment directories cannot be overwritten accidentally.

## Inspect the included example

```bash
python -m iris_models predict --session examples/synthetic_demo/sample_session.json --models examples/synthetic_demo/models
```

The primary output remains rules/catalogue advice. `shadow_candidate` shows ML output separately. Synthetic models cannot be promoted, even when some synthetic metrics look good.

## Extract actual range telemetry

```bash
python -m iris_models extract-range --campaign /path/to/campaign-export --out data/campaign_sessions.jsonl
```

The extractor intentionally does not read scenario/ground-truth files. A reviewer must label each observed session. The optional `context` starts as `null`: join time-valid GRC context before Model 2 training. Do not invent criticality, likelihood or impact from an IP address or topology role.

## Train on reviewed real data

```bash
python -m iris_models train --sessions data/real_sessions.jsonl --reviews data/real_reviews.jsonl --group-by campaign_id --out experiments/real_v1
```

Use multiple independently executed campaigns. At least 25 runs per supported class is the ingestion minimum, not proof of statistical adequacy. Every split must contain all three classes; at least five independent grouping units are required. The additional ten-test-sessions-per-class release check is a proposed conservative safeguard and may require substantially more than 25 runs per class.

If Model 2 labels are not ready, use `controls_reviewed: false`; Model 1 still trains and Model 2 remains a catalogue fallback. Missing GRC context also excludes that session from Model 2 training without blocking Model 1.

## Release is a separate review step

Only after reviewing the reports and passing every relevant gate:

```bash
python -m iris_models promote model1 --models experiments/real_v1 --reviewer project_owner
python -m iris_models promote model2 --models experiments/real_v1 --reviewer control_reviewer
python -m iris_models predict --session data/new_session.json --models experiments/real_v1 --mode advisory
```

A model-level approval does **not** approve any incident response or GRC change. Each proposed operational action still needs an authorized human reviewer in the existing engine.

## Security

Load only models that you trained locally or independently trust. `joblib` uses pickle and can execute Python while loading. SHA-256 detects changes relative to a trusted manifest; it does not authenticate the publisher. This is local prototype code, not a hardened multi-user service.

See `docs/VERIFICATION.md` for the actual checks performed and `docs/MODEL_GUIDE.md` for details.
