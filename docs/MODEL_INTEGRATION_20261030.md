# Local model integration: 2026-10-30

The current local backend now defaults to `iris_models_20261030`. Model 1 runs as a shadow comparison. Model 2 uses the supplied candidate builder with the exact 25-feature contract and 120-control catalogue. Both remain unreleased, synthetic-only components. Existing rules and human approval still control priority/risk changes; recommendations never execute controls.

## Preservation

The authoritative starting point was the local working tree, including its existing uncommitted website changes. No Git pull/reset/checkout, training, database replacement, credential regeneration, or GitHub push was performed.

Before editing, 17 relevant files were copied to:

```text
.local/model_integration_20261030_before_acfde862/
```

Final SHA-256 comparisons against that snapshot confirmed these files are byte-for-byte unchanged:

- `demo.py`
- `demo_app/static/index.html`
- `demo_app/static/style.css`
- `demo_app/server.py`
- `backend/static/index.html`
- `backend/static/style.css`
- `backend/static/app.js`
- `backend/model_manifest.json`
- `backend/config.py`
- `backend/security.py`
- `backend/policy.py`
- `.local/active_demo/access.json`
- `.local/active_demo/state/iris.sqlite3`

The remaining four snapshot files received the small integration changes listed below. No database migration was introduced. Incoming package files and legacy model files were retained. The actual demo database was never opened writable for integration testing; database workflow checks used a copy or temporary databases. The disposable preview server was stopped after browser checks. The actual demo was left stopped.

## Integration behavior

`backend/model_adapter.py` selects the new pinned profile by default, with `IRIS_MODEL_PROFILE=legacy` retaining the existing loader and original manifest. Both artifact hashes, the package files (including reference code), feature contracts, catalogue, and scikit-learn compatibility are checked before loading serialized models. New model identities distinguish new analysis runs from old evidence; existing cases are retained.

Model 1 receives the existing ordered 16 session features from the established 60-second integrator. Unseen categorical values abstain instead of being remapped. Rules remain the primary assessment even when a shadow prediction is available.

Model 2 receives one candidate row per pinned catalogue control, through the supplied reference implementation. It never receives the legacy 22-feature vector. Context is allowlisted from the same immutable three input files after the existing integrator selects session events and point-in-time asset/risk versions. Training labels, scenario annotations and `associations.control_ids` are excluded. Foreign event/asset/risk versions and old `SC*` IDs are rejected rather than translated to `CTL-*` IDs.

Model 2 results appear separately as `model2_review` in the current Admin/GRC contracts. GRC receives names, IDs, reasons, sources, review requirements and implementation-state evidence without learned scores or raw telemetry. SOC does not receive the new control review. The existing proposal view has a small rendering addition for these details and missing-field diagnostics; layout, role selection, sign-in, navigation, chat, HTML and CSS were preserved.

Implementation state comes only from an explicitly supplied matched runtime risk snapshot. Missing, conflicting, unknown or not-assessed state remains `unknown`; the catalogue's global state is never treated as evidence that a control is implemented on an asset. A known state still produces a review suggestion, never an execution instruction.

## Remaining data requirements

The current fixed demo inputs lack the following explicit Model 2 runtime fields:

| Input | Required fields |
| --- | --- |
| Asset inventory version | `control_groups` (string array) |
| Observed SIEM events | `mitre_technique` when an observed technique is available |
| Applicable registered risk version | `existing_control_ids`, `planned_control_ids`, `mitre_attack_techniques` (string arrays) |

The existing session criticality, current likelihood and impact must also be finite pre-decision values. Risk control links must use the exact pinned `CTL-*` catalogue. Known implementation state additionally needs real per-asset `control_states` evidence in the selected risk version. Empty explicit arrays are distinct from absent fields. None of these values is invented from old control IDs or offline labels.

On a copy of the current database and its fixed demo inputs:

- All 132 existing cases remained; analysis added 132 cases with the new model identity.
- Approved risk values, alert working priorities/versions and change history remained unchanged. Existing analysis behavior relinks alert `case_id` references to the new immutable evidence.
- Model 1 produced 34 shadow predictions; 98 sessions abstained because their categorical values were outside the trained vocabulary. For example, the new protocol vocabulary is TCP/UDP; SSH is not silently rewritten.
- Model 2 reported `source=not_run` with missing-field diagnostics for all 132 sessions. It works on enriched canonical three-file inputs, as exercised by the integration/API tests.

The separate `DATA/` files were not transformed or loaded into the current database. Supplying genuine, versioned context in the existing canonical input contract is the remaining data step for Model 2 recommendations on that data. Real-data inference remains blocked while the models are unreleased.

Package-reported performance is limited to synthetic evaluation: Model 1 accuracy was 97.49% on 399 fragments. Model 2 matched synthetic associations on 301 audit fragments, with only 24 positively supported controls; a deterministic catalogue rule matched the same labels. This integration does not establish real-world accuracy, control efficacy, or an ML advantage. Per-control held-out support is not supplied in the package metadata, so status reports it as unavailable instead of substituting fit support.

## Verification

The original packaged smoke test was run successfully **before any backend changes**:

```powershell
.\.venv\Scripts\python.exe incoming_models\iris_models_20261030\smoke_test.py
```

It produced Model 1 `credential_access` and named Model 2 candidates `CTL-MON-004` (Impossible-travel sign-in detection) and `CTL-IAM-002` (Enforce MFA for remote access (VPN)), with unknown implementation state.

Final checks passed:

- 133 Python tests covering the adapters, API, existing core/demo workflow, authentication, role guards, approval, persistence, chat and activity.
- Frontend controller tests, including named/unknown-state Model 2 rendering, missing-field diagnostics and score filtering.
- An actual Uvicorn TCP HTTP workflow: authenticated three-file upload, named Model 2 recommendations, role rejection, human review and upload deduplication, all with temporary storage.
- A disposable Chrome browser check of all three roles, invalid keys, role choice and cross-role sign-in without reload, approvals, live chat, and desktop/mobile layouts.
- Reanalysis of a copy of the existing database, plus protected-file SHA-256 comparisons.
- `python -m backend check` and `python -m pip check`.

Reproduce the Python suite from the repository root with the new profile selected:

```powershell
$env:IRIS_MODEL_PROFILE='iris_models_20261030'
.\.venv\Scripts\python.exe -m unittest backend.tests.test_grounded backend.tests.test_core backend.tests.test_http demo_app.tests.test_demo demo_app.tests.test_chat demo_app.tests.test_activity
$env:IRIS_TEST_PYTHON=(Resolve-Path -LiteralPath '.\.venv\Scripts\python.exe').Path
node demo_app\tests\test_ui_controller.js
```

The local agent environment used its bundled Node executable because `node` was not on its PATH. `IRIS_TEST_PYTHON` selects the actual virtual environment for the controller suite.

The initial environment lacked the project's existing web dependencies. `pip install -r requirements-backend.txt` installed those existing pins and their dependencies, enabling FastAPI/Uvicorn HTTP tests. Requirements files were unchanged. The already-compatible ML versions were preserved: Python 3.12, NumPy 2.3.5, pandas 2.2.3, SciPy 1.17.0, scikit-learn 1.8.0, joblib 1.5.3 and threadpoolctl 3.6.0. No training dependency changes were needed for the packaged smoke test.

## Startup and rollback

Run these PowerShell commands from the existing repository directory:

```powershell
$env:IRIS_MODEL_PROFILE='iris_models_20261030'
.\.venv\Scripts\python.exe -m backend check
.\.venv\Scripts\python.exe demo.py
```

Open `http://127.0.0.1:8010/`. Use the existing role keys. There is no initialization or reset step. An Admin analysis creates new evidence under the new model identity; old evidence remains associated with its original models. Starting the website alone does not retroactively rewrite saved evidence.

To run the original model configuration, stop the running server and restart with:

```powershell
$env:IRIS_MODEL_PROFILE='legacy'
.\.venv\Scripts\python.exe demo.py
```

To switch back, stop it, set `IRIS_MODEL_PROFILE='iris_models_20261030'` and restart. The original `backend/model_manifest.json`, `artifacts/user_colab_run/models/` and legacy catalogue remain in place. Rollback changes the inference profile; it does not delete newer analysis records.

## Files changed by this integration

Existing project files edited:

| File | Change |
| --- | --- |
| `backend/model_adapter.py` | Select the versioned profile, retain legacy rollback and delegate session enrichment/inference/status. |
| `backend/core.py` | Attach allowlisted runtime context; expose role-appropriate review results. |
| `demo_app/engine.py` | Save review evidence and project business-facing fields for GRC. |
| `demo_app/static/app.js` | Small proposal rendering/filtering addition for new review details and diagnostics. |
| `backend/tests/test_core.py` | Update the expected active Model 1 artifact hash. |
| `demo_app/tests/test_demo.py` | Update the hash assertion; handle legitimate shadow abstentions and check SOC isolation. |
| `demo_app/tests/test_ui_controller.js` | Test new review rendering and score filtering. |

New project files:

- `backend/grounded_adapter.py`
- `backend/grounded_context.py`
- `backend/model_profile_20261030.json`
- `backend/tests/test_grounded.py`
- `docs/MODEL_INTEGRATION_20261030.md`

New versioned package files, copied without changing their contents into `artifacts/model_versions/iris_models_20261030/`:

```text
CODEX_TASK.txt
READ_ME_FIRST.txt
SHA256.json
SMOKE_TEST_RESULT.txt
control_catalogue.json
grounded_model2.joblib
grounded_model2.json
model1_metadata.json
model1_scenario.joblib
reference_code/__init__.py
reference_code/contracts.py
reference_code/grounded_controls.py
requirements.txt
smoke_test.py
smoke_test_request.json
```

All 14 entries in `SHA256.json` were verified. Model 1 SHA-256: `ae8ca09ded11a3d7e10be68fbc29999028cf6c456874e4376697a1e7c8fb7bb1`. Model 2 SHA-256: `e29b2879b6c25a02605df4740265c5fdb7eb22849b45dcbf6f34e59736817dea`. Package manifest SHA-256: `4c446379a3cf7333624ce87e973a870f56d84231c6a83c84ebbb745d008c36a5`.

Ignored local verification artifacts:

- `.local/verify_model_integration.py` and `.local/verify_live_model_http.py` were added for the isolated database-copy and real TCP checks.
- The snapshot directory named above contains copies of the 17 preserved starting files, including private keys/database; it remains under ignored `.local/`.
- Existing disposable browser fixtures were reused unchanged. Their generated `reference-login-desktop.png`, `reference-login-mobile.png`, `redesign-admin-final.png`, `redesign-soc-final.png`, `redesign-grc-final.png` and `redesign-mobile-final.png`, and the isolated `.local/redesign-cdp-profile/` browser cache were refreshed.
- Ordinary interpreter caches and virtual-environment dependency files were generated by loading/testing the models and installing the existing backend requirements.

Other changes already present in the working tree (including website documentation, chat implementation, and incoming data) were not replaced or reverted by this integration.
