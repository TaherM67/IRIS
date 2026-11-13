# Expanded scenarios and incident correlation

The default `python demo.py` launch selects `demo/scenarios_v2/` and the pinned
`iris_scenarios_20261109` model profile. The original inputs and model versions
remain available through:

```powershell
.\.venv\Scripts\python.exe demo.py --dataset legacy --model-profile legacy
```

By default the launcher matches the input contract. An explicit `--model-profile`
or `IRIS_MODEL_PROFILE` setting overrides selection. Use
`--model-profile iris_scenarios_20261109` for the expanded classifier. See
[complete input-coverage checks](INPUT_COVERAGE.md) before pairing another dataset/profile.

Switching datasets starts a new exercise in the same local database. Earlier
exercises, approvals, changed records, chat, credentials and audit entries remain
saved. A dataset switch never applies an approval or changes historical evidence.
The reusable `DemoEngine` API still rejects a dataset mismatch unless its caller
explicitly supplies `allow_dataset_change=True`; the launcher opts into this.

## What the demonstration contains

There are 84 distinct sessions on 30 assets, with 1,163 supporting alerts and
180 registered risks. Each of the following seven categories has twelve sessions:

| Category | Evidence used by the transparent primary rules |
| --- | --- |
| Credential attack | Repeated authentication failures and failure ratio |
| Network reconnaissance | Multiple observed network rules and an event burst |
| Malicious execution | Unsigned process observations with a known malicious indicator |
| Privilege escalation | Privilege-change observations with a known malicious indicator |
| Web exploitation | Multiple web-attack signals at elevated observed severity |
| Data exfiltration | Measured outbound bytes, sensitive-data access and an untrusted destination |
| Routine activity | The existing low-failure successful authentication rule |

Primary rules and the learned model are separate outputs. An unrecognized or
unhealthy session can abstain; a missing measurement is not proof of benign
activity. The retained grounded Model 2 receives explicit technique and versioned
risk/control links for each attack family and returns named, review-only control
candidates. Its synthetic association scores do not measure control effectiveness.

The SOC queue defaults to one row per session, displaying its scenario, asset,
time range, original/current priority counts, and supporting-event count. Expand
a row to inspect event identifiers and priority changes. The scenario selector
filters before pagination. Turn off **Group related alerts** for the raw queue.
The updated-only filter retains all supporting events in each changed incident.
Before analysis, uncorrelated events are not guessed into incident groups.

Pending review entries also display scenario and time. Reviews are unique per
exercise/case/team. When a new model or policy produces a new case for an existing
session, pending entries from the older analysis become stale with a saved
supersession reason. Approved/rejected history is preserved; different sessions
are never merged merely because they share an asset or scenario.

## Model fitting and its limits

The new scenario classifier was fitted on 1,050 generated sessions from thirty
artificial campaigns. Every campaign contains all seven classes. Campaigns are
disjoint across five roles: fit (630 sessions), model selection (105), calibration
(105), abstention-threshold selection (105), and final audit (105). A separate
84-session dataset is used for the interactive demonstration.

The classifier uses the existing sixteen telemetry features plus seven observed
measurements: total outbound bytes and counts of unsigned processes, privilege
changes, web-attack signals, sensitive-data accesses, untrusted destinations and
known malicious indicators. Scenario labels, campaign/run/asset identifiers,
criticality, risk scores and control associations are not Model 1 inputs. The
same three-source integrator and evidence aggregation run at fit and serving time.
Offline labels are stored separately and are never a runtime input.

Outbound events identify their reporting asset explicitly and retain the remote
endpoint in `remote_destination_ip`. They omit the legacy `destination_ip` victim
lookup field so a remote recipient is not mistaken for the monitored asset.
Local process/privilege observations have zero outbound bytes. Incomplete expanded
measurements cause the learned classifier to abstain rather than silently treating
unavailable measurements as proof of routine activity.

Logistic regression was selected against random forest and histogram gradient
boosting on the selection split. The selected fit pipeline was frozen, calibrated
on separate campaigns, and evaluated once on the final audit. The audit classified
105/105 generated sessions correctly with full coverage. These deliberately
separable synthetic examples test software behavior; they do not establish
accuracy on real attacks or unfamiliar environments. Both models remain unreleased
and the classifier remains a shadow comparison. Human SOC/GRC approval is retained.

Training outputs, split membership, offline labels, audit predictions, metadata and
the fitted artifact are in `artifacts/model_versions/iris_scenarios_20261109/`.
`backend/model_profile_scenarios.json` pins the model and metadata hashes before
loading. The former model package and its integrity manifest are unchanged.

To reproduce into a **fresh version directory**, run:

```powershell
.\.venv\Scripts\python.exe tools/train_expanded_scenarios.py --out artifacts/model_versions/NEW_VERSION --demo-out demo/NEW_DATASET
```

The script refuses to overwrite a completed trained version. It writes the active
expanded-profile pointer for the generated version; review and retain that change
alongside the new artifacts. To keep the current demonstration inputs, use a fresh
`--demo-out` as shown.

## Verification

```powershell
.\.venv\Scripts\python.exe -m unittest demo_app.tests.test_scenarios backend.tests.test_core demo_app.tests.test_demo
$env:IRIS_TEST_PYTHON = (Resolve-Path .\.venv\Scripts\python.exe).Path
node demo_app/tests/test_ui_controller.js
```

Tests cover fitted classes, disjoint campaign/session splits, evidence/label
separation, sensor-health abstention, exact alert conservation, correlation before
pagination, scenario filters, role guards, approval behavior, superseded reviews,
and preserved history when switching datasets. Frontend controller tests cover
incident evidence, scenario filters, review labels and the raw-event toggle.

On 9 November 2026, 133 relevant Python regressions and the frontend controller
checks passed. A copy of the saved local database was switched and analyzed;
existing exercise/record/approval/audit rows were preserved and the original
database remained byte-for-byte unchanged. A browser visual check was unavailable
because the computer/browser automation bridge was disconnected.
