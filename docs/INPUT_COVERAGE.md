# Input compatibility and complete session checks

The GitHub version already contained the seven-class model and 84-session
expanded demonstration. The earlier 132-session failure counts were from the
older inputs paired with the October model, not the current default demo.

## What was fixed

The batch engine now selects a pinned model from the observed input contract
when no profile is explicitly configured. The expanded demo selects the
23-feature scenario model. The original SSH/TCP demo selects its original
SSH-trained Colab model. The supplied synthetic-v2 exports select the October
TCP/UDP model. Explicit adapters, CLI profiles and environment overrides are
retained; a deliberately mismatched profile is not silently replaced.

The runtime now accepts the supplied v2 `assets`, `risks` and `alerts` JSON
exports rather than requiring the user to run an offline training adapter first.
It preserves historical likelihood/impact, explicit control groups, registered
control links and observed ATT&CK techniques. Canonical JSON alert containers are
converted to JSON Lines; existing canonical JSONL inputs are not rewritten.

The supplied v2 export produces 2,985 retained session fragments, exceeding the
old 2,000-session batch cap. The default and maximum are now bounded at 5,000;
file-size, alert-count, snapshot and risk-expansion limits remain in force.

Every completed batch includes `model_profile` and `model_coverage`. The separate
check script also saves the outcome and exact blocking reasons for every session.
Unsupported categories include the actual field/value, such as
`primary_protocol: SSH`, instead of only an unexplained missing candidate.

**Model weights, model integrity manifests, supplied source datasets, dashboard
HTML/CSS/JavaScript, existing accounts and approvals were not changed.** The
problem was serving/schema compatibility; no new fitting was necessary to obtain
the recorded runtime coverage. Models remain unreleased, synthetic-only and
advisory; primary policy and human approval remain separate.

## Run from the repository root

Activate the existing Python 3.12 environment with the pinned dependencies.

```powershell
python tools/check_input_coverage.py --dataset expanded
python tools/check_input_coverage.py --dataset legacy
python tools/check_input_coverage.py --dataset v2
```

Each command creates a fresh `.local/input_coverage/` result folder and prints
its location. It uses a temporary isolated backend/database, checks every saved
case, and leaves the existing demo database, credentials and source files alone.
The result files are `coverage.json` and `session_outcomes.jsonl`.

To check three explicitly selected files:

```powershell
python tools/check_input_coverage.py --assets DATA/asset_inventory.json --risks DATA/risk_register.json --alerts DATA/siem_alerts.json
```

For the supplied raw v2 data, use its metadata-bearing `siem_alerts.json` export.
Raw v2 JSONL must declare synthetic provenance per event; the adapter must not
silently relabel undeclared or real telemetry as generated data.

The interactive website still runs with `python demo.py`. Use
`python demo.py --dataset legacy` for the original demo; the matching model is
selected automatically. `--model-profile auto` overrides a stale CLI default;
an explicit profile remains available for diagnostic comparison.

## Interpreting the checks

| Inputs | Retained fragments checked | Model 1 predictions | Grounded Model 2 |
| --- | ---: | ---: | --- |
| Expanded demo | 84 | 84 | 72 assessed; 12 have no observed technique |
| Original demo with matching model | 132 | 131 | Original advisor/catalogue, not the grounded 120-control model |
| Supplied v2 JSON exports | 2,985 | 2,985 | 2,388 assessed; 597 have no observed technique |

The original demo intentionally contains one session without healthy-sensor
evidence. It remains blocked. A no-technique outcome means no grounded control
recommendation is issued; it does **not** prove the activity is benign. These
cases remain in the report rather than being dropped from the denominator.

The v2 source has 1,340 original session identifiers, not 2,985 independent
attacks. Account, asset, family and inactivity/context boundaries produce the
fragments. Of 6,764 raw alert rows, 99 redeliveries are removed and 131 events
with unresolved assets are held aside; 6,534 events enter model sessions. Unknown
assets are not assigned an invented inventory/risk record to claim coverage.

The synthetic-v2 adapter explicitly records the same historical assumptions as
the offline adapter: generated sensor health, knowledge timestamps equal to
validity starts, and static control membership because no membership history was
supplied. Control implementation/effectiveness remain unknown. These assumptions
are not allowed for real-data exports.

These results are runtime **coverage**, not new accuracy, F1 or independent
generalization estimates. The v2 source was used in previous fitting; replaying
it cannot establish new test accuracy. No runtime labels were read.

Recorded aggregate reports are in `artifacts/input_coverage_20261113/`.

## Regression commands

```powershell
python -m unittest backend.tests.test_input_coverage backend.tests.test_core backend.tests.test_grounded demo_app.tests.test_scenarios demo_app.tests.test_demo
python -m unittest backend.tests.test_http
$env:PYTHONPATH = 'IRIS_Models_v2'
python -m unittest discover -s IRIS_Models_v2/tests
```

HTTPS-account and prepared-LAN tests need the local certificate/network setup;
unprepared checks remain explicitly skipped. Passing controller tests is not a
browser visual rehearsal or production certification.
