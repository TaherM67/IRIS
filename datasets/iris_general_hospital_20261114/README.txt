IRIS HOSPITAL DATASET
IRIS General Hospital

PURPOSE AND ORGANIZATION

This is a fictional 350-bed general hospital with emergency, ICU, inpatient,
imaging, laboratory, pharmacy, outpatient and administrative services. The
dataset covers 500 selected monitored assets across the main hospital campus
and its fictional cloud tenancy. These are hospital technology assets, not
patient records and not a complete clinical device inventory.

500 assets; 1,860 logical current risks; 15,000 alerts; 2,490 prepared sessions.
Every asset has three or four relevant risks. Every risk has linked attack
observations. The 15,000 alert observations form 1,990 attack scenario sessions
and 500 routine hospital sessions. Of these, 398 attack sessions are subtle/noisy
and 100 routine sessions are benign lookalikes: exactly 20 percent per class.

Open HOSPITAL_CONTEXT_AND_RESULTS.html for the readable hospital role inventory,
risk examples, exact before/after example, control names and executed results.

RUNTIME INPUTS

Upload exactly these three files from data/:
  asset_inventory.json
  risk_register.json
  siem_alerts.jsonl

The file names, fields, enums and format follow the supplied unchanged schemas.
No scenario truth, desired priority, control recommendation target or result
is injected into these runtime inputs. Hostnames describe hospital functions;
IDs are opaque. Owners and addresses are fictional. Supported telemetry remains
authentication/network/process/privilege/web with the exact supported protocol
values. Clinical protocols are not silently relabeled as supported telemetry.

HOSPITAL ASSET TYPES

  workstation: 210
  server: 70
  database: 50
  identity_service: 15
  web_application: 25
  network_device: 60
  cloud_resource: 40
  iot_device: 30

Asset-specific roles, departments, services, data scope and clinical dependence
are in offline/asset_contexts.json. The 41 role groups include EHR applications,
PACS image services, LIS laboratory systems, pharmacy systems, identity/SSO,
patient portals, clinical workstations, segmentation firewalls, backup vaults,
and bedside-monitor and infusion-integration gateways.

RELATED RISKS

Six supported categories are used selectively: Unauthorized Access,
Reconnaissance, Malware Execution, Privilege Escalation, Web Application
Compromise and Data Exfiltration. Workstations have four; databases, network
devices and monitored medical/IoT gateways have three; other selected roles
have four. Web exploitation is registered for assets with an actual application
surface. No blanket assignment of all six risks or all control groups is used.

offline/risk_contexts.jsonl explains the individual risk and hospital consequence
for all 1,860 risks. Existing/planned memberships and implementation states are
explicit in the runtime register, drawn only from the fixed catalogue and
matched to registered technique plus asset applicability. Some records have
only planned controls; a nonexistent installed control is not fabricated.

Risk-level inspection bands use likelihood x impact: Low 1-4, Medium 5-9,
High 10-16, Critical 17-25. These bands are documented inspection conventions,
not extra runtime fields or learned priorities.

WHAT CHANGES OVER TIME

72 assets move from validated standby into live clinical service on 1 Nov 2026.
Their inventory criticality and associated registered risk context have
non-overlapping before/after versions, all known by their effective timestamps.
The same observed pattern is replayed on both sides using separate source runs.
All 72 comparisons produce higher actual IRIS response priority.

For 48 of these risks, earlier November alerts trigger a fictional SOC/GRC risk
review recorded on 5 Nov, effective 6 Nov. It raises registered likelihood and
adds a planned control when an additional supported candidate exists. Follow-up
alerts on 8 Nov use that new historical risk version. Earlier alerts retain
their original context; later information is never used as an earlier feature.

For the EHR application cvh-ehr-app-001.hospital.test, the linked risk is:
  Exploitation of the exposed HTTP application or administrative interface of ehr app
The detector remains Medium in all three measured replays:
  Before activation: criticality 3, registered risk 2 x 3 = 6 (Medium),
                     actual IRIS priority Medium.
  Live care service: criticality 5, registered risk 3 x 5 = 15 (High),
                     actual IRIS priority High.
  After risk review: criticality 5, registered risk 4 x 5 = 20 (Critical),
                     actual IRIS priority remains High under its existing matrix;
                     proposed hospital review reference priority is Critical.

The hospital reference floor is separate from actual IRIS policy and is not
silently presented as an engine result. Reviewing or installing a different
priority policy is a separate decision. All register/priority writes proposed
by the actual run remain pending real SOC/GRC approval.

offline/change_journal.jsonl retains causes, event IDs, version IDs, before/after
values and effective/knowledge times. offline/priority_change_walkthroughs.json
contains 72 fully joined comparisons. offline/actual_iris_reviews.jsonl contains
the actual primary policy and Model 2 results for all 2,490 sessions.
offline/review_queue.jsonl retains the original detector severity. Unresolved
cases have an explicit mapping-review segment. Mapped cases are ordered by
proposed response priority, then registered risk score, then detector level.

EXECUTED QUALIFICATION AND INFERENCE

Official contract qualification: valid true, zero errors, one explained warning.
All 15,000 source events reach exactly one of 2,490 prepared sessions.
Independent checks with the four supplied JSON Schemas: PASS.
Fresh generator rerun: every generated data/context/annotation file byte-identical.
Model 1: 2,091 assessed; 399 explicit confidence abstentions.
Model 2: 1,897 sessions assessed; 5,919 recommendation entries; 593 sessions lack
observed technique context. Those 593 comprise 500 benign and 93 attack sessions.
All accepted cases were read. Model weights and thresholds were unchanged.
Coverage is not model accuracy, review certification or control effectiveness.

The official preparation report is NOT fit-ready: unreviewed labels, only 14
connected independent groups, and insufficient per-class support in some roles.
No train-three, fitting, calibration or activation command was run.

DIRECTORY GUIDE

data/                         exactly three operational sources
offline/training_labels.jsonl exact seven-class annotation schema, unreviewed
offline/scenario_details.jsonl hospital narratives and measured evidence summaries
offline/event_associations.jsonl every event linked to case, asset and risk version
offline/asset_contexts.json    hospital asset roles and services
offline/risk_contexts.jsonl   risk statements and hospital consequences
offline/risk_levels.json      current likelihood/impact products and inspection bands
offline/change_journal.jsonl  inventory and incident-triggered historical changes
offline/temporal_comparisons.json source comparison identities
offline/actual_iris_reviews.jsonl actual engine decisions and recommendations
offline/review_queue.jsonl    source severity and proposed response priority
offline/priority_change_walkthroughs.json actual and reference priority comparisons
offline/hospital_context.json complete organization scope and role counts
offline/generation_summary.json generator counts and variation
reference/agreement/          unchanged contract, schemas, catalogue and original prompt
validation/qualification.json official contract result and every prepared session
validation/training_handoff/  actual official preparation records and split diagnostics
validation/inference/         actual frozen-model coverage and per-session outcomes
validation/workflow_audit.json counts of actual review and priority results
validation/independent_validation.json schema, joins, chronology and reproducibility
validation/source_provenance.json supplied source/model identities and tool hashes
generator/                    runnable generator, verifier, audit and report builder
manifest.json                 checksums and scope overrides for the complete bundle

The original reference prompt requests 40 assets, six risks each and a balanced
1,260-session example. Your later hospital instruction overrides those example
counts and requires three to four relevant risks per asset and 15,000 alerts.
The machine-readable schemas and catalogue are unchanged. All scope differences
are recorded in manifest.json.

REPRODUCE

Python 3.12 and jsonschema are used for independent schema checks. The supplied
IRIS runtime requires its pinned ML requirements and trusted frozen weights.
From this bundle directory, where IRIS_ROOT is the updated agreement checkout:

  python3 generator/generate_hospital.py --output-dir . --seed 20261114
  python3 generator/verify_hospital.py --check-reproducibility
  python3 IRIS_ROOT/tools/validate_inputs.py --input-dir data --out NEW_qualification.json
  python3 IRIS_ROOT/tools/prepare_expanded_training.py --input-dir data --labels offline/training_labels.jsonl --out NEW_TRAINING_REVIEW_DIRECTORY
  python3 IRIS_ROOT/tools/check_input_coverage.py --assets data/asset_inventory.json --risks data/risk_register.json --alerts data/siem_alerts.jsonl --model-profile auto --out NEW_COVERAGE_DIRECTORY

For a new bundle with validation/qualification.json but no existing inference/
directory, capture the actual case audit via:
  python3 generator/run_iris_audit.py --iris-root IRIS_ROOT
It calls the official run_check function unchanged and only adds a read of every
persisted case before its temporary store is removed. Offline labels are joined
after inference and never passed to the engine. Existing outputs are preserved.

Original base source: 4289c59cbea80c41f635c8893fe738de40e24c7f plus the agreement
pack's exact iris_refinement.patch, applied locally. No remote source was changed.
The expected agreement branch is iris-input-agreement-20261114, commit
cdd036e53337fc813fd5a7a672a4e374a591055c, as stated in the supplied pack.
