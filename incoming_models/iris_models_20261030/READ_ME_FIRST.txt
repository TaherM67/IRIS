IRIS MODEL ONLY HANDOFF

This package contains trained Model 1 and the repaired experimental Model 2.
It contains NO website pages, routes, authentication files, keys or databases.
No Git pull, reset or wholesale project replacement is needed.

1. Extract into a NEW folder such as incoming_models/iris_models_20261030
   inside your CURRENT VS Code project. Keep the extracted folder together.
2. Back up or locally commit your existing website changes before integration.
3. Give local Codex CODEX_TASK.txt and this package. Your local project is the
   authoritative version; do not replace it with the GitHub copy.

CONTENTS
model1_scenario.joblib: trained calibrated Logistic Regression classifier.
model1_metadata.json: 16-feature input order, thresholds, metrics and checksum.
grounded_model2.joblib and grounded_model2.json: repaired candidate model and
its checksum and 25-field feature contract.
control_catalogue.json: exact 120-control catalogue required by Model 2.
reference_code: small reference candidate builder and loader, NOT an automatic
replacement for any file in your project.
smoke_test.py and smoke_test_request.json: a single synthetic loading example.
requirements.txt: versions used during training; do not blindly upgrade or
downgrade a working website environment. Test dependency changes separately.

MODEL COMPATIBILITY
Model 1 expects the SAME integrated 60-second session features used in training.
It does not accept raw JSON files directly. Its observed test accuracy was
97.49% on 399 synthetic fragments. This is not real-world validation.
Model 2 is NOT a drop-in replacement for the old 22-field control classifiers.
It needs an enriched session, its observed technique annotations, the affected
asset, applicable registered-risk control links and the exact catalogue.
Its reference recommend method returns named review candidates only.
Unknown control implementation state must remain unknown.

SAFE LOADING EXAMPLE
From your project root, after extracting to incoming_models/iris_models_20261030:
  .\.venv\Scripts\python.exe incoming_models\iris_models_20261030\smoke_test.py
This command exits after loading the models and printing example advice. It
does not start a backend or modify a database. It was verified for this package.

LIMITATIONS
Both components remain experimental and unreleased. The repaired Model 2
matched all synthetic labels on 301 audit fragments, but the deterministic
catalogue rule matched them too. There is no demonstrated ML advantage on
these generated associations, nor expert validation of control effectiveness.
Only 24 catalogue controls had positive audit support. Historical control-link
versions are absent, so the replay assumes static membership. Real-data use
and automatic execution remain blocked in the reference loader.
Serialized joblib files can execute code: load trusted local artifacts only.
