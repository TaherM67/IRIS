IRIS exact input agreement — version 1.0.0

Read IRIS_Input_Agreement_v1.docx for the field-by-field agreement.

TO GENERATE THE NEXT DATASET
Give your data-generating LLM:
  LLM_GENERATION_PROMPT.txt
  contract.json
  schemas/ (all four JSON Schemas)
  control_catalogue_reference.json
The example/ folder illustrates the linked format; it is only seven sessions.
Ask the LLM to return its runnable generator and all generated files.

EXACTLY THREE RUNTIME INPUTS
  asset_inventory.json
  risk_register.json
  siem_alerts.jsonl
For later supervised refinement, also return training_labels.jsonl separately.
The supplied catalogue is fixed reference material, not a fourth upload.

DATASET REQUEST
40 logical assets; 240 current logical risks; historical versions; 60 campaigns;
1,260 nominal sessions across seven classes. The prompt states the exact balance
and difficult-case counts. Initial LLM annotations are unreviewed.

VALIDATION AND CODE
Draft pull request: https://github.com/TaherM67/IRIS/pull/1
Branch: iris-input-agreement-20261114
Commit: cdd036e53337fc813fd5a7a672a4e374a591055c
Tested source tree: c3e6eabc1097d2c3fe3c31c8487a927b41946457
Use that branch's tools/validate_inputs.py and tools/prepare_expanded_training.py
from the IRIS repository. This kit does not contain the full runtime or weights.
The implementation/ folder includes the complete patch and verification notes.
For a clean checkout at the original base commit 4289c59cbea80c41f635c8893fe738de40e24c7f,
the patch can also be applied with git apply after reviewing it.

RESULTS BOUNDARY
The pipeline was refined; learned weights and thresholds have not been retrained.
238 targeted Python checks: 223 passed and 15 environment-dependent skips.
Fresh coverage, per-session audits, example qualification and offline preparation
reports are under verification/. The example is deliberately not fit-ready.
The older v2 source retains 6,534 events after 99 duplicate deliveries and 131
unresolved-asset events. Its 2,985 prepared fragments are all assessed by Model 1;
597 lack observed technique context for Model 2. No event context is invented.
Coverage is not accuracy. New accuracy/F1 figures require the new dataset,
independent annotation review and held-out evaluation.
