# Hospital review, training and integration results

The run uses the supplied IRIS General Hospital sources unchanged. See
`../../docs/HOSPITAL_MODEL_CARD.md` and `../../docs/VSCODE_HOSPITAL_DEMO.md`.

| Evidence | Location |
| --- | --- |
| Fresh runtime qualification | `validation/qualification.json` |
| Original reviewed-fitting readiness diagnostic | `prepared/preparation.json` |
| Fresh independent schema/business/reproducibility checks | `validation/independent_validation.json` |
| Executed training stdout | `training.log` |
| Fitted artifact and final experimental holdout | `../model_versions/iris_hospital_20261114/` |
| Full HTTPS workflow and runtime coverage | `workflow/workflow.json` |
| Every runtime session outcome | `workflow/session_outcomes.jsonl` |
| Backend, demo, ML, input and JavaScript test logs | `validation/` |
| Runtime versions and verification boundaries | `verification_summary.json` |

All records in `datasets/iris_general_hospital_20261114/validation/` are the
**original supplied bundle's** evidence. The files here are the fresh checks
performed with the newly fitted classifier.

The reviewed five-role readiness flag stays false. The separate explicitly
experimental two-role fit preserves groups and unreviewed annotation status.
The high benign false-positive rate blocks release; the application keeps the
model in shadow mode and retains primary rules and human approval.

The temporary verification database, passwords, tokens and private TLS key are
excluded. Full replay coverage includes fitting rows and is not a second test
accuracy measurement.
