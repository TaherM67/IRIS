# IRIS: from Colab training to an examiner demonstration

## The simple idea

**Colab trains the model. The backend runs the saved model. The website displays the results.**

Once the trained files are downloaded, Colab can be closed. A running IRIS backend does not call Colab or retrain for every incoming alert.

This repository now also contains the user's pinned model and a prepared `backend/` adapter with SQLite persistence and a small HTML dashboard. Its core is testable here; FastAPI/Uvicorn HTTP and browser runtime verification must be completed on the target computer. **Use [BACKEND_SETUP.md](BACKEND_SETUP.md) for the current step-by-step instructions.** The older FastAPI/SQLite/Streamlit bundle is separate and is not the server used by the new setup.

## 1. Train in Google Colab

1. While signed into GitHub, choose **Code > Download ZIP** in this private repository.
2. Extract that ZIP on your computer and locate `notebooks/IRIS_Colab_Training.ipynb`.
3. Open [Google Colab](https://colab.research.google.com/) and upload that notebook.
4. Choose a CPU runtime using Python 3.12. A GPU is not needed. Colab's runtime-version selector can provide a Python 3.12 image if the default changes.
5. Run the cells in order. Upload the downloaded repository ZIP when requested. The notebook also accepts the original `IRIS_Model_Code_v2.zip`.
6. Download the final results ZIP before leaving the runtime.

The notebook installs pinned dependencies, runs the tests, combines the three sample sources, trains both components, makes an explicitly limited five-session shadow preview, displays evaluation/release information, and downloads the run outputs. It never requires a GitHub access token.

The notebook's Python syntax and core training flow are checked locally. Google-hosted Colab execution must still be verified in your own account. Install or dependency errors must be fixed without silently removing the project's version pins.

The synthetic samples produce 900 sessions. The runtime sources are the inventory, risk register and SIEM alerts. The separate labels file supplies offline training answers only.

When using real data, first prepare the sessions, obtain independently reviewed session/control labels, and train without `--synthetic` using the appropriate real provenance. Do not relabel generated data as real evidence. At least 25 distinct runs per supported class is an ingestion minimum, not proof of statistical adequacy; use independent campaign holdouts and enough representative benign activity.

Colab runtimes are temporary. Save the model directory, metadata, split/evaluation reports and code/dependency versions. Upload only synthetic data or organizational data explicitly authorized for that environment.

## 2. What the engine contains

The engine is more than the classifier. It needs these responsibilities:

1. Collect SIEM alerts and synchronize asset/risk context.
2. Preserve incoming evidence, validate records and reject or quarantine unsafe data.
3. Resolve each affected asset and attach time-valid, already-known risk context.
4. Group related alerts into sessions and compute the same features used during training.
5. Use Model 1 for technical scenario assessment, explicit policy for business-aware priority, and Model 2 for candidate controls.
6. Store decisions, evidence links, model versions and review history.
7. Provide APIs for the dashboard and authorized approval/rejection actions.
8. Deliver approved outbound messages through connectors with retries and acknowledgements.

The current model library covers validation/preparation, training and guarded inference. The new backend adds batch submission, local evidence/case storage, separate views and local-only reviews. HTTP/UI testing remains pending on the target computer. This is not a finished durable streaming service.

### Connect the new model correctly

- Keep the model directory and its metadata together; do not copy only the `.joblib` file.
- Keep the matching control catalogue, Python environment, pinned dependencies, feature allowlist and aggregation contract.
- Load `ModelService` once per backend process, using FastAPI's startup/lifespan handling, and reuse it for prepared sessions.
- Use the three-source preparation/session contract for models trained by `train-three`. Do not silently substitute the older engine's different aggregation schema.
- Preserve the explicit registered-risk mapping/policy and approval workflow. A representative prior-risk context is not proof that an alert caused that particular risk.
- Keep the synthetic model in shadow mode. The primary output and shadow candidate must be labelled separately.

The new artifact is not a drop-in replacement for either older engine model file. `backend/model_adapter.py` implements the matching three-source adapter; run both its core tests and its target-computer HTTP tests before use. Do not spawn a new training job or reload the model for each alert.

## 3. Where to run the demonstration

For the first examiner demonstration, use:

| Component | Location |
| --- | --- |
| Training | Google Colab; needed only when training/evaluating a version |
| IRIS backend and saved models | Your laptop, or one private lab VM |
| Prototype database | A persistent SQLite file on that backend machine |
| Dashboard | The new HTML interface served by FastAPI on the backend machine |
| Wazuh/Suricata and lab hosts | Your controlled lab VMs/GNS3 environment |

A public domain or public-cloud deployment is not needed for an in-person examination. Keep the lab restricted; do not expose prototype administration endpoints to the internet.

For this repository, after following [the setup guide](BACKEND_SETUP.md), start the new adapter from the repository root with:

```bash
python -m backend serve
```

Its dashboard is `http://127.0.0.1:8000`; API documentation is at `/docs`. The backend loads the uploaded Colab artifact once at startup. You do not need a second Streamlit process. These are prepared instructions; HTTP/UI execution was not verified in the build environment.

If a custom HTML/JavaScript frontend is used, it is another client of the backend API. It does not contain or train the ML model, and it must not write directly to the database.

For continuous use later, deploy the integrated application to a private VM/container environment with persistent model/database storage, automatic restart, source authorization, authenticated roles, HTTPS, backups and logging. Keep training and inference dependency versions aligned. The backend must remain running while users access its website.

## 4. Push and pull, in plain language

**Pull means IRIS asks for new data.** For example, a connector queries the Wazuh Indexer every five seconds for records after its last successful checkpoint. This polling interval is a proposed example, not a guaranteed end-to-end detection latency.

**Push means a source initiates sending data to IRIS.** For example, a configured SIEM integration script sends an alert with an HTTP `POST` to a receiving IRIS endpoint. Both the sender and receiver need implementation/configuration; alerts do not reach the model automatically just because a model file exists.

Start with SIEM pull for the lab. Persist the checkpoint, use stable event IDs, deduplicate retries, paginate results, handle delayed arrivals, and report source failures. Do not advance the checkpoint until the relevant evidence is durably accepted.

Load the inventory and risk register initially, then synchronize their versioned changes. Do not retransmit the complete inventory and register for every alert. Never attach future/backdated-but-later-recorded context to an earlier historical decision.

New alerts are accumulated into sessions. A session model is not necessarily called immediately for each raw event: the collector must apply the same inactivity window and aggregation policy as training, including quiet-period closure. The provided batch path does not implement a continuously running collector, durable session state or watermarking.

These push/pull terms describe data delivery, not GitHub pull requests. They are not strict synonyms for HTTP `POST` and `GET`; some APIs use `POST` for searches.

## 5. The website and the three teams

Use one application and one stored case, with different authorized views:

- **SOC:** alert/session evidence, affected asset, scenario assessment, contextual priority, related risks and investigation suggestions.
- **GRC:** registered-risk context, proposed reassessment, control recommendations/states/exceptions and approval/rejection history.
- **Admin:** connector status, last successful synchronization, failed jobs, unresolved assets, model version, release status and audit history.

The prepared HTML frontend requests the latest results from the backend approximately every ten seconds while connected and visible. Browser runtime behavior still needs target-computer verification.

The older Streamlit selector only switched views. The new adapter instead checks three separately generated local role keys in the backend; its keys are not stored in browser storage or committed to Git. This is a lab role-key scheme, not real individual user accounts or enterprise SSO. Run the HTTP authorization tests on the target computer; hiding buttons alone is not protection.

Displaying results in IRIS is separate from sending them back into an external SIEM or GRC product. That second task needs outbound connectors.

For an approved GRC proposal, track a delivery lifecycle such as **queued > sent > acknowledged**, with explicit failed/retry states. A local outbox row is only queued; it is not evidence that a remote risk register was changed. No control execution or official risk update is authorized merely by a model prediction or model-level release.

## 6. The examiner walkthrough to build toward

1. Show loaded inventory/risk context and healthy data sources.
2. Generate an authorized controlled lab event, or replay a recorded event set with a visible replay label.
3. Show the received evidence, asset/risk match and session construction.
4. Show the SOC assessment and priority; label any ML result as shadow/test while release is blocked.
5. Open the same case in GRC and review its evidence and proposed controls/risk reassessment.
6. Approve or reject a proposal and show the audit trail. If testing delivery, show a real acknowledgement from the explicitly labelled test GRC endpoint.
7. Change approved business context and show a new evaluation/priority for a relevant open case, retaining the prior decision and context version.

Live inbound collection, external GRC delivery/acknowledgement, enterprise user authentication and GRC-change-triggered re-evaluation are still to be built. The new backend records a local follow-up disposition, not an external update or an outbox delivery. Do not present its audit rows or screenshots as proof of live integrations.

The current sample classifier fails the configured false-positive gate and is synthetic. It is appropriate for a transparent prototype demonstration, not a claim of production readiness. Compare real held-out predictions with analyst reviews before considering advisory release.

## 7. Practical build order

1. Reproduce training and label-free prediction in Colab.
2. Add the new three-source preparation and saved-model adapter to the backend.
3. Demonstrate file/replay processing, persistent decisions and separate role views.
4. Add SIEM collection, reliable approved GRC delivery and context-change re-evaluation.
5. Add authenticated roles, security hardening and real campaign validation.

## Official references

- [Colab FAQ and runtime lifetime](https://research.google.com/colaboratory/faq.html)
- [Colab runtime versions](https://research.google.com/colaboratory/runtime-version-faq.html)
- [FastAPI model loading with lifespan](https://fastapi.tiangolo.com/advanced/events/)
- [Wazuh Indexer API](https://documentation.wazuh.com/current/user-manual/indexer-api/index.html)
- [Wazuh custom API integrations](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html)
