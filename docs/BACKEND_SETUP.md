# Run IRIS locally: step by step

**For the active examiner demo, use [`demo.py` and the active demo guide](ACTIVE_DEMO.md).** It applies approved changes to a synthetic risk register and alert queue on port **8010**. The instructions below describe the **earlier passive FastAPI prototype** on port **8000**. The two servers have separate keys and state.

## Read this first

This is a **local, shadow-only prototype**, not a production deployment.

The user's uploaded models loaded successfully and produced predictions for all 900 supplied synthetic sessions. The new model adapter, risk-policy separation, SQLite storage and authentication/body-limit ASGI guard can be tested without FastAPI. **The actual FastAPI/Uvicorn HTTP server and browser interactions were not run in the build environment**: package downloads from PyPI returned `403 Forbidden`.

You explicitly requested the prepared backend despite that limitation. Run the HTTP tests below on your computer before relying on this interface. Do not treat Python syntax checks or core tests as proof that the HTTP/UI integration works.

You do not need to train again, keep Colab open, buy a domain, or rent a server. The uploaded model is already included at `artifacts/user_colab_run/models/`.

## 1. Download the updated project

1. Sign into GitHub and open [TaherM67/IRIS](https://github.com/TaherM67/IRIS).
2. Select **Code > Download ZIP**, then extract it.
3. Open a terminal in the extracted `IRIS-main` folder.
4. Check you can see `backend`, `IRIS_Models_v2`, `artifacts`, and `requirements-backend.txt` in that folder.

If you already use Git, `git pull` in a clean clone is an alternative. Do not overwrite unrelated local work or copy only the backend folder; it needs the model package and artifact beside it.

## 2. Create a Python 3.12 environment

### Windows PowerShell

```powershell
py -3.12 --version
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-backend.txt
```

### macOS or Linux

```bash
python3.12 --version
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements-backend.txt
```

These commands use the environment directly; you do not need to activate it or change PowerShell's execution policy. If Python 3.12 is missing, install it from [python.org](https://www.python.org/downloads/) or your normal trusted OS package manager, then reopen the terminal.

The web dependency pins are preparation targets; installation/resolution was not verified here because downloads were blocked. If installation fails, stop and share the error without credentials. Do not silently remove the scientific-library pins: the model requires matching scikit-learn and feature contracts.

## 3. Check the model and run both test suites

### Windows

```powershell
.\.venv\Scripts\python.exe -m backend check
.\.venv\Scripts\python.exe -m unittest backend.tests.test_core -v
.\.venv\Scripts\python.exe -m unittest backend.tests.test_http -v
```

### macOS or Linux

```bash
.venv/bin/python -m backend check
.venv/bin/python -m unittest backend.tests.test_core -v
.venv/bin/python -m unittest backend.tests.test_http -v
```

Both test commands must finish with **OK**. The HTTP suite deliberately fails rather than silently skipping itself when FastAPI is missing. It exercises authentication, three-file uploads, role restrictions, model reuse, local-only GRC reviews and the actual HTTP integration path.

The model status must show `mode: shadow_only`, the uploaded model hash, and false release/automatic-execution flags. A failed release flag is expected for this synthetic model; do not bypass it.

The original ML checks can also be run from this folder with the same Python executable:

```text
-m unittest discover -s IRIS_Models_v2/tests -v
```

That is the argument suffix, not a standalone shell command. For example, on Windows run `.\.venv\Scripts\python.exe -m unittest discover -s IRIS_Models_v2/tests -v`.

## 4. Optionally run the complete adapter without HTTP

Windows:

```powershell
.\.venv\Scripts\python.exe -m backend smoke
```

macOS/Linux:

```bash
.venv/bin/python -m backend smoke
```

This processes the bundled three sources through the actual uploaded model and SQLite adapter. Expect 900 sessions, `training_labels_read: false`, `automatic_execution: false`, and `official_risk_register_write: false`. Repeating the exact inputs reuses the completed run instead of duplicating cases.

The smoke test stores its own evidence under `.local/smoke`; the website uses `.local/state`. They are separate, so the website still needs its first batch.

## 5. Generate local role keys once

Windows:

```powershell
.\.venv\Scripts\python.exe -m backend init
.\.venv\Scripts\python.exe -m backend keys
```

macOS/Linux:

```bash
.venv/bin/python -m backend init
.venv/bin/python -m backend keys
```

Keep the three generated keys private. The `keys` command intentionally prints them in your terminal; do not screen-record it or paste its output into GitHub or chat.

- **Admin key:** status, audit and read access to both views; can submit data.
- **SOC key:** SOC cases and data submission.
- **GRC key:** GRC cases and local follow-up review; cannot submit batches.

The keys are saved in ignored `.local/access.json`. They are shared lab role keys, not enterprise user accounts or individual reviewer identities. Unix creation uses restrictive file permissions; on Windows protect the folder with your normal private user-account access controls.

If `init` says the file already exists, **do not overwrite it**. Skip `init` and use `keys` to read the existing configuration. No real credentials are committed to the repository.

## 6. Start the backend and website

Windows:

```powershell
.\.venv\Scripts\python.exe -m backend serve
```

macOS/Linux:

```bash
.venv/bin/python -m backend serve
```

Leave this terminal open. Once startup succeeds, open:

**[http://127.0.0.1:8000](http://127.0.0.1:8000)**

The same server provides the backend and the HTML website. There is no separate Streamlit command for this new backend, and Colab is not involved in predictions.

API documentation is at `http://127.0.0.1:8000/docs`; its Swagger assets may need internet access. The main dashboard's HTML/CSS/JavaScript are all local. In Swagger, choose **Authorize** and enter a local role key as `X-IRIS-Key`.

If port 8000 is busy, append `--port 8001` to the serve command and use `http://127.0.0.1:8001`. Binding is deliberately restricted to loopback. Do not change it to a public interface for an examination.

## 7. Run your first browser demonstration

1. Paste the **Admin key** into the website and select **Connect**.
2. Select **Analyze bundled sample**. Wait for completion; processing 900 sessions may take a minute or more.
3. Use the **View** selector to inspect the SOC and GRC read views. Both show the same stored case IDs with different information.
4. SOC shows the primary rule assessment, ML shadow candidate, affected asset, evidence and prototype policy priority.
5. GRC shows registered-risk context, the proposed review and candidate controls. The ML control scores are not probabilities of control effectiveness or risk reduction.
6. To record a review, disconnect and connect with the **GRC key**. Select a case, give a reason, and save **Approve follow-up** or **Reject suggestion**.
7. Reconnect with the **Admin key** and inspect recent audit events.

The Admin role cannot submit a GRC review on behalf of the GRC role. A local review does not deploy a control, deliver a message, or change an official risk register. Prior reviews/evidence are not overwritten.

The page refreshes approximately every ten seconds while connected and visible. Keys stay in page memory only; disconnecting or reloading requires you to enter a key again.

## 8. Try your own three exports

As Admin or SOC, select:

1. `asset_inventory.json`.
2. `risk_register.json`.
3. `siem_alerts.jsonl`.

Then select **Analyze the three files**. The field names, provenance, historical validity and sensor-health evidence must follow [the input contract](../IRIS_Models_v2/docs/THREE_INPUTS_GUIDE.md). This is not a universal vendor-file importer.

Do not upload labels, model files or arbitrary server paths. The HTTP API never trains a model or accepts a replacement pickle. Use only data authorized for the environment.

Limits are 5 MiB each for inventory/register, 20 MiB for alerts, 32 MiB for the whole request, 50,000 alert rows and 2,000 sessions. Inventory/register exports each allow at most 5,000 snapshots. A batch allows at most 10 distinct risks per asset and an upper bound of 200,000 alert-by-risk context links, checked before enrichment to bound expansion. These are prototype resource limits, not a throughput guarantee. This is in-memory batch processing with one worker, not a durable streaming queue. Only one batch may run at a time; a simultaneous submission receives a conflict response and can be retried later.

Identical file bytes plus the same model/policy/window reuse a completed run, including after restart. Changed exports create a new run; historical decisions remain intact. Alert history and `previous_similar_24h` are reconstructed within each batch, not maintained as a live cross-batch stream.

## 9. Stop and restart

Press **Ctrl+C** in the server terminal. To restart, run the same `serve` command. The database, source copies, prepared evidence and local reviews remain under `.local/state`; you do not retrain or regenerate keys.

Do not commit `.local`, share its keys, or delete evidence casually. This prototype has no automated retention, backup or disk-quota system.

## What to tell the examiners

> We trained the two ML components offline in Colab and loaded the saved bundle into a Python backend. The backend validates and combines three operational sources, creates sessions using the training contract, and stores evidence and separate SOC/GRC views. ML results remain shadow-only. Explicit policy produces review proposals; a human review is recorded locally and never automatically changes the official risk register.

Be explicit that the datasets are synthetic and the model fails its configured false-positive release gate. Do not describe these scores as real enterprise validation. The build environment tested the core but not the HTTP/browser runtime; demonstrate the successful target-computer test output after you have run it.

## What is still missing

- Live Wazuh/SIEM polling or push receivers connected to a real source.
- External GRC delivery, retries, acknowledgements and official register writes.
- Automatic GRC-change-triggered re-evaluation of open cases.
- Durable streaming/session state, multiple workers, load/failure testing and retention controls.
- Enterprise users/SSO, TLS deployment, rate limiting and security review.
- Independently reviewed real campaign data and production-quality model validation.

This prototype is a transparent local demonstration foundation, not an internet-facing SOC/GRC product.
