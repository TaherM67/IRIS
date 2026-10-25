# IRIS: active examiner demonstration

This is the new **active demo**, launched by **`demo.py`**. It replaces neither the trained models nor the earlier FastAPI prototype. It reuses the same `backend.core.Engine`, source integration, saved Colab models and explicit policy, with a small loopback HTTP adapter and three new dashboards.

The difference is real: after the appropriate human approval, the backend **writes updated synthetic risk-register records and alert priorities to SQLite**. These are not cosmetic changes in JavaScript. Reloading a page, downloading the current register, or restarting the server shows the saved values.

Everything is fictional. This is a simulated SOC/GRC integration with real local persistence, not a connection to an actual hospital or company.

## 1. Get the updated project

Open [TaherM67/IRIS](https://github.com/TaherM67/IRIS), select **Code → Download ZIP**, extract it, and open a terminal in the extracted `IRIS-main` folder. You must see `demo.py`, `demo_app/`, `demo/data/`, `backend/` and `artifacts/` together.

If you already use a Git clone, update your clone normally instead. Do not run `demo.py` as an isolated downloaded file: it needs the rest of the repository, including the pinned models.

## 2. Prepare Python once

Use **Python 3.12**. No GPU, Colab session, Node.js, database server, cloud account or LLM key is required.

Windows PowerShell, from the project root:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r IRIS_Models_v2/requirements.txt
.\.venv\Scripts\python.exe -m unittest demo_app.tests.test_demo -v
```

macOS/Linux:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r IRIS_Models_v2/requirements.txt
.venv/bin/python -m unittest demo_app.tests.test_demo -v
```

If a suitable `.venv` already exists, skip creating it. The **55 demo tests** should finish with `OK`. Do not proceed to the examination with a dependency error or failed test. Keep the ML dependency pins: the trusted saved models require the matching scikit-learn version.

This demo server uses Python's standard HTTP library, so it does **not** need `requirements-backend.txt` or FastAPI. The older FastAPI interface on port 8000 has its own installation and verification requirements; it is not the active demo described here.

## 3. Run the demo script

Windows:

```powershell
.\.venv\Scripts\python.exe demo.py
```

macOS/Linux:

```bash
.venv/bin/python demo.py
```

Keep this terminal open. The script:

1. Creates separate local **demo** Admin/SOC/GRC keys on the first run only.
2. Checks the three bundled synthetic datasets and the trusted model hashes.
3. Loads the saved model components once; it does not retrain them.
4. Creates or reopens the working demo database.
5. Seeds the original risk register and clean, matched alert queue if this is a new exercise.
6. Serves all three dashboards at port **8010** on **127.0.0.1 only**.

The server never replaces existing keys or discards approved changes on restart. If port 8010 is already occupied, stop your earlier demo instance or run `demo.py --port 8011` and use that port consistently.

## 4. Open the three dashboards

In a **second private terminal**, from the same project folder, display your demo keys:

Windows:

```powershell
.\.venv\Scripts\python.exe demo.py keys
```

macOS/Linux:

```bash
.venv/bin/python demo.py keys
```

Open three browser tabs:

| Tab | URL | Key and responsibility |
| --- | --- | --- |
| Admin | <http://127.0.0.1:8010/admin> | Admin key; analyze, monitor, audit and start a fresh rehearsal |
| SOC | <http://127.0.0.1:8010/soc> | SOC key; inspect and approve/reject alert-priority changes |
| GRC | <http://127.0.0.1:8010/grc> | GRC key; inspect and approve/reject risk-register changes |

Paste only that tab's key into its password field. Keys remain in the tab's memory, not browser storage or URLs. The earlier `python -m backend keys` command produces **different keys for the older passive prototype**: do not mix them up.

The original dark page and direct `/state` sign-in are restored. There is no build/profile/session prerequisite. The redesign-only `doctor` and `keys --role` commands are removed; use the original `demo.py keys` above. See [the access guide](ACCESS_HELP.md); do not delete `.local/` to troubleshoot.

Hide the key terminal before sharing your screen. These are shared lab role keys, not individual enterprise identities or SSO. The Admin can inspect all proposals but **cannot impersonate the SOC or GRC approver**.

## 5. Show the before state

In GRC, the live register initially shows 60 current risks, with original and current values equal. Six historical risk pairs are retained in the source file for point-in-time enrichment, but the working register contains current records only.

In SOC, the working queue contains **2,355 matched unique alerts** sorted by their original technical priority. The source file has **2,367 rows**: six exact duplicate rows, one invalid timestamp, both rows of one conflicting event ID, and three unresolved-asset rows do not become working queue entries.

On Admin, both **Risks updated** and **Alerts reprioritized** must show **0** in a fresh exercise. Each team sees only its own counter.

For a predictable example, find the `identity-server` access risk **`DEMO-R001-1`**. Its original likelihood is **3**, impact is **5**, and normalized score is **0.60**.

## 6. Run the actual analysis

On **Admin**, click **Analyze the three demo datasets**. Only Admin runs analysis; each team receives only its own results.

The backend reads the fixed files in `demo/data/`, combines context before feature engineering, cleans events, creates 60-second-window sessions, runs your saved model bundle, and evaluates the explicit risk policy. It saves **132 cases** and prepares **123 SOC proposals** and **63 GRC proposals** for this initial evidence batch.

No working risk values or alert priorities change merely because analysis finished. Wait for proposals in the team tabs, or press **Refresh**. Visible, connected tabs poll the server every three seconds.

The first pending proposal in each team inbox is the newest `identity-server` example. Its stable session ID is **`SES-65f5edbf869d111d265c`**. Other background sessions can reference the same hostname; use the first proposal. Expand the original evidence section for the selected proposal. SOC receives technical alert evidence; GRC receives registered-risk and control context, not raw telemetry/model confidence. Admin can inspect the full evidence.

## 7. Make the GRC register really change

In the **GRC** tab:

1. Select the first `identity-server` GRC proposal.
2. Expand **Inspect registered risk, control advice and update rationale** to inspect the matched risk, proposed values and control advice. GRC does not receive the raw telemetry or model-confidence report.
3. Confirm the proposed likelihood **3 → 4** and score **0.60 → 0.80**. Impact remains **5**.
4. Enter a reason, for example: `Reviewed the login burst. Approve this synthetic register change for the demonstration.`
5. Click **Approve and apply to demo records**.

The backend checks that you are GRC and that the saved risk revision still matches the proposal, then atomically:

- Updates the current demo risk likelihood to 4 and its revision to 2.
- Saves the approver role, reason, timestamp and proposal identifier.
- Records before/after values and an audit event.
- Marks other proposals based on the same old risk revision stale, preventing repeated increases from the same evidence.

The register row turns green, moves to the top, and shows **0.60 → 0.80**. **Risks actually changed** becomes **1** in GRC and Admin. SOC does not receive this GRC counter. The original input JSON is deliberately unchanged; the simulated GRC system's working database is what changes.

Click **Download current register** to prove the backend export now contains likelihood **4**, not 3. Reloading the page requires reconnecting with the key, but the risk remains changed.

## 8. Make the SOC alert queue really change

In the **SOC** tab:

1. Select the first `identity-server` SOC proposal for the same session.
2. Inspect the proposed **Critical** priority and the saved technical/business evidence.
3. Enter a reason, for example: `Reviewed the evidence and critical asset context. Approve reprioritization in the synthetic SOC queue.`
4. Click **Approve and apply to demo records**.

There are 29 alerts in this session. **19** are lower than Critical and actually change; the remaining **10** were already Critical and are not needlessly rewritten. The backend updates the 19 records, increments their revisions and records their before/after priorities. The queue is sorted from the stored current priority on each read.

The SOC view switches to **Only reprioritized alerts**, making the **19 changed rows** easy to show. Their original priorities remain visible alongside current **Critical**. Uncheck the filter to see them in the whole reordered queue. **Alerts reprioritized** becomes **19** in SOC and Admin. GRC does not receive this SOC counter.

GRC approval does not secretly approve SOC changes, or vice versa: each team explicitly authorizes its own mutation.

## 9. Show rejection, audit and persistence

- **Reject:** choose a different pending proposal and click **Reject** with a reason. It leaves the working values unchanged and audits the rejection.
- **Admin audit:** show `demo_approved` events, their team roles, record counts, and before/after entries. Analysis reports and the loaded model hash are also visible.
- **Persistence:** stop the demo with Ctrl+C, start `demo.py` again, reconnect, and show that the one changed risk and 19 reprioritized alerts are still saved.
- **Download proof:** export the current register and priorities from the respective team dashboards. They reflect the working database, not a hard-coded screenshot.
- **Safe retry:** clicking an already approved proposal through the API is idempotent. It does not apply the same change twice.

## 10. Rehearse again without deleting anything

On Admin, expand **Start a fresh rehearsal without deleting history**, name the exercise, and click **Create new rehearsal**. Confirm the dialog.

This creates another seeded set of synthetic working records and makes it current. Older exercises, changes, immutable model cases and audit history remain saved. Other tabs switch on refresh; old proposals cannot mutate the new exercise.

Click **Analyze the three demo datasets** again. Byte-identical evidence reuses the existing 132 saved model cases; it does not retrain, erase reviews or invent new predictions. New proposal identities belong to the new exercise, so you can repeat the approvals cleanly.

## How the backend works, simply

| Action | Backend behavior | What the examiner sees |
| --- | --- | --- |
| Start `demo.py` | Load models, check synthetic inputs and open SQLite | Separate Admin/SOC/GRC pages |
| Admin clicks Analyze | POST request calls the shared engine; source integration and actual inference create saved cases/proposals | New evidence and approval inboxes; no premature changes |
| GRC approves | Authenticated POST verifies saved proposal + revision, then writes the working risk table | Current likelihood and risk score visibly change |
| SOC approves | Authenticated POST verifies all target revisions, then updates the working alert rows atomically | Current priorities change and the queue is reordered |
| A tab refreshes | GET requests read current database values | All connected dashboards show persisted changes |
| A team exports | GET returns current working records | Downloaded JSON proves the change exists on the backend |

The browser **pushes commands with POST**; it **pulls updated state with GET polling every three seconds**. It does not run the model itself. These are HTTP requests, unrelated to GitHub pull requests.

The persistent state is isolated at **`.local/active_demo/state/iris.sqlite3`**. Demo keys are in **`.local/active_demo/access.json`**. Both stay outside GitHub via `.gitignore`. Source inputs are in `demo/data/`; trusted models remain in `artifacts/user_colab_run/models/`.

Database tables prefixed `demo_` contain working records, approvals and changes. Existing `cases` and `runs` contain immutable analysis evidence. The same database transaction stores the approved mutation and its change/audit evidence, so an approval cannot appear completed without its target write.

## What is and is not driven by ML

Both saved ML components run through the shared engine: scenario candidates and control candidates are available under evidence. They remain **unreleased synthetic-data shadow predictions** because the existing validation gate failed. This feature does not change their training, thresholds or release status.

The executable priorities and proposed likelihoods use the existing **primary rules plus explicit business-risk policy**, not a claim that the ML model predicts official risk values. The model is not a likelihood/impact regressor. The dashboard shows that distinction rather than silently substituting a prediction for an approved decision.

The active part is the **human-approved application** of an engine proposal to the simulated working systems. It is real persistence using fictional data. It is neither a real company integration nor automatic defensive control execution.

## Demonstration limits

- No live SIEM collector, real GRC connector, external push, streaming ingestion, enterprise authentication or patient data is configured.
- No security control is installed, extended or switched off by these approvals. Catalogue advice remains advice.
- The original model's synthetic false-alarm and coverage limitations remain unchanged. Do not present demo pass counts as independent model accuracy.
- A stale risk proposal is blocked; the current implementation does not automatically re-score newly changed organizational data. New real-world evidence would require a fresh export/reanalysis and an appropriate connector workflow.
- The original SIEM technical bands are demo initialization logic; they are not a claim to reproduce an actual vendor's priority configuration.
- Three-second refresh is polling, not WebSockets. Shared role keys are for a private lab only.
- Python's standard-library HTTP server is for a local demonstration, **not production hosting**. It deliberately refuses non-loopback binding. Do not expose it with a tunnel or public port.
- The actual loopback HTTP/API approval workflow is covered by automated tests. Browser layout and click-through still need a rehearsal in your own browser; no headless browser executable was available in the build environment.

## One-minute explanation for the examiners

> These three sources are artificial because we do not have access to a company system. The backend is real: it combines the sources, runs the saved models, applies the explicit risk policy and queues changes for human review. GRC approval writes a new risk revision; SOC approval writes alert priorities and reorders the queue. Both teams then read the saved values from the backend, and Admin can show the audit trail. ML results remain clearly marked as experimental shadow candidates, and no external company records or security controls are changed.
