# Admin backend activity window

Adds one read-only **Backend activity** card to the existing Admin dashboard. Styling, login, models, datasets, risk policy, approvals and database schema are unchanged. The pending GRC missing-control-list fix is included in `app.js`.

## Four runtime files to update

Keep these exact GitHub paths:

1. **Add** `demo_app/activity.py`.
2. Replace `demo_app/server.py`.
3. Replace `demo_app/static/app.js`.
4. Replace `demo_app/static/index.html`.

Extract the ZIP first. Use GitHub **Add file → Upload files** from the repository root and upload the `demo_app` folder, inspecting the changes before committing. Alternatively create/edit each path individually. Do not put files at the repository root or upload the ZIP instead of its source files. Upload all four before running the update.

Keep `.local/`, your models, datasets and virtual environment. No retraining, dependency installation, new keys or migration is needed.

## Show it to the examiners

1. Stop the old server with Ctrl+C.
2. Copy the four files to the matching paths in your existing local project, or pull/download your manual GitHub update. Keep `.local/`.
3. Restart with the same command, for example on Windows:

   ```powershell
   .\.venv\Scripts\python.exe demo.py
   ```

4. Open <http://127.0.0.1:8010/admin>, Ctrl+F5, and use the same Admin key. The new card is above the existing engine controls.
5. Click **Analyze the three demo datasets**. The card shows its real start and completion, duration and session count. It polls while the POST is running. Fast actions may finish between polls; no fake delay or percentage is inserted.
6. In the GRC or SOC tab, approve a proposal. Return to Admin to see the real review outcome and number of records written. Compare it with the existing working tables and persistent audit.

The live switch controls the monitor. It updates every second in a visible Admin tab. SOC/GRC cannot access the activity endpoint. A monitor failure never blocks normal login or actions.

## Boundaries

This is actual authenticated HTTP command activity, not a terminal or per-line engine trace. It observes analysis, rehearsal creation and reviews, but does not separately instrument internal cleaning/model substeps.

Times are UTC and newest first. Only the last 250 events from this server process are kept; restarting clears them. The existing database audit remains the persistent proof.

Keys, request bodies, review reasons, raw URLs and tracebacks are never copied into the feed. Reads/polls do not create command events. No shell, extra approval powers, database migration or control execution is added.

## Verification and publication

177 Python tests and 20 controller scenarios pass, including a real concurrent HTTP check while a command is running and a real 19-record SOC approval count. Controller tests are not browser-render tests; rehearse locally.

Use the repository source or the supplied ZIP to install the update. All four runtime files must be updated together before restarting the local Python server. Updating GitHub alone does not change an already-running local copy.
