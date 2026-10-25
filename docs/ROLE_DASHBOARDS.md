# Focused, role-specific dashboards

The active demo at port 8010 now has three focused workspaces. The saved models, three input datasets, approvals, database schema and existing demo keys are unchanged.

The refreshed interface uses a navy navigation rail, bright workspace, teal action buttons, clear status labels and compact comparison cards. Each role has its own navigation and workflow; data remains real backend state, not decorative sample counters. Detailed evidence stays expandable so the main screen is easy to explain.

**Cannot sign in? Start with [the access recovery steps](ACCESS_HELP.md).** The new `demo.py doctor` checks all three role keys against the running server without printing them. The sign-in page identifies old builds, shows a non-secret key-profile label and accepts a single labelled key paste.

| Workspace | Main content | Hidden from this team's API and page |
| --- | --- | --- |
| SOC | Alert count, priority reviews, reprioritized count, alert queue, technical evidence and priority-change history | Risk register/values, GRC controls/reviews/counters, model evaluation reports, Admin commands and audit |
| GRC | Risk count, risk reviews, updated-risk count, register, likelihood/impact/score, control advice and register-change history | SOC queue/counters, raw telemetry features, scenario-model confidence, model evaluation reports and Admin commands/audit |
| Admin | Both working systems and counters, all review statuses, analysis, full proposal evidence, model reports and audit/history | Team approval authority: Admin still cannot impersonate SOC or GRC |

This is not only visual filtering. The backend chooses a different HTML partial for each page and projects `/api/demo/state` and `/api/demo/proposals` from the **authenticated key**. Other-team table/export endpoints remain forbidden. The browser cannot request more access with a `role` or `actor` parameter.

## How to explain each page

- **SOC:** “These are our alerts. IRIS proposes a new priority. We check the technical reason, approve it, and the queue updates.”
- **GRC:** “This is our risk register. IRIS proposes a likelihood and score update. We review the risk and control context, approve it, and the register changes.”
- **Admin:** “We run the analysis, monitor both teams' saved changes and show the full model/audit evidence.”

Each team starts with only three relevant counters. Its review card shows a clear **Current → Recommended** comparison. **Why this change?** expands the relevant explanation; no raw JSON or internal model report is shown on a team home page. Recent applied changes are collapsed by default. Admin keeps technical JSON under expandable system/evidence sections.

The approvals still apply real changes to synthetic working records. In a fresh rehearsal, the first identity-server risk review changes **0.60 → 0.80**; its SOC review changes **19 alerts to Critical**. Only GRC/Admin see the risk-update count; only SOC/Admin see the alert-change count.

GRC's control recommendations remain advice: approving a risk update does not install a control. SOC's optional model comparison remains an experimental shadow prediction, not an approved decision or risk probability.

## Update the demo you already tried

1. Stop the running server with **Ctrl+C**.
2. If you cloned the repository, pull the updated source normally. If you use GitHub ZIP downloads, extract the new ZIP elsewhere and copy the updated **`demo.py`** and **`demo_app/`** into your existing project. Preserve any local source edits first. Both are required for the new access diagnostics.
3. **Keep your existing `.local/` folder.** It contains your demo keys, approved records and history. No database reset or migration is needed.
4. Start the demo with the same Python command as before, for example on Windows:

   ```powershell
   .\.venv\Scripts\python.exe demo.py
   ```

5. In a second terminal, run `.\.venv\Scripts\python.exe demo.py doctor`. Then reload the three browser tabs with **Ctrl+F5** and reconnect with the same corresponding keys:
   - Admin: <http://127.0.0.1:8010/admin>
   - SOC: <http://127.0.0.1:8010/soc>
   - GRC: <http://127.0.0.1:8010/grc>

You do not need Colab, retraining, a new dependency install or Node.js to run this update. If you intentionally start from a completely new extracted project folder, it will have fresh demo state/keys rather than automatically finding the old folder's `.local` state.

## Verification boundary

The actual model/core/HTTP suites pass, including new role-response and served-HTML isolation checks. Optional Node controller unit checks cover all three roles and their UI requests/rendering. A real-browser visual/layout test was not available in the build environment; rehearse the refreshed pages before presenting. The earlier passive FastAPI interface on port 8000 is unchanged.
