# Dashboard workspaces

The dashboards use a navy/lavender dark workspace with chat as the first panel, sidebar
navigation, compact counters and a scrollable approval inbox. All existing
analysis, approvals, evidence, exports, live records, history and role permissions
remain available. Long explanations and diagnostics expand on demand.

Each workspace shows the data and controls appropriate to its role:

| Page | Content |
| --- | --- |
| Admin | Five counters, engine controls, team approval inbox with SOC/GRC filters, full evidence/model/audit/history, both working tables, read-only chat and backend monitor |
| SOC | Alert count, reprioritized count, SOC pending count, priority proposals and technical evidence, alert queue and SOC changes |
| GRC | Risk count, changed-risk count, GRC pending count, risk proposals and control context, risk register and GRC changes |

SOC receives no risk-register values, GRC control recommendations, cross-team counters or Admin commands. GRC receives no alert queue, raw telemetry, model confidence or Admin commands. Model reports are Admin-only. Team sidebars show workspace sections; only Admin has links to the separate dashboards.

The backend omits unrelated blocks from the shared HTML, and the key-derived API allowlists enforce the same separation. Admin can see both teams but cannot approve on their behalf. SOC and GRC can use the shared chat; Admin monitors it read-only.

The browser independently selects API reads from its server-confirmed role, not from the presence of panels. It also hides unrelated sections/counters if a full template is returned. It never requests another team's table.

## Approval inbox and chat

Select an approval card instead of using a dropdown. The bounded inbox scrolls
independently and supports asset, risk-ID and case-ID search. Admin can filter
the list by SOC or GRC. Filtering does not silently switch your selected decision.
Live refresh preserves the selection, inbox position and decision note; a proposal
that is no longer pending clears the selection rather than choosing another one.

The chat at the top can be collapsed while messages keep updating. An unread badge
counts new messages from other teams while collapsed. At narrow widths the
layout stacks; the Team chat navigation link jumps to the conversation. Chat
history persists across restarts, and Disconnect clears messages from the tab.

## Sign-in uses the existing flow

Run `python demo.py`, then run `python demo.py keys` in a second private terminal **from the same project folder**. On the **Sign in** screen choose Administrator, SOC analyst or GRC officer, then paste the matching role token. Clicking a different role updates the card, key hint and sign-in button in place, without navigation or a page reload. It clears the key field. After the matching key is validated, the role-filtered workspace loads in the same document and the URL updates without reloading. The key stays in memory and still determines the authenticated role.

The entry screen has an IRIS introduction, three actual bundled-input totals and
large role cards. It hides the working sidebar until sign-in succeeds. Model
predictions are described as comparisons; only an authorized approval changes
the demo records. The connected workspace retains every existing function.

The browser authenticates directly with `/api/demo/state`. The new layout adds no build/profile/session gates or new key commands. No key or database reset is needed. See [the access guide](ACCESS_HELP.md).

## Update your existing working project

1. Stop the server with **Ctrl+C**.
2. Pull the latest source if you use Git. For ZIP downloads, extract the updated ZIP elsewhere and copy **`demo.py`** and **`demo_app/`** into your existing working folder, preserving your own edits first. The active page uses only `index.html`, `app.js` and `style.css`; old partial-template files are unused.
3. **Keep `.local/` and your existing virtual environment.** They contain your keys, saved approvals/history and installed dependencies.
4. Restart with the same Python executable as before, for example:

   ```powershell
   .\.venv\Scripts\python.exe demo.py
   ```

5. In a second private terminal in that same folder:

   ```powershell
   .\.venv\Scripts\python.exe demo.py keys
   ```

6. Press **Ctrl+F5** in each tab and reconnect with its own key:
   - Admin: <http://127.0.0.1:8010/admin>
   - SOC: <http://127.0.0.1:8010/soc>
   - GRC: <http://127.0.0.1:8010/grc>

No retraining, Colab session or new dependency installation is needed for this layout. A completely new extracted folder has a different `.local` unless you deliberately preserve your prior state.

## The engine still makes real demo changes

The same models, datasets, explicit risk policy, approval transactions and database schema are used. GRC approval can change the demonstration risk score **0.60 → 0.80**; SOC approval can move **19 alerts to Critical**. The source JSON inputs are not overwritten. Control advice is not executed.

Existing credentials, chat history and saved working records are preserved.

## Verification boundary

All 75 Python demo/chat/activity regressions pass, including real loopback HTTP,
approval writes, authentication and role separation. Frontend controller tests
also cover inbox selection, search, team filters, draft/scroll preservation,
chat collapsing and unread counts. Browser previews use a separate temporary
database and synthetic test keys so they do not change the user's records.
