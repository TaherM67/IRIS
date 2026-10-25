# Original dashboard, team-related content only

The original working dark dashboard is restored from the pre-separation version. Its colours, top navigation, forms, proposal summaries, evidence sections, register, queue and before/after history remain in the original style. Both later redesigns have been removed.

Only the content scope differs:

| Page | Content |
| --- | --- |
| Admin | Original five counters, engine controls, team proposals, full evidence/model/audit/history, plus both original working tables |
| SOC | Alert count, reprioritized count, SOC pending count, priority proposals and technical evidence, alert queue and SOC changes |
| GRC | Risk count, changed-risk count, GRC pending count, risk proposals and control context, risk register and GRC changes |

SOC receives no risk-register values, GRC control recommendations, cross-team counters or Admin commands. GRC receives no alert queue, raw telemetry, model confidence or Admin commands. Model reports are Admin-only. Each team sees only its own dashboard navigation link.

The backend omits unrelated blocks from the **original HTML**, and the existing key-derived API allowlists enforce the same separation. This is not an extra set of redesigned pages. Admin can see both teams but still cannot approve on their behalf.

The browser independently selects API reads from its server-confirmed role, not from the presence of panels. If an older server returns the complete original HTML, the controller hides unrelated sections/counters and still never requests another team's table. This fixes valid SOC sign-in failing with an ADMIN OR GRC permission error while loading records.

## Sign-in is the original flow

Run `python demo.py`, then run `python demo.py keys` in a second private terminal **from the same project folder**. Paste only the matching role token into the original **Connect this dashboard** form.

The browser authenticates directly with `/api/demo/state`, as in the working version. The redesign's build/profile/session gates, new access module, `doctor` command and `keys --role` option have been removed. No key or database reset is needed. See [the access guide](ACCESS_HELP.md).

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

No retraining, Colab session, dependency installation or migration is needed for this restoration. A completely new extracted folder has a different `.local` unless you deliberately preserve your prior state.

## The engine still makes real demo changes

The same models, datasets, explicit risk policy, approval transactions and database schema are used. GRC approval can change the demonstration risk score **0.60 → 0.80**; SOC approval can move **19 alerts to Critical**. The source JSON inputs are not overwritten. Control advice is not executed.

The rejected redesign files remain recoverable in Git history. No user credentials or saved working records are deleted by this update.

## Verification boundary

Core/model/real loopback HTTP regressions and controller unit checks cover the restored workflow and role separation. The original stylesheet rules are byte-identical, followed only by a team-only three-counter layout rule. Controller tests are not a real-browser visual check; rehearse locally before presenting.
