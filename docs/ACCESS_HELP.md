# Original demo sign-in

The working dashboard and its original key flow are restored. **Do not delete `.local/` or regenerate your keys.** There is no build/profile/session prerequisite.

## Windows

1. Stop the old server with **Ctrl+C**, update **`demo.py`** and **`demo_app/`**, and keep your existing `.local/` folder.
2. In your existing project folder, start:

   ```powershell
   .\.venv\Scripts\python.exe demo.py
   ```

3. Leave that terminal running. Open a second private terminal **in the same folder**:

   ```powershell
   .\.venv\Scripts\python.exe demo.py keys
   ```

4. Open the matching page, press **Ctrl+F5**, and paste **only the token after the role label**, not `admin:`, `soc:` or `grc:`:

   | Page | Address | Required token |
   | --- | --- | --- |
   | Admin | <http://127.0.0.1:8010/admin> | Admin |
   | SOC | <http://127.0.0.1:8010/soc> | SOC |
   | GRC | <http://127.0.0.1:8010/grc> | GRC |

5. Click **Connect** in the original form. Hide the key terminal before screen sharing.

On macOS/Linux use `.venv/bin/python` instead. With the correct environment activated, `python` works on either platform. If you selected another server port, use that port in every URL. Open the HTTP page, not the HTML file directly.

## If access still fails

**Correct SOC key, but “This action requires the ADMIN OR GRC role”:** this is a dashboard-loading error, not a rejected key. Older/unfiltered HTML contains both team panels. The previous controller treated the presence of a risk panel as a reason to fetch `/risks`, even after signing in as SOC. The backend correctly denied it. The corrected `demo_app/static/app.js` chooses requests by the authenticated role: SOC never requests risks; GRC never requests alerts; Admin requests both. It also hides unrelated panels/counters if old HTML contains them. Update that controller, restart the server and Ctrl+F5. Keep the same keys; do not try an Admin key on the SOC page or relax backend permissions.

If the page shows variable names or template tokens instead of labels, an older server may be serving newer HTML without rendering it. Update **both `demo.py` and `demo_app/`**, stop the running process with Ctrl+C, restart from that same project folder and press Ctrl+F5. Open **http://127.0.0.1:8010/admin**, not a GitHub source preview or a local HTML file. The updated source contains readable default text and the server provides real headings before JavaScript loads. A different symptom still needs its exact error or screenshot; do not send your key.

- Use **`demo.py keys`**, not **`python -m backend keys`**. The older passive prototype uses different keys and normally runs on port 8000, not 8010.
- Run both commands from the **same existing project folder**. A different extracted ZIP creates its own keys and database.
- Use the matching role's token. Admin credentials do not sign in to the SOC or GRC page.
- Copy the complete token only, without quotes, role labels, JSON punctuation or extra lines.
- Restart the server after intentionally restoring/changing its access file. The running process uses the keys loaded at startup.
- Keep the server terminal open and fix any startup error shown there.
- If it still fails, share the exact page error and startup error, **never your token or access.json**.

The redesign-only `doctor`, `keys --role`, key-profile labels and separate session endpoint are no longer part of this restored version.

Keys stay at `.local/active_demo/access.json`; approved records stay at `.local/active_demo/state/iris.sqlite3`. This update does not change either. The original page uses authenticated `GET /api/demo/state` directly and only opens after the initial role-related records load successfully.
