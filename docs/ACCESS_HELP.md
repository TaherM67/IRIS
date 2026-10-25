# Sign in to the active IRIS demo

Use the updated **`demo.py`** and **`demo_app/`** together. Keep your existing **`.local/`** folder: it contains your keys and saved approvals. This update does not reset either.

## Windows: do this first

1. Stop the old server with **Ctrl+C**. Update the project from GitHub, preserving `.local/` and any of your own source edits. Start in the same project folder you used successfully before.
2. Start the server and leave this terminal open:

   ```powershell
   .\.venv\Scripts\python.exe demo.py
   ```

3. In a second terminal, **in that same folder**, run:

   ```powershell
   .\.venv\Scripts\python.exe demo.py doctor
   ```

   It checks the running build, key profile and all three role keys. It does not print secrets, analyze data, or change records. If you used `--port 8011` for the server, also use `doctor --port 8011`.

4. Get one key at a time in a **private** terminal:

   ```powershell
   .\.venv\Scripts\python.exe demo.py keys --role admin
   .\.venv\Scripts\python.exe demo.py keys --role soc
   .\.venv\Scripts\python.exe demo.py keys --role grc
   ```

5. Open the matching page, press **Ctrl+F5**, paste its key and select **Connect**:

   | Page | Local address | Required key |
   | --- | --- | --- |
   | Admin | <http://127.0.0.1:8010/admin> | Admin |
   | SOC | <http://127.0.0.1:8010/soc> | SOC |
   | GRC | <http://127.0.0.1:8010/grc> | GRC |

On macOS/Linux replace `.\.venv\Scripts\python.exe` with `.venv/bin/python`. If your virtual environment is activated, `python` works on either platform. Do not open the HTML file directly.

## What to copy

Copy the long token on the requested role's line. A single line such as `soc: TOKEN` is also accepted on the SOC page; optional surrounding quotes are handled. Do not copy the entire terminal output, the profile label, or a JSON field. **Show** reveals the input temporarily; hide it before presenting. The key is cleared after sign-in or failure and never stored in a URL or browser storage.

The **Key profile** on the sign-in page must match `demo.py keys` and the server terminal. The profile is a non-secret short fingerprint, not a key; never paste it into the key field.

## If it still fails

| Message or situation | What to do |
| --- | --- |
| Key profile mismatch | The command and running server use different credential sets: often two extracted project folders, or an edited access file. Stop the server and start it from the intended folder. Keep `.local/`. |
| Older/different server or API | Close the old process, update both `demo.py` and `demo_app/`, restart, then Ctrl+F5. The active demo is normally port **8010**, not the older passive interface on **8000**. |
| Wrong role | A working Admin key cannot sign in to the SOC/GRC page. Get that page's own key with `keys --role ...`. |
| Key not accepted | Run `doctor`. Use **`demo.py keys`**, not **`python -m backend keys`**: they read different credential files. |
| Cannot reach server | Leave the server terminal open. Use its printed HTTP loopback address and matching port. If startup failed, fix the terminal error first. |
| Invalid/multiline key | Paste only one complete role token. Do not copy JSON punctuation or the whole output. |
| Doctor succeeds, but the page fails | Ctrl+F5 and try again. Share the exact page error and the **doctor output only**, never your key or access.json. |

Existing keys are read from `.local/active_demo/access.json`. A running server uses the keys it loaded at startup; restart after intentionally restoring that file. A completely separate extracted project has its own keys/state. The update never silently regenerates existing credentials, opens access without authentication, or deletes your database.

## What was checked

Exact configured keys work over real local HTTP for each role. Regressions cover labelled/quoted pastes, malformed input, wrong roles, failed initial dashboard loads, stale builds, mismatched key profiles and read-only diagnostics. The exact cause of an error on a different computer cannot be determined without that computer's diagnostic result. A local browser rehearsal remains necessary before the examination.
