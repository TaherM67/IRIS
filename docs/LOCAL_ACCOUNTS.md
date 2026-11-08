# Local username/password sign-in

The active website on port 8010 now uses individual accounts over HTTPS. The five accounts were configured locally with the exact passwords supplied by the user. Passwords are not included in source files or this guide.

| Workspace | Usernames |
| --- | --- |
| Administrator | `Taher` |
| SOC | `Abduallah`, `Abdualaziz` |
| GRC | `Abduarhman`, `Ahmed` |

These spellings are intentional. Usernames are case-insensitive when signing in; passwords are case-sensitive and are not trimmed. Each SOC/GRC account opens its existing shared team workspace. New chat messages display the authenticated username and team. New approval audit details contain `reviewer_username` alongside the existing team role. Admin still monitors and cannot approve for either team.

## Start and sign in

From the existing project directory in PowerShell:

```powershell
.\.venv\Scripts\python.exe demo.py
```

HTTPS is the default. The previous `demo.py --https` command still works. Open `https://127.0.0.1:8010/admin`, `/soc` or `/grc`, choose the matching workspace card, and enter the account username/password. If the browser has cached the old form, restart the server and press Ctrl+F5. The trusted localhost certificate from the [HTTPS setup](LOCAL_HTTPS.md) is reused.

Workspace selection and sign-in update in place without reloading. Tabs have separate sessions, so signing in or out in one tab does not change the others. Signing out revokes that tab's server session. Refreshing the page or restarting the server requires a new sign-in; the application does not write passwords or session tokens to browser storage. Sessions expire after 8 hours, or 30 minutes without API activity. Repeated failed sign-ins are limited temporarily; wait a minute before retrying.

The active website rejects old `X-IRIS-Key` credentials. `.local/active_demo/access.json` remains intact for rollback and internal legacy settings. The separate older FastAPI prototype on port 8000 has not been converted by this change.

## Local account maintenance

Accounts live at ignored `.local/active_demo/users.json`. The file contains per-user random salts and scrypt hashes, using the versioned `scrypt-v1` parameters (`n=32768`, `r=8`, `p=3`, 32-byte output). Passwords are never saved in plaintext. In-memory sessions contain a hash of each random bearer token and its assigned username/role; the server derives permissions from those records.

On a fresh installation, create accounts interactively; passwords are entered through a hidden prompt:

```powershell
.\.venv\Scripts\python.exe -m demo_app.auth add --username NewUser --role soc
```

Reset an existing account's password:

```powershell
.\.venv\Scripts\python.exe -m demo_app.auth reset-password --username Taher
```

Restart the server after account changes. Existing usernames cannot be overwritten by `add`, and password reset preserves the account's role. Do not delete `.local/`, overwrite the database, or regenerate the legacy keys to fix a sign-in problem. Account setup errors fail before opening the demo database.

The additional step to tighten this file's Windows ACL to only the current user and SYSTEM was not executed: automatic approval review failed because the workspace owner's spend cap had been reached. The existing inherited project permissions remain, including access for Taher, SYSTEM, Administrators and the Codex sandbox identities. The owner must raise that cap before the reviewed ACL step can be retried. Password hashing and HTTPS are already in place; no certificate trust was changed by the account update.

## Preservation and verification

The current local code was used directly. No Git pull/reset, frontend replacement, key regeneration, model change or retraining was performed. The pre-change snapshot is `.local/accounts_before_20261030/`. Final hash comparisons confirmed the actual `.local/active_demo/access.json` and `.local/active_demo/state/iris.sqlite3` remained byte-for-byte unchanged during implementation and testing. Existing source inputs, approved risk/alert values, audit history and chat messages are retained. A small `demo_chat_senders` table is created alongside the existing chat table when the server opens; old messages keep their original team labels. Approval username evidence uses the existing audit JSON format, without changing approval policy. The disposable preview was stopped and the actual demo remains stopped until launched normally.

Checks passed:

- All 13 new password/session/HTTPS account tests.
- All 141 existing backend/model/demo/chat/activity/HTTPS tests.
- Frontend controller regressions for account login, role isolation, failure cleanup, approvals, model reviews, inbox and chat.
- Headless Chrome over trusted HTTPS: all five account names, wrong-workspace rejection, named chat messages, both teams' approval flows, logout revocation, no sign-in reloads, desktop/mobile layout, and independent Admin/SOC tabs. Browser checks used synthetic test passwords and a temporary database. The five actual configured credentials were separately checked against the local password hashes without opening the real database.

Reproduce the Python checks after preparing the local certificate:

```powershell
.\.venv\Scripts\python.exe -m unittest demo_app.tests.test_auth backend.tests.test_grounded backend.tests.test_core backend.tests.test_http demo_app.tests.test_demo demo_app.tests.test_chat demo_app.tests.test_activity demo_app.tests.test_https
```

Existing files changed for this update: `demo.py`, `demo_app/server.py`, `demo_app/engine.py`, `demo_app/chat.py`, `demo_app/static/index.html`, `demo_app/static/style.css`, `demo_app/static/app.js`, `demo_app/tests/test_demo.py`, `demo_app/tests/test_ui_controller.js`, `README.md`, `docs/ACTIVE_DEMO.md`, `docs/ACCESS_HELP.md`, `docs/LOCAL_HTTPS.md`.

New files: `demo_app/auth.py`, `demo_app/tests/test_auth.py`, this guide; private `.local/active_demo/users.json`; disposable `.local/accounts_preview.py` and `.local/accounts_browser.cjs` plus their browser profile/screenshots. Private passwords were provisioned once through an in-memory command and were not written into project scripts, tests, documentation or frontend assets.
