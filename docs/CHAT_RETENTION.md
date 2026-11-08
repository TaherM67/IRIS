# Personal chat clearing and retained logs

Every dashboard has a **Clear chat** button. It clears only the signed-in user's view, including other tabs using that same account. It does not clear another account's conversation, delete message logs, send a message, or discard the user's unsent draft. The account's clear position is saved on the server and survives sign-out and restarts. Messages sent after that position appear normally.

Admin also has **Download logs**. The JSON export contains all recent and archived messages with their original IDs, sender names/roles, text and timestamps, plus a record of who cleared their view and when. The export includes messages hidden by personal clearing. SOC and GRC cannot access the log export or clear another user's view; the server derives the user from the authenticated session and rejects caller-supplied identities/scopes.

## Retention and archive

- Message logs remain in recent storage for at least **three calendar months** from their original creation time, measured in UTC. Month-end anniversaries use the last valid day of the target month; leap years are handled explicitly.
- Older logs are moved into a separate permanent archive table in the same existing SQLite database. No archive purge is scheduled. Clearing a view does not change a message's age or its retention period.
- Archiving runs on startup and is checked hourly by the running server, including when nobody is sending messages. If the app was closed at a deadline, it catches up on the next start. Keeping a due message until the next maintenance pass can extend recent retention by up to an hour while the app is running.
- Copying into the archive and removing the corresponding recent message/sender record happens in one SQLite transaction. If archiving fails, the transaction rolls back and the original logs stay in recent storage. Admin sees an archive-delay notice and the server retries on the next hourly pass.
- Invalid legacy timestamps are retained instead of guessing their age. The archive preserves the original text, identity and timestamps; archiving does not rewrite the conversation.

The new tables are `demo_chat_archive`, `demo_chat_views` and `demo_chat_clear_events`. Existing chat messages, sender links, risk/alert records, proposals and audit history are preserved. Keep backing up the whole `.local/active_demo/state/iris.sqlite3` database to include recent logs, archives and personal clear positions together.

## Restart the existing demo

Stop the old server with Ctrl+C, then run from the existing project directory:

```powershell
.\.venv\Scripts\python.exe demo.py
```

Open the existing HTTPS dashboard and refresh the browser to load the new controls. Username/password accounts, HTTPS and role permissions are unchanged. The pre-change snapshot is `.local/chat_retention_before_20261030/`. Implementation and tests use temporary databases or a copy, leaving the actual credentials/database untouched until the normal server restart applies the additive chat tables.

## Verification

All 164 backend/model/demo/account/HTTPS/chat tests passed. Frontend controller checks also passed, including clearing, log preservation, draft preservation, failure recovery, late polling responses, same-account clear updates and Admin export. A private database-copy rehearsal preserved the existing messages and all approved records/audit entries, then successfully archived the copied logs after simulated aging.

Trusted HTTPS browser checks passed for all five sign-ins, personal clearing by both SOC and both GRC accounts, draft preservation, clear persistence across sign-in, independent tabs, mobile layout and continued chat/approval use. Admin still saw and exported all four test messages after the other users cleared their views. Browser checks used synthetic passwords and a temporary database; Admin clearing was also covered by the frontend controller tests.

```powershell
.\.venv\Scripts\python.exe -m unittest demo_app.tests.test_auth demo_app.tests.test_chat_retention backend.tests.test_grounded backend.tests.test_core backend.tests.test_http demo_app.tests.test_demo demo_app.tests.test_chat demo_app.tests.test_activity demo_app.tests.test_https
$env:IRIS_TEST_PYTHON=(Resolve-Path -LiteralPath '.\.venv\Scripts\python.exe').Path
node demo_app\tests\test_ui_controller.js
```

The tests include exact calendar deadlines, no early archive, indefinite archive preservation, rollback on an injected archive-write failure, retry, startup catch-up, per-user isolation, authentication/role checks, and message-ID continuity after archiving.

Changed files: `demo_app/chat.py`, `demo_app/server.py`, `demo_app/static/index.html`, `demo_app/static/style.css`, `demo_app/static/app.js`, `demo_app/tests/test_chat.py`, `demo_app/tests/test_auth.py`, `demo_app/tests/test_ui_controller.js`, `docs/ACTIVE_DEMO.md`.

New files: `demo_app/tests/test_chat_retention.py`, this guide, and ignored verification helpers `.local/verify_chat_retention_copy.py` and `.local/chat_retention_browser.cjs`. The new browser helper reuses the disposable account preview and never opens the real database.

The disposable browser profile is `.local/chat-retention-cdp-profile/`; generated screenshots use `.local/chat-retention-*.png`. The preview was stopped after verification; restart the actual demo normally to apply the change.
