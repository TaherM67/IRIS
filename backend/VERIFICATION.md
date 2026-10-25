# Backend preparation verification

Date: 25 October 2026. Environment: Python 3.12.14, scikit-learn 1.8.0 and the model package's pinned scientific dependencies.

## Verified here

| Check | Result |
| --- | --- |
| Original ML/integration suite | 79 tests passed |
| New backend core/ASGI-guard suite | 33 tests passed |
| User model checksum, schema and catalogue checks | Passed before loading |
| Actual user scenario and control bundle | Both components loaded |
| Fresh three-source core batch | 900 sessions predicted and persisted to SQLite |
| Runtime training labels | Not read |
| Primary result vs ML shadow | Kept separate; primary ML promotion prohibited |
| Official risk writes / automatic execution | False for all 900 cases |
| Existing held-out test replay | 135 sessions; Model 1 macro-F1 0.940476; benign false alarms 7/45 |
| Repeated batches and restart | Completed runs reused without duplicate cases |
| Local review and evidence | Review stored separately; no overwrite or external delivery |
| Python syntax / JavaScript syntax / guide links | Passed |
| Original ML release manifest | Unchanged files verified |

The held-out replay reproduces the uploaded report; it is not a new independent experiment. All data remains synthetic. The 15.56% benign false-positive rate fails the configured 5% release gate. Model 2 has positive held-out examples for only six catalogue controls; its micro-F1 is not evidence of complete coverage or actual control effectiveness.

The ASGI-guard tests exercise the real middleware callable directly with standard-library async test messages. They cover authentication before reading an upload, role derivation, duplicate/non-ASCII keys, foreign origins, size limits and replaying an accepted body. They are **not** a substitute for a FastAPI/Uvicorn HTTP test.

## Not verified here

FastAPI, Starlette, Uvicorn, HTTPX and multipart dependencies could not be installed: access to the PyPI package index returned `403 Forbidden`. The environment's `backend check` correctly reports the missing web dependencies. The supplied web dependency pins have not been resolver-tested here.

Therefore:

- The actual FastAPI HTTP server, Uvicorn startup/socket behavior and browser UI were **not executed**.
- Twelve HTTP integration tests are supplied in `backend/tests/test_http.py` but **not run here**. They do not silently skip themselves when packages are missing.
- No claim is made that the prepared HTTP/UI integration is already working on the user's machine.
- Run the setup guide's dependency checks, core tests, HTTP tests and browser walkthrough on the target computer before relying on it.

## Still outside this prototype

Live SIEM/GRC connectors, external delivery/acknowledgements, official register writes, GRC-change-triggered re-evaluation, enterprise identities/SSO, multi-worker streaming, TLS deployment, retention/backup and real campaign validation have not been implemented or established.

The server launcher binds to `127.0.0.1`, uses one worker and always requests shadow inference. It must not be exposed to the internet or presented as a production security product.
