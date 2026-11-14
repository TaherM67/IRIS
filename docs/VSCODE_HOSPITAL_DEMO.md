# Run IRIS General Hospital with Codex in VS Code

Use branch `iris-hospital-trained-20261114`. The trained model and data are
included; starting the demo does not train a model or require Colab.

## Paste this into Codex in VS Code

```text
Run the IRIS General Hospital demo from TaherM67/IRIS using branch
iris-hospital-trained-20261114.

First inspect git status. Preserve all local edits and the complete .local/
directory, including accounts, certificates, database, chat and approvals.
Fetch the named branch. If changing branches would conflict with my local
edits, create a separate worktree instead of resetting, cleaning or discarding
anything. Do not merge into or overwrite main.

Use Python 3.12. Reuse a compatible existing .venv, or create a new one for a
fresh checkout. Install requirements-hospital.txt using that interpreter.
Run backend.tests.test_hospital_training and demo.py check --dataset hospital
--model-profile iris_hospital_20261114. Inspect errors before proceeding.

Reuse my existing HTTPS certificate and individual accounts. On a fresh
installation, help me create the localhost certificate with
scripts/New-LocalHttpsCertificate.ps1 and add missing local accounts using
python -m demo_app.auth add. Let me enter passwords in the hidden terminal
prompt; do not place passwords in chat, source files or GitHub. Existing
accounts must not be reset or replaced.

Start .venv\Scripts\python.exe demo.py --dataset hospital --model-profile
iris_hospital_20261114 and leave it running. Open the Admin, SOC and GRC
dashboards at https://127.0.0.1:8010/admin, /soc and /grc. Confirm the hospital
working tables contain 15,000 alerts and 1,860 risks. Admin runs analysis;
SOC and GRC review and approve their own proposals. Do not approve changes
for me or bypass role permissions. Report any setup or startup error exactly.

The new Model 1 is experimental, trained on synthetic unreviewed references.
Keep its results in shadow mode, retain Model 2 and primary rules, and preserve
all human approval gates. Read docs/HOSPITAL_MODEL_CARD.md for limitations.
```

## Manual PowerShell commands

For an existing clean clone:

```powershell
git status --short
git fetch origin
git switch --track origin/iris-hospital-trained-20261114
```

If the local branch already exists, use `git switch iris-hospital-trained-20261114`
and `git pull --ff-only`. If there are conflicting local changes, use a separate
worktree and retain the original installation. A worktree has separate local
state, so create fresh accounts there rather than deleting the original state.

Only for a fresh installation without a virtual environment:

```powershell
py -3.12 -m venv .venv
```

Then:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-hospital.txt
.\.venv\Scripts\python.exe -m unittest backend.tests.test_hospital_training -v
.\.venv\Scripts\python.exe demo.py check --dataset hospital --model-profile iris_hospital_20261114
```

Switching datasets creates a hospital exercise and retains earlier exercises
and approvals in the existing local database. `check` loads the data and model;
it does not run fitting or approve anything.

If certificate/key files are missing, create them once:

```powershell
& .\scripts\New-LocalHttpsCertificate.ps1
```

This creates localhost certificate files; it does not install OS trust. Reuse
an existing valid certificate. The certificate must be accepted/trusted for your
own localhost browser session as described in `docs/LOCAL_HTTPS.md`. Do not
disable HTTPS. If script execution is restricted, follow your machine's normal
PowerShell policy rather than changing a system-wide policy.

On a fresh installation, add one account for each workspace, choosing your own
password at each hidden prompt:

```powershell
.\.venv\Scripts\python.exe -m demo_app.auth add --username Taher --role admin
.\.venv\Scripts\python.exe -m demo_app.auth add --username Abduallah --role soc
.\.venv\Scripts\python.exe -m demo_app.auth add --username Ahmed --role grc
```

Existing installations retain the established usernames, including
`Abdualaziz` (SOC) and `Abduarhman` (GRC). Add only accounts that are absent.
There are no shipped default passwords.

Start:

```powershell
.\.venv\Scripts\python.exe demo.py --dataset hospital --model-profile iris_hospital_20261114
```

Open the three URLs above in separate tabs and sign in to the correct role.
Choose **Run analysis** in Admin, wait for completion, then inspect proposals
in SOC and GRC. Before the first approval the queue has 15,000 alerts and the
register has 1,860 risks. The analysis accounts for 2,490 sessions. Review and
approve one current proposal in each team to see saved record changes and audit
history. Some historical proposals can be stale and are correctly blocked.
Ctrl+C stops the server; approved records persist.

For the former demonstrations, use `--dataset expanded` or `--dataset legacy`
with `--model-profile auto`.

## Optional verification

```powershell
.\.venv\Scripts\python.exe tools/validate_inputs.py --input-dir datasets/iris_general_hospital_20261114/data
.\.venv\Scripts\python.exe tools/check_input_coverage.py --dataset hospital
.\.venv\Scripts\python.exe tools/verify_hospital_demo.py --out .local/hospital-check-NEW --cert-file .local/active_demo/tls/localhost-cert.pem --key-file .local/active_demo/tls/localhost-key.pem
```

The last two commands use temporary databases and preserve existing saved demo
state. Choose a fresh output directory for each verification. Full analysis can
take longer than the small 84-session demonstration. Private-LAN operation
requires the separate existing `docs/LAN_ACCESS.md` setup and local rehearsal.
