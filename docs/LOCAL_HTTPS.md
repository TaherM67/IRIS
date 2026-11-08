# HTTPS for the local demo

HTTPS is supported on this PC with the existing loopback-only demo server. It uses the same website, models and SQLite database. The active website now uses [username/password accounts](LOCAL_ACCOUNTS.md); legacy role keys are retained separately. No network exposure, firewall change, hosted domain or new Python dependency is required.

Optional [same-network LAN sharing](LAN_ACCESS.md) now adds a separate IP certificate, listener and scoped firewall rule. The localhost certificate and trust setup described here remain unchanged.

## Certificate preparation

From the repository root in Windows PowerShell:

```powershell
.\scripts\New-LocalHttpsCertificate.ps1
```

The script creates a self-signed server certificate and RSA private key in ignored `.local/active_demo/tls/`. It covers `localhost` and `127.0.0.1`, expires after 90 days, and is explicitly not a certificate authority. The directory permissions restrict access to the current Windows account and SYSTEM. The script creates files only: it does not install a certificate, alter Windows/browser trust, or replace existing keys/certificates. No download or dependency installation is needed.

For this setup, the prepared certificate has:

- Subject: `CN=localhost`
- Names: `localhost`, `127.0.0.1`
- SHA-1 thumbprint (Windows certificate identifier): `00040212917CBB810DCD71CFB78B025F75E3BD6E`
- Expiry: `2027-01-28 10:49:07 UTC`

## Trust this specific certificate

Trust is a separate, explicit Windows account change. After approval, the public server certificate can be added to `CurrentUser\Root`, so browsers using Windows trust accept this local HTTPS endpoint. This step does not install the private key or trust a new signing CA. Until trusted, a normal browser will show a certificate warning; testing can instead trust the certificate only in the test client's SSL context.

Inspect the public certificate and verify its thumbprint before trusting it:

```powershell
$localCertPath=(Resolve-Path -LiteralPath '.local\active_demo\tls\localhost-cert.pem').Path
$localCert=[Security.Cryptography.X509Certificates.X509Certificate2]::new($localCertPath)
$localCert | Format-List Subject,Thumbprint,NotAfter
```

Only after approving this certificate, import it for your current Windows account:

```powershell
if ($localCert.Thumbprint -ne '00040212917CBB810DCD71CFB78B025F75E3BD6E') { throw 'Certificate does not match the reviewed certificate.' }
$localTrust=[Security.Cryptography.X509Certificates.X509Store]::new('Root','CurrentUser')
try {
    $localTrust.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $localTrust.Add($localCert)
} finally {
    $localTrust.Dispose()
    $localCert.Dispose()
}
```

Windows may ask for confirmation. Restart the browser if it has cached the earlier certificate warning. The VS Code embedded browser may also need its webview or VS Code restarted to refresh trust.

On 30 October 2026, the user approved this exact certificate and it was installed successfully in `CurrentUser\Root`. A headless Chrome check using normal certificate verification then accepted the HTTPS site, signed in across all three roles without page reloads, exercised approval and chat, and checked desktop/mobile layouts. The verification used a temporary database and separate browser profile; the actual demo server was left stopped.

To remove this one trust entry later, after stopping the HTTPS server:

```powershell
Remove-Item -LiteralPath 'Cert:\CurrentUser\Root\00040212917CBB810DCD71CFB78B025F75E3BD6E'
```

## Start HTTPS

```powershell
.\.venv\Scripts\python.exe demo.py --https
```

Open `https://127.0.0.1:8010/admin`, `/soc` or `/grc`. `https://localhost:8010/` also works. Use your username and password for that workspace. The server still accepts connections only from this PC. Plain HTTP requests to the HTTPS port are rejected. If certificate loading fails, startup fails instead of silently falling back to HTTP.

HTTPS is now enabled by default for account sign-in; omitting `--https` also starts HTTPS. Stop the current server with Ctrl+C before restarting. HTTPS uses TLS 1.2 or newer, and origin checks use the actual connection scheme; same-origin API requests, sign-in, approvals and chat work through HTTPS. The older plain-HTTP adapter is retained only for legacy backend regression fixtures; an account-enabled server refuses to start without TLS.

For a different valid PEM certificate and matching private key:

```powershell
.\.venv\Scripts\python.exe demo.py --https --cert-file 'path\certificate.pem' --key-file 'path\private-key.pem'
```

Both custom file options are required together. The certificate must cover the hostname/IP used in the browser. See [LAN access](LAN_ACCESS.md) for the separately prepared same-network listener and client certificate package.

## Renewal

The certificate helper refuses to overwrite existing files. To renew, stop the server, generate into a new empty directory, review/trust the new public certificate, and pass its paths explicitly:

```powershell
.\scripts\New-LocalHttpsCertificate.ps1 -OutputDirectory '.local\active_demo\tls-renewed'
.\.venv\Scripts\python.exe demo.py --https --cert-file '.local\active_demo\tls-renewed\localhost-cert.pem' --key-file '.local\active_demo\tls-renewed\localhost-key.pem'
```

Use the new thumbprint when trusting the renewal, then remove the old certificate's trust entry. Keep private key files in ignored local storage.

## Verification and changed files

Run:

```powershell
.\.venv\Scripts\python.exe -m unittest demo_app.tests.test_https -v
```

TLS workflow tests use temporary databases and a verified SSL client that trusts only the prepared certificate for that client. They do not modify Windows trust or the real demo database. Tests cover pages/static assets, authentication, HTTPS origin validation, chat/role separation, approval/export, hostname validation, untrusted certificates, plain HTTP rejection, startup validation, and a stalled handshake while another client connects. TLS workflow tests are skipped if certificate files have not been prepared; the configuration tests still run.

The 8 HTTPS tests and all 133 existing backend/model/demo/chat/activity tests passed during setup. The subsequent Chrome browser check also passed after the approved Windows trust step.

Existing workflow regression command:

```powershell
.\.venv\Scripts\python.exe -m unittest backend.tests.test_grounded backend.tests.test_core backend.tests.test_http demo_app.tests.test_demo demo_app.tests.test_chat demo_app.tests.test_activity
```

Changed project files: `demo.py`, `demo_app/server.py`, `docs/ACTIVE_DEMO.md`.

Added project files: `demo_app/tls.py`, `demo_app/tests/test_https.py`, `scripts/New-LocalHttpsCertificate.ps1`, this document.

Generated local files: `.local/active_demo/tls/localhost-cert.pem`, `.local/active_demo/tls/localhost-key.pem`; pre-change snapshot `.local/https_before_20261030/`. Disposable browser verification helpers `.local/https_preview.py` and `.local/https_browser.cjs` use temporary state and the existing browser regression; they do not disable browser certificate verification. Their screenshots are `.local/https-reference-login-desktop.png`, `.local/https-reference-login-mobile.png`, `.local/https-redesign-admin-final.png`, `.local/https-redesign-soc-final.png`, `.local/https-redesign-grc-final.png` and `.local/https-redesign-mobile-final.png`; their isolated Chrome profile is `.local/https-cdp-profile/`. Website HTML/CSS/JavaScript, role credentials, model integration and the existing database are preserved.
