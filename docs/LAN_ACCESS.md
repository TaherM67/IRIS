# Sharing IRIS on the same network

LAN mode keeps the existing localhost website and adds a second HTTPS listener on the selected network interface. All users share the same saved data, chat and approvals, and use their existing individual usernames/passwords. Role permissions, chat retention, models and frontend design are unchanged.

## This PC's prepared network

| Setting | Value |
| --- | --- |
| Network | `uaeu.ac.ae`, Wi-Fi interface 3 |
| LAN address | `10.140.132.216` |
| Allowed client subnet | `10.140.128.0/20` |
| HTTPS port | `8010` |
| Windows profile | Public (unchanged) |
| SOC | `https://10.140.132.216:8010/soc` |
| GRC | `https://10.140.132.216:8010/grc` |
| Admin | `https://10.140.132.216:8010/admin` |

Localhost continues at `https://127.0.0.1:8010/` with the previously trusted localhost certificate. LAN mode uses a separate certificate covering the network IP. Its private key remains on this PC. Only the public certificate and instructions go to clients.

## Start the website

```powershell
.\.venv\Scripts\python.exe demo.py --lan
```

Keep the server terminal open and the PC awake and connected to that network. Every client uses this PC's LAN address, not their own `localhost` or `127.0.0.1`. The existing `python demo.py` command still serves this PC only, without opening the LAN listener.

## Client certificate and sign-in

The generated client package is:

```text
.local/active_demo/IRIS-LAN-client.zip
```

It contains only the public certificate and `README.txt`; no passwords, account file, database or private key. Transfer the package to the other users and have them verify the certificate fingerprint with the server owner before trusting it.

Current public certificate: `IRIS-LAN-10.140.132.216-16BE9A716840.cer`.

- Windows certificate thumbprint: `16BE9A716840D54DCF06CC8D9C7EBF0F15C73A7A`
- SHA-256 of the public `.cer` file: `2e9c7b6e365c7b8b5813a39700026ba8f690b14bc33ca62ecb0cf653044c7c57`

For Windows clients, extract the ZIP and run in that directory:

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath '.\IRIS-LAN-10.140.132.216-16BE9A716840.cer'
Import-Certificate -FilePath '.\IRIS-LAN-10.140.132.216-16BE9A716840.cer' -CertStoreLocation Cert:\CurrentUser\Root
```

Approve the import only after checking the fingerprint. Restart the browser if needed. On macOS, import the public certificate into the user's login keychain and trust it for SSL after checking the fingerprint. Mobile or managed devices may require an IT-issued certificate or a different managed trust setup; do not transfer the server private key or bypass certificate validation to work around device restrictions.

Then open the appropriate LAN link, choose the matching workspace and sign in with the existing account. The server's localhost trust entry is unchanged; trusting a certificate on this PC does not automatically trust it on anyone else's device.

## Firewall setup

The prepared exception is deliberately limited to:

- TCP port 8010 on local address `10.140.132.216`.
- Remote clients in `10.140.128.0/20` on the Wi-Fi interface.
- The current Public profile and the actual Python listener executable.
- No edge traversal. Other rules, network profile settings and Windows Firewall itself are unchanged.

Preview the rule without applying changes:

```powershell
.\scripts\Set-LanFirewall.ps1 -WhatIf
```

An Administrator PowerShell window is required to apply it:

```powershell
.\scripts\Set-LanFirewall.ps1
```

The script owns only rule `IRIS-Demo-LAN-HTTPS-8010`. To remove that exception later, use an Administrator PowerShell window:

```powershell
.\scripts\Set-LanFirewall.ps1 -Remove
```

Stopping the LAN server or running it without `--lan` stops network sharing. No router forwarding or tunnel is configured.

## If your address or network changes

Stop the server, prepare the current interface again, and update the firewall rule as Administrator:

```powershell
.\scripts\Prepare-LanAccess.ps1 -InterfaceIndex 3
.\scripts\Set-LanFirewall.ps1
.\.venv\Scripts\python.exe demo.py --lan
```

Preparation reuses the existing LAN certificate if the address is unchanged and it is still valid. A changed address creates a new certificate/public package; clients then need the updated URL and certificate. Use `-RenewCertificate` to renew explicitly. Existing certificates are retained in versioned ignored directories. For a different port, supply the same `-Port` when preparing and `--port` when starting.

University Wi-Fi can apply device isolation or routing restrictions even when both devices use the same SSID. If another device cannot open the LAN address after certificate trust and firewall setup, check that its address is in the allowed subnet; IT may need to permit client-to-client traffic. A successful connection on the server PC alone does not prove that the university permits traffic from another physical device.

## Implementation and checks

LAN mode requires HTTPS, account authentication, a concrete RFC1918 IPv4 address and an explicit subnet. The server rejects clients outside that subnet before TLS/authentication, and only accepts the listener's exact IP/hostname and port in `Host`/`Origin`. It does not bind all interfaces. Both listeners share the existing engine, storage and session manager; localhost retains its original certificate.

The prepared LAN suite covers private-address policy, mandatory TLS/accounts, peer rejection before TLS, certificate pinning, stale-address detection, actual verified HTTPS on the LAN IP, localhost session compatibility, chat, role checks, logout and listener shutdown:

```powershell
$env:IRIS_TEST_LAN='1'
.\.venv\Scripts\python.exe -m unittest demo_app.tests.test_lan -v
```

Tests use temporary databases and synthetic passwords, not the saved live records. The pre-change snapshot is `.local/lan_before_20261030/`.

Changed source files: `demo.py`, `demo_app/server.py`, `scripts/New-LocalHttpsCertificate.ps1`. Added files: `demo_app/lan.py`, `demo_app/tests/test_lan.py`, `scripts/Prepare-LanAccess.ps1`, `scripts/Set-LanFirewall.ps1`, this guide. The active demo/HTTPS guides link to this setup. Generated local configuration, certificates and the public ZIP live under ignored `.local/active_demo/`; deployment helper/results live under `.local/`.
