# Three synthetic demonstration inputs

These are the same three datasets supplied in the downloadable demo pack:

| File | Contents |
| --- | --- |
| `asset_inventory.json` | 30 assets, 36 historical snapshots |
| `risk_register.json` | 60 risks, 72 historical snapshots |
| `siem_alerts.jsonl` | 2,367 alert rows, producing 132 sessions |

`demo_manifest.json` pins their byte hashes. Only those three files are operational inputs; there is no training-label input. Everything is fictional. Six duplicate rows, one invalid timestamp, one conflicting event ID represented by two rows, and three unresolved-asset events intentionally exercise cleaning. After exclusions there are **2,355 matched unique alerts** in the working demo SOC queue.

Run **`python demo.py` from the repository root** for the active, approval-gated demonstration. Follow [the active demo guide](../../docs/ACTIVE_DEMO.md). The earlier downloadable pack's walkthrough describes the older passive interface, not this new active server.

Never edit these files to make the display change. Approvals update separate, persistent synthetic records in SQLite. The original inputs remain unchanged as evidence.
