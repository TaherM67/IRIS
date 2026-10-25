"""Generate linked artificial inventory, risk-register and SIEM training samples.

All targets live in a separate offline label sidecar. None are embedded in the
three operational datasets. No attacks are executed and no real people appear.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np

from .contracts import CLASSES, write_json, write_jsonl
from .three_sources import ASSET_SCHEMA, RISK_SCHEMA


def generate_samples(out: Path, *, campaigns=60, runs_per_class=5, asset_count=60, seed=20261025) -> dict:
    if out.exists() and any(out.iterdir()):
        raise ValueError("Sample directory is not empty; choose a fresh directory")
    if campaigns < 5 or runs_per_class < 1 or asset_count < 2:
        raise ValueError("Need at least 5 campaigns, 1 run/class/campaign and 2 assets")
    rng = np.random.default_rng(seed)
    baseline = datetime(2026, 7, 1, tzinfo=timezone.utc)
    change = baseline + timedelta(days=31)
    assets, risks = [], []
    asset_lookup, risk_lookup = {}, {}
    for i in range(asset_count):
        aid = f"AST-{i+1:03d}"
        for phase in (0, 1):
            start = baseline if phase == 0 else change
            end = change if phase == 0 else None
            criticality = int(rng.integers(1, 6))
            record = {"asset_id": aid, "asset_version_id": f"{aid}-V{phase+1}",
                      "hostname": f"{'server' if i % 3 == 0 else 'workstation'}-{i+1:03d}",
                      "asset_type": "server" if i % 3 == 0 else "workstation",
                      "ip_addresses": [f"10.{44+phase}.0.{i+11}"],
                      "criticality": criticality, "zone": "service_zone" if i % 3 == 0 else "user_zone",
                      "owner": "Infrastructure" if i % 3 == 0 else "IT Operations",
                      "valid_from": start.isoformat(), "valid_to": end.isoformat() if end else None,
                      "recorded_at": start.isoformat()}
            assets.append(record)
            asset_lookup[(aid, phase)] = record
            for r, category in enumerate(("Unauthorized Access", "Reconnaissance"), 1):
                rid = f"RSK-{i+1:03d}-{r}"
                states = ({"SC005": ["missing", "partial", "implemented"][i % 3], "SC007": "partial", "SC006": "missing"}
                          if r == 1 else {"SC012": ["missing", "partial", "implemented"][i % 3], "SC029": "partial", "SC011": "implemented"})
                risk = {"risk_id": rid, "risk_version_id": f"{rid}-V{phase+1}", "asset_id": aid,
                        "risk_category": category, "likelihood": int(rng.integers(1, 6)),
                        "impact": int(rng.integers(1, 6)), "control_states": states,
                        "active_exception_control_ids": ["SC006"] if i % 9 == 0 and r == 1 else [],
                        "valid_from": start.isoformat(), "valid_to": end.isoformat() if end else None,
                        "recorded_at": start.isoformat()}
                risks.append(risk)
                risk_lookup[(rid, phase)] = risk
    alerts, labels, counter = [], [], 0
    class_runs = Counter()
    for campaign in range(campaigns):
        campaign_start = baseline + timedelta(days=campaign+1, hours=9)
        schedule = [label for label in CLASSES for _ in range(runs_per_class)]
        rng.shuffle(schedule)
        for slot, label in enumerate(schedule):
            counter += 1
            run_id, campaign_id = f"RUN-{counter:06d}", f"SYN-CAMPAIGN-{campaign+1:03d}"
            start = campaign_start + timedelta(minutes=3*slot)
            phase = int(start >= change)
            aid = f"AST-{int(rng.integers(1, asset_count+1)):03d}"
            asset = asset_lookup[(aid, phase)]
            benign_scan = label == "benign" and rng.random() < .15
            family = "network" if label == "reconnaissance" or benign_scan else "authentication"
            if family == "authentication":
                failed = int(rng.integers(8, 46)) if label == "credential_access" else int(rng.integers(1, 5))
                success = int(rng.integers(0, 3)) if label == "credential_access" else int(rng.integers(1, 3))
                outcomes = ["failed"]*failed + ["success"]*success
                n = len(outcomes)
                rule_count = int(rng.integers(1, 5))
                max_level = int(rng.integers(5, 12)) if label == "credential_access" else int(rng.integers(2, 8))
            else:
                n = int(rng.integers(22, 81)) if label == "reconnaissance" else int(rng.integers(15, 46))
                failed, success, outcomes = 0, 0, ["unknown"]*n
                rule_count = int(rng.integers(1, 7))
                max_level = int(rng.choice([4, 7, 10]))
            duration = float(rng.uniform(5, 50))
            account = str(rng.choice(["alice", "bob", "carol", "secops"])) if family == "authentication" else None
            actor = f"10.88.{campaign % 4}.{int(rng.integers(10, 240))}"
            event_ids = []
            for ordinal in range(n):
                eid = f"EVT-{counter:06d}-{ordinal+1:03d}"
                event_ids.append(eid)
                alerts.append({"event_id": eid, "timestamp": (start+timedelta(seconds=duration*ordinal/max(n-1, 1))).isoformat(),
                               "asset_id": aid, "destination_ip": asset["ip_addresses"][0],
                               "agent_name": asset["hostname"], "source_ip": actor,
                               "account": account, "event_family": family,
                               "protocol": "SSH" if family == "authentication" else "TCP",
                               "rule_id": str((5700 if family == 'authentication' else 2100000) + ordinal % rule_count),
                               "rule_level": max_level if ordinal == 0 else int(rng.integers(2, max_level+1)),
                               "outcome": outcomes[ordinal], "sensor_healthy": True,
                               "campaign_id": campaign_id, "run_id": run_id, "data_provenance": "synthetic"})
            controls = ["SC005", "SC007"] if label == "credential_access" else ["SC012", "SC029"] if label == "reconnaissance" else []
            if label == "credential_access" and failed >= 20:
                controls.append("SC006")
            if label != "benign" and asset["criticality"] >= 4:
                controls.append("SC026")
            labels.append({"case_id": f"SYN-LABEL-{counter:06d}", "event_ids": event_ids,
                           "campaign_id": campaign_id, "run_id": run_id,
                           "scenario_class": label, "template_group": f"{label}-behavioral-variant-{campaign % 5}",
                           "label_verified": True, "reviewer": "SYNTHETIC_GENERATOR_NOT_AN_EXPERT",
                           "recommended_control_ids": controls, "controls_reviewed": True,
                           "control_reviewer": "SYNTHETIC_GENERATOR_NOT_AN_EXPERT"})
            class_runs[label] += 1
    # Representative input-quality cases do not become training labels.
    duplicate_count = min(12, len(alerts))
    alerts.extend([dict(alerts[i]) for i in range(duplicate_count)])
    for ordinal in range(2):
        unknown = dict(alerts[0])
        unknown.update({"event_id": f"QA-UNRESOLVED-{ordinal}", "asset_id": "AST-NOT-IN-INVENTORY"})
        alerts.append(unknown)
    bad = dict(alerts[0])
    bad.update({"event_id": "QA-INVALID-TIMESTAMP", "timestamp": "not-a-timestamp"})
    alerts.append(bad)
    rng.shuffle(alerts)
    header = {"data_provenance": "synthetic", "notice": "Artificial development/training samples. Not actual SIEM, hospital or expert-review evidence."}
    write_json(out / "asset_inventory.json", {"schema_version": ASSET_SCHEMA, **header, "records": assets})
    write_json(out / "risk_register.json", {"schema_version": RISK_SCHEMA, **header, "records": risks})
    write_jsonl(out / "siem_alerts.jsonl", alerts)
    write_jsonl(out / "training_labels.jsonl", labels)
    summary = {"data_provenance": "synthetic", "seed": seed,
               "asset_count": asset_count, "asset_snapshots": len(assets),
               "risk_count": 2*asset_count, "risk_snapshots": len(risks),
               "siem_alert_rows": len(alerts), "labeled_sessions_expected": len(labels),
               "campaign_count": campaigns, "runs_per_class": dict(class_runs),
               "qa_cases": {"exact_duplicate_rows": duplicate_count, "unresolved_asset_alerts": 2, "invalid_timestamp_alerts": 1},
               "operational_inputs": ["asset_inventory.json", "risk_register.json", "siem_alerts.jsonl"],
               "offline_training_only": "training_labels.jsonl", "release_allowed": False}
    write_json(out / "sample_manifest.json", summary)
    return summary
