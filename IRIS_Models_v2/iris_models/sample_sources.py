# IRIS EXPLAIN: File purpose: Generates linked synthetic asset, risk, and SIEM inputs plus a separate offline annotation
# IRIS EXPLAIN: sidecar; no attacks are executed.
# IRIS EXPLAIN: Existing documentation/literal text below is kept exactly as written; the explanation is outside the string so
# IRIS EXPLAIN: its value does not change.
"""Generate linked artificial inventory, risk-register and SIEM training samples.

All targets live in a separate offline label sidecar. None are embedded in the
three operational datasets. No attacks are executed and no real people appear.
"""
# IRIS EXPLAIN: Keep type annotations unevaluated at definition time; this does not add a model feature or change runtime
# IRIS EXPLAIN: settings.
from __future__ import annotations

# IRIS EXPLAIN: Import Counter from collections to count values and build efficient grouping/history containers.
from collections import Counter
# IRIS EXPLAIN: Import datetime, timedelta, timezone from datetime to represent timezone-aware timestamps and elapsed-time
# IRIS EXPLAIN: windows.
from datetime import datetime, timedelta, timezone
# IRIS EXPLAIN: Import Path from pathlib to resolve server-owned paths without trusting uploaded filenames.
from pathlib import Path

# IRIS EXPLAIN: Import numpy as np to perform reproducible numeric sampling, vectorized predictions and array calculations.
import numpy as np

# IRIS EXPLAIN: Import CLASSES, write_json, write_jsonl from .contracts to reuse the shared project contract/implementation
# IRIS EXPLAIN: rather than duplicate it.
from .contracts import CLASSES, write_json, write_jsonl
# IRIS EXPLAIN: Import ASSET_SCHEMA, RISK_SCHEMA from .three_sources to reuse the shared project contract/implementation rather
# IRIS EXPLAIN: than duplicate it.
from .three_sources import ASSET_SCHEMA, RISK_SCHEMA


# IRIS EXPLAIN: Function generate_samples: Write three linked synthetic source datasets, historical snapshots, deliberate
# IRIS EXPLAIN: quality examples and a separate offline label sidecar to an empty destination.
# IRIS EXPLAIN: Inputs: out: the destination path; existing safety checks govern overwrite behavior; campaigns: the explicit
# IRIS EXPLAIN: campaigns input used by the unchanged statements below; runs_per_class: the explicit runs per class input used
# IRIS EXPLAIN: by the unchanged statements below; asset_count: the explicit asset count input used by the unchanged statements
# IRIS EXPLAIN: below; seed: the reproducible random seed.
# IRIS EXPLAIN: Declared return type: dict; the return statements below show each actual result/fallback.
def generate_samples(out: Path, *, campaigns=60, runs_per_class=5, asset_count=60, seed=20261025) -> dict:
    # IRIS EXPLAIN: Enter this branch only when out.exists() and any(out.iterdir()).
    if out.exists() and any(out.iterdir()):
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Sample directory is not empty; choose a
        # IRIS EXPLAIN: fresh directory'); the caller's existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError("Sample directory is not empty; choose a fresh directory")
    # IRIS EXPLAIN: Enter this branch only when campaigns < 5 or runs_per_class < 1 or asset_count < 2.
    if campaigns < 5 or runs_per_class < 1 or asset_count < 2:
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Need at least 5 campaigns, 1
        # IRIS EXPLAIN: run/class/campaign and 2 assets'); the caller's existing boundary determines rollback or the HTTP
        # IRIS EXPLAIN: diagnostic.
        raise ValueError("Need at least 5 campaigns, 1 run/class/campaign and 2 assets")
    # IRIS EXPLAIN: Store the result of np.random.default_rng(seed) in rng; later lines use this named result.
    rng = np.random.default_rng(seed)
    # IRIS EXPLAIN: Store the result of datetime(2026, 7, 1, tzinfo=timezone.utc) in baseline; later lines use this named
    # IRIS EXPLAIN: result.
    baseline = datetime(2026, 7, 1, tzinfo=timezone.utc)
    # IRIS EXPLAIN: Store the computed value baseline + timedelta(days=31) in change; later lines use this named result.
    change = baseline + timedelta(days=31)
    # IRIS EXPLAIN: Store ([], []) in (assets, risks); later lines use this named result.
    assets, risks = [], []
    # IRIS EXPLAIN: Store ({}, {}) in (asset_lookup, risk_lookup); later lines use this named result.
    asset_lookup, risk_lookup = {}, {}
    # IRIS EXPLAIN: Iterate range(asset_count), binding each item to i; process only the existing observed/fixture collection.
    for i in range(asset_count):
        # IRIS EXPLAIN: Store the formatted text f'AST-{i + 1:03d}' in aid; later lines use this named result.
        aid = f"AST-{i+1:03d}"
        # IRIS EXPLAIN: Iterate (0, 1), binding each item to phase; process only the existing observed/fixture collection.
        for phase in (0, 1):
            # IRIS EXPLAIN: Store baseline when phase == 0; otherwise change in start; later lines use this named result.
            start = baseline if phase == 0 else change
            # IRIS EXPLAIN: Store change when phase == 0; otherwise None (no result/value) in end; later lines use this named
            # IRIS EXPLAIN: result.
            end = change if phase == 0 else None
            # IRIS EXPLAIN: Store int(rng.integers(1, 6)) in criticality; later lines use this named result.
            criticality = int(rng.integers(1, 6))
            # IRIS EXPLAIN: Store a mapping containing asset_id, asset_version_id, hostname, asset_type, ip_addresses,
            # IRIS EXPLAIN: criticality, zone and additional fields in record; later lines use this named result.
            record = {"asset_id": aid, "asset_version_id": f"{aid}-V{phase+1}",
                      # IRIS EXPLAIN: Continue the current record with hostname; each value comes from the expression shown on
                      # IRIS EXPLAIN: this unchanged line.
                      "hostname": f"{'server' if i % 3 == 0 else 'workstation'}-{i+1:03d}",
                      # IRIS EXPLAIN: Set/describe these existing record fields: asset_type: the existing inventory
                      # IRIS EXPLAIN: business-context category.
                      "asset_type": "server" if i % 3 == 0 else "workstation",
                      # IRIS EXPLAIN: Continue the current record with ip_addresses; each value comes from the expression shown
                      # IRIS EXPLAIN: on this unchanged line.
                      "ip_addresses": [f"10.{44+phase}.0.{i+11}"],
                      # IRIS EXPLAIN: Continue the current record with criticality, zone; each value comes from the expression
                      # IRIS EXPLAIN: shown on this unchanged line.
                      "criticality": criticality, "zone": "service_zone" if i % 3 == 0 else "user_zone",
                      # IRIS EXPLAIN: Continue the current record with owner; each value comes from the expression shown on this
                      # IRIS EXPLAIN: unchanged line.
                      "owner": "Infrastructure" if i % 3 == 0 else "IT Operations",
                      # IRIS EXPLAIN: Set/describe these existing record fields: valid_from: inclusive start of a source
                      # IRIS EXPLAIN: snapshot's effective interval; valid_to: exclusive expiry, or None for an open-ended
                      # IRIS EXPLAIN: interval.
                      "valid_from": start.isoformat(), "valid_to": end.isoformat() if end else None,
                      # IRIS EXPLAIN: Set/describe these existing record fields: recorded_at: when the source snapshot was
                      # IRIS EXPLAIN: known; prevents information leaking backward in time.
                      "recorded_at": start.isoformat()}
            # IRIS EXPLAIN: Call assets.append(record): append one item to the working list.
            assets.append(record)
            # IRIS EXPLAIN: Store record in asset_lookup[aid, phase]; later lines use this named result.
            asset_lookup[(aid, phase)] = record
            # IRIS EXPLAIN: Iterate enumerate(('Unauthorized Access', 'Reconnaissance'), 1), binding each item to (r, category);
            # IRIS EXPLAIN: process only the existing observed/fixture collection.
            for r, category in enumerate(("Unauthorized Access", "Reconnaissance"), 1):
                # IRIS EXPLAIN: Store the formatted text f'RSK-{i + 1:03d}-{r}' in rid; later lines use this named result.
                rid = f"RSK-{i+1:03d}-{r}"
                # IRIS EXPLAIN: Store a mapping containing SC005, SC007, SC006 when r == 1; otherwise a mapping containing
                # IRIS EXPLAIN: SC012, SC029, SC011 in states; later lines use this named result.
                states = ({"SC005": ["missing", "partial", "implemented"][i % 3], "SC007": "partial", "SC006": "missing"}
                          # IRIS EXPLAIN: Continue the current record with SC012, SC029, SC011; each value comes from the
                          # IRIS EXPLAIN: expression shown on this unchanged line.
                          if r == 1 else {"SC012": ["missing", "partial", "implemented"][i % 3], "SC029": "partial", "SC011": "implemented"})
                # IRIS EXPLAIN: Store a mapping containing risk_id, risk_version_id, asset_id, risk_category, likelihood,
                # IRIS EXPLAIN: impact, control_states and additional fields in risk; later lines use this named result.
                risk = {"risk_id": rid, "risk_version_id": f"{rid}-V{phase+1}", "asset_id": aid,
                        # IRIS EXPLAIN: Set/describe these existing record fields: risk_category: the existing registered risk
                        # IRIS EXPLAIN: taxonomy used for explicit scenario-to-risk mapping; likelihood: the stored or
                        # IRIS EXPLAIN: explicitly proposed 1-5 likelihood in this record, not an invented ML risk probability.
                        "risk_category": category, "likelihood": int(rng.integers(1, 6)),
                        # IRIS EXPLAIN: Set/describe these existing record fields: impact: the same registered risk's impact; it
                        # IRIS EXPLAIN: must not be independently maximized across risks; control_states: asset/risk-specific
                        # IRIS EXPLAIN: implementation evidence such as missing, partial or implemented.
                        "impact": int(rng.integers(1, 6)), "control_states": states,
                        # IRIS EXPLAIN: Set/describe these existing record fields: active_exception_control_ids: controls
                        # IRIS EXPLAIN: requiring exception/compensating-control review before a response.
                        "active_exception_control_ids": ["SC006"] if i % 9 == 0 and r == 1 else [],
                        # IRIS EXPLAIN: Set/describe these existing record fields: valid_from: inclusive start of a source
                        # IRIS EXPLAIN: snapshot's effective interval; valid_to: exclusive expiry, or None for an open-ended
                        # IRIS EXPLAIN: interval.
                        "valid_from": start.isoformat(), "valid_to": end.isoformat() if end else None,
                        # IRIS EXPLAIN: Set/describe these existing record fields: recorded_at: when the source snapshot was
                        # IRIS EXPLAIN: known; prevents information leaking backward in time.
                        "recorded_at": start.isoformat()}
                # IRIS EXPLAIN: Call risks.append(risk): append one item to the working list.
                risks.append(risk)
                # IRIS EXPLAIN: Store risk in risk_lookup[rid, phase]; later lines use this named result.
                risk_lookup[(rid, phase)] = risk
    # IRIS EXPLAIN: Store ([], [], 0) in (alerts, labels, counter); later lines use this named result.
    alerts, labels, counter = [], [], 0
    # IRIS EXPLAIN: Store the result of Counter() in class_runs; later lines use this named result.
    class_runs = Counter()
    # IRIS EXPLAIN: Iterate range(campaigns), binding each item to campaign; process only the existing observed/fixture
    # IRIS EXPLAIN: collection.
    for campaign in range(campaigns):
        # IRIS EXPLAIN: Store the computed value baseline + timedelta(days=campaign + 1, hours=9) in campaign_start; later lines
        # IRIS EXPLAIN: use this named result.
        campaign_start = baseline + timedelta(days=campaign+1, hours=9)
        # IRIS EXPLAIN: Store the comprehension [label for label in CLASSES for _ in range(runs_per_class)] in schedule; later
        # IRIS EXPLAIN: lines use this named result.
        schedule = [label for label in CLASSES for _ in range(runs_per_class)]
        # IRIS EXPLAIN: Call rng.shuffle(schedule) using the existing explicit arguments.
        rng.shuffle(schedule)
        # IRIS EXPLAIN: Iterate enumerate(schedule), binding each item to (slot, label); process only the existing
        # IRIS EXPLAIN: observed/fixture collection.
        for slot, label in enumerate(schedule):
            # IRIS EXPLAIN: Update counter using the existing Add operation and 1.
            counter += 1
            # IRIS EXPLAIN: Store (f'RUN-{counter:06d}', f'SYN-CAMPAIGN-{campaign + 1:03d}') in (run_id, campaign_id); later
            # IRIS EXPLAIN: lines use this named result.
            run_id, campaign_id = f"RUN-{counter:06d}", f"SYN-CAMPAIGN-{campaign+1:03d}"
            # IRIS EXPLAIN: Store the computed value campaign_start + timedelta(minutes=3 * slot) in start; later lines use this
            # IRIS EXPLAIN: named result.
            start = campaign_start + timedelta(minutes=3*slot)
            # IRIS EXPLAIN: Store int(start >= change) in phase; later lines use this named result.
            phase = int(start >= change)
            # IRIS EXPLAIN: Store the formatted text f'AST-{int(rng.integers(1, asset_count + 1)):03d}' in aid; later lines use
            # IRIS EXPLAIN: this named result.
            aid = f"AST-{int(rng.integers(1, asset_count+1)):03d}"
            # IRIS EXPLAIN: Store asset_lookup[aid, phase] in asset; later lines use this named result.
            asset = asset_lookup[(aid, phase)]
            # IRIS EXPLAIN: Store label == 'benign' and rng.random() < 0.15 in benign_scan; later lines use this named result.
            benign_scan = label == "benign" and rng.random() < .15
            # IRIS EXPLAIN: Store 'network' when label == 'reconnaissance' or benign_scan; otherwise 'authentication' in family;
            # IRIS EXPLAIN: later lines use this named result.
            family = "network" if label == "reconnaissance" or benign_scan else "authentication"
            # IRIS EXPLAIN: Enter this branch only when family == 'authentication'.
            if family == "authentication":
                # IRIS EXPLAIN: Store int(rng.integers(8, 46)) when label == 'credential_access'; otherwise int(rng.integers(1,
                # IRIS EXPLAIN: 5)) in failed; later lines use this named result.
                failed = int(rng.integers(8, 46)) if label == "credential_access" else int(rng.integers(1, 5))
                # IRIS EXPLAIN: Store int(rng.integers(0, 3)) when label == 'credential_access'; otherwise int(rng.integers(1,
                # IRIS EXPLAIN: 3)) in success; later lines use this named result.
                success = int(rng.integers(0, 3)) if label == "credential_access" else int(rng.integers(1, 3))
                # IRIS EXPLAIN: Store the computed value ['failed'] * failed + ['success'] * success in outcomes; later lines
                # IRIS EXPLAIN: use this named result.
                outcomes = ["failed"]*failed + ["success"]*success
                # IRIS EXPLAIN: Store len(outcomes) in n; later lines use this named result.
                n = len(outcomes)
                # IRIS EXPLAIN: Store int(rng.integers(1, 5)) in rule_count; later lines use this named result.
                rule_count = int(rng.integers(1, 5))
                # IRIS EXPLAIN: Store int(rng.integers(5, 12)) when label == 'credential_access'; otherwise int(rng.integers(2,
                # IRIS EXPLAIN: 8)) in max_level; later lines use this named result.
                max_level = int(rng.integers(5, 12)) if label == "credential_access" else int(rng.integers(2, 8))
            # IRIS EXPLAIN: Handle the alternative to the preceding condition/loop exactly as originally defined.
            else:
                # IRIS EXPLAIN: Store int(rng.integers(22, 81)) when label == 'reconnaissance'; otherwise int(rng.integers(15,
                # IRIS EXPLAIN: 46)) in n; later lines use this named result.
                n = int(rng.integers(22, 81)) if label == "reconnaissance" else int(rng.integers(15, 46))
                # IRIS EXPLAIN: Store (0, 0, ['unknown'] * n) in (failed, success, outcomes); later lines use this named result.
                failed, success, outcomes = 0, 0, ["unknown"]*n
                # IRIS EXPLAIN: Store int(rng.integers(1, 7)) in rule_count; later lines use this named result.
                rule_count = int(rng.integers(1, 7))
                # IRIS EXPLAIN: Store int(rng.choice([4, 7, 10])) in max_level; later lines use this named result.
                max_level = int(rng.choice([4, 7, 10]))
            # IRIS EXPLAIN: Store float(rng.uniform(5, 50)) in duration; later lines use this named result.
            duration = float(rng.uniform(5, 50))
            # IRIS EXPLAIN: Store str(rng.choice(['alice', 'bob', 'carol', 'secops'])) when family == 'authentication';
            # IRIS EXPLAIN: otherwise None (no result/value) in account; later lines use this named result.
            account = str(rng.choice(["alice", "bob", "carol", "secops"])) if family == "authentication" else None
            # IRIS EXPLAIN: Store the formatted text f'10.88.{campaign % 4}.{int(rng.integers(10, 240))}' in actor; later lines
            # IRIS EXPLAIN: use this named result.
            actor = f"10.88.{campaign % 4}.{int(rng.integers(10, 240))}"
            # IRIS EXPLAIN: Store [] in event_ids; later lines use this named result.
            event_ids = []
            # IRIS EXPLAIN: Iterate range(n), binding each item to ordinal; process only the existing observed/fixture
            # IRIS EXPLAIN: collection.
            for ordinal in range(n):
                # IRIS EXPLAIN: Store the formatted text f'EVT-{counter:06d}-{ordinal + 1:03d}' in eid; later lines use this
                # IRIS EXPLAIN: named result.
                eid = f"EVT-{counter:06d}-{ordinal+1:03d}"
                # IRIS EXPLAIN: Call event_ids.append(eid): append one item to the working list.
                event_ids.append(eid)
                # IRIS EXPLAIN: Call alerts.append({'event_id': eid, 'timestamp': (start + timedelta(seconds=duration * ordinal
                # IRIS EXPLAIN: / max(n - 1, 1))).isoformat(), 'asset_id': aid, 'destination_ip': ...: append one item to the
                # IRIS EXPLAIN: working list.
                alerts.append({"event_id": eid, "timestamp": (start+timedelta(seconds=duration*ordinal/max(n-1, 1))).isoformat(),
                               # IRIS EXPLAIN: Set/describe these existing record fields: asset_id: exact target-asset identity;
                               # IRIS EXPLAIN: not an attacker source-IP guess.
                               "asset_id": aid, "destination_ip": asset["ip_addresses"][0],
                               # IRIS EXPLAIN: Continue the current record with agent_name, source_ip; each value comes from the
                               # IRIS EXPLAIN: expression shown on this unchanged line.
                               "agent_name": asset["hostname"], "source_ip": actor,
                               # IRIS EXPLAIN: Set/describe these existing record fields: event_family: observed telemetry
                               # IRIS EXPLAIN: family; a Model 1 categorical predictor, not a truth label.
                               "account": account, "event_family": family,
                               # IRIS EXPLAIN: Continue the current record with protocol; each value comes from the expression
                               # IRIS EXPLAIN: shown on this unchanged line.
                               "protocol": "SSH" if family == "authentication" else "TCP",
                               # IRIS EXPLAIN: Continue the current record with rule_id; each value comes from the expression
                               # IRIS EXPLAIN: shown on this unchanged line.
                               "rule_id": str((5700 if family == 'authentication' else 2100000) + ordinal % rule_count),
                               # IRIS EXPLAIN: Continue the current record with rule_level; each value comes from the expression
                               # IRIS EXPLAIN: shown on this unchanged line.
                               "rule_level": max_level if ordinal == 0 else int(rng.integers(2, max_level+1)),
                               # IRIS EXPLAIN: Set/describe these existing record fields: sensor_healthy: explicit health
                               # IRIS EXPLAIN: evidence; a missing/false value must not be treated as benign.
                               "outcome": outcomes[ordinal], "sensor_healthy": True,
                               # IRIS EXPLAIN: Set/describe these existing record fields: campaign_id: group provenance retained
                               # IRIS EXPLAIN: for split/session identity; not a telemetry predictor; run_id: run/batch
                               # IRIS EXPLAIN: provenance retained for traceability; not a hidden attack-label feature;
                               # IRIS EXPLAIN: data_provenance: explicit synthetic/cyber_range/operational source identity.
                               "campaign_id": campaign_id, "run_id": run_id, "data_provenance": "synthetic"})
            # IRIS EXPLAIN: Store ['SC005', 'SC007'] when label == 'credential_access'; otherwise ['SC012', 'SC029'] when label
            # IRIS EXPLAIN: == 'reconnaissance'; otherwise [] in controls; later lines use this named result.
            controls = ["SC005", "SC007"] if label == "credential_access" else ["SC012", "SC029"] if label == "reconnaissance" else []
            # IRIS EXPLAIN: Enter this branch only when label == 'credential_access' and failed >= 20.
            if label == "credential_access" and failed >= 20:
                # IRIS EXPLAIN: Call controls.append('SC006'): append one item to the working list.
                controls.append("SC006")
            # IRIS EXPLAIN: Enter this branch only when label != 'benign' and asset['criticality'] >= 4.
            if label != "benign" and asset["criticality"] >= 4:
                # IRIS EXPLAIN: Call controls.append('SC026'): append one item to the working list.
                controls.append("SC026")
            # IRIS EXPLAIN: Call labels.append({'case_id': f'SYN-LABEL-{counter:06d}', 'event_ids': event_ids, 'campaign_id':
            # IRIS EXPLAIN: campaign_id, 'run_id': run_id, 'scenario_class': label, 'templat...: append one item to the working
            # IRIS EXPLAIN: list.
            labels.append({"case_id": f"SYN-LABEL-{counter:06d}", "event_ids": event_ids,
                           # IRIS EXPLAIN: Set/describe these existing record fields: campaign_id: group provenance retained for
                           # IRIS EXPLAIN: split/session identity; not a telemetry predictor; run_id: run/batch provenance
                           # IRIS EXPLAIN: retained for traceability; not a hidden attack-label feature.
                           "campaign_id": campaign_id, "run_id": run_id,
                           # IRIS EXPLAIN: Set/describe these existing record fields: scenario_class: a reviewed training target
                           # IRIS EXPLAIN: or the explicitly identified prediction field; never silently added to telemetry
                           # IRIS EXPLAIN: predictors.
                           "scenario_class": label, "template_group": f"{label}-behavioral-variant-{campaign % 5}",
                           # IRIS EXPLAIN: Continue the current record with label_verified, reviewer; each value comes from the
                           # IRIS EXPLAIN: expression shown on this unchanged line.
                           "label_verified": True, "reviewer": "SYNTHETIC_GENERATOR_NOT_AN_EXPERT",
                           # IRIS EXPLAIN: Continue the current record with recommended_control_ids, controls_reviewed; each
                           # IRIS EXPLAIN: value comes from the expression shown on this unchanged line.
                           "recommended_control_ids": controls, "controls_reviewed": True,
                           # IRIS EXPLAIN: Continue the current record with control_reviewer; each value comes from the
                           # IRIS EXPLAIN: expression shown on this unchanged line.
                           "control_reviewer": "SYNTHETIC_GENERATOR_NOT_AN_EXPERT"})
            # IRIS EXPLAIN: Update class_runs[label] using the existing Add operation and 1.
            class_runs[label] += 1
    # Representative input-quality cases do not become training labels.
    # IRIS EXPLAIN: Store min(12, len(alerts)) in duplicate_count; later lines use this named result.
    duplicate_count = min(12, len(alerts))
    # IRIS EXPLAIN: Call alerts.extend([dict(alerts[i]) for i in range(duplicate_count)]): append all supplied items to the
    # IRIS EXPLAIN: working list.
    alerts.extend([dict(alerts[i]) for i in range(duplicate_count)])
    # IRIS EXPLAIN: Iterate range(2), binding each item to ordinal; process only the existing observed/fixture collection.
    for ordinal in range(2):
        # IRIS EXPLAIN: Store dict(alerts[0]) in unknown; later lines use this named result.
        unknown = dict(alerts[0])
        # IRIS EXPLAIN: Call unknown.update({'event_id': f'QA-UNRESOLVED-{ordinal}', 'asset_id': 'AST-NOT-IN-INVENTORY'}): merge
        # IRIS EXPLAIN: the supplied fields into this existing mapping.
        unknown.update({"event_id": f"QA-UNRESOLVED-{ordinal}", "asset_id": "AST-NOT-IN-INVENTORY"})
        # IRIS EXPLAIN: Call alerts.append(unknown): append one item to the working list.
        alerts.append(unknown)
    # IRIS EXPLAIN: Store dict(alerts[0]) in bad; later lines use this named result.
    bad = dict(alerts[0])
    # IRIS EXPLAIN: Call bad.update({'event_id': 'QA-INVALID-TIMESTAMP', 'timestamp': 'not-a-timestamp'}): merge the supplied
    # IRIS EXPLAIN: fields into this existing mapping.
    bad.update({"event_id": "QA-INVALID-TIMESTAMP", "timestamp": "not-a-timestamp"})
    # IRIS EXPLAIN: Call alerts.append(bad): append one item to the working list.
    alerts.append(bad)
    # IRIS EXPLAIN: Call rng.shuffle(alerts) using the existing explicit arguments.
    rng.shuffle(alerts)
    # IRIS EXPLAIN: Store a mapping containing data_provenance, notice in header; later lines use this named result.
    header = {"data_provenance": "synthetic", "notice": "Artificial development/training samples. Not actual SIEM, hospital or expert-review evidence."}
    # IRIS EXPLAIN: Call write_json(out / 'asset_inventory.json', {'schema_version': ASSET_SCHEMA, **header, 'records': assets})
    # IRIS EXPLAIN: using the existing explicit arguments.
    write_json(out / "asset_inventory.json", {"schema_version": ASSET_SCHEMA, **header, "records": assets})
    # IRIS EXPLAIN: Call write_json(out / 'risk_register.json', {'schema_version': RISK_SCHEMA, **header, 'records': risks})
    # IRIS EXPLAIN: using the existing explicit arguments.
    write_json(out / "risk_register.json", {"schema_version": RISK_SCHEMA, **header, "records": risks})
    # IRIS EXPLAIN: Call write_jsonl(out / 'siem_alerts.jsonl', alerts) using the existing explicit arguments.
    write_jsonl(out / "siem_alerts.jsonl", alerts)
    # IRIS EXPLAIN: Call write_jsonl(out / 'training_labels.jsonl', labels) using the existing explicit arguments.
    write_jsonl(out / "training_labels.jsonl", labels)
    # IRIS EXPLAIN: Store a mapping containing data_provenance, seed, asset_count, asset_snapshots, risk_count, risk_snapshots,
    # IRIS EXPLAIN: siem_alert_rows and additional fields in summary; later lines use this named result.
    summary = {"data_provenance": "synthetic", "seed": seed,
               # IRIS EXPLAIN: Continue the current record with asset_count, asset_snapshots; each value comes from the
               # IRIS EXPLAIN: expression shown on this unchanged line.
               "asset_count": asset_count, "asset_snapshots": len(assets),
               # IRIS EXPLAIN: Set/describe these existing record fields: risk_snapshots: all time-valid registered risks nested
               # IRIS EXPLAIN: on the session, not duplicated alert rows.
               "risk_count": 2*asset_count, "risk_snapshots": len(risks),
               # IRIS EXPLAIN: Continue the current record with siem_alert_rows, labeled_sessions_expected; each value comes
               # IRIS EXPLAIN: from the expression shown on this unchanged line.
               "siem_alert_rows": len(alerts), "labeled_sessions_expected": len(labels),
               # IRIS EXPLAIN: Continue the current record with campaign_count, runs_per_class; each value comes from the
               # IRIS EXPLAIN: expression shown on this unchanged line.
               "campaign_count": campaigns, "runs_per_class": dict(class_runs),
               # IRIS EXPLAIN: Continue the current record with qa_cases, exact_duplicate_rows, unresolved_asset_alerts,
               # IRIS EXPLAIN: invalid_timestamp_alerts; each value comes from the expression shown on this unchanged line.
               "qa_cases": {"exact_duplicate_rows": duplicate_count, "unresolved_asset_alerts": 2, "invalid_timestamp_alerts": 1},
               # IRIS EXPLAIN: Continue the current record with operational_inputs; each value comes from the expression shown
               # IRIS EXPLAIN: on this unchanged line.
               "operational_inputs": ["asset_inventory.json", "risk_register.json", "siem_alerts.jsonl"],
               # IRIS EXPLAIN: Continue the current record with offline_training_only, release_allowed; each value comes from
               # IRIS EXPLAIN: the expression shown on this unchanged line.
               "offline_training_only": "training_labels.jsonl", "release_allowed": False}
    # IRIS EXPLAIN: Call write_json(out / 'sample_manifest.json', summary) using the existing explicit arguments.
    write_json(out / "sample_manifest.json", summary)
    # IRIS EXPLAIN: Return summary to the caller; this ends the current function path.
    return summary
