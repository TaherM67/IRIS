"""CyberRangeV1 telemetry adapter. This module NEVER opens the truth plane."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from .contracts import digest, read_jsonl, validate_features


def timestamp(value) -> datetime:
    if not isinstance(value, str):
        raise ValueError("Missing/invalid timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Timestamp has no timezone")
    return parsed.astimezone(timezone.utc)


def get(row, *paths):
    for path in paths:
        value = row
        for key in path.split("."):
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(key)
        if value is not None and value != "":
            return value
    return None


def external(value) -> bool:
    if not value:
        return False
    address = ipaddress.ip_address(value)
    return not (address.is_private or address.is_loopback or address.is_link_local)


def normalize_event(row, sensor: str, raw_ref: str) -> dict | None:
    row = row.get("_source", row)
    if not isinstance(row, dict):
        raise ValueError("Event must be an object")
    # Wazuh commonly wraps the original EVE alert in full_log or data.
    if sensor == "wazuh":
        wrapped = row.get("data", {})
        if isinstance(wrapped, dict) and wrapped.get("event_type") == "alert" and "alert" in wrapped:
            result = normalize_event(wrapped, "suricata", raw_ref)
            if result and result.get("ts"):
                return result
        try:
            raw = json.loads(row.get("full_log", ""))
        except (ValueError, TypeError):
            raw = None
        if isinstance(raw, dict) and raw.get("event_type") == "alert":
            return normalize_event(raw, "suricata", raw_ref)
    ts = timestamp(get(row, "timestamp", "@timestamp", "event_timestamp"))
    if sensor == "suricata":
        if row.get("event_type") != "alert":
            return None  # Flow/DNS/statistics need a different feature schema.
        severity = int(row["alert"]["severity"])
        if severity not in {1, 2, 3}:
            raise ValueError("Unsupported Suricata severity")
        src, dst = row.get("src_ip"), row.get("dest_ip")
        sig = str(row["alert"]["signature_id"])
        level = {1: 10, 2: 7, 3: 4}[severity]
        family, protocol, account, outcome = "network", str(row.get("proto", "unknown")).upper(), None, "unknown"
        event_key = f"suricata|{row.get('flow_id')}|{sig}|{ts.isoformat()}|{src}|{dst}|{row.get('src_port')}|{row.get('dest_port')}"
        agent = None
    else:
        src = get(row, "data.srcip", "source_ip", "src_ip")
        dst = get(row, "data.dstip", "destination_ip", "dst_ip")
        agent = get(row, "agent.name", "agent_name", "host.name")
        account = get(row, "data.dstuser", "data.srcuser", "account", "username", "user")
        groups = get(row, "rule.groups", "rule_groups") or []
        groups = [groups] if isinstance(groups, str) else groups
        description = str(get(row, "rule.description", "description") or "")
        text = " ".join([*map(str, groups), description, str(row.get("full_log", "")), str(row.get("outcome", ""))]).casefold()
        explicit = get(row, "event_family")
        family = str(explicit).casefold() if explicit else "authentication" if any(w in text for w in ("sshd", "authentication", "login", "password")) else "network" if any(w in text for w in ("suricata", "firewall", "scan")) else "unknown"
        protocol = str(get(row, "data.protocol", "protocol", "proto") or ("SSH" if "sshd" in text else "unknown")).upper()
        if re.search(r"\b(failed|failure|denied|invalid|unsuccessful)\b", text):
            outcome = "failed"
        elif re.search(r"\b(success|successful|accepted|granted)\b", text):
            outcome = "success"
        else:
            outcome = "unknown"
        level = float(get(row, "rule.level", "rule_level") or 0)
        if not 0 <= level <= 16:
            raise ValueError("Wazuh level outside 0..16")
        sig = str(get(row, "rule.id", "rule_id") or "unknown")
        stable = json.dumps(row, sort_keys=True, separators=(",", ":"))
        event_key = "wazuh|" + hashlib.sha256(stable.encode()).hexdigest()
    for ip in (src, dst):
        if ip:
            ipaddress.ip_address(ip)
    return {"ts": ts, "src": src, "dst": dst, "agent": agent,
            "account": str(account) if account else "unknown", "family": family,
            "protocol": protocol, "outcome": outcome, "level": level,
            "rule": sig, "key": event_key, "raw_ref": raw_ref}


def aggregate(events: list[dict]) -> dict:
    events = sorted(events, key=lambda e: (e["ts"], e["key"]))
    n = len(events)
    failed = sum(e["outcome"] == "failed" for e in events)
    successful = sum(e["outcome"] == "success" for e in events)
    seen_fail, later_success = False, False
    for event in events:
        seen_fail |= event["outcome"] == "failed"
        later_success |= seen_fail and event["outcome"] == "success"
    left, burst = 0, 0
    for right, event in enumerate(events):
        while (event["ts"] - events[left]["ts"]).total_seconds() > 10:
            left += 1
        burst = max(burst, right-left+1)
    duration = (events[-1]["ts"] - events[0]["ts"]).total_seconds()
    return validate_features({
        "event_family": events[0]["family"],
        "primary_protocol": Counter(e["protocol"] for e in events).most_common(1)[0][0],
        "event_count": n, "duration_seconds": duration,
        "max_rule_level": max(e["level"] for e in events),
        "mean_rule_level": sum(e["level"] for e in events)/n,
        "distinct_rules": len({e["rule"] for e in events}),
        "distinct_sources": len({e["src"] for e in events if e["src"]}),
        "distinct_accounts": len({e["account"] for e in events if e["account"] != "unknown"}),
        "failed_count": failed, "success_count": successful,
        "failure_ratio": failed/(failed+successful) if failed+successful else 0,
        "success_after_failures": int(later_success), "max_events_in_10s": burst,
        "external_source_fraction": sum(external(e["src"]) for e in events)/n,
        "event_rate_per_minute": n*60/max(duration, 1),
    })


def verify_campaign_hashes(campaign: Path) -> list[str]:
    manifest_path = campaign / "campaign_manifest.json"
    if not manifest_path.exists():
        return ["Missing campaign_manifest.json; source integrity not verified"]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        return ["Campaign manifest has no file hashes"]
    verified = set()
    for item in files:
        parts = Path(item["path"]).parts
        # Ground truth and scenario plans are offline annotation material only.
        if "truth" in parts or "scenarios" in parts or Path(item["path"]).name in {
            "activity_ground_truth.jsonl", "campaign_plan.json",
        }:
            continue
        path = (campaign / item["path"]).resolve()
        if not path.is_relative_to(campaign.resolve()) or not path.is_file():
            raise ValueError("Campaign manifest references an unsafe/missing path")
        if digest(path) != item["sha256"] or path.stat().st_size != item["bytes"]:
            raise ValueError(f"Campaign integrity mismatch: {item['path']}")
        verified.add(str(path.relative_to(campaign.resolve())))
    required = {str(p.relative_to(campaign)) for run in (campaign / "runs").glob("run-*")
                for p in [run / "topology.json", run / "identity_data.json",
                          run / "wazuh_stuff/alerts.jsonl", run / "suricata_stuff/eve.json",
                          run / "quality/sensor_health.json"]}
    if not required.issubset(verified):
        return ["Manifest omits hashes for required runtime files"]
    return []


def sensor_health(run: Path, topology: dict) -> bool:
    path = run / "quality/sensor_health.json"
    if not path.is_file():
        return False
    health = json.loads(path.read_text(encoding="utf-8"))
    if health.get("action_error") or health.get("telemetry_errors"):
        return False
    hosts = health.get("health", {})
    if not isinstance(hosts, dict) or not hosts or any(not isinstance(v, dict) or v.get("status") != "ok" for v in hosts.values()):
        return False
    manager = hosts.get("wazuh-manager", {})
    active = set(manager.get("active_agents", []))
    expected = {a["hostname"] for a in topology["assets"] if a.get("role") != "wazuh_manager"}
    return expected.issubset(active) and {"wazuh-manager", "suricata-sensor"}.issubset(hosts)


def extract_run(run: Path, campaign_id: str, *, window_seconds: int = 60) -> tuple[list[dict], list[dict]]:
    if isinstance(window_seconds, bool) or window_seconds not in {30, 60, 120}:
        raise ValueError("window_seconds must be 30, 60 or 120")
    topology = json.loads((run / "topology.json").read_text(encoding="utf-8"))
    ip_to_asset, host_to_asset = {}, {}
    for asset in topology["assets"]:
        ip = str(ipaddress.ip_address(asset["ip"]))
        if ip in ip_to_asset or asset["hostname"] in host_to_asset:
            raise ValueError("Ambiguous topology mapping")
        ip_to_asset[ip], host_to_asset[asset["hostname"]] = asset["asset_id"], asset["asset_id"]
    identities = json.loads((run / "identity_data.json").read_text(encoding="utf-8"))
    accounts = {a["username"] for a in identities.get("accounts", [])}
    healthy = sensor_health(run, topology)
    events, quarantine, seen = [], [], set()
    for relative, sensor in [("wazuh_stuff/alerts.jsonl", "wazuh"), ("suricata_stuff/eve.json", "suricata")]:
        source = run / relative
        raw_rows = read_jsonl(source)
        if not raw_rows:
            healthy = False
        for index, raw in enumerate(raw_rows, 1):
            ref = f"{campaign_id}/{run.name}/{relative}#L{index}"
            try:
                event = normalize_event(raw, sensor, ref)
                if event is None:
                    continue
                if event["key"] in seen:
                    continue
                seen.add(event["key"])
                # Destination-first avoids assigning a sensor's alert to the sensor itself.
                asset = ip_to_asset.get(event["dst"]) if event["dst"] else host_to_asset.get(event["agent"])
                if not asset:
                    raise ValueError("Asset cannot be resolved exactly; no truth-derived target is used")
                event["asset_id"] = asset
                event["identity_unresolved"] = event["account"] != "unknown" and event["account"] not in accounts
                events.append(event)
            except (KeyError, TypeError, ValueError) as exc:
                quarantine.append({"raw_ref": ref, "reason": str(exc)})
    groups = defaultdict(list)
    for e in events:
        groups[(e["asset_id"], e["account"], e["src"], e["family"])].append(e)
    output = []
    def append(members, key):
        fingerprint = f"{campaign_id}|{run.name}|{key}|{members[0]['key']}|{window_seconds}"
        sid = "SES-" + hashlib.sha256(fingerprint.encode()).hexdigest()[:20]
        output.append({"session_id": sid, "run_id": run.name, "campaign_id": campaign_id,
                       "asset_id": key[0], "start_utc": members[0]["ts"].isoformat(),
                       "end_utc": members[-1]["ts"].isoformat(), "window_seconds": window_seconds,
                       "data_provenance": "cyber_range", "sensor_healthy": healthy and not quarantine,
                       "aggregation_schema": f"cyberrange-session-v1-window{window_seconds}",
                       "features": aggregate(members),
                       "identity_status": "UNRESOLVED" if any(e["identity_unresolved"] for e in members) else "EXACT_OR_UNOBSERVED",
                       "evidence_refs": [e["raw_ref"] for e in members],
                       "context": None,
                       "context_note": "Join time-valid GRC asset_type, asset_criticality, current_likelihood, impact, previous_similar_24h before training Model 2; topology does not establish business criticality."})
    for key, members in groups.items():
        members.sort(key=lambda e: (e["ts"], e["key"]))
        current = []
        for e in members:
            if current and (e["ts"] - current[-1]["ts"]).total_seconds() > window_seconds:
                append(current, key)
                current = []
            current.append(e)
        if current:
            append(current, key)
    return sorted(output, key=lambda o: (o["start_utc"], o["session_id"])), quarantine


def extract_campaign(campaign: Path, *, window_seconds: int = 60) -> tuple[list[dict], dict]:
    warnings = verify_campaign_hashes(campaign)
    rows, quarantine = [], []
    run_paths = sorted((campaign / "runs").glob("run-*"))
    if not run_paths:
        raise ValueError("Expected campaign/runs/run-* directories")
    for run in run_paths:
        try:
            part, invalid = extract_run(run, campaign.name, window_seconds=window_seconds)
            rows.extend(part)
            quarantine.extend(invalid)
        except (OSError, TypeError, KeyError, ValueError) as exc:
            quarantine.append({"run_id": run.name, "reason": str(exc)})
    if warnings:
        for row in rows:
            row["sensor_healthy"] = False
    return rows, {"run_count": len(run_paths), "session_count": len(rows),
                  "quarantine": quarantine, "warnings": warnings,
                  "truth_files_read": False, "automatic_labels_created": False,
                  "note": "Review and label each session independently. Run-level attack truth does not label background sessions."}
