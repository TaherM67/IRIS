"""Three-source, point-in-time integration before feature engineering/ML.

One SIEM alert stays one unified event; risks are nested, not a row multiplier.
No training label file is opened anywhere in this runtime preparation module.
"""
from __future__ import annotations

import bisect
import hashlib
import heapq
import ipaddress
import json
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .contracts import digest, finite, write_json, write_jsonl
from .telemetry import aggregate, get, normalize_event, timestamp

PROVENANCES = {"synthetic", "cyber_range", "operational"}
ASSET_SCHEMA = "iris-asset-inventory-v1"
RISK_SCHEMA = "iris-risk-register-v1"
CONTEXT_POLICY = "highest_preexisting_likelihood_times_impact_then_risk_id"
CONTROL_STATES = {"implemented", "partial", "missing", "not_assessed", "compensating", "exception", "unknown"}


def text(value, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be nonempty text")
    return value.strip()


def bounded_integer(value, name, low=1, high=5) -> int:
    number = finite(value, name, low, high)
    if int(number) != number:
        raise ValueError(f"{name} must be an integer")
    return int(number)


def valid_times(row: dict) -> dict:
    start = timestamp(row.get("valid_from"))
    end = timestamp(row["valid_to"]) if row.get("valid_to") else None
    known = timestamp(row.get("recorded_at"))
    if end is not None and end <= start:
        raise ValueError("valid_to must be later than valid_from")
    return {"_from": start, "_to": end, "_known": known,
            "valid_from": start.isoformat(), "valid_to": end.isoformat() if end else None,
            "recorded_at": known.isoformat()}


def public(record: dict | None) -> dict | None:
    return {key: value for key, value in record.items() if not key.startswith("_")} if record else None


class TemporalIndex:
    """Validated non-overlapping histories; O(log V) point lookup per key."""
    def __init__(self, rows: list[dict], key: str):
        self.rows = defaultdict(list)
        self.starts = {}
        for row in rows:
            self.rows[row[key]].append(row)
        for identifier, history in self.rows.items():
            history.sort(key=lambda row: row["_from"])
            for prior, current in zip(history, history[1:]):
                if prior["_to"] is None or prior["_to"] > current["_from"]:
                    raise ValueError(f"Overlapping versions for {key}={identifier}; resolve ambiguity in the source")
            self.starts[identifier] = [r["_from"] for r in history]

    def at(self, key: str, at: datetime) -> dict | None:
        starts = self.starts.get(key, [])
        i = bisect.bisect_right(starts, at)-1
        if i < 0:
            return None
        row = self.rows[key][i]
        if row["_known"] > at or (row["_to"] is not None and at >= row["_to"]):
            return None
        return row


@dataclass
class Sources:
    assets: TemporalIndex
    risks: TemporalIndex
    ip_assets: dict
    hostname_assets: dict
    asset_risks: dict
    provenance: str
    asset_count: int
    risk_count: int


def read_source(path: Path, schema: str) -> tuple[list[dict], str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema_version") != schema:
        raise ValueError(f"{path.name}: expected schema_version={schema}")
    provenance = payload.get("data_provenance")
    if provenance not in PROVENANCES:
        raise ValueError(f"{path.name}: explicit synthetic/cyber_range/operational provenance required")
    rows = payload.get("records")
    if not isinstance(rows, list) or not rows or any(not isinstance(r, dict) for r in rows):
        raise ValueError(f"{path.name}: records must be a nonempty object array")
    return rows, provenance


def load_sources(asset_path: Path, risk_path: Path) -> Sources:
    asset_raw, provenance = read_source(asset_path, ASSET_SCHEMA)
    risk_raw, risk_provenance = read_source(risk_path, RISK_SCHEMA)
    if provenance != risk_provenance:
        raise ValueError("Do not mix synthetic and real sources or inconsistent provenance")
    assets, risks, version_ids = [], [], set()
    for row in asset_raw:
        aid = text(row.get("asset_id"), "asset_id")
        vid = text(row.get("asset_version_id"), "asset_version_id")
        if vid in version_ids:
            raise ValueError("Duplicate asset_version_id")
        version_ids.add(vid)
        ips = row.get("ip_addresses")
        if not isinstance(ips, list) or not ips:
            raise ValueError("Every asset snapshot needs an ip_addresses array")
        ips = sorted({str(ipaddress.ip_address(ip)) for ip in ips})
        assets.append({"asset_id": aid, "asset_version_id": vid,
                       "hostname": text(row.get("hostname"), "hostname").casefold(),
                       "ip_addresses": ips, "asset_type": text(row.get("asset_type"), "asset_type"),
                       "criticality": bounded_integer(row.get("criticality"), "criticality"),
                       "zone": text(row.get("zone"), "zone"),
                       "owner": text(row.get("owner"), "owner"), **valid_times(row)})
    known_assets = {row["asset_id"] for row in assets}
    risk_owner, version_ids = {}, set()
    for row in risk_raw:
        rid = text(row.get("risk_id"), "risk_id")
        aid = text(row.get("asset_id"), "risk.asset_id")
        vid = text(row.get("risk_version_id"), "risk_version_id")
        if vid in version_ids:
            raise ValueError("Duplicate risk_version_id")
        version_ids.add(vid)
        if aid not in known_assets:
            raise ValueError(f"Risk {rid} references an asset absent from inventory")
        if rid in risk_owner and risk_owner[rid] != aid:
            raise ValueError("One risk_id cannot ambiguously reference multiple assets")
        risk_owner[rid] = aid
        states = row.get("control_states", {})
        if not isinstance(states, dict) or any(not isinstance(k, str) or not isinstance(v, str) or v not in CONTROL_STATES for k, v in states.items()):
            raise ValueError("Invalid control_states mapping")
        exceptions = row.get("active_exception_control_ids", [])
        if not isinstance(exceptions, list) or any(not isinstance(c, str) for c in exceptions):
            raise ValueError("active_exception_control_ids must be a string list")
        risks.append({"risk_id": rid, "risk_version_id": vid, "asset_id": aid,
                      "risk_category": text(row.get("risk_category"), "risk_category"),
                      "likelihood": bounded_integer(row.get("likelihood"), "likelihood"),
                      "impact": bounded_integer(row.get("impact"), "impact"),
                      "control_states": states, "active_exception_control_ids": sorted(set(exceptions)),
                      **valid_times(row)})
    ip_assets, hostname_assets, asset_risks = defaultdict(set), defaultdict(set), defaultdict(set)
    for asset in assets:
        for ip in asset["ip_addresses"]:
            ip_assets[ip].add(asset["asset_id"])
        hostname_assets[asset["hostname"]].add(asset["asset_id"])
    for risk in risks:
        asset_risks[risk["asset_id"]].add(risk["risk_id"])
    return Sources(TemporalIndex(assets, "asset_id"), TemporalIndex(risks, "risk_id"),
                   ip_assets, hostname_assets, asset_risks, provenance, len(assets), len(risks))


def normalize_alert(raw: dict, line: int, source_name: str) -> dict | None:
    if not isinstance(raw, dict):
        raise ValueError("SIEM alert must be a JSON object")
    row = raw.get("_source", raw)
    if not isinstance(row, dict):
        raise ValueError("SIEM _source must be an object")
    def metadata(name, default=None):
        return row[name] if name in row else raw.get(name, default)
    # Canonical flat alerts have explicit outcome, avoiding text-only inference.
    if all(k in row for k in ("event_family", "rule_level", "outcome")):
        ts = timestamp(row.get("timestamp"))
        outcome = row["outcome"]
        if outcome not in {"failed", "success", "unknown"}:
            raise ValueError("outcome must be failed, success or unknown")
        event = {"ts": ts, "src": row.get("source_ip"), "dst": row.get("destination_ip"),
                 "agent": row.get("agent_name"), "account": row.get("account") or "unknown",
                 "family": text(row["event_family"], "event_family").casefold(),
                 "protocol": text(row.get("protocol"), "protocol").upper(),
                 "outcome": outcome, "level": finite(row["rule_level"], "rule_level", 0, 16),
                 "rule": text(str(row.get("rule_id", "")), "rule_id"),
                 "raw_ref": f"{source_name}#L{line}"}
        semantic_key = None
    else:
        sensor = "suricata" if row.get("event_type") else "wazuh"
        event = normalize_event(row, sensor, f"{source_name}#L{line}")
        if event is None:
            return None
        semantic_key = event.get("key")
    eid = get(row, "event_id", "id", "_id")
    if eid is None:
        eid = raw.get("_id")
    if eid is None:
        raise ValueError("A stable SIEM event_id/id/_id is required; line numbers are not event identities")
    for field in ("src", "dst"):
        if event[field]:
            event[field] = str(ipaddress.ip_address(event[field]))
    if event.get("agent"):
        event["agent"] = str(event["agent"]).strip().casefold()
    event["account"] = str(event["account"])
    event.update({"event_id": text(str(eid), "event_id"),
                  "asset_id_hint": get(row, "asset_id", "resolved_asset_id") or get(raw, "asset_id", "resolved_asset_id"),
                  "campaign_id": str(metadata("campaign_id") or "runtime-source"),
                  "run_id": str(metadata("run_id") or "runtime-batch"),
                  "sensor_healthy": metadata("sensor_healthy") is True,
                  "data_provenance": metadata("data_provenance"),
                  "semantic_key": semantic_key})
    event["key"] = event["event_id"]
    return event


def fingerprint(event: dict) -> str:
    value = {k: (v.isoformat() if isinstance(v, datetime) else v)
             for k, v in event.items() if k not in {"raw_ref", "key"}}
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def resolve_asset(event: dict, sources: Sources) -> tuple[dict | None, str]:
    at = event["ts"]
    hint = event.get("asset_id_hint")
    if hint:
        asset = sources.assets.at(str(hint).strip(), at)
        if asset is None:
            return None, "asset_id has no inventory snapshot valid and known at event time"
        if event["dst"] and event["dst"] not in asset["ip_addresses"]:
            return None, "SIEM asset_id and destination IP disagree"
        return asset, "exact_asset_id"
    if event["dst"]:
        candidates = [sources.assets.at(aid, at) for aid in sources.ip_assets.get(event["dst"], [])]
        candidates = [a for a in candidates if a and event["dst"] in a["ip_addresses"]]
        return (candidates[0], "exact_destination_ip") if len(candidates) == 1 else (None, "destination IP unresolved or ambiguous at event time")
    if event.get("agent"):
        candidates = [sources.assets.at(aid, at) for aid in sources.hostname_assets.get(event["agent"], [])]
        candidates = [a for a in candidates if a and a["hostname"] == event["agent"]]
        return (candidates[0], "exact_agent_hostname") if len(candidates) == 1 else (None, "agent hostname unresolved or ambiguous at event time")
    return None, "No trustworthy asset_id, destination IP or agent hostname; source IP is not a victim lookup"


def choose_context(asset: dict, risks: list[dict], previous: int) -> dict | None:
    if not risks:
        return None
    representative = sorted(risks, key=lambda r: (-r["likelihood"]*r["impact"], r["risk_id"]))[0]
    return {"asset_type": asset["asset_type"], "asset_criticality": asset["criticality"],
            "current_likelihood": representative["likelihood"], "impact": representative["impact"],
            "previous_similar_24h": previous, "controls": representative["control_states"],
            "active_exception_control_ids": representative["active_exception_control_ids"],
            "context_risk_id": representative["risk_id"],
            "context_risk_version_id": representative["risk_version_id"],
            "risk_selection_policy": CONTEXT_POLICY}


def build_sessions(events: list[dict], window_seconds=60) -> list[dict]:
    if window_seconds not in {30, 60, 120}:
        raise ValueError("Session window must be 30, 60 or 120 seconds")
    buckets = defaultdict(list)
    for event in events:
        if event["asset"] is None:
            continue
        key = (event["campaign_id"], event["run_id"], event["asset"]["asset_id"],
               event["account"], event["src"], event["family"])
        buckets[key].append(event)
    groups = []
    for key, members in buckets.items():
        members.sort(key=lambda e: (e["ts"], e["event_id"]))
        current, last_signature = [], None
        for event in members:
            signature = (event["asset"]["asset_version_id"], tuple(r["risk_version_id"] for r in event["risks"]))
            if current and ((event["ts"]-current[-1]["ts"]).total_seconds() > window_seconds or signature != last_signature):
                groups.append(current)
                current = []
            current.append(event)
            last_signature = signature
        if current:
            groups.append(current)
    groups.sort(key=lambda members: (members[0]["ts"], members[0]["event_id"]))
    # Only sessions completed strictly before this session starts are available.
    recent, pending, sessions = defaultdict(deque), [], []
    for members in groups:
        first, last = members[0], members[-1]
        start = first["ts"]
        while pending and pending[0][0] < start:
            ended, _, history_key = heapq.heappop(pending)
            recent[history_key].append(ended)
        features = aggregate(members)
        history_key = (first["asset"]["asset_id"], features["event_family"], features["primary_protocol"])
        history = recent[history_key]
        while history and history[0] < start-timedelta(hours=24):
            history.popleft()
        sid_parts = [first["campaign_id"], first["run_id"], *[e["event_id"] for e in members], str(window_seconds)]
        sid = "SES-" + hashlib.sha256("|".join(sid_parts).encode()).hexdigest()[:20]
        context = choose_context(first["asset"], first["risks"], len(history))
        sessions.append({"session_id": sid, "run_id": first["run_id"], "campaign_id": first["campaign_id"],
                         "asset_id": first["asset"]["asset_id"], "start_utc": start.isoformat(),
                         "end_utc": last["ts"].isoformat(), "context_as_of_utc": start.isoformat(),
                         "data_provenance": first["data_provenance"],
                         "aggregation_schema": f"iris-three-source-session-v1-window{window_seconds}",
                         "sensor_healthy": all(e["sensor_healthy"] for e in members),
                         "features": features, "context": context,
                         "asset_snapshot": public(first["asset"]),
                         "risk_snapshots": [public(r) for r in first["risks"]],
                         "context_status": "MATCHED" if context else "MISSING_RISK_CONTEXT",
                         "source_event_ids": [e["event_id"] for e in members],
                         "evidence_refs": [e["raw_ref"] for e in members]})
        heapq.heappush(pending, (last["ts"], sid, history_key))
    return sessions


def integrate(asset_path: Path, risk_path: Path, alerts_path: Path, *, window_seconds=60) -> tuple[list[dict], list[dict], dict]:
    started = time.perf_counter()
    sources = load_sources(asset_path, risk_path)
    unique, hashes, conflicts, quarantine = {}, {}, set(), []
    rows_in, duplicates, ignored = 0, 0, 0
    with alerts_path.open(encoding="utf-8") as stream:
        for line, content in enumerate(stream, 1):
            if not content.strip():
                continue
            rows_in += 1
            try:
                event = normalize_alert(json.loads(content), line, alerts_path.name)
                if event is None:
                    ignored += 1
                    continue
                if event["data_provenance"] != sources.provenance:
                    raise ValueError("SIEM provenance differs from inventory/risk provenance")
                eid, h = event["event_id"], fingerprint(event)
                if eid in hashes:
                    if hashes[eid] != h:
                        conflicts.add(eid)
                        quarantine.append({"line": line, "event_id": eid, "reason": "Conflicting duplicate event ID; all versions excluded"})
                    else:
                        duplicates += 1
                    continue
                hashes[eid], unique[eid] = h, event
            except (ValueError, TypeError, KeyError) as exc:
                quarantine.append({"line": line, "reason": str(exc)})
    for eid in conflicts:
        unique.pop(eid, None)
    enriched, unified = [], []
    unresolved, no_risk = 0, 0
    for event in sorted(unique.values(), key=lambda e: (e["ts"], e["event_id"])):
        asset, method = resolve_asset(event, sources)
        risks = []
        if asset:
            risks = [sources.risks.at(rid, event["ts"]) for rid in sorted(sources.asset_risks.get(asset["asset_id"], []))]
            risks = [r for r in risks if r is not None]
            no_risk += not risks
        else:
            unresolved += 1
        event["asset"], event["risks"] = asset, risks
        enriched.append(event)
        unified.append({"event_id": event["event_id"], "timestamp": event["ts"].isoformat(),
                        "campaign_id": event["campaign_id"], "run_id": event["run_id"],
                        "data_provenance": sources.provenance,
                        "asset_match_status": "MATCHED" if asset else "UNRESOLVED",
                        "asset_match_method": method, "asset": public(asset),
                        "risk_match_status": "MATCHED" if risks else "MISSING",
                        "risks": [public(r) for r in risks],
                        "alert": {k: v for k, v in event.items()
                                  if k not in {"ts", "asset", "risks", "semantic_key"}}})
    sessions = build_sessions(enriched, window_seconds)
    report = {
        "data_provenance": sources.provenance, "input_alert_rows": rows_in,
        "deduplicated_alerts": len(unique), "exact_duplicate_rows_removed": duplicates,
        "conflicting_event_ids_excluded": sorted(conflicts), "ignored_non_alert_sensor_records": ignored,
        "quarantine": quarantine, "unresolved_asset_events": unresolved,
        "matched_events_without_risk_context": int(no_risk),
        "unified_event_rows": len(unified), "model_sessions": len(sessions),
        "asset_snapshots": sources.asset_count, "risk_snapshots": sources.risk_count,
        "join_does_not_multiply_alerts": len(unified) == len(unique),
        "risk_selection_policy": CONTEXT_POLICY, "session_window_seconds": window_seconds,
        "source_sha256": {"asset_inventory": digest(asset_path), "risk_register": digest(risk_path), "siem_alerts": digest(alerts_path)},
        "elapsed_seconds": round(time.perf_counter()-started, 6),
        "training_labels_read": False,
        "memory_model": "Indexed snapshots and deduplicated alerts retained in memory; batch O(E log E) sorting, no cartesian event-risk expansion. Not a streaming production connector.",
    }
    return unified, sessions, report


def prepare_three(asset_path: Path, risk_path: Path, alerts_path: Path, out: Path, *, window_seconds=60) -> dict:
    if out.exists() and any(out.iterdir()):
        raise ValueError("Preparation directory is not empty; choose a new output to preserve prior evidence")
    unified, sessions, report = integrate(asset_path, risk_path, alerts_path, window_seconds=window_seconds)
    out.mkdir(parents=True, exist_ok=True)
    write_jsonl(out / "unified_events.jsonl", unified)
    write_jsonl(out / "model_sessions.jsonl", sessions)
    write_json(out / "integration_report.json", report)
    return report
