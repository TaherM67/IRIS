# IRIS EXPLAIN: File purpose: Normalizes Wazuh/Suricata cyber-range observations and aggregates telemetry-only features without
# IRIS EXPLAIN: reading hidden attack truth.
# IRIS EXPLAIN: Existing documentation/literal text below is kept exactly as written; the explanation is outside the string so
# IRIS EXPLAIN: its value does not change.
"""CyberRangeV1 telemetry adapter. This module NEVER opens the truth plane."""
# IRIS EXPLAIN: Keep type annotations unevaluated at definition time; this does not add a model feature or change runtime
# IRIS EXPLAIN: settings.
from __future__ import annotations

# IRIS EXPLAIN: Import hashlib to compute deterministic byte identities and content fingerprints.
import hashlib
# IRIS EXPLAIN: Import ipaddress to validate and canonicalize IPv4/IPv6 addresses.
import ipaddress
# IRIS EXPLAIN: Import json to encode and decode structured finite JSON payloads.
import json
# IRIS EXPLAIN: Import re to match supported telemetry text or constrained local HTTP paths/arguments.
import re
# IRIS EXPLAIN: Import Counter, defaultdict from collections to count values and build efficient grouping/history containers.
from collections import Counter, defaultdict
# IRIS EXPLAIN: Import datetime, timezone from datetime to represent timezone-aware timestamps and elapsed-time windows.
from datetime import datetime, timezone
# IRIS EXPLAIN: Import Path from pathlib to resolve server-owned paths without trusting uploaded filenames.
from pathlib import Path

# IRIS EXPLAIN: Import digest, read_jsonl, validate_features from .contracts to reuse the shared project contract/implementation
# IRIS EXPLAIN: rather than duplicate it.
from .contracts import digest, read_jsonl, validate_features


# IRIS EXPLAIN: Function timestamp: Require an explicit timezone, parse ISO timestamps, and normalize them to UTC so historical
# IRIS EXPLAIN: joins compare actual instants.
# IRIS EXPLAIN: Inputs: value: the supplied value to validate/normalize/serialize.
# IRIS EXPLAIN: Declared return type: datetime; the return statements below show each actual result/fallback.
def timestamp(value) -> datetime:
    # IRIS EXPLAIN: Enter this branch only when not isinstance(value, str).
    if not isinstance(value, str):
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Missing/invalid timestamp'); the
        # IRIS EXPLAIN: caller's existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError("Missing/invalid timestamp")
    # IRIS EXPLAIN: Store the result of datetime.fromisoformat(value.replace('Z', '+00:00')) in parsed; later lines use this
    # IRIS EXPLAIN: named result.
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    # IRIS EXPLAIN: Enter this branch only when parsed.tzinfo is None or parsed.utcoffset() is None.
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Timestamp has no timezone'); the
        # IRIS EXPLAIN: caller's existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError("Timestamp has no timezone")
    # IRIS EXPLAIN: Return the result of parsed.astimezone(timezone.utc) to the caller; this ends the current function path.
    return parsed.astimezone(timezone.utc)


# IRIS EXPLAIN: Function get: Try alternative dotted dictionary paths in order and return the first nonempty observed value, or
# IRIS EXPLAIN: None.
# IRIS EXPLAIN: Inputs: row: the existing input record to inspect without inventing missing evidence; paths: the exact three
# IRIS EXPLAIN: named operational input paths.
def get(row, *paths):
    # IRIS EXPLAIN: Iterate paths, binding each item to path; process only the existing observed/fixture collection.
    for path in paths:
        # IRIS EXPLAIN: Store row in value; later lines use this named result.
        value = row
        # IRIS EXPLAIN: Iterate path.split('.'), binding each item to key; process only the existing observed/fixture
        # IRIS EXPLAIN: collection.
        for key in path.split("."):
            # IRIS EXPLAIN: Enter this branch only when not isinstance(value, dict).
            if not isinstance(value, dict):
                # IRIS EXPLAIN: Store None (no result/value) in value; later lines use this named result.
                value = None
                # IRIS EXPLAIN: Stop the innermost loop on this condition; the surrounding code retains its existing
                # IRIS EXPLAIN: unresolved/error handling.
                break
            # IRIS EXPLAIN: Store the result of value.get(key) (read an optional mapping field using its stated fallback) in
            # IRIS EXPLAIN: value; later lines use this named result.
            value = value.get(key)
        # IRIS EXPLAIN: Enter this branch only when value is not None and value != ''.
        if value is not None and value != "":
            # IRIS EXPLAIN: Return value to the caller; this ends the current function path.
            return value
    # IRIS EXPLAIN: Return None (no result/value) to the caller; this ends the current function path.
    return None


# IRIS EXPLAIN: Function external: Classify an observed IP as external only if it is not private, loopback or link-local; absent
# IRIS EXPLAIN: addresses return False.
# IRIS EXPLAIN: Inputs: value: the supplied value to validate/normalize/serialize.
# IRIS EXPLAIN: Declared return type: bool; the return statements below show each actual result/fallback.
def external(value) -> bool:
    # IRIS EXPLAIN: Enter this branch only when not value.
    if not value:
        # IRIS EXPLAIN: Return False to the caller; this ends the current function path.
        return False
    # IRIS EXPLAIN: Store the result of ipaddress.ip_address(value) in address; later lines use this named result.
    address = ipaddress.ip_address(value)
    # IRIS EXPLAIN: Return not (address.is_private or address.is_loopback or address.is_link_local) to the caller; this ends the
    # IRIS EXPLAIN: current function path.
    return not (address.is_private or address.is_loopback or address.is_link_local)


# IRIS EXPLAIN: Function normalize_event: Translate supported Wazuh/Suricata records into one telemetry schema, validate
# IRIS EXPLAIN: times/IPs/severity, and ignore unsupported non-alert sensor records.
# IRIS EXPLAIN: Inputs: row: the existing input record to inspect without inventing missing evidence; sensor: the explicit
# IRIS EXPLAIN: sensor input used by the unchanged statements below; raw_ref: the explicit raw ref input used by the unchanged
# IRIS EXPLAIN: statements below.
# IRIS EXPLAIN: Declared return type: dict | None; the return statements below show each actual result/fallback.
def normalize_event(row, sensor: str, raw_ref: str) -> dict | None:
    # IRIS EXPLAIN: Store the result of row.get('_source', row) (read an optional mapping field using its stated fallback) in
    # IRIS EXPLAIN: row; later lines use this named result.
    row = row.get("_source", row)
    # IRIS EXPLAIN: Enter this branch only when not isinstance(row, dict).
    if not isinstance(row, dict):
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Event must be an object'); the caller's
        # IRIS EXPLAIN: existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError("Event must be an object")
    # Wazuh commonly wraps the original EVE alert in full_log or data.
    # IRIS EXPLAIN: Enter this branch only when sensor == 'wazuh'.
    if sensor == "wazuh":
        # IRIS EXPLAIN: Store the result of row.get('data', {}) (read an optional mapping field using its stated fallback) in
        # IRIS EXPLAIN: wrapped; later lines use this named result.
        wrapped = row.get("data", {})
        # IRIS EXPLAIN: Enter this branch only when isinstance(wrapped, dict) and wrapped.get('event_type') == 'alert' and
        # IRIS EXPLAIN: ('alert' in wrapped).
        if isinstance(wrapped, dict) and wrapped.get("event_type") == "alert" and "alert" in wrapped:
            # IRIS EXPLAIN: Store the result of normalize_event(wrapped, 'suricata', raw_ref) in result; later lines use this
            # IRIS EXPLAIN: named result.
            result = normalize_event(wrapped, "suricata", raw_ref)
            # IRIS EXPLAIN: Enter this branch only when result and result.get('ts').
            if result and result.get("ts"):
                # IRIS EXPLAIN: Return result to the caller; this ends the current function path.
                return result
        # IRIS EXPLAIN: Attempt this operation inside the following explicit error boundary; the existing except/finally blocks
        # IRIS EXPLAIN: decide fallback and cleanup.
        try:
            # IRIS EXPLAIN: Store the result of json.loads(row.get('full_log', '')) (decode the existing JSON text) in raw;
            # IRIS EXPLAIN: later lines use this named result.
            raw = json.loads(row.get("full_log", ""))
        # IRIS EXPLAIN: Catch (ValueError, TypeError); execute the existing error/fallback path rather than silently treating it
        # IRIS EXPLAIN: as success.
        except (ValueError, TypeError):
            # IRIS EXPLAIN: Store None (no result/value) in raw; later lines use this named result.
            raw = None
        # IRIS EXPLAIN: Enter this branch only when isinstance(raw, dict) and raw.get('event_type') == 'alert'.
        if isinstance(raw, dict) and raw.get("event_type") == "alert":
            # IRIS EXPLAIN: Return the result of normalize_event(raw, 'suricata', raw_ref) to the caller; this ends the current
            # IRIS EXPLAIN: function path.
            return normalize_event(raw, "suricata", raw_ref)
    # IRIS EXPLAIN: Store the result of timestamp(get(row, 'timestamp', '@timestamp', 'event_timestamp')) in ts; later lines use
    # IRIS EXPLAIN: this named result.
    ts = timestamp(get(row, "timestamp", "@timestamp", "event_timestamp"))
    # IRIS EXPLAIN: Enter this branch only when sensor == 'suricata'.
    if sensor == "suricata":
        # IRIS EXPLAIN: Enter this branch only when row.get('event_type') != 'alert'.
        if row.get("event_type") != "alert":
            # IRIS EXPLAIN: Return None (no result/value) to the caller; this ends the current function path.
            return None  # Flow/DNS/statistics need a different feature schema.
        # IRIS EXPLAIN: Store int(row['alert']['severity']) in severity; later lines use this named result.
        severity = int(row["alert"]["severity"])
        # IRIS EXPLAIN: Enter this branch only when severity not in {1, 2, 3}.
        if severity not in {1, 2, 3}:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Unsupported Suricata severity');
            # IRIS EXPLAIN: the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError("Unsupported Suricata severity")
        # IRIS EXPLAIN: Store (row.get('src_ip'), row.get('dest_ip')) in (src, dst); later lines use this named result.
        src, dst = row.get("src_ip"), row.get("dest_ip")
        # IRIS EXPLAIN: Store str(row['alert']['signature_id']) in sig; later lines use this named result.
        sig = str(row["alert"]["signature_id"])
        # IRIS EXPLAIN: Store {1: 10, 2: 7, 3: 4}[severity] in level; later lines use this named result.
        level = {1: 10, 2: 7, 3: 4}[severity]
        # IRIS EXPLAIN: Store ('network', str(row.get('proto', 'unknown')).upper(), None, 'unknown') in (family, protocol,
        # IRIS EXPLAIN: account, outcome); later lines use this named result.
        family, protocol, account, outcome = "network", str(row.get("proto", "unknown")).upper(), None, "unknown"
        # IRIS EXPLAIN: Store the formatted text
        # IRIS EXPLAIN: f"suricata|{row.get('flow_id')}|{sig}|{ts.isoformat()}|{src}|{dst}|{row.get('src_port')}|{row.get('dest_port')}"
        # IRIS EXPLAIN: in event_key; later lines use this named result.
        event_key = f"suricata|{row.get('flow_id')}|{sig}|{ts.isoformat()}|{src}|{dst}|{row.get('src_port')}|{row.get('dest_port')}"
        # IRIS EXPLAIN: Store None (no result/value) in agent; later lines use this named result.
        agent = None
    # IRIS EXPLAIN: Handle the alternative to the preceding condition/loop exactly as originally defined.
    else:
        # IRIS EXPLAIN: Store the result of get(row, 'data.srcip', 'source_ip', 'src_ip') (read an optional mapping field using
        # IRIS EXPLAIN: its stated fallback) in src; later lines use this named result.
        src = get(row, "data.srcip", "source_ip", "src_ip")
        # IRIS EXPLAIN: Store the result of get(row, 'data.dstip', 'destination_ip', 'dst_ip') (read an optional mapping field
        # IRIS EXPLAIN: using its stated fallback) in dst; later lines use this named result.
        dst = get(row, "data.dstip", "destination_ip", "dst_ip")
        # IRIS EXPLAIN: Store the result of get(row, 'agent.name', 'agent_name', 'host.name') (read an optional mapping field
        # IRIS EXPLAIN: using its stated fallback) in agent; later lines use this named result.
        agent = get(row, "agent.name", "agent_name", "host.name")
        # IRIS EXPLAIN: Store the result of get(row, 'data.dstuser', 'data.srcuser', 'account', 'username', 'user') (read an
        # IRIS EXPLAIN: optional mapping field using its stated fallback) in account; later lines use this named result.
        account = get(row, "data.dstuser", "data.srcuser", "account", "username", "user")
        # IRIS EXPLAIN: Store get(row, 'rule.groups', 'rule_groups') or [] in groups; later lines use this named result.
        groups = get(row, "rule.groups", "rule_groups") or []
        # IRIS EXPLAIN: Store [groups] when isinstance(groups, str); otherwise groups in groups; later lines use this named
        # IRIS EXPLAIN: result.
        groups = [groups] if isinstance(groups, str) else groups
        # IRIS EXPLAIN: Store str(get(row, 'rule.description', 'description') or '') in description; later lines use this named
        # IRIS EXPLAIN: result.
        description = str(get(row, "rule.description", "description") or "")
        # IRIS EXPLAIN: Store the result of ' '.join([*map(str, groups), description, str(row.get('full_log', '')),
        # IRIS EXPLAIN: str(row.get('outcome', ''))]).casefold() (normalize text case for matching) in text; later lines use
        # IRIS EXPLAIN: this named result.
        text = " ".join([*map(str, groups), description, str(row.get("full_log", "")), str(row.get("outcome", ""))]).casefold()
        # IRIS EXPLAIN: Store the result of get(row, 'event_family') (read an optional mapping field using its stated fallback)
        # IRIS EXPLAIN: in explicit; later lines use this named result.
        explicit = get(row, "event_family")
        # IRIS EXPLAIN: Store the result of str(explicit).casefold() (normalize text case for matching) when explicit; otherwise
        # IRIS EXPLAIN: 'authentication' when any((w in text for w in ('sshd', 'authentication', 'login', 'password')));
        # IRIS EXPLAIN: otherwise 'network' when any((w in text for w in ('suricata', 'firewall', 'scan'))); otherwise 'unknown'
        # IRIS EXPLAIN: in family; later lines use this named result.
        family = str(explicit).casefold() if explicit else "authentication" if any(w in text for w in ("sshd", "authentication", "login", "password")) else "network" if any(w in text for w in ("suricata", "firewall", "scan")) else "unknown"
        # IRIS EXPLAIN: Store the result of str(get(row, 'data.protocol', 'protocol', 'proto') or ('SSH' if 'sshd' in text else
        # IRIS EXPLAIN: 'unknown')).upper() (normalize protocol/text to uppercase) in protocol; later lines use this named
        # IRIS EXPLAIN: result.
        protocol = str(get(row, "data.protocol", "protocol", "proto") or ("SSH" if "sshd" in text else "unknown")).upper()
        # IRIS EXPLAIN: Enter this branch only when re.search('\\b(failed|failure|denied|invalid|unsuccessful)\\b', text).
        if re.search(r"\b(failed|failure|denied|invalid|unsuccessful)\b", text):
            # IRIS EXPLAIN: Store 'failed' in outcome; later lines use this named result.
            outcome = "failed"
        # IRIS EXPLAIN: Check this alternative branch when re.search('\\b(success|successful|accepted|granted)\\b', text).
        elif re.search(r"\b(success|successful|accepted|granted)\b", text):
            # IRIS EXPLAIN: Store 'success' in outcome; later lines use this named result.
            outcome = "success"
        # IRIS EXPLAIN: Handle the alternative to the preceding condition/loop exactly as originally defined.
        else:
            # IRIS EXPLAIN: Store 'unknown' in outcome; later lines use this named result.
            outcome = "unknown"
        # IRIS EXPLAIN: Store float(get(row, 'rule.level', 'rule_level') or 0) in level; later lines use this named result.
        level = float(get(row, "rule.level", "rule_level") or 0)
        # IRIS EXPLAIN: Enter this branch only when not 0 <= level <= 16.
        if not 0 <= level <= 16:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Wazuh level outside 0..16'); the
            # IRIS EXPLAIN: caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError("Wazuh level outside 0..16")
        # IRIS EXPLAIN: Store str(get(row, 'rule.id', 'rule_id') or 'unknown') in sig; later lines use this named result.
        sig = str(get(row, "rule.id", "rule_id") or "unknown")
        # IRIS EXPLAIN: Store the result of json.dumps(row, sort_keys=True, separators=(',', ':')) (serialize the existing
        # IRIS EXPLAIN: payload as JSON) in stable; later lines use this named result.
        stable = json.dumps(row, sort_keys=True, separators=(",", ":"))
        # IRIS EXPLAIN: Store the computed value 'wazuh|' + hashlib.sha256(stable.encode()).hexdigest() in event_key; later
        # IRIS EXPLAIN: lines use this named result.
        event_key = "wazuh|" + hashlib.sha256(stable.encode()).hexdigest()
    # IRIS EXPLAIN: Iterate (src, dst), binding each item to ip; process only the existing observed/fixture collection.
    for ip in (src, dst):
        # IRIS EXPLAIN: Enter this branch only when ip.
        if ip:
            # IRIS EXPLAIN: Call ipaddress.ip_address(ip) using the existing explicit arguments.
            ipaddress.ip_address(ip)
    # IRIS EXPLAIN: Return a mapping containing ts, src, dst, agent, account, family, protocol and additional fields to the
    # IRIS EXPLAIN: caller; this ends the current function path.
    return {"ts": ts, "src": src, "dst": dst, "agent": agent,
            # IRIS EXPLAIN: Continue the current record with account, family; each value comes from the expression shown on this
            # IRIS EXPLAIN: unchanged line.
            "account": str(account) if account else "unknown", "family": family,
            # IRIS EXPLAIN: Continue the current record with protocol, outcome, level; each value comes from the expression
            # IRIS EXPLAIN: shown on this unchanged line.
            "protocol": protocol, "outcome": outcome, "level": level,
            # IRIS EXPLAIN: Continue the current record with rule, key, raw_ref; each value comes from the expression shown on
            # IRIS EXPLAIN: this unchanged line.
            "rule": sig, "key": event_key, "raw_ref": raw_ref}


# IRIS EXPLAIN: Function aggregate: Sort observed session events and derive the allowlisted counts, severities, outcomes, burst
# IRIS EXPLAIN: rate and other telemetry-only model features.
# IRIS EXPLAIN: Inputs: events: normalized observed events, not hidden truth labels.
# IRIS EXPLAIN: Declared return type: dict; the return statements below show each actual result/fallback.
def aggregate(events: list[dict]) -> dict:
    # IRIS EXPLAIN: Store sorted(events, key=lambda e: (e['ts'], e['key'])) in events; later lines use this named result.
    events = sorted(events, key=lambda e: (e["ts"], e["key"]))
    # IRIS EXPLAIN: Store len(events) in n; later lines use this named result.
    n = len(events)
    # IRIS EXPLAIN: Store sum((e['outcome'] == 'failed' for e in events)) in failed; later lines use this named result.
    failed = sum(e["outcome"] == "failed" for e in events)
    # IRIS EXPLAIN: Store sum((e['outcome'] == 'success' for e in events)) in successful; later lines use this named result.
    successful = sum(e["outcome"] == "success" for e in events)
    # IRIS EXPLAIN: Store (False, False) in (seen_fail, later_success); later lines use this named result.
    seen_fail, later_success = False, False
    # IRIS EXPLAIN: Iterate events, binding each item to event; process only the existing observed/fixture collection.
    for event in events:
        # IRIS EXPLAIN: Update seen_fail using the existing BitOr operation and the comparison event['outcome'] == 'failed'.
        seen_fail |= event["outcome"] == "failed"
        # IRIS EXPLAIN: Update later_success using the existing BitOr operation and seen_fail and event['outcome'] == 'success'.
        later_success |= seen_fail and event["outcome"] == "success"
    # IRIS EXPLAIN: Store (0, 0) in (left, burst); later lines use this named result.
    left, burst = 0, 0
    # IRIS EXPLAIN: Iterate enumerate(events), binding each item to (right, event); process only the existing observed/fixture
    # IRIS EXPLAIN: collection.
    for right, event in enumerate(events):
        # IRIS EXPLAIN: Repeat while (event['ts'] - events[left]['ts']).total_seconds() > 10; the block advances the
        # IRIS EXPLAIN: read/window/history state.
        while (event["ts"] - events[left]["ts"]).total_seconds() > 10:
            # IRIS EXPLAIN: Update left using the existing Add operation and 1.
            left += 1
        # IRIS EXPLAIN: Store max(burst, right - left + 1) in burst; later lines use this named result.
        burst = max(burst, right-left+1)
    # IRIS EXPLAIN: Store the result of (events[-1]['ts'] - events[0]['ts']).total_seconds() in duration; later lines use this
    # IRIS EXPLAIN: named result.
    duration = (events[-1]["ts"] - events[0]["ts"]).total_seconds()
    # IRIS EXPLAIN: Return the result of validate_features({'event_family': events[0]['family'], 'primary_protocol':
    # IRIS EXPLAIN: Counter((e['protocol'] for e in... to the caller; this ends the current function path.
    return validate_features({
        # IRIS EXPLAIN: Set/describe these existing record fields: event_family: observed telemetry family; a Model 1
        # IRIS EXPLAIN: categorical predictor, not a truth label.
        "event_family": events[0]["family"],
        # IRIS EXPLAIN: Set/describe these existing record fields: primary_protocol: observed protocol used as a categorical
        # IRIS EXPLAIN: predictor.
        "primary_protocol": Counter(e["protocol"] for e in events).most_common(1)[0][0],
        # IRIS EXPLAIN: Set/describe these existing record fields: event_count: number of observed events in the session;
        # IRIS EXPLAIN: duration_seconds: elapsed observed session time.
        "event_count": n, "duration_seconds": duration,
        # IRIS EXPLAIN: Set/describe these existing record fields: max_rule_level: highest observed SIEM severity on the 0-16
        # IRIS EXPLAIN: scale.
        "max_rule_level": max(e["level"] for e in events),
        # IRIS EXPLAIN: Set/describe these existing record fields: mean_rule_level: mean observed SIEM severity.
        "mean_rule_level": sum(e["level"] for e in events)/n,
        # IRIS EXPLAIN: Set/describe these existing record fields: distinct_rules: number of unique rule identifiers in the
        # IRIS EXPLAIN: session.
        "distinct_rules": len({e["rule"] for e in events}),
        # IRIS EXPLAIN: Set/describe these existing record fields: distinct_sources: number of observed nonempty source
        # IRIS EXPLAIN: addresses.
        "distinct_sources": len({e["src"] for e in events if e["src"]}),
        # IRIS EXPLAIN: Set/describe these existing record fields: distinct_accounts: number of observed known account names.
        "distinct_accounts": len({e["account"] for e in events if e["account"] != "unknown"}),
        # IRIS EXPLAIN: Set/describe these existing record fields: failed_count: observed failed authentication count;
        # IRIS EXPLAIN: success_count: observed successful authentication count.
        "failed_count": failed, "success_count": successful,
        # IRIS EXPLAIN: Set/describe these existing record fields: failure_ratio: failed divided by known authentication
        # IRIS EXPLAIN: outcomes, with a safe zero-outcome fallback.
        "failure_ratio": failed/(failed+successful) if failed+successful else 0,
        # IRIS EXPLAIN: Set/describe these existing record fields: success_after_failures: whether observed success occurs after
        # IRIS EXPLAIN: a failure; max_events_in_10s: largest observed ten-second event burst.
        "success_after_failures": int(later_success), "max_events_in_10s": burst,
        # IRIS EXPLAIN: Set/describe these existing record fields: external_source_fraction: fraction of observed
        # IRIS EXPLAIN: non-private/non-local source addresses.
        "external_source_fraction": sum(external(e["src"]) for e in events)/n,
        # IRIS EXPLAIN: Set/describe these existing record fields: event_rate_per_minute: observed event count normalized by
        # IRIS EXPLAIN: max(duration, 1 second).
        "event_rate_per_minute": n*60/max(duration, 1),
    # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain unchanged.
    })


# IRIS EXPLAIN: Function verify_campaign_hashes: Check runtime-source file hashes and path safety while excluding hidden
# IRIS EXPLAIN: truth/plan files; report missing runtime integrity coverage.
# IRIS EXPLAIN: Inputs: campaign: the cyber-range campaign directory or explicit generator index.
# IRIS EXPLAIN: Declared return type: list[str]; the return statements below show each actual result/fallback.
def verify_campaign_hashes(campaign: Path) -> list[str]:
    # IRIS EXPLAIN: Store the computed value campaign / 'campaign_manifest.json' in manifest_path; later lines use this named
    # IRIS EXPLAIN: result.
    manifest_path = campaign / "campaign_manifest.json"
    # IRIS EXPLAIN: Enter this branch only when not manifest_path.exists().
    if not manifest_path.exists():
        # IRIS EXPLAIN: Return ['Missing campaign_manifest.json; source integrity not verified'] to the caller; this ends the
        # IRIS EXPLAIN: current function path.
        return ["Missing campaign_manifest.json; source integrity not verified"]
    # IRIS EXPLAIN: Store the result of json.loads(manifest_path.read_text(encoding='utf-8')) (decode the existing JSON text) in
    # IRIS EXPLAIN: manifest; later lines use this named result.
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    # IRIS EXPLAIN: Store the result of manifest.get('files') (read an optional mapping field using its stated fallback) in
    # IRIS EXPLAIN: files; later lines use this named result.
    files = manifest.get("files")
    # IRIS EXPLAIN: Enter this branch only when not isinstance(files, list) or not files.
    if not isinstance(files, list) or not files:
        # IRIS EXPLAIN: Return ['Campaign manifest has no file hashes'] to the caller; this ends the current function path.
        return ["Campaign manifest has no file hashes"]
    # IRIS EXPLAIN: Store set() in verified; later lines use this named result.
    verified = set()
    # IRIS EXPLAIN: Iterate files, binding each item to item; process only the existing observed/fixture collection.
    for item in files:
        # IRIS EXPLAIN: Store Path(item['path']).parts in parts; later lines use this named result.
        parts = Path(item["path"]).parts
        # Ground truth and scenario plans are offline annotation material only.
        # IRIS EXPLAIN: Enter this branch only when 'truth' in parts or 'scenarios' in parts or Path(item['path']).name in
        # IRIS EXPLAIN: {'activity_ground_truth.jsonl', 'campaign_plan.json'}.
        if "truth" in parts or "scenarios" in parts or Path(item["path"]).name in {
            # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
            # IRIS EXPLAIN: "activity_ground_truth.jsonl", "campaign_plan.json",.
            "activity_ground_truth.jsonl", "campaign_plan.json",
        # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain
        # IRIS EXPLAIN: unchanged.
        }:
            # IRIS EXPLAIN: Skip the remainder of this iteration and move to the next item; do not fabricate an accepted result
            # IRIS EXPLAIN: for this skipped input.
            continue
        # IRIS EXPLAIN: Store the result of (campaign / item['path']).resolve() (normalize the filesystem path) in path; later
        # IRIS EXPLAIN: lines use this named result.
        path = (campaign / item["path"]).resolve()
        # IRIS EXPLAIN: Enter this branch only when not path.is_relative_to(campaign.resolve()) or not path.is_file().
        if not path.is_relative_to(campaign.resolve()) or not path.is_file():
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Campaign manifest references an
            # IRIS EXPLAIN: unsafe/missing path'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError("Campaign manifest references an unsafe/missing path")
        # IRIS EXPLAIN: Enter this branch only when digest(path) != item['sha256'] or path.stat().st_size != item['bytes'].
        if digest(path) != item["sha256"] or path.stat().st_size != item["bytes"]:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError(f"Campaign integrity mismatch:
            # IRIS EXPLAIN: {item['path']}"); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError(f"Campaign integrity mismatch: {item['path']}")
        # IRIS EXPLAIN: Call verified.add(str(path.relative_to(campaign.resolve()))): record membership in the set.
        verified.add(str(path.relative_to(campaign.resolve())))
    # IRIS EXPLAIN: Store the comprehension {str(p.relative_to(campaign)) for run in (campaign / 'runs').glob('run-*') for p in
    # IRIS EXPLAIN: [run / 'topology.json', run / 'identity_data.json', run / 'wazuh_stuff/alerts.jsonl', ru... in required;
    # IRIS EXPLAIN: later lines use this named result.
    required = {str(p.relative_to(campaign)) for run in (campaign / "runs").glob("run-*")
                # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                # IRIS EXPLAIN: arguments/items: for p in [run / "topology.json", run / "identity_data.json",.
                for p in [run / "topology.json", run / "identity_data.json",
                          # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                          # IRIS EXPLAIN: arguments/items: run / "wazuh_stuff/alerts.jsonl", run / "suricata_stuff/eve.json",.
                          run / "wazuh_stuff/alerts.jsonl", run / "suricata_stuff/eve.json",
                          # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                          # IRIS EXPLAIN: arguments/items: run / "quality/sensor_health.json"]}.
                          run / "quality/sensor_health.json"]}
    # IRIS EXPLAIN: Enter this branch only when not required.issubset(verified).
    if not required.issubset(verified):
        # IRIS EXPLAIN: Return ['Manifest omits hashes for required runtime files'] to the caller; this ends the current
        # IRIS EXPLAIN: function path.
        return ["Manifest omits hashes for required runtime files"]
    # IRIS EXPLAIN: Return [] to the caller; this ends the current function path.
    return []


# IRIS EXPLAIN: Function sensor_health: Require explicit healthy manager/sensor records and expected active agents before
# IRIS EXPLAIN: treating cyber-range observations as healthy.
# IRIS EXPLAIN: Inputs: run: the existing cyber-range run directory or run identity; topology: the observed runtime asset/agent
# IRIS EXPLAIN: topology, not business criticality evidence.
# IRIS EXPLAIN: Declared return type: bool; the return statements below show each actual result/fallback.
def sensor_health(run: Path, topology: dict) -> bool:
    # IRIS EXPLAIN: Store the computed value run / 'quality/sensor_health.json' in path; later lines use this named result.
    path = run / "quality/sensor_health.json"
    # IRIS EXPLAIN: Enter this branch only when not path.is_file().
    if not path.is_file():
        # IRIS EXPLAIN: Return False to the caller; this ends the current function path.
        return False
    # IRIS EXPLAIN: Store the result of json.loads(path.read_text(encoding='utf-8')) (decode the existing JSON text) in health;
    # IRIS EXPLAIN: later lines use this named result.
    health = json.loads(path.read_text(encoding="utf-8"))
    # IRIS EXPLAIN: Enter this branch only when health.get('action_error') or health.get('telemetry_errors').
    if health.get("action_error") or health.get("telemetry_errors"):
        # IRIS EXPLAIN: Return False to the caller; this ends the current function path.
        return False
    # IRIS EXPLAIN: Store the result of health.get('health', {}) (read an optional mapping field using its stated fallback) in
    # IRIS EXPLAIN: hosts; later lines use this named result.
    hosts = health.get("health", {})
    # IRIS EXPLAIN: Enter this branch only when not isinstance(hosts, dict) or not hosts or any((not isinstance(v, dict) or
    # IRIS EXPLAIN: v.get('status') != 'ok' for v in hosts.values())).
    if not isinstance(hosts, dict) or not hosts or any(not isinstance(v, dict) or v.get("status") != "ok" for v in hosts.values()):
        # IRIS EXPLAIN: Return False to the caller; this ends the current function path.
        return False
    # IRIS EXPLAIN: Store the result of hosts.get('wazuh-manager', {}) (read an optional mapping field using its stated
    # IRIS EXPLAIN: fallback) in manager; later lines use this named result.
    manager = hosts.get("wazuh-manager", {})
    # IRIS EXPLAIN: Store set(manager.get('active_agents', [])) in active; later lines use this named result.
    active = set(manager.get("active_agents", []))
    # IRIS EXPLAIN: Store the comprehension {a['hostname'] for a in topology['assets'] if a.get('role') != 'wazuh_manager'} in
    # IRIS EXPLAIN: expected; later lines use this named result.
    expected = {a["hostname"] for a in topology["assets"] if a.get("role") != "wazuh_manager"}
    # IRIS EXPLAIN: Return expected.issubset(active) and {'wazuh-manager', 'suricata-sensor'}.issubset(hosts) to the caller;
    # IRIS EXPLAIN: this ends the current function path.
    return expected.issubset(active) and {"wazuh-manager", "suricata-sensor"}.issubset(hosts)


# IRIS EXPLAIN: Function extract_run: Normalize and deduplicate one cyber-range run, resolve target assets exactly, sessionize
# IRIS EXPLAIN: observations, and preserve quarantine/evidence references without reading truth labels.
# IRIS EXPLAIN: Inputs: run: the existing cyber-range run directory or run identity; campaign_id: the explicit campaign id input
# IRIS EXPLAIN: used by the unchanged statements below; window_seconds: the allowed inactivity window; serving must match the
# IRIS EXPLAIN: trained aggregation schema.
# IRIS EXPLAIN: Declared return type: tuple[list[dict], list[dict]]; the return statements below show each actual
# IRIS EXPLAIN: result/fallback.
def extract_run(run: Path, campaign_id: str, *, window_seconds: int = 60) -> tuple[list[dict], list[dict]]:
    # IRIS EXPLAIN: Enter this branch only when isinstance(window_seconds, bool) or window_seconds not in {30, 60, 120}.
    if isinstance(window_seconds, bool) or window_seconds not in {30, 60, 120}:
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('window_seconds must be 30, 60 or 120');
        # IRIS EXPLAIN: the caller's existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError("window_seconds must be 30, 60 or 120")
    # IRIS EXPLAIN: Store the result of json.loads((run / 'topology.json').read_text(encoding='utf-8')) (decode the existing
    # IRIS EXPLAIN: JSON text) in topology; later lines use this named result.
    topology = json.loads((run / "topology.json").read_text(encoding="utf-8"))
    # IRIS EXPLAIN: Store ({}, {}) in (ip_to_asset, host_to_asset); later lines use this named result.
    ip_to_asset, host_to_asset = {}, {}
    # IRIS EXPLAIN: Iterate topology['assets'], binding each item to asset; process only the existing observed/fixture
    # IRIS EXPLAIN: collection.
    for asset in topology["assets"]:
        # IRIS EXPLAIN: Store str(ipaddress.ip_address(asset['ip'])) in ip; later lines use this named result.
        ip = str(ipaddress.ip_address(asset["ip"]))
        # IRIS EXPLAIN: Enter this branch only when ip in ip_to_asset or asset['hostname'] in host_to_asset.
        if ip in ip_to_asset or asset["hostname"] in host_to_asset:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Ambiguous topology mapping'); the
            # IRIS EXPLAIN: caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError("Ambiguous topology mapping")
        # IRIS EXPLAIN: Store (asset['asset_id'], asset['asset_id']) in (ip_to_asset[ip], host_to_asset[asset['hostname']]);
        # IRIS EXPLAIN: later lines use this named result.
        ip_to_asset[ip], host_to_asset[asset["hostname"]] = asset["asset_id"], asset["asset_id"]
    # IRIS EXPLAIN: Store the result of json.loads((run / 'identity_data.json').read_text(encoding='utf-8')) (decode the
    # IRIS EXPLAIN: existing JSON text) in identities; later lines use this named result.
    identities = json.loads((run / "identity_data.json").read_text(encoding="utf-8"))
    # IRIS EXPLAIN: Store the comprehension {a['username'] for a in identities.get('accounts', [])} in accounts; later lines use
    # IRIS EXPLAIN: this named result.
    accounts = {a["username"] for a in identities.get("accounts", [])}
    # IRIS EXPLAIN: Store the result of sensor_health(run, topology) in healthy; later lines use this named result.
    healthy = sensor_health(run, topology)
    # IRIS EXPLAIN: Store ([], [], set()) in (events, quarantine, seen); later lines use this named result.
    events, quarantine, seen = [], [], set()
    # IRIS EXPLAIN: Iterate [('wazuh_stuff/alerts.jsonl', 'wazuh'), ('suricata_stuff/eve.json', 'suricata')], binding each item
    # IRIS EXPLAIN: to (relative, sensor); process only the existing observed/fixture collection.
    for relative, sensor in [("wazuh_stuff/alerts.jsonl", "wazuh"), ("suricata_stuff/eve.json", "suricata")]:
        # IRIS EXPLAIN: Store the computed value run / relative in source; later lines use this named result.
        source = run / relative
        # IRIS EXPLAIN: Store the result of read_jsonl(source) in raw_rows; later lines use this named result.
        raw_rows = read_jsonl(source)
        # IRIS EXPLAIN: Enter this branch only when not raw_rows.
        if not raw_rows:
            # IRIS EXPLAIN: Store False in healthy; later lines use this named result.
            healthy = False
        # IRIS EXPLAIN: Iterate enumerate(raw_rows, 1), binding each item to (index, raw); process only the existing
        # IRIS EXPLAIN: observed/fixture collection.
        for index, raw in enumerate(raw_rows, 1):
            # IRIS EXPLAIN: Store the formatted text f'{campaign_id}/{run.name}/{relative}#L{index}' in ref; later lines use
            # IRIS EXPLAIN: this named result.
            ref = f"{campaign_id}/{run.name}/{relative}#L{index}"
            # IRIS EXPLAIN: Attempt this operation inside the following explicit error boundary; the existing except/finally
            # IRIS EXPLAIN: blocks decide fallback and cleanup.
            try:
                # IRIS EXPLAIN: Store the result of normalize_event(raw, sensor, ref) in event; later lines use this named
                # IRIS EXPLAIN: result.
                event = normalize_event(raw, sensor, ref)
                # IRIS EXPLAIN: Enter this branch only when event is None.
                if event is None:
                    # IRIS EXPLAIN: Skip the remainder of this iteration and move to the next item; do not fabricate an accepted
                    # IRIS EXPLAIN: result for this skipped input.
                    continue
                # IRIS EXPLAIN: Enter this branch only when event['key'] in seen.
                if event["key"] in seen:
                    # IRIS EXPLAIN: Skip the remainder of this iteration and move to the next item; do not fabricate an accepted
                    # IRIS EXPLAIN: result for this skipped input.
                    continue
                # IRIS EXPLAIN: Call seen.add(event['key']): record membership in the set.
                seen.add(event["key"])
                # Destination-first avoids assigning a sensor's alert to the sensor itself.
                # IRIS EXPLAIN: Store the result of ip_to_asset.get(event['dst']) (read an optional mapping field using its
                # IRIS EXPLAIN: stated fallback) when event['dst']; otherwise the result of host_to_asset.get(event['agent'])
                # IRIS EXPLAIN: (read an optional mapping field using its stated fallback) in asset; later lines use this named
                # IRIS EXPLAIN: result.
                asset = ip_to_asset.get(event["dst"]) if event["dst"] else host_to_asset.get(event["agent"])
                # IRIS EXPLAIN: Enter this branch only when not asset.
                if not asset:
                    # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Asset cannot be resolved
                    # IRIS EXPLAIN: exactly; no truth-derived target is used'); the caller's existing boundary determines
                    # IRIS EXPLAIN: rollback or the HTTP diagnostic.
                    raise ValueError("Asset cannot be resolved exactly; no truth-derived target is used")
                # IRIS EXPLAIN: Store asset in event['asset_id']; later lines use this named result.
                event["asset_id"] = asset
                # IRIS EXPLAIN: Store event['account'] != 'unknown' and event['account'] not in accounts in
                # IRIS EXPLAIN: event['identity_unresolved']; later lines use this named result.
                event["identity_unresolved"] = event["account"] != "unknown" and event["account"] not in accounts
                # IRIS EXPLAIN: Call events.append(event): append one item to the working list.
                events.append(event)
            # IRIS EXPLAIN: Catch (KeyError, TypeError, ValueError) as exc; execute the existing error/fallback path rather than
            # IRIS EXPLAIN: silently treating it as success.
            except (KeyError, TypeError, ValueError) as exc:
                # IRIS EXPLAIN: Call quarantine.append({'raw_ref': ref, 'reason': str(exc)}): append one item to the working
                # IRIS EXPLAIN: list.
                quarantine.append({"raw_ref": ref, "reason": str(exc)})
    # IRIS EXPLAIN: Store the result of defaultdict(list) in groups; later lines use this named result.
    groups = defaultdict(list)
    # IRIS EXPLAIN: Iterate events, binding each item to e; process only the existing observed/fixture collection.
    for e in events:
        # IRIS EXPLAIN: Call groups[e['asset_id'], e['account'], e['src'], e['family']].append(e): append one item to the
        # IRIS EXPLAIN: working list.
        groups[(e["asset_id"], e["account"], e["src"], e["family"])].append(e)
    # IRIS EXPLAIN: Store [] in output; later lines use this named result.
    output = []
    # IRIS EXPLAIN: Function append: Build and append one observed-session record with deterministic identity, aggregated
    # IRIS EXPLAIN: features and sensor-health status.
    # IRIS EXPLAIN: Inputs: members: the observed events belonging to this session/group; key: the exact grouping/lookup field
    # IRIS EXPLAIN: or identity.
    def append(members, key):
        # IRIS EXPLAIN: Store the formatted text f"{campaign_id}|{run.name}|{key}|{members[0]['key']}|{window_seconds}" in
        # IRIS EXPLAIN: fingerprint; later lines use this named result.
        fingerprint = f"{campaign_id}|{run.name}|{key}|{members[0]['key']}|{window_seconds}"
        # IRIS EXPLAIN: Store the computed value 'SES-' + hashlib.sha256(fingerprint.encode()).hexdigest()[:20] in sid; later
        # IRIS EXPLAIN: lines use this named result.
        sid = "SES-" + hashlib.sha256(fingerprint.encode()).hexdigest()[:20]
        # IRIS EXPLAIN: Call output.append({'session_id': sid, 'run_id': run.name, 'campaign_id': campaign_id, 'asset_id':
        # IRIS EXPLAIN: key[0], 'start_utc': members[0]['ts'].isoformat(), 'end_utc': m...: append one item to the working list.
        output.append({"session_id": sid, "run_id": run.name, "campaign_id": campaign_id,
                       # IRIS EXPLAIN: Set/describe these existing record fields: asset_id: exact target-asset identity; not an
                       # IRIS EXPLAIN: attacker source-IP guess.
                       "asset_id": key[0], "start_utc": members[0]["ts"].isoformat(),
                       # IRIS EXPLAIN: Continue the current record with end_utc, window_seconds; each value comes from the
                       # IRIS EXPLAIN: expression shown on this unchanged line.
                       "end_utc": members[-1]["ts"].isoformat(), "window_seconds": window_seconds,
                       # IRIS EXPLAIN: Set/describe these existing record fields: data_provenance: explicit
                       # IRIS EXPLAIN: synthetic/cyber_range/operational source identity; sensor_healthy: explicit health
                       # IRIS EXPLAIN: evidence; a missing/false value must not be treated as benign.
                       "data_provenance": "cyber_range", "sensor_healthy": healthy and not quarantine,
                       # IRIS EXPLAIN: Set/describe these existing record fields: aggregation_schema: the exact
                       # IRIS EXPLAIN: normalization/session-window contract used for training and inference.
                       "aggregation_schema": f"cyberrange-session-v1-window{window_seconds}",
                       # IRIS EXPLAIN: Continue the current record with features; each value comes from the expression shown on
                       # IRIS EXPLAIN: this unchanged line.
                       "features": aggregate(members),
                       # IRIS EXPLAIN: Continue the current record with identity_status; each value comes from the expression
                       # IRIS EXPLAIN: shown on this unchanged line.
                       "identity_status": "UNRESOLVED" if any(e["identity_unresolved"] for e in members) else "EXACT_OR_UNOBSERVED",
                       # IRIS EXPLAIN: Set/describe these existing record fields: evidence_refs: source-file/line references
                       # IRIS EXPLAIN: retained for traceability.
                       "evidence_refs": [e["raw_ref"] for e in members],
                       # IRIS EXPLAIN: Continue the current record with context; each value comes from the expression shown on
                       # IRIS EXPLAIN: this unchanged line.
                       "context": None,
                       # IRIS EXPLAIN: Continue the current record with context_note; each value comes from the expression shown
                       # IRIS EXPLAIN: on this unchanged line.
                       "context_note": "Join time-valid GRC asset_type, asset_criticality, current_likelihood, impact, previous_similar_24h before training Model 2; topology does not establish business criticality."})
    # IRIS EXPLAIN: Iterate groups.items(), binding each item to (key, members); process only the existing observed/fixture
    # IRIS EXPLAIN: collection.
    for key, members in groups.items():
        # IRIS EXPLAIN: Call members.sort(key=lambda e: (e['ts'], e['key'])): sort the existing collection using the declared
        # IRIS EXPLAIN: stable key.
        members.sort(key=lambda e: (e["ts"], e["key"]))
        # IRIS EXPLAIN: Store [] in current; later lines use this named result.
        current = []
        # IRIS EXPLAIN: Iterate members, binding each item to e; process only the existing observed/fixture collection.
        for e in members:
            # IRIS EXPLAIN: Enter this branch only when current and (e['ts'] - current[-1]['ts']).total_seconds() >
            # IRIS EXPLAIN: window_seconds.
            if current and (e["ts"] - current[-1]["ts"]).total_seconds() > window_seconds:
                # IRIS EXPLAIN: Call append(current, key): append one item to the working list.
                append(current, key)
                # IRIS EXPLAIN: Store [] in current; later lines use this named result.
                current = []
            # IRIS EXPLAIN: Call current.append(e): append one item to the working list.
            current.append(e)
        # IRIS EXPLAIN: Enter this branch only when current.
        if current:
            # IRIS EXPLAIN: Call append(current, key): append one item to the working list.
            append(current, key)
    # IRIS EXPLAIN: Return (sorted(output, key=lambda o: (o['start_utc'], o['session_id'])), quarantine) to the caller; this
    # IRIS EXPLAIN: ends the current function path.
    return sorted(output, key=lambda o: (o["start_utc"], o["session_id"])), quarantine


# IRIS EXPLAIN: Function extract_campaign: Combine runtime observations across campaign runs, record failed inputs, and mark
# IRIS EXPLAIN: sessions unhealthy when integrity evidence is missing.
# IRIS EXPLAIN: Inputs: campaign: the cyber-range campaign directory or explicit generator index; window_seconds: the allowed
# IRIS EXPLAIN: inactivity window; serving must match the trained aggregation schema.
# IRIS EXPLAIN: Declared return type: tuple[list[dict], dict]; the return statements below show each actual result/fallback.
def extract_campaign(campaign: Path, *, window_seconds: int = 60) -> tuple[list[dict], dict]:
    # IRIS EXPLAIN: Store the result of verify_campaign_hashes(campaign) in warnings; later lines use this named result.
    warnings = verify_campaign_hashes(campaign)
    # IRIS EXPLAIN: Store ([], []) in (rows, quarantine); later lines use this named result.
    rows, quarantine = [], []
    # IRIS EXPLAIN: Store sorted((campaign / 'runs').glob('run-*')) in run_paths; later lines use this named result.
    run_paths = sorted((campaign / "runs").glob("run-*"))
    # IRIS EXPLAIN: Enter this branch only when not run_paths.
    if not run_paths:
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Expected campaign/runs/run-*
        # IRIS EXPLAIN: directories'); the caller's existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError("Expected campaign/runs/run-* directories")
    # IRIS EXPLAIN: Iterate run_paths, binding each item to run; process only the existing observed/fixture collection.
    for run in run_paths:
        # IRIS EXPLAIN: Attempt this operation inside the following explicit error boundary; the existing except/finally blocks
        # IRIS EXPLAIN: decide fallback and cleanup.
        try:
            # IRIS EXPLAIN: Store the result of extract_run(run, campaign.name, window_seconds=window_seconds) in (part,
            # IRIS EXPLAIN: invalid); later lines use this named result.
            part, invalid = extract_run(run, campaign.name, window_seconds=window_seconds)
            # IRIS EXPLAIN: Call rows.extend(part): append all supplied items to the working list.
            rows.extend(part)
            # IRIS EXPLAIN: Call quarantine.extend(invalid): append all supplied items to the working list.
            quarantine.extend(invalid)
        # IRIS EXPLAIN: Catch (OSError, TypeError, KeyError, ValueError) as exc; execute the existing error/fallback path rather
        # IRIS EXPLAIN: than silently treating it as success.
        except (OSError, TypeError, KeyError, ValueError) as exc:
            # IRIS EXPLAIN: Call quarantine.append({'run_id': run.name, 'reason': str(exc)}): append one item to the working
            # IRIS EXPLAIN: list.
            quarantine.append({"run_id": run.name, "reason": str(exc)})
    # IRIS EXPLAIN: Enter this branch only when warnings.
    if warnings:
        # IRIS EXPLAIN: Iterate rows, binding each item to row; process only the existing observed/fixture collection.
        for row in rows:
            # IRIS EXPLAIN: Store False in row['sensor_healthy']; later lines use this named result.
            row["sensor_healthy"] = False
    # IRIS EXPLAIN: Return (rows, {'run_count': len(run_paths), 'session_count': len(rows), 'quarantine': quarantine,
    # IRIS EXPLAIN: 'warnings': warnings, 'truth_files_read': False, 'automa... to the caller; this ends the current function
    # IRIS EXPLAIN: path.
    return rows, {"run_count": len(run_paths), "session_count": len(rows),
                  # IRIS EXPLAIN: Continue the current record with quarantine, warnings; each value comes from the expression
                  # IRIS EXPLAIN: shown on this unchanged line.
                  "quarantine": quarantine, "warnings": warnings,
                  # IRIS EXPLAIN: Continue the current record with truth_files_read, automatic_labels_created; each value comes
                  # IRIS EXPLAIN: from the expression shown on this unchanged line.
                  "truth_files_read": False, "automatic_labels_created": False,
                  # IRIS EXPLAIN: Continue the current record with note; each value comes from the expression shown on this
                  # IRIS EXPLAIN: unchanged line.
                  "note": "Review and label each session independently. Run-level attack truth does not label background sessions."}
