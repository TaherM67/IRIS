# IRIS EXPLAIN: File purpose: The shared training/serving integration path: exact point-in-time joins, deduplication,
# IRIS EXPLAIN: quarantine, nested risk context, and session construction.
# IRIS EXPLAIN: Existing documentation/literal text below is kept exactly as written; the explanation is outside the string so
# IRIS EXPLAIN: its value does not change.
"""Three-source, point-in-time integration before feature engineering/ML.

One SIEM alert stays one unified event; risks are nested, not a row multiplier.
No training label file is opened anywhere in this runtime preparation module.
"""
# IRIS EXPLAIN: Keep type annotations unevaluated at definition time; this does not add a model feature or change runtime
# IRIS EXPLAIN: settings.
from __future__ import annotations

# IRIS EXPLAIN: Import bisect to binary-search snapshot effective-start times.
import bisect
# IRIS EXPLAIN: Import hashlib to compute deterministic byte identities and content fingerprints.
import hashlib
# IRIS EXPLAIN: Import heapq to release completed sessions into causal history in end-time order.
import heapq
# IRIS EXPLAIN: Import ipaddress to validate and canonicalize IPv4/IPv6 addresses.
import ipaddress
# IRIS EXPLAIN: Import json to encode and decode structured finite JSON payloads.
import json
# IRIS EXPLAIN: Import time to measure elapsed integration time without changing event-time semantics.
import time
# IRIS EXPLAIN: Import Counter, defaultdict, deque from collections to count values and build efficient grouping/history
# IRIS EXPLAIN: containers.
from collections import Counter, defaultdict, deque
# IRIS EXPLAIN: Import dataclass from dataclasses to declare validated structured settings/source containers.
from dataclasses import dataclass
# IRIS EXPLAIN: Import datetime, timedelta from datetime to represent timezone-aware timestamps and elapsed-time windows.
from datetime import datetime, timedelta
# IRIS EXPLAIN: Import Path from pathlib to resolve server-owned paths without trusting uploaded filenames.
from pathlib import Path
# IRIS EXPLAIN: Import Any from typing to declare expected interfaces/types for readers and type-checking tools.
from typing import Any

# IRIS EXPLAIN: Import digest, finite, write_json, write_jsonl from .contracts to reuse the shared project
# IRIS EXPLAIN: contract/implementation rather than duplicate it.
from .contracts import digest, finite, write_json, write_jsonl
# IRIS EXPLAIN: Import aggregate, get, normalize_event, timestamp from .telemetry to reuse the shared project
# IRIS EXPLAIN: contract/implementation rather than duplicate it.
from .telemetry import aggregate, get, normalize_event, timestamp

# IRIS EXPLAIN: Store {'synthetic', 'cyber_range', 'operational'} in PROVENANCES; later lines use this named result.
PROVENANCES = {"synthetic", "cyber_range", "operational"}
# IRIS EXPLAIN: Store 'iris-asset-inventory-v1' in ASSET_SCHEMA; later lines use this named result.
ASSET_SCHEMA = "iris-asset-inventory-v1"
# IRIS EXPLAIN: Store 'iris-risk-register-v1' in RISK_SCHEMA; later lines use this named result.
RISK_SCHEMA = "iris-risk-register-v1"
# IRIS EXPLAIN: Store 'highest_preexisting_likelihood_times_impact_then_risk_id' in CONTEXT_POLICY; later lines use this named
# IRIS EXPLAIN: result.
CONTEXT_POLICY = "highest_preexisting_likelihood_times_impact_then_risk_id"
# IRIS EXPLAIN: Store {'implemented', 'partial', 'missing', 'not_assessed', 'compensating', 'exception', 'unknown'} in
# IRIS EXPLAIN: CONTROL_STATES; later lines use this named result.
CONTROL_STATES = {"implemented", "partial", "missing", "not_assessed", "compensating", "exception", "unknown"}


# IRIS EXPLAIN: Function text: Require nonempty source text and strip surrounding whitespace without inventing an identifier.
# IRIS EXPLAIN: Inputs: value: the supplied value to validate/normalize/serialize; name: the field, record or test name used for
# IRIS EXPLAIN: the stated lookup/diagnostic.
# IRIS EXPLAIN: Declared return type: str; the return statements below show each actual result/fallback.
def text(value, name: str) -> str:
    # IRIS EXPLAIN: Enter this branch only when not isinstance(value, str) or not value.strip().
    if not isinstance(value, str) or not value.strip():
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError(f'{name} must be nonempty text'); the
        # IRIS EXPLAIN: caller's existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError(f"{name} must be nonempty text")
    # IRIS EXPLAIN: Return the result of value.strip() (remove surrounding whitespace) to the caller; this ends the current
    # IRIS EXPLAIN: function path.
    return value.strip()


# IRIS EXPLAIN: Function bounded_integer: Require a finite integer inside the requested bounds, used for the existing 1-5
# IRIS EXPLAIN: asset/risk scale.
# IRIS EXPLAIN: Inputs: value: the supplied value to validate/normalize/serialize; name: the field, record or test name used for
# IRIS EXPLAIN: the stated lookup/diagnostic; low: the inclusive permitted numeric minimum; high: the inclusive permitted
# IRIS EXPLAIN: numeric maximum.
# IRIS EXPLAIN: Declared return type: int; the return statements below show each actual result/fallback.
def bounded_integer(value, name, low=1, high=5) -> int:
    # IRIS EXPLAIN: Store the result of finite(value, name, low, high) in number; later lines use this named result.
    number = finite(value, name, low, high)
    # IRIS EXPLAIN: Enter this branch only when int(number) != number.
    if int(number) != number:
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError(f'{name} must be an integer'); the
        # IRIS EXPLAIN: caller's existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError(f"{name} must be an integer")
    # IRIS EXPLAIN: Return int(number) to the caller; this ends the current function path.
    return int(number)


# IRIS EXPLAIN: Function valid_times: Validate snapshot effective/expiry/recorded timestamps and prepare both internal datetime
# IRIS EXPLAIN: keys and public ISO values.
# IRIS EXPLAIN: Inputs: row: the existing input record to inspect without inventing missing evidence.
# IRIS EXPLAIN: Declared return type: dict; the return statements below show each actual result/fallback.
def valid_times(row: dict) -> dict:
    # IRIS EXPLAIN: Store the result of timestamp(row.get('valid_from')) in start; later lines use this named result.
    start = timestamp(row.get("valid_from"))
    # IRIS EXPLAIN: Store the result of timestamp(row['valid_to']) when row.get('valid_to'); otherwise None (no result/value) in
    # IRIS EXPLAIN: end; later lines use this named result.
    end = timestamp(row["valid_to"]) if row.get("valid_to") else None
    # IRIS EXPLAIN: Store the result of timestamp(row.get('recorded_at')) in known; later lines use this named result.
    known = timestamp(row.get("recorded_at"))
    # IRIS EXPLAIN: Enter this branch only when end is not None and end <= start.
    if end is not None and end <= start:
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('valid_to must be later than
        # IRIS EXPLAIN: valid_from'); the caller's existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError("valid_to must be later than valid_from")
    # IRIS EXPLAIN: Return a mapping containing _from, _to, _known, valid_from, valid_to, recorded_at to the caller; this ends
    # IRIS EXPLAIN: the current function path.
    return {"_from": start, "_to": end, "_known": known,
            # IRIS EXPLAIN: Set/describe these existing record fields: valid_from: inclusive start of a source snapshot's
            # IRIS EXPLAIN: effective interval; valid_to: exclusive expiry, or None for an open-ended interval.
            "valid_from": start.isoformat(), "valid_to": end.isoformat() if end else None,
            # IRIS EXPLAIN: Set/describe these existing record fields: recorded_at: when the source snapshot was known; prevents
            # IRIS EXPLAIN: information leaking backward in time.
            "recorded_at": known.isoformat()}


# IRIS EXPLAIN: Function public: Return the public snapshot fields while removing internal underscore-prefixed indexing helpers.
# IRIS EXPLAIN: Inputs: record: the explicit record input used by the unchanged statements below.
# IRIS EXPLAIN: Declared return type: dict | None; the return statements below show each actual result/fallback.
def public(record: dict | None) -> dict | None:
    # IRIS EXPLAIN: Return the comprehension {key: value for key, value in record.items() if not key.startswith('_')} when
    # IRIS EXPLAIN: record; otherwise None (no result/value) to the caller; this ends the current function path.
    return {key: value for key, value in record.items() if not key.startswith("_")} if record else None


# IRIS EXPLAIN: Class TemporalIndex: Exact, non-overlapping historical lookup for point-in-time source enrichment.
class TemporalIndex:
    # IRIS EXPLAIN: Existing documentation/literal text below is kept exactly as written; the explanation is outside the string
    # IRIS EXPLAIN: so its value does not change.
    """Validated non-overlapping histories; O(log V) point lookup per key."""
    # IRIS EXPLAIN: Function TemporalIndex.__init__: Build sorted histories and binary-search start indexes; reject overlapping
    # IRIS EXPLAIN: versions rather than guessing a valid snapshot.
    # IRIS EXPLAIN: Inputs: rows: the existing records/feature rows passed by the caller; key: the exact grouping/lookup field
    # IRIS EXPLAIN: or identity.
    def __init__(self, rows: list[dict], key: str):
        # IRIS EXPLAIN: Store the result of defaultdict(list) in self.rows; later lines use this named result.
        self.rows = defaultdict(list)
        # IRIS EXPLAIN: Store a mapping containing  in self.starts; later lines use this named result.
        self.starts = {}
        # IRIS EXPLAIN: Iterate rows, binding each item to row; process only the existing observed/fixture collection.
        for row in rows:
            # IRIS EXPLAIN: Call self.rows[row[key]].append(row): append one item to the working list.
            self.rows[row[key]].append(row)
        # IRIS EXPLAIN: Iterate self.rows.items(), binding each item to (identifier, history); process only the existing
        # IRIS EXPLAIN: observed/fixture collection.
        for identifier, history in self.rows.items():
            # IRIS EXPLAIN: Call history.sort(key=lambda row: row['_from']): sort the existing collection using the declared
            # IRIS EXPLAIN: stable key.
            history.sort(key=lambda row: row["_from"])
            # IRIS EXPLAIN: Iterate zip(history, history[1:]), binding each item to (prior, current); process only the existing
            # IRIS EXPLAIN: observed/fixture collection.
            for prior, current in zip(history, history[1:]):
                # IRIS EXPLAIN: Enter this branch only when prior['_to'] is None or prior['_to'] > current['_from'].
                if prior["_to"] is None or prior["_to"] > current["_from"]:
                    # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError(f'Overlapping versions for
                    # IRIS EXPLAIN: {key}={identifier}; resolve ambiguity in the source'); the caller's existing boundary
                    # IRIS EXPLAIN: determines rollback or the HTTP diagnostic.
                    raise ValueError(f"Overlapping versions for {key}={identifier}; resolve ambiguity in the source")
            # IRIS EXPLAIN: Store the comprehension [r['_from'] for r in history] in self.starts[identifier]; later lines use
            # IRIS EXPLAIN: this named result.
            self.starts[identifier] = [r["_from"] for r in history]

    # IRIS EXPLAIN: Function TemporalIndex.at: Find the version effective at the event time and already recorded by then; reject
    # IRIS EXPLAIN: unavailable, future-known or expired snapshots.
    # IRIS EXPLAIN: Inputs: key: the exact grouping/lookup field or identity; at: the timezone-aware event instant for a
    # IRIS EXPLAIN: point-in-time lookup.
    # IRIS EXPLAIN: Declared return type: dict | None; the return statements below show each actual result/fallback.
    def at(self, key: str, at: datetime) -> dict | None:
        # IRIS EXPLAIN: Store the result of self.starts.get(key, []) (read an optional mapping field using its stated fallback)
        # IRIS EXPLAIN: in starts; later lines use this named result.
        starts = self.starts.get(key, [])
        # IRIS EXPLAIN: Store the computed value bisect.bisect_right(starts, at) - 1 in i; later lines use this named result.
        i = bisect.bisect_right(starts, at)-1
        # IRIS EXPLAIN: Enter this branch only when i < 0.
        if i < 0:
            # IRIS EXPLAIN: Return None (no result/value) to the caller; this ends the current function path.
            return None
        # IRIS EXPLAIN: Store self.rows[key][i] in row; later lines use this named result.
        row = self.rows[key][i]
        # IRIS EXPLAIN: Enter this branch only when row['_known'] > at or (row['_to'] is not None and at >= row['_to']).
        if row["_known"] > at or (row["_to"] is not None and at >= row["_to"]):
            # IRIS EXPLAIN: Return None (no result/value) to the caller; this ends the current function path.
            return None
        # IRIS EXPLAIN: Return row to the caller; this ends the current function path.
        return row


# IRIS EXPLAIN: Generate the structured dataclass constructor/fields from the existing annotations and declared options.
@dataclass
# IRIS EXPLAIN: Class Sources: Dataclass holding validated temporal histories and reverse lookup indexes; counts represent
# IRIS EXPLAIN: snapshots.
class Sources:
    # IRIS EXPLAIN: Declare the existing assets field and its type; the surrounding dataclass/schema supplies construction
    # IRIS EXPLAIN: behavior.
    assets: TemporalIndex
    # IRIS EXPLAIN: Declare the existing risks field and its type; the surrounding dataclass/schema supplies construction
    # IRIS EXPLAIN: behavior.
    risks: TemporalIndex
    # IRIS EXPLAIN: Declare the existing ip_assets field and its type; the surrounding dataclass/schema supplies construction
    # IRIS EXPLAIN: behavior.
    ip_assets: dict
    # IRIS EXPLAIN: Declare the existing hostname_assets field and its type; the surrounding dataclass/schema supplies
    # IRIS EXPLAIN: construction behavior.
    hostname_assets: dict
    # IRIS EXPLAIN: Declare the existing asset_risks field and its type; the surrounding dataclass/schema supplies construction
    # IRIS EXPLAIN: behavior.
    asset_risks: dict
    # IRIS EXPLAIN: Declare the existing provenance field and its type; the surrounding dataclass/schema supplies construction
    # IRIS EXPLAIN: behavior.
    provenance: str
    # IRIS EXPLAIN: Declare the existing asset_count field and its type; the surrounding dataclass/schema supplies construction
    # IRIS EXPLAIN: behavior.
    asset_count: int
    # IRIS EXPLAIN: Declare the existing risk_count field and its type; the surrounding dataclass/schema supplies construction
    # IRIS EXPLAIN: behavior.
    risk_count: int


# IRIS EXPLAIN: Function read_source: Read one inventory/register JSON envelope and validate its exact schema, provenance and
# IRIS EXPLAIN: nonempty records array.
# IRIS EXPLAIN: Inputs: path: the explicit local file path used by this helper; schema: the exact expected inventory/register
# IRIS EXPLAIN: schema identifier.
# IRIS EXPLAIN: Declared return type: tuple[list[dict], str]; the return statements below show each actual result/fallback.
def read_source(path: Path, schema: str) -> tuple[list[dict], str]:
    # IRIS EXPLAIN: Store the result of json.loads(path.read_text(encoding='utf-8')) (decode the existing JSON text) in payload;
    # IRIS EXPLAIN: later lines use this named result.
    payload = json.loads(path.read_text(encoding="utf-8"))
    # IRIS EXPLAIN: Enter this branch only when not isinstance(payload, dict) or payload.get('schema_version') != schema.
    if not isinstance(payload, dict) or payload.get("schema_version") != schema:
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError(f'{path.name}: expected
        # IRIS EXPLAIN: schema_version={schema}'); the caller's existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError(f"{path.name}: expected schema_version={schema}")
    # IRIS EXPLAIN: Store the result of payload.get('data_provenance') (read an optional mapping field using its stated
    # IRIS EXPLAIN: fallback) in provenance; later lines use this named result.
    provenance = payload.get("data_provenance")
    # IRIS EXPLAIN: Enter this branch only when provenance not in PROVENANCES.
    if provenance not in PROVENANCES:
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError(f'{path.name}: explicit
        # IRIS EXPLAIN: synthetic/cyber_range/operational provenance required'); the caller's existing boundary determines
        # IRIS EXPLAIN: rollback or the HTTP diagnostic.
        raise ValueError(f"{path.name}: explicit synthetic/cyber_range/operational provenance required")
    # IRIS EXPLAIN: Store the result of payload.get('records') (read an optional mapping field using its stated fallback) in
    # IRIS EXPLAIN: rows; later lines use this named result.
    rows = payload.get("records")
    # IRIS EXPLAIN: Enter this branch only when not isinstance(rows, list) or not rows or any((not isinstance(r, dict) for r in
    # IRIS EXPLAIN: rows)).
    if not isinstance(rows, list) or not rows or any(not isinstance(r, dict) for r in rows):
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError(f'{path.name}: records must be a
        # IRIS EXPLAIN: nonempty object array'); the caller's existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError(f"{path.name}: records must be a nonempty object array")
    # IRIS EXPLAIN: Return (rows, provenance) to the caller; this ends the current function path.
    return rows, provenance


# IRIS EXPLAIN: Function load_sources: Validate both snapshot histories, risk ownership, control states and exceptions, then
# IRIS EXPLAIN: build exact temporal, IP, hostname and asset-risk indexes.
# IRIS EXPLAIN: Inputs: asset_path: the asset inventory source path; risk_path: the risk register source path.
# IRIS EXPLAIN: Declared return type: Sources; the return statements below show each actual result/fallback.
def load_sources(asset_path: Path, risk_path: Path) -> Sources:
    # IRIS EXPLAIN: Store the result of read_source(asset_path, ASSET_SCHEMA) in (asset_raw, provenance); later lines use this
    # IRIS EXPLAIN: named result.
    asset_raw, provenance = read_source(asset_path, ASSET_SCHEMA)
    # IRIS EXPLAIN: Store the result of read_source(risk_path, RISK_SCHEMA) in (risk_raw, risk_provenance); later lines use this
    # IRIS EXPLAIN: named result.
    risk_raw, risk_provenance = read_source(risk_path, RISK_SCHEMA)
    # IRIS EXPLAIN: Enter this branch only when provenance != risk_provenance.
    if provenance != risk_provenance:
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Do not mix synthetic and real sources
        # IRIS EXPLAIN: or inconsistent provenance'); the caller's existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError("Do not mix synthetic and real sources or inconsistent provenance")
    # IRIS EXPLAIN: Store ([], [], set()) in (assets, risks, version_ids); later lines use this named result.
    assets, risks, version_ids = [], [], set()
    # IRIS EXPLAIN: Iterate asset_raw, binding each item to row; process only the existing observed/fixture collection.
    for row in asset_raw:
        # IRIS EXPLAIN: Store the result of text(row.get('asset_id'), 'asset_id') in aid; later lines use this named result.
        aid = text(row.get("asset_id"), "asset_id")
        # IRIS EXPLAIN: Store the result of text(row.get('asset_version_id'), 'asset_version_id') in vid; later lines use this
        # IRIS EXPLAIN: named result.
        vid = text(row.get("asset_version_id"), "asset_version_id")
        # IRIS EXPLAIN: Enter this branch only when vid in version_ids.
        if vid in version_ids:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Duplicate asset_version_id'); the
            # IRIS EXPLAIN: caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError("Duplicate asset_version_id")
        # IRIS EXPLAIN: Call version_ids.add(vid): record membership in the set.
        version_ids.add(vid)
        # IRIS EXPLAIN: Store the result of row.get('ip_addresses') (read an optional mapping field using its stated fallback)
        # IRIS EXPLAIN: in ips; later lines use this named result.
        ips = row.get("ip_addresses")
        # IRIS EXPLAIN: Enter this branch only when not isinstance(ips, list) or not ips.
        if not isinstance(ips, list) or not ips:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Every asset snapshot needs an
            # IRIS EXPLAIN: ip_addresses array'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError("Every asset snapshot needs an ip_addresses array")
        # IRIS EXPLAIN: Store sorted({str(ipaddress.ip_address(ip)) for ip in ips}) in ips; later lines use this named result.
        ips = sorted({str(ipaddress.ip_address(ip)) for ip in ips})
        # IRIS EXPLAIN: Call assets.append({'asset_id': aid, 'asset_version_id': vid, 'hostname': text(row.get('hostname'),
        # IRIS EXPLAIN: 'hostname').casefold(), 'ip_addresses': ips, 'asset_type': tex...: append one item to the working list.
        assets.append({"asset_id": aid, "asset_version_id": vid,
                       # IRIS EXPLAIN: Continue the current record with hostname; each value comes from the expression shown on
                       # IRIS EXPLAIN: this unchanged line.
                       "hostname": text(row.get("hostname"), "hostname").casefold(),
                       # IRIS EXPLAIN: Set/describe these existing record fields: asset_type: the existing inventory
                       # IRIS EXPLAIN: business-context category.
                       "ip_addresses": ips, "asset_type": text(row.get("asset_type"), "asset_type"),
                       # IRIS EXPLAIN: Continue the current record with criticality; each value comes from the expression shown
                       # IRIS EXPLAIN: on this unchanged line.
                       "criticality": bounded_integer(row.get("criticality"), "criticality"),
                       # IRIS EXPLAIN: Continue the current record with zone; each value comes from the expression shown on this
                       # IRIS EXPLAIN: unchanged line.
                       "zone": text(row.get("zone"), "zone"),
                       # IRIS EXPLAIN: Continue the current record with owner; each value comes from the expression shown on
                       # IRIS EXPLAIN: this unchanged line.
                       "owner": text(row.get("owner"), "owner"), **valid_times(row)})
    # IRIS EXPLAIN: Store the comprehension {row['asset_id'] for row in assets} in known_assets; later lines use this named
    # IRIS EXPLAIN: result.
    known_assets = {row["asset_id"] for row in assets}
    # IRIS EXPLAIN: Store ({}, set()) in (risk_owner, version_ids); later lines use this named result.
    risk_owner, version_ids = {}, set()
    # IRIS EXPLAIN: Iterate risk_raw, binding each item to row; process only the existing observed/fixture collection.
    for row in risk_raw:
        # IRIS EXPLAIN: Store the result of text(row.get('risk_id'), 'risk_id') in rid; later lines use this named result.
        rid = text(row.get("risk_id"), "risk_id")
        # IRIS EXPLAIN: Store the result of text(row.get('asset_id'), 'risk.asset_id') in aid; later lines use this named
        # IRIS EXPLAIN: result.
        aid = text(row.get("asset_id"), "risk.asset_id")
        # IRIS EXPLAIN: Store the result of text(row.get('risk_version_id'), 'risk_version_id') in vid; later lines use this
        # IRIS EXPLAIN: named result.
        vid = text(row.get("risk_version_id"), "risk_version_id")
        # IRIS EXPLAIN: Enter this branch only when vid in version_ids.
        if vid in version_ids:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Duplicate risk_version_id'); the
            # IRIS EXPLAIN: caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError("Duplicate risk_version_id")
        # IRIS EXPLAIN: Call version_ids.add(vid): record membership in the set.
        version_ids.add(vid)
        # IRIS EXPLAIN: Enter this branch only when aid not in known_assets.
        if aid not in known_assets:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError(f'Risk {rid} references an asset
            # IRIS EXPLAIN: absent from inventory'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError(f"Risk {rid} references an asset absent from inventory")
        # IRIS EXPLAIN: Enter this branch only when rid in risk_owner and risk_owner[rid] != aid.
        if rid in risk_owner and risk_owner[rid] != aid:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('One risk_id cannot ambiguously
            # IRIS EXPLAIN: reference multiple assets'); the caller's existing boundary determines rollback or the HTTP
            # IRIS EXPLAIN: diagnostic.
            raise ValueError("One risk_id cannot ambiguously reference multiple assets")
        # IRIS EXPLAIN: Store aid in risk_owner[rid]; later lines use this named result.
        risk_owner[rid] = aid
        # IRIS EXPLAIN: Store the result of row.get('control_states', {}) (read an optional mapping field using its stated
        # IRIS EXPLAIN: fallback) in states; later lines use this named result.
        states = row.get("control_states", {})
        # IRIS EXPLAIN: Enter this branch only when not isinstance(states, dict) or any((not isinstance(k, str) or not
        # IRIS EXPLAIN: isinstance(v, str) or v not in CONTROL_STATES for k, v in states.items())).
        if not isinstance(states, dict) or any(not isinstance(k, str) or not isinstance(v, str) or v not in CONTROL_STATES for k, v in states.items()):
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Invalid control_states mapping');
            # IRIS EXPLAIN: the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError("Invalid control_states mapping")
        # IRIS EXPLAIN: Store the result of row.get('active_exception_control_ids', []) (read an optional mapping field using
        # IRIS EXPLAIN: its stated fallback) in exceptions; later lines use this named result.
        exceptions = row.get("active_exception_control_ids", [])
        # IRIS EXPLAIN: Enter this branch only when not isinstance(exceptions, list) or any((not isinstance(c, str) for c in
        # IRIS EXPLAIN: exceptions)).
        if not isinstance(exceptions, list) or any(not isinstance(c, str) for c in exceptions):
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('active_exception_control_ids must
            # IRIS EXPLAIN: be a string list'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError("active_exception_control_ids must be a string list")
        # IRIS EXPLAIN: Call risks.append({'risk_id': rid, 'risk_version_id': vid, 'asset_id': aid, 'risk_category':
        # IRIS EXPLAIN: text(row.get('risk_category'), 'risk_category'), 'likelihood': bounde...: append one item to the working
        # IRIS EXPLAIN: list.
        risks.append({"risk_id": rid, "risk_version_id": vid, "asset_id": aid,
                      # IRIS EXPLAIN: Set/describe these existing record fields: risk_category: the existing registered risk
                      # IRIS EXPLAIN: taxonomy used for explicit scenario-to-risk mapping.
                      "risk_category": text(row.get("risk_category"), "risk_category"),
                      # IRIS EXPLAIN: Set/describe these existing record fields: likelihood: the stored or explicitly proposed
                      # IRIS EXPLAIN: 1-5 likelihood in this record, not an invented ML risk probability.
                      "likelihood": bounded_integer(row.get("likelihood"), "likelihood"),
                      # IRIS EXPLAIN: Set/describe these existing record fields: impact: the same registered risk's impact; it
                      # IRIS EXPLAIN: must not be independently maximized across risks.
                      "impact": bounded_integer(row.get("impact"), "impact"),
                      # IRIS EXPLAIN: Set/describe these existing record fields: control_states: asset/risk-specific
                      # IRIS EXPLAIN: implementation evidence such as missing, partial or implemented;
                      # IRIS EXPLAIN: active_exception_control_ids: controls requiring exception/compensating-control review
                      # IRIS EXPLAIN: before a response.
                      "control_states": states, "active_exception_control_ids": sorted(set(exceptions)),
                      # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                      # IRIS EXPLAIN: arguments/items: **valid_times(row)}).
                      **valid_times(row)})
    # IRIS EXPLAIN: Store (defaultdict(set), defaultdict(set), defaultdict(set)) in (ip_assets, hostname_assets, asset_risks);
    # IRIS EXPLAIN: later lines use this named result.
    ip_assets, hostname_assets, asset_risks = defaultdict(set), defaultdict(set), defaultdict(set)
    # IRIS EXPLAIN: Iterate assets, binding each item to asset; process only the existing observed/fixture collection.
    for asset in assets:
        # IRIS EXPLAIN: Iterate asset['ip_addresses'], binding each item to ip; process only the existing observed/fixture
        # IRIS EXPLAIN: collection.
        for ip in asset["ip_addresses"]:
            # IRIS EXPLAIN: Call ip_assets[ip].add(asset['asset_id']): record membership in the set.
            ip_assets[ip].add(asset["asset_id"])
        # IRIS EXPLAIN: Call hostname_assets[asset['hostname']].add(asset['asset_id']): record membership in the set.
        hostname_assets[asset["hostname"]].add(asset["asset_id"])
    # IRIS EXPLAIN: Iterate risks, binding each item to risk; process only the existing observed/fixture collection.
    for risk in risks:
        # IRIS EXPLAIN: Call asset_risks[risk['asset_id']].add(risk['risk_id']): record membership in the set.
        asset_risks[risk["asset_id"]].add(risk["risk_id"])
    # IRIS EXPLAIN: Return the result of Sources(TemporalIndex(assets, 'asset_id'), TemporalIndex(risks, 'risk_id'), ip_assets,
    # IRIS EXPLAIN: hostname_assets, ass... to the caller; this ends the current function path.
    return Sources(TemporalIndex(assets, "asset_id"), TemporalIndex(risks, "risk_id"),
                   # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                   # IRIS EXPLAIN: arguments/items: ip_assets, hostname_assets, asset_risks, provenance, len(assets),
                   # IRIS EXPLAIN: len(risks)).
                   ip_assets, hostname_assets, asset_risks, provenance, len(assets), len(risks))


# IRIS EXPLAIN: Function normalize_alert: Normalize a canonical or wrapped SIEM alert, require stable event
# IRIS EXPLAIN: identity/provenance/health metadata, and retain raw line evidence.
# IRIS EXPLAIN: Inputs: raw: the original SIEM observation or collector wrapper; line: the original one-based JSONL line number
# IRIS EXPLAIN: for evidence/quarantine; source_name: the existing source filename for traceable evidence references.
# IRIS EXPLAIN: Declared return type: dict | None; the return statements below show each actual result/fallback.
def normalize_alert(raw: dict, line: int, source_name: str) -> dict | None:
    # IRIS EXPLAIN: Enter this branch only when not isinstance(raw, dict).
    if not isinstance(raw, dict):
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('SIEM alert must be a JSON object'); the
        # IRIS EXPLAIN: caller's existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError("SIEM alert must be a JSON object")
    # IRIS EXPLAIN: Store the result of raw.get('_source', raw) (read an optional mapping field using its stated fallback) in
    # IRIS EXPLAIN: row; later lines use this named result.
    row = raw.get("_source", raw)
    # IRIS EXPLAIN: Enter this branch only when not isinstance(row, dict).
    if not isinstance(row, dict):
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('SIEM _source must be an object'); the
        # IRIS EXPLAIN: caller's existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError("SIEM _source must be an object")
    # IRIS EXPLAIN: Function metadata: Read collector metadata from the normalized record first, then its outer indexer wrapper,
    # IRIS EXPLAIN: with the supplied default.
    # IRIS EXPLAIN: Inputs: name: the field, record or test name used for the stated lookup/diagnostic; default: the existing
    # IRIS EXPLAIN: explicit fallback when a field/query value is absent.
    def metadata(name, default=None):
        # IRIS EXPLAIN: Return row[name] when name in row; otherwise the result of raw.get(name, default) (read an optional
        # IRIS EXPLAIN: mapping field using its stated fallback) to the caller; this ends the current function path.
        return row[name] if name in row else raw.get(name, default)
    # Canonical flat alerts have explicit outcome, avoiding text-only inference.
    # IRIS EXPLAIN: Enter this branch only when all((k in row for k in ('event_family', 'rule_level', 'outcome'))).
    if all(k in row for k in ("event_family", "rule_level", "outcome")):
        # IRIS EXPLAIN: Store the result of timestamp(row.get('timestamp')) in ts; later lines use this named result.
        ts = timestamp(row.get("timestamp"))
        # IRIS EXPLAIN: Store row['outcome'] in outcome; later lines use this named result.
        outcome = row["outcome"]
        # IRIS EXPLAIN: Enter this branch only when outcome not in {'failed', 'success', 'unknown'}.
        if outcome not in {"failed", "success", "unknown"}:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('outcome must be failed, success or
            # IRIS EXPLAIN: unknown'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError("outcome must be failed, success or unknown")
        # IRIS EXPLAIN: Store a mapping containing ts, src, dst, agent, account, family, protocol and additional fields in
        # IRIS EXPLAIN: event; later lines use this named result.
        event = {"ts": ts, "src": row.get("source_ip"), "dst": row.get("destination_ip"),
                 # IRIS EXPLAIN: Continue the current record with agent, account; each value comes from the expression shown on
                 # IRIS EXPLAIN: this unchanged line.
                 "agent": row.get("agent_name"), "account": row.get("account") or "unknown",
                 # IRIS EXPLAIN: Continue the current record with family; each value comes from the expression shown on this
                 # IRIS EXPLAIN: unchanged line.
                 "family": text(row["event_family"], "event_family").casefold(),
                 # IRIS EXPLAIN: Continue the current record with protocol; each value comes from the expression shown on this
                 # IRIS EXPLAIN: unchanged line.
                 "protocol": text(row.get("protocol"), "protocol").upper(),
                 # IRIS EXPLAIN: Continue the current record with outcome, level; each value comes from the expression shown on
                 # IRIS EXPLAIN: this unchanged line.
                 "outcome": outcome, "level": finite(row["rule_level"], "rule_level", 0, 16),
                 # IRIS EXPLAIN: Continue the current record with rule; each value comes from the expression shown on this
                 # IRIS EXPLAIN: unchanged line.
                 "rule": text(str(row.get("rule_id", "")), "rule_id"),
                 # IRIS EXPLAIN: Continue the current record with raw_ref; each value comes from the expression shown on this
                 # IRIS EXPLAIN: unchanged line.
                 "raw_ref": f"{source_name}#L{line}"}
        # IRIS EXPLAIN: Store None (no result/value) in semantic_key; later lines use this named result.
        semantic_key = None
    # IRIS EXPLAIN: Handle the alternative to the preceding condition/loop exactly as originally defined.
    else:
        # IRIS EXPLAIN: Store 'suricata' when row.get('event_type'); otherwise 'wazuh' in sensor; later lines use this named
        # IRIS EXPLAIN: result.
        sensor = "suricata" if row.get("event_type") else "wazuh"
        # IRIS EXPLAIN: Store the result of normalize_event(row, sensor, f'{source_name}#L{line}') in event; later lines use
        # IRIS EXPLAIN: this named result.
        event = normalize_event(row, sensor, f"{source_name}#L{line}")
        # IRIS EXPLAIN: Enter this branch only when event is None.
        if event is None:
            # IRIS EXPLAIN: Return None (no result/value) to the caller; this ends the current function path.
            return None
        # IRIS EXPLAIN: Store the result of event.get('key') (read an optional mapping field using its stated fallback) in
        # IRIS EXPLAIN: semantic_key; later lines use this named result.
        semantic_key = event.get("key")
    # IRIS EXPLAIN: Store the result of get(row, 'event_id', 'id', '_id') (read an optional mapping field using its stated
    # IRIS EXPLAIN: fallback) in eid; later lines use this named result.
    eid = get(row, "event_id", "id", "_id")
    # IRIS EXPLAIN: Enter this branch only when eid is None.
    if eid is None:
        # IRIS EXPLAIN: Store the result of raw.get('_id') (read an optional mapping field using its stated fallback) in eid;
        # IRIS EXPLAIN: later lines use this named result.
        eid = raw.get("_id")
    # IRIS EXPLAIN: Enter this branch only when eid is None.
    if eid is None:
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('A stable SIEM event_id/id/_id is
        # IRIS EXPLAIN: required; line numbers are not event identities'); the caller's existing boundary determines rollback or
        # IRIS EXPLAIN: the HTTP diagnostic.
        raise ValueError("A stable SIEM event_id/id/_id is required; line numbers are not event identities")
    # IRIS EXPLAIN: Iterate ('src', 'dst'), binding each item to field; process only the existing observed/fixture collection.
    for field in ("src", "dst"):
        # IRIS EXPLAIN: Enter this branch only when event[field].
        if event[field]:
            # IRIS EXPLAIN: Store str(ipaddress.ip_address(event[field])) in event[field]; later lines use this named result.
            event[field] = str(ipaddress.ip_address(event[field]))
    # IRIS EXPLAIN: Enter this branch only when event.get('agent').
    if event.get("agent"):
        # IRIS EXPLAIN: Store the result of str(event['agent']).strip().casefold() (normalize text case for matching) in
        # IRIS EXPLAIN: event['agent']; later lines use this named result.
        event["agent"] = str(event["agent"]).strip().casefold()
    # IRIS EXPLAIN: Store str(event['account']) in event['account']; later lines use this named result.
    event["account"] = str(event["account"])
    # IRIS EXPLAIN: Call event.update({'event_id': text(str(eid), 'event_id'), 'asset_id_hint': get(row, 'asset_id',
    # IRIS EXPLAIN: 'resolved_asset_id') or get(raw, 'asset_id', 'resolved_asset_id')...: merge the supplied fields into this
    # IRIS EXPLAIN: existing mapping.
    event.update({"event_id": text(str(eid), "event_id"),
                  # IRIS EXPLAIN: Continue the current record with asset_id_hint; each value comes from the expression shown on
                  # IRIS EXPLAIN: this unchanged line.
                  "asset_id_hint": get(row, "asset_id", "resolved_asset_id") or get(raw, "asset_id", "resolved_asset_id"),
                  # IRIS EXPLAIN: Set/describe these existing record fields: campaign_id: group provenance retained for
                  # IRIS EXPLAIN: split/session identity; not a telemetry predictor.
                  "campaign_id": str(metadata("campaign_id") or "runtime-source"),
                  # IRIS EXPLAIN: Set/describe these existing record fields: run_id: run/batch provenance retained for
                  # IRIS EXPLAIN: traceability; not a hidden attack-label feature.
                  "run_id": str(metadata("run_id") or "runtime-batch"),
                  # IRIS EXPLAIN: Set/describe these existing record fields: sensor_healthy: explicit health evidence; a
                  # IRIS EXPLAIN: missing/false value must not be treated as benign.
                  "sensor_healthy": metadata("sensor_healthy") is True,
                  # IRIS EXPLAIN: Set/describe these existing record fields: data_provenance: explicit
                  # IRIS EXPLAIN: synthetic/cyber_range/operational source identity.
                  "data_provenance": metadata("data_provenance"),
                  # IRIS EXPLAIN: Continue the current record with semantic_key; each value comes from the expression shown on
                  # IRIS EXPLAIN: this unchanged line.
                  "semantic_key": semantic_key})
    # IRIS EXPLAIN: Store event['event_id'] in event['key']; later lines use this named result.
    event["key"] = event["event_id"]
    # IRIS EXPLAIN: Return event to the caller; this ends the current function path.
    return event


# IRIS EXPLAIN: Function fingerprint: Hash normalized event content excluding source-line bookkeeping, so exact duplicates and
# IRIS EXPLAIN: conflicting reused event IDs are distinguishable.
# IRIS EXPLAIN: Inputs: event: the explicit event input used by the unchanged statements below.
# IRIS EXPLAIN: Declared return type: str; the return statements below show each actual result/fallback.
def fingerprint(event: dict) -> str:
    # IRIS EXPLAIN: Store the comprehension {k: v.isoformat() if isinstance(v, datetime) else v for k, v in event.items() if k
    # IRIS EXPLAIN: not in {'raw_ref', 'key'}} in value; later lines use this named result.
    value = {k: (v.isoformat() if isinstance(v, datetime) else v)
             # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
             # IRIS EXPLAIN: for k, v in event.items() if k not in {"raw_ref", "key"}}.
             for k, v in event.items() if k not in {"raw_ref", "key"}}
    # IRIS EXPLAIN: Return the result of hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest() (return the
    # IRIS EXPLAIN: hexadecimal content digest) to the caller; this ends the current function path.
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


# IRIS EXPLAIN: Function resolve_asset: Resolve the target from explicit asset ID, unique destination IP or unique agent
# IRIS EXPLAIN: hostname at event time; never use an attacker source IP as the victim.
# IRIS EXPLAIN: Inputs: event: the explicit event input used by the unchanged statements below; sources: validated temporal
# IRIS EXPLAIN: histories and exact reverse-lookup indexes.
# IRIS EXPLAIN: Declared return type: tuple[dict | None, str]; the return statements below show each actual result/fallback.
def resolve_asset(event: dict, sources: Sources) -> tuple[dict | None, str]:
    # IRIS EXPLAIN: Store event['ts'] in at; later lines use this named result.
    at = event["ts"]
    # IRIS EXPLAIN: Store the result of event.get('asset_id_hint') (read an optional mapping field using its stated fallback) in
    # IRIS EXPLAIN: hint; later lines use this named result.
    hint = event.get("asset_id_hint")
    # IRIS EXPLAIN: Enter this branch only when hint.
    if hint:
        # IRIS EXPLAIN: Store the result of sources.assets.at(str(hint).strip(), at) in asset; later lines use this named
        # IRIS EXPLAIN: result.
        asset = sources.assets.at(str(hint).strip(), at)
        # IRIS EXPLAIN: Enter this branch only when asset is None.
        if asset is None:
            # IRIS EXPLAIN: Return (None, 'asset_id has no inventory snapshot valid and known at event time') to the caller;
            # IRIS EXPLAIN: this ends the current function path.
            return None, "asset_id has no inventory snapshot valid and known at event time"
        # IRIS EXPLAIN: Enter this branch only when event['dst'] and event['dst'] not in asset['ip_addresses'].
        if event["dst"] and event["dst"] not in asset["ip_addresses"]:
            # IRIS EXPLAIN: Return (None, 'SIEM asset_id and destination IP disagree') to the caller; this ends the current
            # IRIS EXPLAIN: function path.
            return None, "SIEM asset_id and destination IP disagree"
        # IRIS EXPLAIN: Return (asset, 'exact_asset_id') to the caller; this ends the current function path.
        return asset, "exact_asset_id"
    # IRIS EXPLAIN: Enter this branch only when event['dst'].
    if event["dst"]:
        # IRIS EXPLAIN: Store the comprehension [sources.assets.at(aid, at) for aid in sources.ip_assets.get(event['dst'], [])]
        # IRIS EXPLAIN: in candidates; later lines use this named result.
        candidates = [sources.assets.at(aid, at) for aid in sources.ip_assets.get(event["dst"], [])]
        # IRIS EXPLAIN: Store the comprehension [a for a in candidates if a and event['dst'] in a['ip_addresses']] in
        # IRIS EXPLAIN: candidates; later lines use this named result.
        candidates = [a for a in candidates if a and event["dst"] in a["ip_addresses"]]
        # IRIS EXPLAIN: Return (candidates[0], 'exact_destination_ip') when len(candidates) == 1; otherwise (None, 'destination
        # IRIS EXPLAIN: IP unresolved or ambiguous at event time') to the caller; this ends the current function path.
        return (candidates[0], "exact_destination_ip") if len(candidates) == 1 else (None, "destination IP unresolved or ambiguous at event time")
    # IRIS EXPLAIN: Enter this branch only when event.get('agent').
    if event.get("agent"):
        # IRIS EXPLAIN: Store the comprehension [sources.assets.at(aid, at) for aid in
        # IRIS EXPLAIN: sources.hostname_assets.get(event['agent'], [])] in candidates; later lines use this named result.
        candidates = [sources.assets.at(aid, at) for aid in sources.hostname_assets.get(event["agent"], [])]
        # IRIS EXPLAIN: Store the comprehension [a for a in candidates if a and a['hostname'] == event['agent']] in candidates;
        # IRIS EXPLAIN: later lines use this named result.
        candidates = [a for a in candidates if a and a["hostname"] == event["agent"]]
        # IRIS EXPLAIN: Return (candidates[0], 'exact_agent_hostname') when len(candidates) == 1; otherwise (None, 'agent
        # IRIS EXPLAIN: hostname unresolved or ambiguous at event time') to the caller; this ends the current function path.
        return (candidates[0], "exact_agent_hostname") if len(candidates) == 1 else (None, "agent hostname unresolved or ambiguous at event time")
    # IRIS EXPLAIN: Return (None, 'No trustworthy asset_id, destination IP or agent hostname; source IP is not a victim lookup')
    # IRIS EXPLAIN: to the caller; this ends the current function path.
    return None, "No trustworthy asset_id, destination IP or agent hostname; source IP is not a victim lookup"


# IRIS EXPLAIN: Function choose_context: Select one real prior-risk likelihood/impact pair using the declared
# IRIS EXPLAIN: representative-risk policy; this ML context is not a scenario-specific official risk match.
# IRIS EXPLAIN: Inputs: asset: the time-valid resolved inventory snapshot; risks: the time-valid registered risk snapshots;
# IRIS EXPLAIN: previous: the causally available earlier completed session count.
# IRIS EXPLAIN: Declared return type: dict | None; the return statements below show each actual result/fallback.
def choose_context(asset: dict, risks: list[dict], previous: int) -> dict | None:
    # IRIS EXPLAIN: Enter this branch only when not risks.
    if not risks:
        # IRIS EXPLAIN: Return None (no result/value) to the caller; this ends the current function path.
        return None
    # IRIS EXPLAIN: Store sorted(risks, key=lambda r: (-r['likelihood'] * r['impact'], r['risk_id']))[0] in representative;
    # IRIS EXPLAIN: later lines use this named result.
    representative = sorted(risks, key=lambda r: (-r["likelihood"]*r["impact"], r["risk_id"]))[0]
    # IRIS EXPLAIN: Return a mapping containing asset_type, asset_criticality, current_likelihood, impact, previous_similar_24h,
    # IRIS EXPLAIN: controls, active_exception_control_ids and additional fields to the caller; this ends the current function
    # IRIS EXPLAIN: path.
    return {"asset_type": asset["asset_type"], "asset_criticality": asset["criticality"],
            # IRIS EXPLAIN: Set/describe these existing record fields: current_likelihood: current working or pre-decision
            # IRIS EXPLAIN: likelihood, according to this record's context; impact: the same registered risk's impact; it must
            # IRIS EXPLAIN: not be independently maximized across risks.
            "current_likelihood": representative["likelihood"], "impact": representative["impact"],
            # IRIS EXPLAIN: Set/describe these existing record fields: previous_similar_24h: count of earlier completed similar
            # IRIS EXPLAIN: sessions available inside this batch; controls: control implementation context or separately
            # IRIS EXPLAIN: identified recommendations; labels remain offline-only targets.
            "previous_similar_24h": previous, "controls": representative["control_states"],
            # IRIS EXPLAIN: Set/describe these existing record fields: active_exception_control_ids: controls requiring
            # IRIS EXPLAIN: exception/compensating-control review before a response.
            "active_exception_control_ids": representative["active_exception_control_ids"],
            # IRIS EXPLAIN: Continue the current record with context_risk_id; each value comes from the expression shown on this
            # IRIS EXPLAIN: unchanged line.
            "context_risk_id": representative["risk_id"],
            # IRIS EXPLAIN: Continue the current record with context_risk_version_id; each value comes from the expression shown
            # IRIS EXPLAIN: on this unchanged line.
            "context_risk_version_id": representative["risk_version_id"],
            # IRIS EXPLAIN: Set/describe these existing record fields: risk_selection_policy: declared rule for choosing
            # IRIS EXPLAIN: representative pre-decision ML context.
            "risk_selection_policy": CONTEXT_POLICY}


# IRIS EXPLAIN: Function build_sessions: Group resolved events by observed activity and context version, split inactivity gaps,
# IRIS EXPLAIN: and compute only previously completed 24-hour history within the batch.
# IRIS EXPLAIN: Inputs: events: normalized observed events, not hidden truth labels; window_seconds: the allowed inactivity
# IRIS EXPLAIN: window; serving must match the trained aggregation schema.
# IRIS EXPLAIN: Declared return type: list[dict]; the return statements below show each actual result/fallback.
def build_sessions(events: list[dict], window_seconds=60) -> list[dict]:
    # IRIS EXPLAIN: Enter this branch only when window_seconds not in {30, 60, 120}.
    if window_seconds not in {30, 60, 120}:
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Session window must be 30, 60 or 120
        # IRIS EXPLAIN: seconds'); the caller's existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError("Session window must be 30, 60 or 120 seconds")
    # IRIS EXPLAIN: Store the result of defaultdict(list) in buckets; later lines use this named result.
    buckets = defaultdict(list)
    # IRIS EXPLAIN: Iterate events, binding each item to event; process only the existing observed/fixture collection.
    for event in events:
        # IRIS EXPLAIN: Enter this branch only when event['asset'] is None.
        if event["asset"] is None:
            # IRIS EXPLAIN: Skip the remainder of this iteration and move to the next item; do not fabricate an accepted result
            # IRIS EXPLAIN: for this skipped input.
            continue
        # IRIS EXPLAIN: Store (event['campaign_id'], event['run_id'], event['asset']['asset_id'], event['account'],
        # IRIS EXPLAIN: event['src'], event['family']) in key; later lines use this named result.
        key = (event["campaign_id"], event["run_id"], event["asset"]["asset_id"],
               # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
               # IRIS EXPLAIN: event["account"], event["src"], event["family"]).
               event["account"], event["src"], event["family"])
        # IRIS EXPLAIN: Call buckets[key].append(event): append one item to the working list.
        buckets[key].append(event)
    # IRIS EXPLAIN: Store [] in groups; later lines use this named result.
    groups = []
    # IRIS EXPLAIN: Iterate buckets.items(), binding each item to (key, members); process only the existing observed/fixture
    # IRIS EXPLAIN: collection.
    for key, members in buckets.items():
        # IRIS EXPLAIN: Call members.sort(key=lambda e: (e['ts'], e['event_id'])): sort the existing collection using the
        # IRIS EXPLAIN: declared stable key.
        members.sort(key=lambda e: (e["ts"], e["event_id"]))
        # IRIS EXPLAIN: Store ([], None) in (current, last_signature); later lines use this named result.
        current, last_signature = [], None
        # IRIS EXPLAIN: Iterate members, binding each item to event; process only the existing observed/fixture collection.
        for event in members:
            # IRIS EXPLAIN: Store (event['asset']['asset_version_id'], tuple((r['risk_version_id'] for r in event['risks']))) in
            # IRIS EXPLAIN: signature; later lines use this named result.
            signature = (event["asset"]["asset_version_id"], tuple(r["risk_version_id"] for r in event["risks"]))
            # IRIS EXPLAIN: Enter this branch only when current and ((event['ts'] - current[-1]['ts']).total_seconds() >
            # IRIS EXPLAIN: window_seconds or signature != last_signature).
            if current and ((event["ts"]-current[-1]["ts"]).total_seconds() > window_seconds or signature != last_signature):
                # IRIS EXPLAIN: Call groups.append(current): append one item to the working list.
                groups.append(current)
                # IRIS EXPLAIN: Store [] in current; later lines use this named result.
                current = []
            # IRIS EXPLAIN: Call current.append(event): append one item to the working list.
            current.append(event)
            # IRIS EXPLAIN: Store signature in last_signature; later lines use this named result.
            last_signature = signature
        # IRIS EXPLAIN: Enter this branch only when current.
        if current:
            # IRIS EXPLAIN: Call groups.append(current): append one item to the working list.
            groups.append(current)
    # IRIS EXPLAIN: Call groups.sort(key=lambda members: (members[0]['ts'], members[0]['event_id'])): sort the existing
    # IRIS EXPLAIN: collection using the declared stable key.
    groups.sort(key=lambda members: (members[0]["ts"], members[0]["event_id"]))
    # Only sessions completed strictly before this session starts are available.
    # IRIS EXPLAIN: Store (defaultdict(deque), [], []) in (recent, pending, sessions); later lines use this named result.
    recent, pending, sessions = defaultdict(deque), [], []
    # IRIS EXPLAIN: Iterate groups, binding each item to members; process only the existing observed/fixture collection.
    for members in groups:
        # IRIS EXPLAIN: Store (members[0], members[-1]) in (first, last); later lines use this named result.
        first, last = members[0], members[-1]
        # IRIS EXPLAIN: Store first['ts'] in start; later lines use this named result.
        start = first["ts"]
        # IRIS EXPLAIN: Repeat while pending and pending[0][0] < start; the block advances the read/window/history state.
        while pending and pending[0][0] < start:
            # IRIS EXPLAIN: Store the result of heapq.heappop(pending) in (ended, _, history_key); later lines use this named
            # IRIS EXPLAIN: result.
            ended, _, history_key = heapq.heappop(pending)
            # IRIS EXPLAIN: Call recent[history_key].append(ended): append one item to the working list.
            recent[history_key].append(ended)
        # IRIS EXPLAIN: Store the result of aggregate(members) in features; later lines use this named result.
        features = aggregate(members)
        # IRIS EXPLAIN: Store (first['asset']['asset_id'], features['event_family'], features['primary_protocol']) in
        # IRIS EXPLAIN: history_key; later lines use this named result.
        history_key = (first["asset"]["asset_id"], features["event_family"], features["primary_protocol"])
        # IRIS EXPLAIN: Store recent[history_key] in history; later lines use this named result.
        history = recent[history_key]
        # IRIS EXPLAIN: Repeat while history and history[0] < start - timedelta(hours=24); the block advances the
        # IRIS EXPLAIN: read/window/history state.
        while history and history[0] < start-timedelta(hours=24):
            # IRIS EXPLAIN: Call history.popleft(): remove the oldest history item.
            history.popleft()
        # IRIS EXPLAIN: Store [first['campaign_id'], first['run_id'], *[e['event_id'] for e in members], str(window_seconds)] in
        # IRIS EXPLAIN: sid_parts; later lines use this named result.
        sid_parts = [first["campaign_id"], first["run_id"], *[e["event_id"] for e in members], str(window_seconds)]
        # IRIS EXPLAIN: Store the computed value 'SES-' + hashlib.sha256('|'.join(sid_parts).encode()).hexdigest()[:20] in sid;
        # IRIS EXPLAIN: later lines use this named result.
        sid = "SES-" + hashlib.sha256("|".join(sid_parts).encode()).hexdigest()[:20]
        # IRIS EXPLAIN: Store the result of choose_context(first['asset'], first['risks'], len(history)) in context; later lines
        # IRIS EXPLAIN: use this named result.
        context = choose_context(first["asset"], first["risks"], len(history))
        # IRIS EXPLAIN: Call sessions.append({'session_id': sid, 'run_id': first['run_id'], 'campaign_id': first['campaign_id'],
        # IRIS EXPLAIN: 'asset_id': first['asset']['asset_id'], 'start_utc': star...: append one item to the working list.
        sessions.append({"session_id": sid, "run_id": first["run_id"], "campaign_id": first["campaign_id"],
                         # IRIS EXPLAIN: Set/describe these existing record fields: asset_id: exact target-asset identity; not
                         # IRIS EXPLAIN: an attacker source-IP guess.
                         "asset_id": first["asset"]["asset_id"], "start_utc": start.isoformat(),
                         # IRIS EXPLAIN: Continue the current record with end_utc, context_as_of_utc; each value comes from the
                         # IRIS EXPLAIN: expression shown on this unchanged line.
                         "end_utc": last["ts"].isoformat(), "context_as_of_utc": start.isoformat(),
                         # IRIS EXPLAIN: Set/describe these existing record fields: data_provenance: explicit
                         # IRIS EXPLAIN: synthetic/cyber_range/operational source identity.
                         "data_provenance": first["data_provenance"],
                         # IRIS EXPLAIN: Set/describe these existing record fields: aggregation_schema: the exact
                         # IRIS EXPLAIN: normalization/session-window contract used for training and inference.
                         "aggregation_schema": f"iris-three-source-session-v1-window{window_seconds}",
                         # IRIS EXPLAIN: Set/describe these existing record fields: sensor_healthy: explicit health evidence; a
                         # IRIS EXPLAIN: missing/false value must not be treated as benign.
                         "sensor_healthy": all(e["sensor_healthy"] for e in members),
                         # IRIS EXPLAIN: Continue the current record with features, context; each value comes from the
                         # IRIS EXPLAIN: expression shown on this unchanged line.
                         "features": features, "context": context,
                         # IRIS EXPLAIN: Set/describe these existing record fields: asset_snapshot: the exact inventory version
                         # IRIS EXPLAIN: valid and known at event time.
                         "asset_snapshot": public(first["asset"]),
                         # IRIS EXPLAIN: Set/describe these existing record fields: risk_snapshots: all time-valid registered
                         # IRIS EXPLAIN: risks nested on the session, not duplicated alert rows.
                         "risk_snapshots": [public(r) for r in first["risks"]],
                         # IRIS EXPLAIN: Continue the current record with context_status; each value comes from the expression
                         # IRIS EXPLAIN: shown on this unchanged line.
                         "context_status": "MATCHED" if context else "MISSING_RISK_CONTEXT",
                         # IRIS EXPLAIN: Set/describe these existing record fields: source_event_ids: stable source event
                         # IRIS EXPLAIN: identities supporting the session.
                         "source_event_ids": [e["event_id"] for e in members],
                         # IRIS EXPLAIN: Set/describe these existing record fields: evidence_refs: source-file/line references
                         # IRIS EXPLAIN: retained for traceability.
                         "evidence_refs": [e["raw_ref"] for e in members]})
        # IRIS EXPLAIN: Call heapq.heappush(pending, (last['ts'], sid, history_key)) using the existing explicit arguments.
        heapq.heappush(pending, (last["ts"], sid, history_key))
    # IRIS EXPLAIN: Return sessions to the caller; this ends the current function path.
    return sessions


# IRIS EXPLAIN: Function integrate: Validate/normalize/deduplicate SIEM records, exclude conflicting IDs, enrich with time-valid
# IRIS EXPLAIN: asset and nested risk context, and return unified events, sessions and quality counts.
# IRIS EXPLAIN: Inputs: asset_path: the asset inventory source path; risk_path: the risk register source path; alerts_path: the
# IRIS EXPLAIN: SIEM JSONL source path; window_seconds: the allowed inactivity window; serving must match the trained
# IRIS EXPLAIN: aggregation schema.
# IRIS EXPLAIN: Declared return type: tuple[list[dict], list[dict], dict]; the return statements below show each actual
# IRIS EXPLAIN: result/fallback.
def integrate(asset_path: Path, risk_path: Path, alerts_path: Path, *, window_seconds=60) -> tuple[list[dict], list[dict], dict]:
    # IRIS EXPLAIN: Store the result of time.perf_counter() in started; later lines use this named result.
    started = time.perf_counter()
    # IRIS EXPLAIN: Store the result of load_sources(asset_path, risk_path) in sources; later lines use this named result.
    sources = load_sources(asset_path, risk_path)
    # IRIS EXPLAIN: Store ({}, {}, set(), []) in (unique, hashes, conflicts, quarantine); later lines use this named result.
    unique, hashes, conflicts, quarantine = {}, {}, set(), []
    # IRIS EXPLAIN: Store (0, 0, 0) in (rows_in, duplicates, ignored); later lines use this named result.
    rows_in, duplicates, ignored = 0, 0, 0
    # IRIS EXPLAIN: Enter alerts_path.open(encoding='utf-8') as stream; its context manager supplies the existing
    # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
    with alerts_path.open(encoding="utf-8") as stream:
        # IRIS EXPLAIN: Iterate enumerate(stream, 1), binding each item to (line, content); process only the existing
        # IRIS EXPLAIN: observed/fixture collection.
        for line, content in enumerate(stream, 1):
            # IRIS EXPLAIN: Enter this branch only when not content.strip().
            if not content.strip():
                # IRIS EXPLAIN: Skip the remainder of this iteration and move to the next item; do not fabricate an accepted
                # IRIS EXPLAIN: result for this skipped input.
                continue
            # IRIS EXPLAIN: Update rows_in using the existing Add operation and 1.
            rows_in += 1
            # IRIS EXPLAIN: Attempt this operation inside the following explicit error boundary; the existing except/finally
            # IRIS EXPLAIN: blocks decide fallback and cleanup.
            try:
                # IRIS EXPLAIN: Store the result of normalize_alert(json.loads(content), line, alerts_path.name) in event; later
                # IRIS EXPLAIN: lines use this named result.
                event = normalize_alert(json.loads(content), line, alerts_path.name)
                # IRIS EXPLAIN: Enter this branch only when event is None.
                if event is None:
                    # IRIS EXPLAIN: Update ignored using the existing Add operation and 1.
                    ignored += 1
                    # IRIS EXPLAIN: Skip the remainder of this iteration and move to the next item; do not fabricate an accepted
                    # IRIS EXPLAIN: result for this skipped input.
                    continue
                # IRIS EXPLAIN: Enter this branch only when event['data_provenance'] != sources.provenance.
                if event["data_provenance"] != sources.provenance:
                    # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('SIEM provenance differs
                    # IRIS EXPLAIN: from inventory/risk provenance'); the caller's existing boundary determines rollback or the
                    # IRIS EXPLAIN: HTTP diagnostic.
                    raise ValueError("SIEM provenance differs from inventory/risk provenance")
                # IRIS EXPLAIN: Store (event['event_id'], fingerprint(event)) in (eid, h); later lines use this named result.
                eid, h = event["event_id"], fingerprint(event)
                # IRIS EXPLAIN: Enter this branch only when eid in hashes.
                if eid in hashes:
                    # IRIS EXPLAIN: Enter this branch only when hashes[eid] != h.
                    if hashes[eid] != h:
                        # IRIS EXPLAIN: Call conflicts.add(eid): record membership in the set.
                        conflicts.add(eid)
                        # IRIS EXPLAIN: Call quarantine.append({'line': line, 'event_id': eid, 'reason': 'Conflicting duplicate
                        # IRIS EXPLAIN: event ID; all versions excluded'}): append one item to the working list.
                        quarantine.append({"line": line, "event_id": eid, "reason": "Conflicting duplicate event ID; all versions excluded"})
                    # IRIS EXPLAIN: Handle the alternative to the preceding condition/loop exactly as originally defined.
                    else:
                        # IRIS EXPLAIN: Update duplicates using the existing Add operation and 1.
                        duplicates += 1
                    # IRIS EXPLAIN: Skip the remainder of this iteration and move to the next item; do not fabricate an accepted
                    # IRIS EXPLAIN: result for this skipped input.
                    continue
                # IRIS EXPLAIN: Store (h, event) in (hashes[eid], unique[eid]); later lines use this named result.
                hashes[eid], unique[eid] = h, event
            # IRIS EXPLAIN: Catch (ValueError, TypeError, KeyError) as exc; execute the existing error/fallback path rather than
            # IRIS EXPLAIN: silently treating it as success.
            except (ValueError, TypeError, KeyError) as exc:
                # IRIS EXPLAIN: Call quarantine.append({'line': line, 'reason': str(exc)}): append one item to the working list.
                quarantine.append({"line": line, "reason": str(exc)})
    # IRIS EXPLAIN: Iterate conflicts, binding each item to eid; process only the existing observed/fixture collection.
    for eid in conflicts:
        # IRIS EXPLAIN: Call unique.pop(eid, None): remove and return the selected item.
        unique.pop(eid, None)
    # IRIS EXPLAIN: Store ([], []) in (enriched, unified); later lines use this named result.
    enriched, unified = [], []
    # IRIS EXPLAIN: Store (0, 0) in (unresolved, no_risk); later lines use this named result.
    unresolved, no_risk = 0, 0
    # IRIS EXPLAIN: Iterate sorted(unique.values(), key=lambda e: (e['ts'], e['event_id'])), binding each item to event; process
    # IRIS EXPLAIN: only the existing observed/fixture collection.
    for event in sorted(unique.values(), key=lambda e: (e["ts"], e["event_id"])):
        # IRIS EXPLAIN: Store the result of resolve_asset(event, sources) in (asset, method); later lines use this named result.
        asset, method = resolve_asset(event, sources)
        # IRIS EXPLAIN: Store [] in risks; later lines use this named result.
        risks = []
        # IRIS EXPLAIN: Enter this branch only when asset.
        if asset:
            # IRIS EXPLAIN: Store the comprehension [sources.risks.at(rid, event['ts']) for rid in
            # IRIS EXPLAIN: sorted(sources.asset_risks.get(asset['asset_id'], []))] in risks; later lines use this named result.
            risks = [sources.risks.at(rid, event["ts"]) for rid in sorted(sources.asset_risks.get(asset["asset_id"], []))]
            # IRIS EXPLAIN: Store the comprehension [r for r in risks if r is not None] in risks; later lines use this named
            # IRIS EXPLAIN: result.
            risks = [r for r in risks if r is not None]
            # IRIS EXPLAIN: Update no_risk using the existing Add operation and not risks.
            no_risk += not risks
        # IRIS EXPLAIN: Handle the alternative to the preceding condition/loop exactly as originally defined.
        else:
            # IRIS EXPLAIN: Update unresolved using the existing Add operation and 1.
            unresolved += 1
        # IRIS EXPLAIN: Store (asset, risks) in (event['asset'], event['risks']); later lines use this named result.
        event["asset"], event["risks"] = asset, risks
        # IRIS EXPLAIN: Call enriched.append(event): append one item to the working list.
        enriched.append(event)
        # IRIS EXPLAIN: Call unified.append({'event_id': event['event_id'], 'timestamp': event['ts'].isoformat(), 'campaign_id':
        # IRIS EXPLAIN: event['campaign_id'], 'run_id': event['run_id'], 'data_pr...: append one item to the working list.
        unified.append({"event_id": event["event_id"], "timestamp": event["ts"].isoformat(),
                        # IRIS EXPLAIN: Set/describe these existing record fields: campaign_id: group provenance retained for
                        # IRIS EXPLAIN: split/session identity; not a telemetry predictor; run_id: run/batch provenance retained
                        # IRIS EXPLAIN: for traceability; not a hidden attack-label feature.
                        "campaign_id": event["campaign_id"], "run_id": event["run_id"],
                        # IRIS EXPLAIN: Set/describe these existing record fields: data_provenance: explicit
                        # IRIS EXPLAIN: synthetic/cyber_range/operational source identity.
                        "data_provenance": sources.provenance,
                        # IRIS EXPLAIN: Continue the current record with asset_match_status; each value comes from the
                        # IRIS EXPLAIN: expression shown on this unchanged line.
                        "asset_match_status": "MATCHED" if asset else "UNRESOLVED",
                        # IRIS EXPLAIN: Continue the current record with asset_match_method, asset; each value comes from the
                        # IRIS EXPLAIN: expression shown on this unchanged line.
                        "asset_match_method": method, "asset": public(asset),
                        # IRIS EXPLAIN: Continue the current record with risk_match_status; each value comes from the expression
                        # IRIS EXPLAIN: shown on this unchanged line.
                        "risk_match_status": "MATCHED" if risks else "MISSING",
                        # IRIS EXPLAIN: Continue the current record with risks; each value comes from the expression shown on
                        # IRIS EXPLAIN: this unchanged line.
                        "risks": [public(r) for r in risks],
                        # IRIS EXPLAIN: Continue the current record with alert; each value comes from the expression shown on
                        # IRIS EXPLAIN: this unchanged line.
                        "alert": {k: v for k, v in event.items()
                                  # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these
                                  # IRIS EXPLAIN: existing arguments/items: if k not in {"ts", "asset", "risks",
                                  # IRIS EXPLAIN: "semantic_key"}}}).
                                  if k not in {"ts", "asset", "risks", "semantic_key"}}})
    # IRIS EXPLAIN: Store the result of build_sessions(enriched, window_seconds) in sessions; later lines use this named result.
    sessions = build_sessions(enriched, window_seconds)
    # IRIS EXPLAIN: Store a mapping containing data_provenance, input_alert_rows, deduplicated_alerts,
    # IRIS EXPLAIN: exact_duplicate_rows_removed, conflicting_event_ids_excluded, ignored_non_alert_sensor_records, quarantine
    # IRIS EXPLAIN: and additional fields in report; later lines use this named result.
    report = {
        # IRIS EXPLAIN: Set/describe these existing record fields: data_provenance: explicit synthetic/cyber_range/operational
        # IRIS EXPLAIN: source identity.
        "data_provenance": sources.provenance, "input_alert_rows": rows_in,
        # IRIS EXPLAIN: Continue the current record with deduplicated_alerts, exact_duplicate_rows_removed; each value comes
        # IRIS EXPLAIN: from the expression shown on this unchanged line.
        "deduplicated_alerts": len(unique), "exact_duplicate_rows_removed": duplicates,
        # IRIS EXPLAIN: Continue the current record with conflicting_event_ids_excluded, ignored_non_alert_sensor_records; each
        # IRIS EXPLAIN: value comes from the expression shown on this unchanged line.
        "conflicting_event_ids_excluded": sorted(conflicts), "ignored_non_alert_sensor_records": ignored,
        # IRIS EXPLAIN: Continue the current record with quarantine, unresolved_asset_events; each value comes from the
        # IRIS EXPLAIN: expression shown on this unchanged line.
        "quarantine": quarantine, "unresolved_asset_events": unresolved,
        # IRIS EXPLAIN: Continue the current record with matched_events_without_risk_context; each value comes from the
        # IRIS EXPLAIN: expression shown on this unchanged line.
        "matched_events_without_risk_context": int(no_risk),
        # IRIS EXPLAIN: Continue the current record with unified_event_rows, model_sessions; each value comes from the
        # IRIS EXPLAIN: expression shown on this unchanged line.
        "unified_event_rows": len(unified), "model_sessions": len(sessions),
        # IRIS EXPLAIN: Set/describe these existing record fields: risk_snapshots: all time-valid registered risks nested on the
        # IRIS EXPLAIN: session, not duplicated alert rows.
        "asset_snapshots": sources.asset_count, "risk_snapshots": sources.risk_count,
        # IRIS EXPLAIN: Continue the current record with join_does_not_multiply_alerts; each value comes from the expression
        # IRIS EXPLAIN: shown on this unchanged line.
        "join_does_not_multiply_alerts": len(unified) == len(unique),
        # IRIS EXPLAIN: Set/describe these existing record fields: risk_selection_policy: declared rule for choosing
        # IRIS EXPLAIN: representative pre-decision ML context.
        "risk_selection_policy": CONTEXT_POLICY, "session_window_seconds": window_seconds,
        # IRIS EXPLAIN: Continue the current record with source_sha256, asset_inventory, risk_register, siem_alerts; each value
        # IRIS EXPLAIN: comes from the expression shown on this unchanged line.
        "source_sha256": {"asset_inventory": digest(asset_path), "risk_register": digest(risk_path), "siem_alerts": digest(alerts_path)},
        # IRIS EXPLAIN: Continue the current record with elapsed_seconds; each value comes from the expression shown on this
        # IRIS EXPLAIN: unchanged line.
        "elapsed_seconds": round(time.perf_counter()-started, 6),
        # IRIS EXPLAIN: Set/describe these existing record fields: training_labels_read: runtime provenance flag proving labels
        # IRIS EXPLAIN: are not operational inputs.
        "training_labels_read": False,
        # IRIS EXPLAIN: Continue the current record with memory_model; each value comes from the expression shown on this
        # IRIS EXPLAIN: unchanged line.
        "memory_model": "Indexed snapshots and deduplicated alerts retained in memory; batch O(E log E) sorting, no cartesian event-risk expansion. Not a streaming production connector.",
    # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain unchanged.
    }
    # IRIS EXPLAIN: Return (unified, sessions, report) to the caller; this ends the current function path.
    return unified, sessions, report


# IRIS EXPLAIN: Function prepare_three: Write the shared three-input unified evidence, model sessions and integration report to
# IRIS EXPLAIN: a fresh directory; no training label input is read.
# IRIS EXPLAIN: Inputs: asset_path: the asset inventory source path; risk_path: the risk register source path; alerts_path: the
# IRIS EXPLAIN: SIEM JSONL source path; out: the destination path; existing safety checks govern overwrite behavior;
# IRIS EXPLAIN: window_seconds: the allowed inactivity window; serving must match the trained aggregation schema.
# IRIS EXPLAIN: Declared return type: dict; the return statements below show each actual result/fallback.
def prepare_three(asset_path: Path, risk_path: Path, alerts_path: Path, out: Path, *, window_seconds=60) -> dict:
    # IRIS EXPLAIN: Enter this branch only when out.exists() and any(out.iterdir()).
    if out.exists() and any(out.iterdir()):
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Preparation directory is not empty;
        # IRIS EXPLAIN: choose a new output to preserve prior evidence'); the caller's existing boundary determines rollback or
        # IRIS EXPLAIN: the HTTP diagnostic.
        raise ValueError("Preparation directory is not empty; choose a new output to preserve prior evidence")
    # IRIS EXPLAIN: Store the result of integrate(asset_path, risk_path, alerts_path, window_seconds=window_seconds) in
    # IRIS EXPLAIN: (unified, sessions, report); later lines use this named result.
    unified, sessions, report = integrate(asset_path, risk_path, alerts_path, window_seconds=window_seconds)
    # IRIS EXPLAIN: Call out.mkdir(parents=True, exist_ok=True): create the required directory if permitted by the existing
    # IRIS EXPLAIN: flags.
    out.mkdir(parents=True, exist_ok=True)
    # IRIS EXPLAIN: Call write_jsonl(out / 'unified_events.jsonl', unified) using the existing explicit arguments.
    write_jsonl(out / "unified_events.jsonl", unified)
    # IRIS EXPLAIN: Call write_jsonl(out / 'model_sessions.jsonl', sessions) using the existing explicit arguments.
    write_jsonl(out / "model_sessions.jsonl", sessions)
    # IRIS EXPLAIN: Call write_json(out / 'integration_report.json', report) using the existing explicit arguments.
    write_json(out / "integration_report.json", report)
    # IRIS EXPLAIN: Return report to the caller; this ends the current function path.
    return report
