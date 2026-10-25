# IRIS EXPLAIN: File purpose: Shared allowlisted feature schema, JSON helpers, validation, and transparent rule baseline;
# IRIS EXPLAIN: training and inference must agree on this contract.
# IRIS EXPLAIN: Existing documentation/literal text below is kept exactly as written; the explanation is outside the string so
# IRIS EXPLAIN: its value does not change.
"""One explicit feature contract shared by training, adapters and inference."""
# IRIS EXPLAIN: Keep type annotations unevaluated at definition time; this does not add a model feature or change runtime
# IRIS EXPLAIN: settings.
from __future__ import annotations

# IRIS EXPLAIN: Import hashlib to compute deterministic byte identities and content fingerprints.
import hashlib
# IRIS EXPLAIN: Import json to encode and decode structured finite JSON payloads.
import json
# IRIS EXPLAIN: Import math to check finite values and numeric consistency.
import math
# IRIS EXPLAIN: Import Path from pathlib to resolve server-owned paths without trusting uploaded filenames.
from pathlib import Path
# IRIS EXPLAIN: Import Any from typing to declare expected interfaces/types for readers and type-checking tools.
from typing import Any

# IRIS EXPLAIN: Import pandas as pd to assemble allowlisted feature tables and catalogue records.
import pandas as pd

# IRIS EXPLAIN: Store ('benign', 'credential_access', 'reconnaissance') in CLASSES; later lines use this named result.
CLASSES = ("benign", "credential_access", "reconnaissance")
# IRIS EXPLAIN: Store ['event_family', 'primary_protocol'] in CATEGORICAL; later lines use this named result.
CATEGORICAL = ["event_family", "primary_protocol"]
# IRIS EXPLAIN: Store ['event_count', 'duration_seconds', 'max_rule_level', 'mean_rule_level', 'distinct_rules',
# IRIS EXPLAIN: 'distinct_sources', 'distinct_accounts', 'failed_count',... in NUMERIC; later lines use this named result.
NUMERIC = [
    # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
    # IRIS EXPLAIN: "event_count", "duration_seconds", "max_rule_level", "mean_rule_level",.
    "event_count", "duration_seconds", "max_rule_level", "mean_rule_level",
    # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
    # IRIS EXPLAIN: "distinct_rules", "distinct_sources", "distinct_accounts", "failed_count",.
    "distinct_rules", "distinct_sources", "distinct_accounts", "failed_count",
    # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
    # IRIS EXPLAIN: "success_count", "failure_ratio", "success_after_failures",.
    "success_count", "failure_ratio", "success_after_failures",
    # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
    # IRIS EXPLAIN: "max_events_in_10s", "external_source_fraction", "event_rate_per_minute",.
    "max_events_in_10s", "external_source_fraction", "event_rate_per_minute",
# IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain unchanged.
]
# IRIS EXPLAIN: Store the computed value CATEGORICAL + NUMERIC in FEATURES; later lines use this named result.
FEATURES = CATEGORICAL + NUMERIC
# IRIS EXPLAIN: Store ['asset_type', 'predicted_scenario'] in CONTEXT_CATEGORICAL; later lines use this named result.
CONTEXT_CATEGORICAL = ["asset_type", "predicted_scenario"]
# IRIS EXPLAIN: Store ['asset_criticality', 'current_likelihood', 'impact', 'previous_similar_24h'] in CONTEXT_NUMERIC; later
# IRIS EXPLAIN: lines use this named result.
CONTEXT_NUMERIC = ["asset_criticality", "current_likelihood", "impact", "previous_similar_24h"]
# IRIS EXPLAIN: Store the computed value FEATURES + CONTEXT_CATEGORICAL + CONTEXT_NUMERIC in CONTROL_FEATURES; later lines use
# IRIS EXPLAIN: this named result.
CONTROL_FEATURES = FEATURES + CONTEXT_CATEGORICAL + CONTEXT_NUMERIC
# IRIS EXPLAIN: Store 'iris-telemetry-session-v1' in FEATURE_SCHEMA; later lines use this named result.
FEATURE_SCHEMA = "iris-telemetry-session-v1"
# IRIS EXPLAIN: Store {'event_count', 'distinct_rules', 'distinct_sources', 'distinct_accounts', 'failed_count',
# IRIS EXPLAIN: 'success_count', 'max_events_in_10s'} in COUNT_FIELDS; later lines use this named result.
COUNT_FIELDS = {
    # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
    # IRIS EXPLAIN: "event_count", "distinct_rules", "distinct_sources", "distinct_accounts",.
    "event_count", "distinct_rules", "distinct_sources", "distinct_accounts",
    # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
    # IRIS EXPLAIN: "failed_count", "success_count", "max_events_in_10s",.
    "failed_count", "success_count", "max_events_in_10s",
# IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain unchanged.
}


# IRIS EXPLAIN: Function utc_now: Return the current timezone-aware UTC timestamp as ISO text for evidence and audit records.
# IRIS EXPLAIN: Declared return type: str; the return statements below show each actual result/fallback.
def utc_now() -> str:
    # IRIS EXPLAIN: Import datetime, timezone from datetime to represent timezone-aware timestamps and elapsed-time windows.
    from datetime import datetime, timezone
    # IRIS EXPLAIN: Return the result of datetime.now(timezone.utc).isoformat() to the caller; this ends the current function
    # IRIS EXPLAIN: path.
    return datetime.now(timezone.utc).isoformat()


# IRIS EXPLAIN: Function digest: Stream a file in chunks into SHA-256 and return its hexadecimal content digest; this checks
# IRIS EXPLAIN: bytes, not the trustworthiness of a publisher.
# IRIS EXPLAIN: Inputs: path: the explicit local file path used by this helper.
# IRIS EXPLAIN: Declared return type: str; the return statements below show each actual result/fallback.
def digest(path: Path) -> str:
    # IRIS EXPLAIN: Store the result of hashlib.sha256() in h; later lines use this named result.
    h = hashlib.sha256()
    # IRIS EXPLAIN: Enter path.open('rb') as stream; its context manager supplies the existing
    # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
    with path.open("rb") as stream:
        # IRIS EXPLAIN: Iterate iter(lambda: stream.read(1024 * 1024), b''), binding each item to block; process only the
        # IRIS EXPLAIN: existing observed/fixture collection.
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            # IRIS EXPLAIN: Call h.update(block): merge the supplied fields into this existing mapping.
            h.update(block)
    # IRIS EXPLAIN: Return the result of h.hexdigest() (return the hexadecimal content digest) to the caller; this ends the
    # IRIS EXPLAIN: current function path.
    return h.hexdigest()


# IRIS EXPLAIN: Function write_json: Serialize finite JSON to a temporary sibling file, then replace the destination so readers
# IRIS EXPLAIN: do not see a partly written document.
# IRIS EXPLAIN: Inputs: path: the explicit local file path used by this helper; value: the supplied value to
# IRIS EXPLAIN: validate/normalize/serialize.
# IRIS EXPLAIN: Declared return type: None; the return statements below show each actual result/fallback.
def write_json(path: Path, value: Any) -> None:
    # IRIS EXPLAIN: Call path.parent.mkdir(parents=True, exist_ok=True): create the required directory if permitted by the
    # IRIS EXPLAIN: existing flags.
    path.parent.mkdir(parents=True, exist_ok=True)
    # IRIS EXPLAIN: Store the result of path.with_suffix(path.suffix + '.tmp') (derive the sibling filename with the specified
    # IRIS EXPLAIN: suffix) in temporary; later lines use this named result.
    temporary = path.with_suffix(path.suffix + ".tmp")
    # IRIS EXPLAIN: Call temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + '\n', encoding='utf-8'): write the
    # IRIS EXPLAIN: existing text payload.
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    # IRIS EXPLAIN: Call temporary.replace(path): replace the selected destination.
    temporary.replace(path)


# IRIS EXPLAIN: Function read_jsonl: Read one JSON object per nonblank line; reject malformed JSON or non-object rows with a
# IRIS EXPLAIN: filename/line reference.
# IRIS EXPLAIN: Inputs: path: the explicit local file path used by this helper.
# IRIS EXPLAIN: Declared return type: list[dict]; the return statements below show each actual result/fallback.
def read_jsonl(path: Path) -> list[dict]:
    # IRIS EXPLAIN: Store [] in rows; later lines use this named result.
    rows = []
    # IRIS EXPLAIN: Enter path.open(encoding='utf-8') as stream; its context manager supplies the existing
    # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
    with path.open(encoding="utf-8") as stream:
        # IRIS EXPLAIN: Iterate enumerate(stream, 1), binding each item to (number, line); process only the existing
        # IRIS EXPLAIN: observed/fixture collection.
        for number, line in enumerate(stream, 1):
            # IRIS EXPLAIN: Enter this branch only when not line.strip().
            if not line.strip():
                # IRIS EXPLAIN: Skip the remainder of this iteration and move to the next item; do not fabricate an accepted
                # IRIS EXPLAIN: result for this skipped input.
                continue
            # IRIS EXPLAIN: Attempt this operation inside the following explicit error boundary; the existing except/finally
            # IRIS EXPLAIN: blocks decide fallback and cleanup.
            try:
                # IRIS EXPLAIN: Store the result of json.loads(line) (decode the existing JSON text) in row; later lines use
                # IRIS EXPLAIN: this named result.
                row = json.loads(line)
            # IRIS EXPLAIN: Catch json.JSONDecodeError as exc; execute the existing error/fallback path rather than silently
            # IRIS EXPLAIN: treating it as success.
            except json.JSONDecodeError as exc:
                # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError(f'{path.name}:{number}: invalid
                # IRIS EXPLAIN: JSON'); the caller's existing boundary determines rollback or the HTTP diagnostic.
                raise ValueError(f"{path.name}:{number}: invalid JSON") from exc
            # IRIS EXPLAIN: Enter this branch only when not isinstance(row, dict).
            if not isinstance(row, dict):
                # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError(f'{path.name}:{number}: expected
                # IRIS EXPLAIN: an object'); the caller's existing boundary determines rollback or the HTTP diagnostic.
                raise ValueError(f"{path.name}:{number}: expected an object")
            # IRIS EXPLAIN: Call rows.append(row): append one item to the working list.
            rows.append(row)
    # IRIS EXPLAIN: Return rows to the caller; this ends the current function path.
    return rows


# IRIS EXPLAIN: Function write_jsonl: Write one finite JSON object per line, creating the parent directory as needed.
# IRIS EXPLAIN: Inputs: path: the explicit local file path used by this helper; rows: the existing records/feature rows passed
# IRIS EXPLAIN: by the caller.
# IRIS EXPLAIN: Declared return type: None; the return statements below show each actual result/fallback.
def write_jsonl(path: Path, rows: list[dict]) -> None:
    # IRIS EXPLAIN: Call path.parent.mkdir(parents=True, exist_ok=True): create the required directory if permitted by the
    # IRIS EXPLAIN: existing flags.
    path.parent.mkdir(parents=True, exist_ok=True)
    # IRIS EXPLAIN: Enter path.open('w', encoding='utf-8') as stream; its context manager supplies the existing
    # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
    with path.open("w", encoding="utf-8") as stream:
        # IRIS EXPLAIN: Iterate rows, binding each item to row; process only the existing observed/fixture collection.
        for row in rows:
            # IRIS EXPLAIN: Call stream.write(json.dumps(row, allow_nan=False) + '\n'): write the already prepared payload.
            stream.write(json.dumps(row, allow_nan=False) + "\n")


# IRIS EXPLAIN: Function finite: Convert a numeric value to a finite float inside the supplied inclusive bounds; reject invalid,
# IRIS EXPLAIN: NaN, infinite, or out-of-range values.
# IRIS EXPLAIN: Inputs: value: the supplied value to validate/normalize/serialize; name: the field, record or test name used for
# IRIS EXPLAIN: the stated lookup/diagnostic; low: the inclusive permitted numeric minimum; high: the inclusive permitted
# IRIS EXPLAIN: numeric maximum.
# IRIS EXPLAIN: Declared return type: float; the return statements below show each actual result/fallback.
def finite(value: Any, name: str, low: float = 0, high: float = 1e12) -> float:
    # IRIS EXPLAIN: Enter this branch only when isinstance(value, bool).
    if isinstance(value, bool):
        # IRIS EXPLAIN: Store int(value) in value; later lines use this named result.
        value = int(value)
    # IRIS EXPLAIN: Attempt this operation inside the following explicit error boundary; the existing except/finally blocks
    # IRIS EXPLAIN: decide fallback and cleanup.
    try:
        # IRIS EXPLAIN: Store float(value) in result; later lines use this named result.
        result = float(value)
    # IRIS EXPLAIN: Catch (TypeError, ValueError) as exc; execute the existing error/fallback path rather than silently treating
    # IRIS EXPLAIN: it as success.
    except (TypeError, ValueError) as exc:
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError(f'{name} must be numeric'); the caller's
        # IRIS EXPLAIN: existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError(f"{name} must be numeric") from exc
    # IRIS EXPLAIN: Enter this branch only when not math.isfinite(result) or not low <= result <= high.
    if not math.isfinite(result) or not low <= result <= high:
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError(f'{name} must be finite and in [{low},
        # IRIS EXPLAIN: {high}]'); the caller's existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError(f"{name} must be finite and in [{low}, {high}]")
    # IRIS EXPLAIN: Return result to the caller; this ends the current function path.
    return result


# IRIS EXPLAIN: Function validate_features: Enforce the exact telemetry feature allowlist and internal count/rate consistency;
# IRIS EXPLAIN: reject leaked labels, missing fields, and fabricated inconsistent features.
# IRIS EXPLAIN: Inputs: row: the existing input record to inspect without inventing missing evidence.
# IRIS EXPLAIN: Declared return type: dict; the return statements below show each actual result/fallback.
def validate_features(row: dict) -> dict:
    # IRIS EXPLAIN: Enter this branch only when not isinstance(row, dict) or set(row) != set(FEATURES).
    if not isinstance(row, dict) or set(row) != set(FEATURES):
        # IRIS EXPLAIN: Store the computed value set(row) - set(FEATURES) when isinstance(row, dict); otherwise set() in extra;
        # IRIS EXPLAIN: later lines use this named result.
        extra = set(row) - set(FEATURES) if isinstance(row, dict) else set()
        # IRIS EXPLAIN: Store the computed value set(FEATURES) - set(row) when isinstance(row, dict); otherwise set(FEATURES) in
        # IRIS EXPLAIN: missing; later lines use this named result.
        missing = set(FEATURES) - set(row) if isinstance(row, dict) else set(FEATURES)
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError(f'Feature allowlist violation;
        # IRIS EXPLAIN: missing={sorted(missing)}, extra={sorted(extra)}'); the caller's existing boundary determines rollback
        # IRIS EXPLAIN: or the HTTP diagnostic.
        raise ValueError(f"Feature allowlist violation; missing={sorted(missing)}, extra={sorted(extra)}")
    # IRIS EXPLAIN: Store a mapping containing  in out; later lines use this named result.
    out = {}
    # IRIS EXPLAIN: Iterate CATEGORICAL, binding each item to key; process only the existing observed/fixture collection.
    for key in CATEGORICAL:
        # IRIS EXPLAIN: Enter this branch only when not isinstance(row[key], str) or not row[key].strip().
        if not isinstance(row[key], str) or not row[key].strip():
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError(f'{key} must be nonempty text'); the
            # IRIS EXPLAIN: caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError(f"{key} must be nonempty text")
        # IRIS EXPLAIN: Store the result of row[key].strip().casefold() (normalize text case for matching) when key ==
        # IRIS EXPLAIN: 'event_family'; otherwise the result of row[key].strip().upper() (normalize protocol/text to uppercase)
        # IRIS EXPLAIN: in out[key]; later lines use this named result.
        out[key] = row[key].strip().casefold() if key == "event_family" else row[key].strip().upper()
    # IRIS EXPLAIN: Iterate NUMERIC, binding each item to key; process only the existing observed/fixture collection.
    for key in NUMERIC:
        # IRIS EXPLAIN: Store 1 when key in {'failure_ratio', 'external_source_fraction', 'success_after_failures'}; otherwise
        # IRIS EXPLAIN: 16 when key in {'max_rule_level', 'mean_rule_level'}; otherwise 1000000000000.0 in high; later lines use
        # IRIS EXPLAIN: this named result.
        high = 1 if key in {"failure_ratio", "external_source_fraction", "success_after_failures"} else 16 if key in {"max_rule_level", "mean_rule_level"} else 1e12
        # IRIS EXPLAIN: Store the result of finite(row[key], key, 0, high) in out[key]; later lines use this named result.
        out[key] = finite(row[key], key, 0, high)
        # IRIS EXPLAIN: Enter this branch only when key in COUNT_FIELDS | {'success_after_failures'} and out[key] !=
        # IRIS EXPLAIN: int(out[key]).
        if key in COUNT_FIELDS | {"success_after_failures"} and out[key] != int(out[key]):
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError(f'{key} must be an integer'); the
            # IRIS EXPLAIN: caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError(f"{key} must be an integer")
    # IRIS EXPLAIN: Store out['event_count'] in n; later lines use this named result.
    n = out["event_count"]
    # IRIS EXPLAIN: Enter this branch only when n < 1 or out['max_events_in_10s'] < 1.
    if n < 1 or out["max_events_in_10s"] < 1:
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('A session must contain at least one
        # IRIS EXPLAIN: observed event'); the caller's existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError("A session must contain at least one observed event")
    # IRIS EXPLAIN: Enter this branch only when out['failed_count'] + out['success_count'] > n.
    if out["failed_count"] + out["success_count"] > n:
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Authentication outcome counts exceed
        # IRIS EXPLAIN: event_count'); the caller's existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError("Authentication outcome counts exceed event_count")
    # IRIS EXPLAIN: Enter this branch only when any((out[key] > n for key in COUNT_FIELDS - {'event_count'})).
    if any(out[key] > n for key in COUNT_FIELDS - {"event_count"}):
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('A session count exceeds event_count');
        # IRIS EXPLAIN: the caller's existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError("A session count exceeds event_count")
    # IRIS EXPLAIN: Enter this branch only when out['mean_rule_level'] > out['max_rule_level'].
    if out["mean_rule_level"] > out["max_rule_level"]:
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Mean severity exceeds max severity');
        # IRIS EXPLAIN: the caller's existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError("Mean severity exceeds max severity")
    # IRIS EXPLAIN: Store the computed value out['failed_count'] + out['success_count'] in known; later lines use this named
    # IRIS EXPLAIN: result.
    known = out["failed_count"] + out["success_count"]
    # IRIS EXPLAIN: Store the computed value out['failed_count'] / known when known; otherwise 0.0 in expected_ratio; later
    # IRIS EXPLAIN: lines use this named result.
    expected_ratio = out["failed_count"] / known if known else 0.0
    # IRIS EXPLAIN: Enter this branch only when abs(out['failure_ratio'] - expected_ratio) > 1e-06.
    if abs(out["failure_ratio"] - expected_ratio) > 1e-6:
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('failure_ratio is inconsistent with
        # IRIS EXPLAIN: outcome counts'); the caller's existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError("failure_ratio is inconsistent with outcome counts")
    # IRIS EXPLAIN: Store the computed value n * 60 / max(out['duration_seconds'], 1) in expected_rate; later lines use this
    # IRIS EXPLAIN: named result.
    expected_rate = n * 60 / max(out["duration_seconds"], 1)
    # IRIS EXPLAIN: Enter this branch only when not math.isclose(out['event_rate_per_minute'], expected_rate, rel_tol=1e-06,
    # IRIS EXPLAIN: abs_tol=1e-06).
    if not math.isclose(out["event_rate_per_minute"], expected_rate, rel_tol=1e-6, abs_tol=1e-6):
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('event_rate_per_minute is inconsistent
        # IRIS EXPLAIN: with count/duration'); the caller's existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError("event_rate_per_minute is inconsistent with count/duration")
    # IRIS EXPLAIN: Return out to the caller; this ends the current function path.
    return out


# IRIS EXPLAIN: Function validate_context: Validate the pre-decision asset/risk context needed by Model 2, including integer
# IRIS EXPLAIN: criticality, likelihood, impact, and history counts.
# IRIS EXPLAIN: Inputs: context: existing pre-decision business/control context.
# IRIS EXPLAIN: Declared return type: dict; the return statements below show each actual result/fallback.
def validate_context(context: dict) -> dict:
    # IRIS EXPLAIN: Enter this branch only when not isinstance(context, dict).
    if not isinstance(context, dict):
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Context must be an object'); the
        # IRIS EXPLAIN: caller's existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError("Context must be an object")
    # IRIS EXPLAIN: Store a mapping containing asset_type in out; later lines use this named result.
    out = {"asset_type": str(context.get("asset_type", "unknown")).strip() or "unknown"}
    # IRIS EXPLAIN: Iterate CONTEXT_NUMERIC, binding each item to key; process only the existing observed/fixture collection.
    for key in CONTEXT_NUMERIC:
        # IRIS EXPLAIN: Enter this branch only when key not in context.
        if key not in context:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError(f'Missing pre-decision GRC context:
            # IRIS EXPLAIN: {key}'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError(f"Missing pre-decision GRC context: {key}")
        # IRIS EXPLAIN: Store the result of finite(context[key], key, 0 if key == 'previous_similar_24h' else 1, 1000000000.0 if
        # IRIS EXPLAIN: key == 'previous_simil... in out[key]; later lines use this named result.
        out[key] = finite(context[key], key, 0 if key == "previous_similar_24h" else 1, 1e9 if key == "previous_similar_24h" else 5)
        # IRIS EXPLAIN: Enter this branch only when out[key] != int(out[key]).
        if out[key] != int(out[key]):
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError(f'{key} must be an integer'); the
            # IRIS EXPLAIN: caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError(f"{key} must be an integer")
    # IRIS EXPLAIN: Return out to the caller; this ends the current function path.
    return out


# IRIS EXPLAIN: Function frame: Validate each feature row and construct a pandas table in the exact training/inference column
# IRIS EXPLAIN: order.
# IRIS EXPLAIN: Inputs: rows: the existing records/feature rows passed by the caller.
# IRIS EXPLAIN: Declared return type: pd.DataFrame; the return statements below show each actual result/fallback.
def frame(rows: list[dict]) -> pd.DataFrame:
    # IRIS EXPLAIN: Return the result of pd.DataFrame([validate_features(row) for row in rows], columns=FEATURES) to the caller;
    # IRIS EXPLAIN: this ends the current function path.
    return pd.DataFrame([validate_features(row) for row in rows], columns=FEATURES)


# IRIS EXPLAIN: Function rule_label: Apply the fixed transparent authentication/network rules; return a supported class only
# IRIS EXPLAIN: when its evidence threshold is met, otherwise abstain with None.
# IRIS EXPLAIN: Inputs: row: the existing input record to inspect without inventing missing evidence.
# IRIS EXPLAIN: Declared return type: str | None; the return statements below show each actual result/fallback.
def rule_label(row: dict) -> str | None:
    # IRIS EXPLAIN: Existing documentation/literal text below is kept exactly as written; the explanation is outside the string
    # IRIS EXPLAIN: so its value does not change.
    """Frozen transparent baseline; no numeric confidence is fabricated."""
    # IRIS EXPLAIN: Store the result of validate_features(row) in row; later lines use this named result.
    row = validate_features(row)
    # IRIS EXPLAIN: Enter this branch only when row['event_family'] == 'authentication'.
    if row["event_family"] == "authentication":
        # IRIS EXPLAIN: Enter this branch only when row['failed_count'] >= 12 and row['failure_ratio'] >= 0.75.
        if row["failed_count"] >= 12 and row["failure_ratio"] >= 0.75:
            # IRIS EXPLAIN: Return 'credential_access' to the caller; this ends the current function path.
            return "credential_access"
        # IRIS EXPLAIN: Enter this branch only when row['failed_count'] <= 3 and row['success_after_failures'] == 1.
        if row["failed_count"] <= 3 and row["success_after_failures"] == 1:
            # IRIS EXPLAIN: Return 'benign' to the caller; this ends the current function path.
            return "benign"
        # IRIS EXPLAIN: Return None (no result/value) to the caller; this ends the current function path.
        return None
    # IRIS EXPLAIN: Enter this branch only when row['event_family'] == 'network' and row['distinct_rules'] >= 4 and
    # IRIS EXPLAIN: (row['event_count'] >= 15).
    if row["event_family"] == "network" and row["distinct_rules"] >= 4 and row["event_count"] >= 15:
        # IRIS EXPLAIN: Return 'reconnaissance' to the caller; this ends the current function path.
        return "reconnaissance"
    # Missing evidence is not a benign label. Unsupported families abstain.
    # IRIS EXPLAIN: Return None (no result/value) to the caller; this ends the current function path.
    return None
