"""One explicit feature contract shared by training, adapters and inference."""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any

import pandas as pd

CLASSES = ("benign", "credential_access", "reconnaissance")
CATEGORICAL = ["event_family", "primary_protocol"]
NUMERIC = [
    "event_count", "duration_seconds", "max_rule_level", "mean_rule_level",
    "distinct_rules", "distinct_sources", "distinct_accounts", "failed_count",
    "success_count", "failure_ratio", "success_after_failures",
    "max_events_in_10s", "external_source_fraction", "event_rate_per_minute",
]
FEATURES = CATEGORICAL + NUMERIC
CONTEXT_CATEGORICAL = ["asset_type", "predicted_scenario"]
CONTEXT_NUMERIC = ["asset_criticality", "current_likelihood", "impact", "previous_similar_24h"]
CONTROL_FEATURES = FEATURES + CONTEXT_CATEGORICAL + CONTEXT_NUMERIC
FEATURE_SCHEMA = "iris-telemetry-session-v1"
COUNT_FIELDS = {
    "event_count", "distinct_rules", "distinct_sources", "distinct_accounts",
    "failed_count", "success_count", "max_events_in_10s",
}


def utc_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path.name}:{number}: invalid JSON") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path.name}:{number}: expected an object")
            rows.append(row)
    return rows


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row, allow_nan=False) + "\n")


def finite(value: Any, name: str, low: float = 0, high: float = 1e12) -> float:
    if isinstance(value, bool):
        value = int(value)
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be numeric") from exc
    if not math.isfinite(result) or not low <= result <= high:
        raise ValueError(f"{name} must be finite and in [{low}, {high}]")
    return result


def validate_features(row: dict) -> dict:
    if not isinstance(row, dict) or set(row) != set(FEATURES):
        extra = set(row) - set(FEATURES) if isinstance(row, dict) else set()
        missing = set(FEATURES) - set(row) if isinstance(row, dict) else set(FEATURES)
        raise ValueError(f"Feature allowlist violation; missing={sorted(missing)}, extra={sorted(extra)}")
    out = {}
    for key in CATEGORICAL:
        if not isinstance(row[key], str) or not row[key].strip():
            raise ValueError(f"{key} must be nonempty text")
        out[key] = row[key].strip().casefold() if key == "event_family" else row[key].strip().upper()
    for key in NUMERIC:
        high = 1 if key in {"failure_ratio", "external_source_fraction", "success_after_failures"} else 16 if key in {"max_rule_level", "mean_rule_level"} else 1e12
        out[key] = finite(row[key], key, 0, high)
        if key in COUNT_FIELDS | {"success_after_failures"} and out[key] != int(out[key]):
            raise ValueError(f"{key} must be an integer")
    n = out["event_count"]
    if n < 1 or out["max_events_in_10s"] < 1:
        raise ValueError("A session must contain at least one observed event")
    if out["failed_count"] + out["success_count"] > n:
        raise ValueError("Authentication outcome counts exceed event_count")
    if any(out[key] > n for key in COUNT_FIELDS - {"event_count"}):
        raise ValueError("A session count exceeds event_count")
    if out["mean_rule_level"] > out["max_rule_level"]:
        raise ValueError("Mean severity exceeds max severity")
    known = out["failed_count"] + out["success_count"]
    expected_ratio = out["failed_count"] / known if known else 0.0
    if abs(out["failure_ratio"] - expected_ratio) > 1e-6:
        raise ValueError("failure_ratio is inconsistent with outcome counts")
    expected_rate = n * 60 / max(out["duration_seconds"], 1)
    if not math.isclose(out["event_rate_per_minute"], expected_rate, rel_tol=1e-6, abs_tol=1e-6):
        raise ValueError("event_rate_per_minute is inconsistent with count/duration")
    return out


def validate_context(context: dict) -> dict:
    if not isinstance(context, dict):
        raise ValueError("Context must be an object")
    out = {"asset_type": str(context.get("asset_type", "unknown")).strip() or "unknown"}
    for key in CONTEXT_NUMERIC:
        if key not in context:
            raise ValueError(f"Missing pre-decision GRC context: {key}")
        out[key] = finite(context[key], key, 0 if key == "previous_similar_24h" else 1, 1e9 if key == "previous_similar_24h" else 5)
        if out[key] != int(out[key]):
            raise ValueError(f"{key} must be an integer")
    return out


def frame(rows: list[dict]) -> pd.DataFrame:
    return pd.DataFrame([validate_features(row) for row in rows], columns=FEATURES)


def rule_label(row: dict) -> str | None:
    """Frozen transparent baseline; no numeric confidence is fabricated."""
    row = validate_features(row)
    if row["event_family"] == "authentication":
        if row["failed_count"] >= 12 and row["failure_ratio"] >= 0.75:
            return "credential_access"
        if row["failed_count"] <= 3 and row["success_after_failures"] == 1:
            return "benign"
        return None
    if row["event_family"] == "network" and row["distinct_rules"] >= 4 and row["event_count"] >= 15:
        return "reconnaissance"
    # Missing evidence is not a benign label. Unsupported families abstain.
    return None
