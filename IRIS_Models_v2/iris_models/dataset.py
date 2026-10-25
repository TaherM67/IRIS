"""Offline observed-session/review join, quarantine and group holdout."""
from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

from .contracts import CLASSES, FEATURES, digest, read_jsonl, validate_context, validate_features


def load_dataset(sessions: Path, reviews: Path, *, synthetic: bool = False) -> tuple[pd.DataFrame, dict]:
    observations = read_jsonl(sessions)
    annotations = read_jsonl(reviews)
    by_id = {}
    for annotation in annotations:
        sid = annotation.get("session_id")
        if not isinstance(sid, str) or not sid or sid in by_id:
            raise ValueError("Reviews require unique nonempty session_id values")
        by_id[sid] = annotation
    seen = set()
    rows, quarantine = [], []
    seen_runs = {}
    for observation in observations:
        sid = observation.get("session_id")
        if not isinstance(sid, str) or not sid or sid in seen:
            raise ValueError("Observed sessions require unique nonempty session_id values")
        seen.add(sid)
        try:
            review = by_id.get(sid)
            if review is None:
                raise ValueError("No reviewed session-level label; do not copy a run label to every session")
            features = validate_features(observation["features"])
            raw_context = observation.get("context")
            context = validate_context(raw_context) if raw_context is not None else {
                "asset_type": "unknown", "asset_criticality": None, "current_likelihood": None,
                "impact": None, "previous_similar_24h": None,
            }
            if review.get("label_verified") is not True or not str(review.get("reviewer", "")).strip():
                raise ValueError("Label lacks explicit verification and named reviewer")
            if observation.get("sensor_healthy") is not True:
                raise ValueError("Sensor health is unknown or failed")
            provenance = observation.get("data_provenance")
            if provenance not in {"cyber_range", "synthetic", "operational"}:
                raise ValueError("data_provenance must be cyber_range, operational or synthetic")
            if (provenance == "synthetic") != synthetic:
                raise ValueError("Synthetic/real provenance does not match this experiment")
            aggregation_schema = observation.get("aggregation_schema")
            if not isinstance(aggregation_schema, str) or not aggregation_schema.strip():
                raise ValueError("Missing aggregation_schema identifying the exact sessionizer/normalizer")
            label = review.get("scenario_class")
            if label not in CLASSES:
                raise ValueError(f"Unsupported class: {label}")
            metadata = {}
            for key in ("run_id", "campaign_id"):
                value = observation.get(key)
                if not isinstance(value, str) or not value.strip() or review.get(key) != value:
                    raise ValueError(f"Observation/review {key} is missing or mismatched")
                metadata[key] = value
            template_group = review.get("template_group")
            if not isinstance(template_group, str) or not template_group.strip():
                raise ValueError("template_group must identify a behavioral template family/variant")
            metadata["template_group"] = template_group
            global_run = (metadata["campaign_id"], metadata["run_id"])
            if global_run in seen_runs and seen_runs[global_run] != template_group:
                raise ValueError("Sessions from one run disagree on template grouping")
            seen_runs[global_run] = template_group
            controls = review.get("recommended_control_ids", [])
            if not isinstance(controls, list) or any(not isinstance(c, str) or not c for c in controls):
                raise ValueError("recommended_control_ids must be a list of catalogue IDs")
            controls_reviewed = (raw_context is not None and review.get("controls_reviewed") is True
                                 and bool(str(review.get("control_reviewer", "")).strip()))
            rows.append({**features, **context, **metadata, "session_id": sid,
                         "scenario_class": label, "controls": sorted(set(controls)),
                         "controls_reviewed": controls_reviewed, "data_provenance": provenance,
                         "aggregation_schema": aggregation_schema})
        except (ValueError, TypeError, KeyError) as exc:
            quarantine.append({"session_id": sid, "reason": str(exc)})
    orphan_reviews = sorted(set(by_id) - seen)
    if orphan_reviews:
        raise ValueError(f"Reviews reference absent sessions: {orphan_reviews[:5]}")
    if not rows:
        raise ValueError(f"No eligible reviewed sessions. Quarantine: {quarantine[:5]}")
    data = pd.DataFrame(rows)
    if data.aggregation_schema.nunique() != 1:
        raise ValueError("Do not mix different normalization/sessionization contracts in one experiment")
    if set(data.scenario_class) != set(CLASSES):
        raise ValueError("Need verified benign, credential_access and reconnaissance sessions")
    run_counts = {label: len(set(zip(part.campaign_id, part.run_id)))
                  for label, part in data.groupby("scenario_class")}
    if min(run_counts.values()) < 25:
        raise ValueError(f"Need at least 25 independent runs per class, not 25 rows: {run_counts}")
    # Exact repeated feature vectors are recorded, not automatically discarded:
    # discrete sessions can genuinely be identical. Group provenance is still essential.
    duplicate_features = int(data[FEATURES].duplicated().sum())
    return data, {
        "accepted_sessions": len(data), "independent_runs_per_class": run_counts,
        "quarantined": quarantine, "exact_duplicate_feature_rows": duplicate_features,
        "sessions_sha256": digest(sessions), "reviews_sha256": digest(reviews),
        "synthetic": synthetic, "aggregation_schema": str(data.aggregation_schema.iloc[0]),
    }


def split_groups(data: pd.DataFrame, group_by: str = "campaign_id", seed: int = 42) -> tuple[dict, dict]:
    if group_by not in {"campaign_id", "template_group", "run_id"}:
        raise ValueError("group_by must be campaign_id, template_group, or run_id")
    if group_by == "run_id":
        group_values = data.campaign_id + "/" + data.run_id
    else:
        group_values = data[group_by].astype(str)
    groups = np.array(sorted(group_values.unique()), dtype=object)
    n = len(groups)
    if n < 5:
        raise ValueError(f"Need at least 5 independent {group_by} groups for fit/selection/calibration/threshold/test; found {n}. Collect more campaigns/variants or use run_id for a development-only experiment.")
    np.random.default_rng(seed).shuffle(groups)
    sizes = [max(1, int(n * fraction)) for fraction in (.15, .10, .10, .15)]
    # Train gets the remaining groups. Each other role has its own data.
    names = ["test", "threshold", "calibration", "selection", "train"]
    sizes.append(n - sum(sizes))
    if sizes[-1] < 1:
        raise ValueError("Not enough independent groups")
    indexes, assignments = {}, {}
    start = 0
    for name, size in zip(names, sizes, strict=True):
        chosen = set(groups[start:start + size])
        start += size
        indexes[name] = np.flatnonzero(group_values.isin(chosen).to_numpy())
        assignments[name] = sorted(chosen)
        if set(data.iloc[indexes[name]].scenario_class) != set(CLASSES):
            raise ValueError(f"{name} split lacks a supported class. Collect class-balanced independent campaigns/variants. Do not optimize the split seed against test scores.")
    # A coarser grouping must never tear a physical run across partitions.
    run_partition = {}
    for name, ix in indexes.items():
        for row in data.iloc[ix].itertuples():
            key = (row.campaign_id, row.run_id)
            if key in run_partition and run_partition[key] != name:
                raise ValueError("One physical run crosses partitions")
            run_partition[key] = name
    manifest = {"seed": seed, "group_by": group_by, "groups": assignments,
                "rows": {name: len(ix) for name, ix in indexes.items()},
                "class_counts": {name: dict(Counter(data.iloc[ix].scenario_class)) for name, ix in indexes.items()},
                "claim": {"campaign_id": "unseen campaign holdout", "template_group": "unseen template-family/variant holdout", "run_id": "unseen run only; not independent campaign/template validation"}[group_by]}
    return indexes, manifest
