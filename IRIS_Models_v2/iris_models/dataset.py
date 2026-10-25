# IRIS EXPLAIN: File purpose: Offline-only join of observed sessions to verified reviews, with quarantine and independent
# IRIS EXPLAIN: grouped holdouts; this is not a runtime fourth input.
# IRIS EXPLAIN: Existing documentation/literal text below is kept exactly as written; the explanation is outside the string so
# IRIS EXPLAIN: its value does not change.
"""Offline observed-session/review join, quarantine and group holdout."""
# IRIS EXPLAIN: Keep type annotations unevaluated at definition time; this does not add a model feature or change runtime
# IRIS EXPLAIN: settings.
from __future__ import annotations

# IRIS EXPLAIN: Import Counter, defaultdict from collections to count values and build efficient grouping/history containers.
from collections import Counter, defaultdict
# IRIS EXPLAIN: Import Path from pathlib to resolve server-owned paths without trusting uploaded filenames.
from pathlib import Path

# IRIS EXPLAIN: Import numpy as np to perform reproducible numeric sampling, vectorized predictions and array calculations.
import numpy as np
# IRIS EXPLAIN: Import pandas as pd to assemble allowlisted feature tables and catalogue records.
import pandas as pd

# IRIS EXPLAIN: Import CLASSES, FEATURES, digest, read_jsonl, validate_context, validate_features from .contracts to reuse the
# IRIS EXPLAIN: shared project contract/implementation rather than duplicate it.
from .contracts import CLASSES, FEATURES, digest, read_jsonl, validate_context, validate_features


# IRIS EXPLAIN: Function load_dataset: Join observed sessions to separately reviewed labels, quarantine ineligible sessions, and
# IRIS EXPLAIN: require supported classes and independent runs before offline training.
# IRIS EXPLAIN: Inputs: sessions: observed prepared sessions, not automatically reviewed labels; reviews: the separate
# IRIS EXPLAIN: offline/session review file or saved local opinions; synthetic: whether this offline experiment explicitly uses
# IRIS EXPLAIN: artificial data.
# IRIS EXPLAIN: Declared return type: tuple[pd.DataFrame, dict]; the return statements below show each actual result/fallback.
def load_dataset(sessions: Path, reviews: Path, *, synthetic: bool = False) -> tuple[pd.DataFrame, dict]:
    # IRIS EXPLAIN: Store the result of read_jsonl(sessions) in observations; later lines use this named result.
    observations = read_jsonl(sessions)
    # IRIS EXPLAIN: Store the result of read_jsonl(reviews) in annotations; later lines use this named result.
    annotations = read_jsonl(reviews)
    # IRIS EXPLAIN: Store a mapping containing  in by_id; later lines use this named result.
    by_id = {}
    # IRIS EXPLAIN: Iterate annotations, binding each item to annotation; process only the existing observed/fixture collection.
    for annotation in annotations:
        # IRIS EXPLAIN: Store the result of annotation.get('session_id') (read an optional mapping field using its stated
        # IRIS EXPLAIN: fallback) in sid; later lines use this named result.
        sid = annotation.get("session_id")
        # IRIS EXPLAIN: Enter this branch only when not isinstance(sid, str) or not sid or sid in by_id.
        if not isinstance(sid, str) or not sid or sid in by_id:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Reviews require unique nonempty
            # IRIS EXPLAIN: session_id values'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError("Reviews require unique nonempty session_id values")
        # IRIS EXPLAIN: Store annotation in by_id[sid]; later lines use this named result.
        by_id[sid] = annotation
    # IRIS EXPLAIN: Store set() in seen; later lines use this named result.
    seen = set()
    # IRIS EXPLAIN: Store ([], []) in (rows, quarantine); later lines use this named result.
    rows, quarantine = [], []
    # IRIS EXPLAIN: Store a mapping containing  in seen_runs; later lines use this named result.
    seen_runs = {}
    # IRIS EXPLAIN: Iterate observations, binding each item to observation; process only the existing observed/fixture
    # IRIS EXPLAIN: collection.
    for observation in observations:
        # IRIS EXPLAIN: Store the result of observation.get('session_id') (read an optional mapping field using its stated
        # IRIS EXPLAIN: fallback) in sid; later lines use this named result.
        sid = observation.get("session_id")
        # IRIS EXPLAIN: Enter this branch only when not isinstance(sid, str) or not sid or sid in seen.
        if not isinstance(sid, str) or not sid or sid in seen:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Observed sessions require unique
            # IRIS EXPLAIN: nonempty session_id values'); the caller's existing boundary determines rollback or the HTTP
            # IRIS EXPLAIN: diagnostic.
            raise ValueError("Observed sessions require unique nonempty session_id values")
        # IRIS EXPLAIN: Call seen.add(sid): record membership in the set.
        seen.add(sid)
        # IRIS EXPLAIN: Attempt this operation inside the following explicit error boundary; the existing except/finally blocks
        # IRIS EXPLAIN: decide fallback and cleanup.
        try:
            # IRIS EXPLAIN: Store the result of by_id.get(sid) (read an optional mapping field using its stated fallback) in
            # IRIS EXPLAIN: review; later lines use this named result.
            review = by_id.get(sid)
            # IRIS EXPLAIN: Enter this branch only when review is None.
            if review is None:
                # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('No reviewed session-level
                # IRIS EXPLAIN: label; do not copy a run label to every session'); the caller's existing boundary determines
                # IRIS EXPLAIN: rollback or the HTTP diagnostic.
                raise ValueError("No reviewed session-level label; do not copy a run label to every session")
            # IRIS EXPLAIN: Store the result of validate_features(observation['features']) in features; later lines use this
            # IRIS EXPLAIN: named result.
            features = validate_features(observation["features"])
            # IRIS EXPLAIN: Store the result of observation.get('context') (read an optional mapping field using its stated
            # IRIS EXPLAIN: fallback) in raw_context; later lines use this named result.
            raw_context = observation.get("context")
            # IRIS EXPLAIN: Store the result of validate_context(raw_context) when raw_context is not None; otherwise a mapping
            # IRIS EXPLAIN: containing asset_type, asset_criticality, current_likelihood, impact, previous_similar_24h in
            # IRIS EXPLAIN: context; later lines use this named result.
            context = validate_context(raw_context) if raw_context is not None else {
                # IRIS EXPLAIN: Set/describe these existing record fields: asset_type: the existing inventory business-context
                # IRIS EXPLAIN: category; asset_criticality: pre-decision business criticality on the existing 1-5 scale; not a
                # IRIS EXPLAIN: Model 1 telemetry input; current_likelihood: current working or pre-decision likelihood,
                # IRIS EXPLAIN: according to this record's context.
                "asset_type": "unknown", "asset_criticality": None, "current_likelihood": None,
                # IRIS EXPLAIN: Set/describe these existing record fields: impact: the same registered risk's impact; it must
                # IRIS EXPLAIN: not be independently maximized across risks; previous_similar_24h: count of earlier completed
                # IRIS EXPLAIN: similar sessions available inside this batch.
                "impact": None, "previous_similar_24h": None,
            # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain
            # IRIS EXPLAIN: unchanged.
            }
            # IRIS EXPLAIN: Enter this branch only when review.get('label_verified') is not True or not
            # IRIS EXPLAIN: str(review.get('reviewer', '')).strip().
            if review.get("label_verified") is not True or not str(review.get("reviewer", "")).strip():
                # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Label lacks explicit
                # IRIS EXPLAIN: verification and named reviewer'); the caller's existing boundary determines rollback or the
                # IRIS EXPLAIN: HTTP diagnostic.
                raise ValueError("Label lacks explicit verification and named reviewer")
            # IRIS EXPLAIN: Enter this branch only when observation.get('sensor_healthy') is not True.
            if observation.get("sensor_healthy") is not True:
                # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Sensor health is unknown or
                # IRIS EXPLAIN: failed'); the caller's existing boundary determines rollback or the HTTP diagnostic.
                raise ValueError("Sensor health is unknown or failed")
            # IRIS EXPLAIN: Store the result of observation.get('data_provenance') (read an optional mapping field using its
            # IRIS EXPLAIN: stated fallback) in provenance; later lines use this named result.
            provenance = observation.get("data_provenance")
            # IRIS EXPLAIN: Enter this branch only when provenance not in {'cyber_range', 'synthetic', 'operational'}.
            if provenance not in {"cyber_range", "synthetic", "operational"}:
                # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('data_provenance must be
                # IRIS EXPLAIN: cyber_range, operational or synthetic'); the caller's existing boundary determines rollback or
                # IRIS EXPLAIN: the HTTP diagnostic.
                raise ValueError("data_provenance must be cyber_range, operational or synthetic")
            # IRIS EXPLAIN: Enter this branch only when (provenance == 'synthetic') != synthetic.
            if (provenance == "synthetic") != synthetic:
                # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Synthetic/real provenance does
                # IRIS EXPLAIN: not match this experiment'); the caller's existing boundary determines rollback or the HTTP
                # IRIS EXPLAIN: diagnostic.
                raise ValueError("Synthetic/real provenance does not match this experiment")
            # IRIS EXPLAIN: Store the result of observation.get('aggregation_schema') (read an optional mapping field using its
            # IRIS EXPLAIN: stated fallback) in aggregation_schema; later lines use this named result.
            aggregation_schema = observation.get("aggregation_schema")
            # IRIS EXPLAIN: Enter this branch only when not isinstance(aggregation_schema, str) or not
            # IRIS EXPLAIN: aggregation_schema.strip().
            if not isinstance(aggregation_schema, str) or not aggregation_schema.strip():
                # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Missing aggregation_schema
                # IRIS EXPLAIN: identifying the exact sessionizer/normalizer'); the caller's existing boundary determines
                # IRIS EXPLAIN: rollback or the HTTP diagnostic.
                raise ValueError("Missing aggregation_schema identifying the exact sessionizer/normalizer")
            # IRIS EXPLAIN: Store the result of review.get('scenario_class') (read an optional mapping field using its stated
            # IRIS EXPLAIN: fallback) in label; later lines use this named result.
            label = review.get("scenario_class")
            # IRIS EXPLAIN: Enter this branch only when label not in CLASSES.
            if label not in CLASSES:
                # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError(f'Unsupported class: {label}');
                # IRIS EXPLAIN: the caller's existing boundary determines rollback or the HTTP diagnostic.
                raise ValueError(f"Unsupported class: {label}")
            # IRIS EXPLAIN: Store a mapping containing  in metadata; later lines use this named result.
            metadata = {}
            # IRIS EXPLAIN: Iterate ('run_id', 'campaign_id'), binding each item to key; process only the existing
            # IRIS EXPLAIN: observed/fixture collection.
            for key in ("run_id", "campaign_id"):
                # IRIS EXPLAIN: Store the result of observation.get(key) (read an optional mapping field using its stated
                # IRIS EXPLAIN: fallback) in value; later lines use this named result.
                value = observation.get(key)
                # IRIS EXPLAIN: Enter this branch only when not isinstance(value, str) or not value.strip() or review.get(key)
                # IRIS EXPLAIN: != value.
                if not isinstance(value, str) or not value.strip() or review.get(key) != value:
                    # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError(f'Observation/review {key}
                    # IRIS EXPLAIN: is missing or mismatched'); the caller's existing boundary determines rollback or the HTTP
                    # IRIS EXPLAIN: diagnostic.
                    raise ValueError(f"Observation/review {key} is missing or mismatched")
                # IRIS EXPLAIN: Store value in metadata[key]; later lines use this named result.
                metadata[key] = value
            # IRIS EXPLAIN: Store the result of review.get('template_group') (read an optional mapping field using its stated
            # IRIS EXPLAIN: fallback) in template_group; later lines use this named result.
            template_group = review.get("template_group")
            # IRIS EXPLAIN: Enter this branch only when not isinstance(template_group, str) or not template_group.strip().
            if not isinstance(template_group, str) or not template_group.strip():
                # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('template_group must identify a
                # IRIS EXPLAIN: behavioral template family/variant'); the caller's existing boundary determines rollback or the
                # IRIS EXPLAIN: HTTP diagnostic.
                raise ValueError("template_group must identify a behavioral template family/variant")
            # IRIS EXPLAIN: Store template_group in metadata['template_group']; later lines use this named result.
            metadata["template_group"] = template_group
            # IRIS EXPLAIN: Store (metadata['campaign_id'], metadata['run_id']) in global_run; later lines use this named
            # IRIS EXPLAIN: result.
            global_run = (metadata["campaign_id"], metadata["run_id"])
            # IRIS EXPLAIN: Enter this branch only when global_run in seen_runs and seen_runs[global_run] != template_group.
            if global_run in seen_runs and seen_runs[global_run] != template_group:
                # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Sessions from one run disagree
                # IRIS EXPLAIN: on template grouping'); the caller's existing boundary determines rollback or the HTTP
                # IRIS EXPLAIN: diagnostic.
                raise ValueError("Sessions from one run disagree on template grouping")
            # IRIS EXPLAIN: Store template_group in seen_runs[global_run]; later lines use this named result.
            seen_runs[global_run] = template_group
            # IRIS EXPLAIN: Store the result of review.get('recommended_control_ids', []) (read an optional mapping field using
            # IRIS EXPLAIN: its stated fallback) in controls; later lines use this named result.
            controls = review.get("recommended_control_ids", [])
            # IRIS EXPLAIN: Enter this branch only when not isinstance(controls, list) or any((not isinstance(c, str) or not c
            # IRIS EXPLAIN: for c in controls)).
            if not isinstance(controls, list) or any(not isinstance(c, str) or not c for c in controls):
                # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('recommended_control_ids must be
                # IRIS EXPLAIN: a list of catalogue IDs'); the caller's existing boundary determines rollback or the HTTP
                # IRIS EXPLAIN: diagnostic.
                raise ValueError("recommended_control_ids must be a list of catalogue IDs")
            # IRIS EXPLAIN: Store raw_context is not None and review.get('controls_reviewed') is True and
            # IRIS EXPLAIN: bool(str(review.get('control_reviewer', '')).strip()) in controls_reviewed; later lines use this
            # IRIS EXPLAIN: named result.
            controls_reviewed = (raw_context is not None and review.get("controls_reviewed") is True
                                 # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these
                                 # IRIS EXPLAIN: existing arguments/items: and bool(str(review.get("control_reviewer",
                                 # IRIS EXPLAIN: "")).strip())).
                                 and bool(str(review.get("control_reviewer", "")).strip()))
            # IRIS EXPLAIN: Call rows.append({**features, **context, **metadata, 'session_id': sid, 'scenario_class': label,
            # IRIS EXPLAIN: 'controls': sorted(set(controls)), 'controls_reviewed': controls_...: append one item to the working
            # IRIS EXPLAIN: list.
            rows.append({**features, **context, **metadata, "session_id": sid,
                         # IRIS EXPLAIN: Set/describe these existing record fields: scenario_class: a reviewed training target
                         # IRIS EXPLAIN: or the explicitly identified prediction field; never silently added to telemetry
                         # IRIS EXPLAIN: predictors; controls: control implementation context or separately identified
                         # IRIS EXPLAIN: recommendations; labels remain offline-only targets.
                         "scenario_class": label, "controls": sorted(set(controls)),
                         # IRIS EXPLAIN: Set/describe these existing record fields: data_provenance: explicit
                         # IRIS EXPLAIN: synthetic/cyber_range/operational source identity.
                         "controls_reviewed": controls_reviewed, "data_provenance": provenance,
                         # IRIS EXPLAIN: Set/describe these existing record fields: aggregation_schema: the exact
                         # IRIS EXPLAIN: normalization/session-window contract used for training and inference.
                         "aggregation_schema": aggregation_schema})
        # IRIS EXPLAIN: Catch (ValueError, TypeError, KeyError) as exc; execute the existing error/fallback path rather than
        # IRIS EXPLAIN: silently treating it as success.
        except (ValueError, TypeError, KeyError) as exc:
            # IRIS EXPLAIN: Call quarantine.append({'session_id': sid, 'reason': str(exc)}): append one item to the working
            # IRIS EXPLAIN: list.
            quarantine.append({"session_id": sid, "reason": str(exc)})
    # IRIS EXPLAIN: Store sorted(set(by_id) - seen) in orphan_reviews; later lines use this named result.
    orphan_reviews = sorted(set(by_id) - seen)
    # IRIS EXPLAIN: Enter this branch only when orphan_reviews.
    if orphan_reviews:
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError(f'Reviews reference absent sessions:
        # IRIS EXPLAIN: {orphan_reviews[:5]}'); the caller's existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError(f"Reviews reference absent sessions: {orphan_reviews[:5]}")
    # IRIS EXPLAIN: Enter this branch only when not rows.
    if not rows:
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError(f'No eligible reviewed sessions.
        # IRIS EXPLAIN: Quarantine: {quarantine[:5]}'); the caller's existing boundary determines rollback or the HTTP
        # IRIS EXPLAIN: diagnostic.
        raise ValueError(f"No eligible reviewed sessions. Quarantine: {quarantine[:5]}")
    # IRIS EXPLAIN: Store the result of pd.DataFrame(rows) in data; later lines use this named result.
    data = pd.DataFrame(rows)
    # IRIS EXPLAIN: Enter this branch only when data.aggregation_schema.nunique() != 1.
    if data.aggregation_schema.nunique() != 1:
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Do not mix different
        # IRIS EXPLAIN: normalization/sessionization contracts in one experiment'); the caller's existing boundary determines
        # IRIS EXPLAIN: rollback or the HTTP diagnostic.
        raise ValueError("Do not mix different normalization/sessionization contracts in one experiment")
    # IRIS EXPLAIN: Enter this branch only when set(data.scenario_class) != set(CLASSES).
    if set(data.scenario_class) != set(CLASSES):
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Need verified benign, credential_access
        # IRIS EXPLAIN: and reconnaissance sessions'); the caller's existing boundary determines rollback or the HTTP
        # IRIS EXPLAIN: diagnostic.
        raise ValueError("Need verified benign, credential_access and reconnaissance sessions")
    # IRIS EXPLAIN: Store the comprehension {label: len(set(zip(part.campaign_id, part.run_id))) for label, part in
    # IRIS EXPLAIN: data.groupby('scenario_class')} in run_counts; later lines use this named result.
    run_counts = {label: len(set(zip(part.campaign_id, part.run_id)))
                  # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                  # IRIS EXPLAIN: arguments/items: for label, part in data.groupby("scenario_class")}.
                  for label, part in data.groupby("scenario_class")}
    # IRIS EXPLAIN: Enter this branch only when min(run_counts.values()) < 25.
    if min(run_counts.values()) < 25:
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError(f'Need at least 25 independent runs per
        # IRIS EXPLAIN: class, not 25 rows: {run_counts}'); the caller's existing boundary determines rollback or the HTTP
        # IRIS EXPLAIN: diagnostic.
        raise ValueError(f"Need at least 25 independent runs per class, not 25 rows: {run_counts}")
    # Exact repeated feature vectors are recorded, not automatically discarded:
    # discrete sessions can genuinely be identical. Group provenance is still essential.
    # IRIS EXPLAIN: Store int(data[FEATURES].duplicated().sum()) in duplicate_features; later lines use this named result.
    duplicate_features = int(data[FEATURES].duplicated().sum())
    # IRIS EXPLAIN: Return (data, {'accepted_sessions': len(data), 'independent_runs_per_class': run_counts, 'quarantined':
    # IRIS EXPLAIN: quarantine, 'exact_duplicate_feature_rows': duplic... to the caller; this ends the current function path.
    return data, {
        # IRIS EXPLAIN: Continue the current record with accepted_sessions, independent_runs_per_class; each value comes from
        # IRIS EXPLAIN: the expression shown on this unchanged line.
        "accepted_sessions": len(data), "independent_runs_per_class": run_counts,
        # IRIS EXPLAIN: Continue the current record with quarantined, exact_duplicate_feature_rows; each value comes from the
        # IRIS EXPLAIN: expression shown on this unchanged line.
        "quarantined": quarantine, "exact_duplicate_feature_rows": duplicate_features,
        # IRIS EXPLAIN: Continue the current record with sessions_sha256, reviews_sha256; each value comes from the expression
        # IRIS EXPLAIN: shown on this unchanged line.
        "sessions_sha256": digest(sessions), "reviews_sha256": digest(reviews),
        # IRIS EXPLAIN: Set/describe these existing record fields: aggregation_schema: the exact normalization/session-window
        # IRIS EXPLAIN: contract used for training and inference.
        "synthetic": synthetic, "aggregation_schema": str(data.aggregation_schema.iloc[0]),
    # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain unchanged.
    }


# IRIS EXPLAIN: Function split_groups: Assign whole campaign/template/run groups to train, selection, calibration, threshold and
# IRIS EXPLAIN: test roles; prevent a physical run crossing partitions.
# IRIS EXPLAIN: Inputs: data: validated tabular observations; group_by: the experiment independence unit: campaign, template
# IRIS EXPLAIN: family or run; seed: the reproducible random seed.
# IRIS EXPLAIN: Declared return type: tuple[dict, dict]; the return statements below show each actual result/fallback.
def split_groups(data: pd.DataFrame, group_by: str = "campaign_id", seed: int = 42) -> tuple[dict, dict]:
    # IRIS EXPLAIN: Enter this branch only when group_by not in {'campaign_id', 'template_group', 'run_id'}.
    if group_by not in {"campaign_id", "template_group", "run_id"}:
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('group_by must be campaign_id,
        # IRIS EXPLAIN: template_group, or run_id'); the caller's existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError("group_by must be campaign_id, template_group, or run_id")
    # IRIS EXPLAIN: Enter this branch only when group_by == 'run_id'.
    if group_by == "run_id":
        # IRIS EXPLAIN: Store the computed value data.campaign_id + '/' + data.run_id in group_values; later lines use this
        # IRIS EXPLAIN: named result.
        group_values = data.campaign_id + "/" + data.run_id
    # IRIS EXPLAIN: Handle the alternative to the preceding condition/loop exactly as originally defined.
    else:
        # IRIS EXPLAIN: Store the result of data[group_by].astype(str) in group_values; later lines use this named result.
        group_values = data[group_by].astype(str)
    # IRIS EXPLAIN: Store the result of np.array(sorted(group_values.unique()), dtype=object) in groups; later lines use this
    # IRIS EXPLAIN: named result.
    groups = np.array(sorted(group_values.unique()), dtype=object)
    # IRIS EXPLAIN: Store len(groups) in n; later lines use this named result.
    n = len(groups)
    # IRIS EXPLAIN: Enter this branch only when n < 5.
    if n < 5:
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError(f'Need at least 5 independent {group_by}
        # IRIS EXPLAIN: groups for fit/selection/calibration/threshold/test; found {n}. Collect more campaigns/variants or use
        # IRIS EXPLAIN: run_id for a development-only experiment.'); the caller's existing boundary determines rollback or the
        # IRIS EXPLAIN: HTTP diagnostic.
        raise ValueError(f"Need at least 5 independent {group_by} groups for fit/selection/calibration/threshold/test; found {n}. Collect more campaigns/variants or use run_id for a development-only experiment.")
    # IRIS EXPLAIN: Call np.random.default_rng(seed).shuffle(groups) using the existing explicit arguments.
    np.random.default_rng(seed).shuffle(groups)
    # IRIS EXPLAIN: Store the comprehension [max(1, int(n * fraction)) for fraction in (0.15, 0.1, 0.1, 0.15)] in sizes; later
    # IRIS EXPLAIN: lines use this named result.
    sizes = [max(1, int(n * fraction)) for fraction in (.15, .10, .10, .15)]
    # Train gets the remaining groups. Each other role has its own data.
    # IRIS EXPLAIN: Store ['test', 'threshold', 'calibration', 'selection', 'train'] in names; later lines use this named
    # IRIS EXPLAIN: result.
    names = ["test", "threshold", "calibration", "selection", "train"]
    # IRIS EXPLAIN: Call sizes.append(n - sum(sizes)): append one item to the working list.
    sizes.append(n - sum(sizes))
    # IRIS EXPLAIN: Enter this branch only when sizes[-1] < 1.
    if sizes[-1] < 1:
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Not enough independent groups'); the
        # IRIS EXPLAIN: caller's existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError("Not enough independent groups")
    # IRIS EXPLAIN: Store ({}, {}) in (indexes, assignments); later lines use this named result.
    indexes, assignments = {}, {}
    # IRIS EXPLAIN: Store 0 in start; later lines use this named result.
    start = 0
    # IRIS EXPLAIN: Iterate zip(names, sizes, strict=True), binding each item to (name, size); process only the existing
    # IRIS EXPLAIN: observed/fixture collection.
    for name, size in zip(names, sizes, strict=True):
        # IRIS EXPLAIN: Store set(groups[start:start + size]) in chosen; later lines use this named result.
        chosen = set(groups[start:start + size])
        # IRIS EXPLAIN: Update start using the existing Add operation and size.
        start += size
        # IRIS EXPLAIN: Store the result of np.flatnonzero(group_values.isin(chosen).to_numpy()) in indexes[name]; later lines
        # IRIS EXPLAIN: use this named result.
        indexes[name] = np.flatnonzero(group_values.isin(chosen).to_numpy())
        # IRIS EXPLAIN: Store sorted(chosen) in assignments[name]; later lines use this named result.
        assignments[name] = sorted(chosen)
        # IRIS EXPLAIN: Enter this branch only when set(data.iloc[indexes[name]].scenario_class) != set(CLASSES).
        if set(data.iloc[indexes[name]].scenario_class) != set(CLASSES):
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError(f'{name} split lacks a supported
            # IRIS EXPLAIN: class. Collect class-balanced independent campaigns/variants. Do not optimize the split seed against
            # IRIS EXPLAIN: test scores.'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError(f"{name} split lacks a supported class. Collect class-balanced independent campaigns/variants. Do not optimize the split seed against test scores.")
    # A coarser grouping must never tear a physical run across partitions.
    # IRIS EXPLAIN: Store a mapping containing  in run_partition; later lines use this named result.
    run_partition = {}
    # IRIS EXPLAIN: Iterate indexes.items(), binding each item to (name, ix); process only the existing observed/fixture
    # IRIS EXPLAIN: collection.
    for name, ix in indexes.items():
        # IRIS EXPLAIN: Iterate data.iloc[ix].itertuples(), binding each item to row; process only the existing observed/fixture
        # IRIS EXPLAIN: collection.
        for row in data.iloc[ix].itertuples():
            # IRIS EXPLAIN: Store (row.campaign_id, row.run_id) in key; later lines use this named result.
            key = (row.campaign_id, row.run_id)
            # IRIS EXPLAIN: Enter this branch only when key in run_partition and run_partition[key] != name.
            if key in run_partition and run_partition[key] != name:
                # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('One physical run crosses
                # IRIS EXPLAIN: partitions'); the caller's existing boundary determines rollback or the HTTP diagnostic.
                raise ValueError("One physical run crosses partitions")
            # IRIS EXPLAIN: Store name in run_partition[key]; later lines use this named result.
            run_partition[key] = name
    # IRIS EXPLAIN: Store a mapping containing seed, group_by, groups, rows, class_counts, claim in manifest; later lines use
    # IRIS EXPLAIN: this named result.
    manifest = {"seed": seed, "group_by": group_by, "groups": assignments,
                # IRIS EXPLAIN: Continue the current record with rows; each value comes from the expression shown on this
                # IRIS EXPLAIN: unchanged line.
                "rows": {name: len(ix) for name, ix in indexes.items()},
                # IRIS EXPLAIN: Continue the current record with class_counts; each value comes from the expression shown on
                # IRIS EXPLAIN: this unchanged line.
                "class_counts": {name: dict(Counter(data.iloc[ix].scenario_class)) for name, ix in indexes.items()},
                # IRIS EXPLAIN: Set/describe these existing record fields: campaign_id: group provenance retained for
                # IRIS EXPLAIN: split/session identity; not a telemetry predictor; run_id: run/batch provenance retained for
                # IRIS EXPLAIN: traceability; not a hidden attack-label feature.
                "claim": {"campaign_id": "unseen campaign holdout", "template_group": "unseen template-family/variant holdout", "run_id": "unseen run only; not independent campaign/template validation"}[group_by]}
    # IRIS EXPLAIN: Return (indexes, manifest) to the caller; this ends the current function path.
    return indexes, manifest
