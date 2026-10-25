# IRIS EXPLAIN: File purpose: Generates artificial observed-session and review fixtures for software experiments, not real
# IRIS EXPLAIN: detection evidence.
# IRIS EXPLAIN: Existing documentation/literal text below is kept exactly as written; the explanation is outside the string so
# IRIS EXPLAIN: its value does not change.
"""Artificial fixtures only: do not report these scores as detection evidence."""
# IRIS EXPLAIN: Keep type annotations unevaluated at definition time; this does not add a model feature or change runtime
# IRIS EXPLAIN: settings.
from __future__ import annotations

# IRIS EXPLAIN: Import Path from pathlib to resolve server-owned paths without trusting uploaded filenames.
from pathlib import Path

# IRIS EXPLAIN: Import numpy as np to perform reproducible numeric sampling, vectorized predictions and array calculations.
import numpy as np

# IRIS EXPLAIN: Import CLASSES, validate_features, write_json, write_jsonl from .contracts to reuse the shared project
# IRIS EXPLAIN: contract/implementation rather than duplicate it.
from .contracts import CLASSES, validate_features, write_json, write_jsonl


# IRIS EXPLAIN: Function generate: Create synthetic observed-session/review fixtures and an example session for software tests,
# IRIS EXPLAIN: without claiming actual attack-detection evidence.
# IRIS EXPLAIN: Inputs: destination: the explicit destination input used by the unchanged statements below; seed: the
# IRIS EXPLAIN: reproducible random seed.
# IRIS EXPLAIN: Declared return type: tuple[Path, Path, dict]; the return statements below show each actual result/fallback.
def generate(destination: Path, seed: int = 123) -> tuple[Path, Path, dict]:
    # IRIS EXPLAIN: Enter this branch only when (destination / 'sessions.jsonl').exists().
    if (destination / "sessions.jsonl").exists():
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Demo output exists. Choose a fresh
        # IRIS EXPLAIN: output directory.'); the caller's existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError("Demo output exists. Choose a fresh output directory.")
    # IRIS EXPLAIN: Store the result of np.random.default_rng(seed) in rng; later lines use this named result.
    rng = np.random.default_rng(seed)
    # IRIS EXPLAIN: Store ([], []) in (sessions, reviews); later lines use this named result.
    sessions, reviews = [], []
    # IRIS EXPLAIN: Store None (no result/value) in sample; later lines use this named result.
    sample = None
    # IRIS EXPLAIN: Iterate range(20), binding each item to campaign; process only the existing observed/fixture collection.
    for campaign in range(20):
        # IRIS EXPLAIN: Iterate CLASSES, binding each item to label; process only the existing observed/fixture collection.
        for label in CLASSES:
            # IRIS EXPLAIN: Iterate range(3), binding each item to replicate; process only the existing observed/fixture
            # IRIS EXPLAIN: collection.
            for replicate in range(3):
                # IRIS EXPLAIN: Store the formatted text f'DEMO-{campaign:02d}-{label}-{replicate}' in sid; later lines use this
                # IRIS EXPLAIN: named result.
                sid = f"DEMO-{campaign:02d}-{label}-{replicate}"
                # IRIS EXPLAIN: Store 'network' when label == 'reconnaissance' or (label == 'benign' and rng.random() < 0.2);
                # IRIS EXPLAIN: otherwise 'authentication' in family; later lines use this named result.
                family = "network" if label == "reconnaissance" or (label == "benign" and rng.random() < .2) else "authentication"
                # IRIS EXPLAIN: Enter this branch only when family == 'authentication'.
                if family == "authentication":
                    # IRIS EXPLAIN: Store int(rng.integers(8, 65)) when label == 'credential_access'; otherwise
                    # IRIS EXPLAIN: int(rng.integers(0, 7)) in failed; later lines use this named result.
                    failed = int(rng.integers(8, 65)) if label == "credential_access" else int(rng.integers(0, 7))
                    # IRIS EXPLAIN: Store int(rng.integers(0, 3)) when label == 'credential_access'; otherwise
                    # IRIS EXPLAIN: int(rng.integers(1, 4)) in success; later lines use this named result.
                    success = int(rng.integers(0, 3)) if label == "credential_access" else int(rng.integers(1, 4))
                    # IRIS EXPLAIN: Store the computed value failed + success + int(rng.integers(0, 5)) in n; later lines use
                    # IRIS EXPLAIN: this named result.
                    n = failed + success + int(rng.integers(0, 5))
                    # IRIS EXPLAIN: Store min(n, int(rng.integers(1, 5))) in rules; later lines use this named result.
                    rules = min(n, int(rng.integers(1, 5)))
                    # IRIS EXPLAIN: Store int(rng.integers(4, 12)) when label == 'credential_access'; otherwise
                    # IRIS EXPLAIN: int(rng.integers(2, 8)) in max_level; later lines use this named result.
                    max_level = int(rng.integers(4, 12)) if label == "credential_access" else int(rng.integers(2, 8))
                # IRIS EXPLAIN: Handle the alternative to the preceding condition/loop exactly as originally defined.
                else:
                    # IRIS EXPLAIN: Store (0, 0) in (failed, success); later lines use this named result.
                    failed, success = 0, 0
                    # IRIS EXPLAIN: Store int(rng.integers(15, 160)) when label == 'reconnaissance'; otherwise
                    # IRIS EXPLAIN: int(rng.integers(10, 90)) in n; later lines use this named result.
                    n = int(rng.integers(15, 160)) if label == "reconnaissance" else int(rng.integers(10, 90))
                    # IRIS EXPLAIN: Store int(rng.integers(1, 8)) in rules; later lines use this named result.
                    rules = int(rng.integers(1, 8))
                    # IRIS EXPLAIN: Store int(rng.choice([4, 7, 10])) in max_level; later lines use this named result.
                    max_level = int(rng.choice([4, 7, 10]))
                # IRIS EXPLAIN: Store float(rng.uniform(5, 90)) in duration; later lines use this named result.
                duration = float(rng.uniform(5, 90))
                # IRIS EXPLAIN: Store the result of validate_features({'event_family': family, 'primary_protocol': 'SSH' if
                # IRIS EXPLAIN: family == 'authentication' else 'TC... in features; later lines use this named result.
                features = validate_features({
                    # IRIS EXPLAIN: Set/describe these existing record fields: event_family: observed telemetry family; a Model
                    # IRIS EXPLAIN: 1 categorical predictor, not a truth label; primary_protocol: observed protocol used as a
                    # IRIS EXPLAIN: categorical predictor.
                    "event_family": family, "primary_protocol": "SSH" if family == "authentication" else "TCP",
                    # IRIS EXPLAIN: Set/describe these existing record fields: event_count: number of observed events in the
                    # IRIS EXPLAIN: session; duration_seconds: elapsed observed session time.
                    "event_count": n, "duration_seconds": duration,
                    # IRIS EXPLAIN: Set/describe these existing record fields: max_rule_level: highest observed SIEM severity on
                    # IRIS EXPLAIN: the 0-16 scale; mean_rule_level: mean observed SIEM severity.
                    "max_rule_level": max_level, "mean_rule_level": max_level * float(rng.uniform(.5, 1)),
                    # IRIS EXPLAIN: Set/describe these existing record fields: distinct_rules: number of unique rule identifiers
                    # IRIS EXPLAIN: in the session; distinct_sources: number of observed nonempty source addresses;
                    # IRIS EXPLAIN: distinct_accounts: number of observed known account names.
                    "distinct_rules": rules, "distinct_sources": 1, "distinct_accounts": 1 if family == "authentication" else 0,
                    # IRIS EXPLAIN: Set/describe these existing record fields: failed_count: observed failed authentication
                    # IRIS EXPLAIN: count; success_count: observed successful authentication count.
                    "failed_count": failed, "success_count": success,
                    # IRIS EXPLAIN: Set/describe these existing record fields: failure_ratio: failed divided by known
                    # IRIS EXPLAIN: authentication outcomes, with a safe zero-outcome fallback.
                    "failure_ratio": failed / (failed+success) if failed+success else 0,
                    # IRIS EXPLAIN: Set/describe these existing record fields: success_after_failures: whether observed success
                    # IRIS EXPLAIN: occurs after a failure.
                    "success_after_failures": int(failed > 0 and success > 0),
                    # IRIS EXPLAIN: Set/describe these existing record fields: max_events_in_10s: largest observed ten-second
                    # IRIS EXPLAIN: event burst.
                    "max_events_in_10s": max(1, min(n, int(n*float(rng.uniform(.1, .8))))),
                    # IRIS EXPLAIN: Set/describe these existing record fields: external_source_fraction: fraction of observed
                    # IRIS EXPLAIN: non-private/non-local source addresses; event_rate_per_minute: observed event count
                    # IRIS EXPLAIN: normalized by max(duration, 1 second).
                    "external_source_fraction": 0, "event_rate_per_minute": n*60/max(duration, 1),
                # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain
                # IRIS EXPLAIN: unchanged.
                })
                # IRIS EXPLAIN: Store a mapping containing asset_type, asset_criticality, current_likelihood, impact,
                # IRIS EXPLAIN: previous_similar_24h, controls, active_exception_control_ids in context; later lines use this
                # IRIS EXPLAIN: named result.
                context = {"asset_type": str(rng.choice(["workstation", "server"])),
                           # IRIS EXPLAIN: Set/describe these existing record fields: asset_criticality: pre-decision business
                           # IRIS EXPLAIN: criticality on the existing 1-5 scale; not a Model 1 telemetry input;
                           # IRIS EXPLAIN: current_likelihood: current working or pre-decision likelihood, according to this
                           # IRIS EXPLAIN: record's context.
                           "asset_criticality": int(rng.integers(1, 6)), "current_likelihood": int(rng.integers(1, 6)),
                           # IRIS EXPLAIN: Set/describe these existing record fields: impact: the same registered risk's impact;
                           # IRIS EXPLAIN: it must not be independently maximized across risks; previous_similar_24h: count of
                           # IRIS EXPLAIN: earlier completed similar sessions available inside this batch.
                           "impact": int(rng.integers(1, 6)), "previous_similar_24h": int(rng.integers(0, 4)),
                           # IRIS EXPLAIN: Set/describe these existing record fields: controls: control implementation context
                           # IRIS EXPLAIN: or separately identified recommendations; labels remain offline-only targets.
                           "controls": {"SC005": "implemented", "SC012": "partial", "SC029": "missing"},
                           # IRIS EXPLAIN: Set/describe these existing record fields: active_exception_control_ids: controls
                           # IRIS EXPLAIN: requiring exception/compensating-control review before a response.
                           "active_exception_control_ids": ["SC006"]}
                # IRIS EXPLAIN: Store a mapping containing session_id, run_id, campaign_id, data_provenance, sensor_healthy,
                # IRIS EXPLAIN: aggregation_schema, features and additional fields in observation; later lines use this named
                # IRIS EXPLAIN: result.
                observation = {"session_id": sid, "run_id": f"run-{label}-{replicate}",
                               # IRIS EXPLAIN: Set/describe these existing record fields: campaign_id: group provenance retained
                               # IRIS EXPLAIN: for split/session identity; not a telemetry predictor.
                               "campaign_id": f"synthetic-campaign-{campaign:02d}",
                               # IRIS EXPLAIN: Set/describe these existing record fields: data_provenance: explicit
                               # IRIS EXPLAIN: synthetic/cyber_range/operational source identity; sensor_healthy: explicit
                               # IRIS EXPLAIN: health evidence; a missing/false value must not be treated as benign.
                               "data_provenance": "synthetic", "sensor_healthy": True,
                               # IRIS EXPLAIN: Set/describe these existing record fields: aggregation_schema: the exact
                               # IRIS EXPLAIN: normalization/session-window contract used for training and inference.
                               "aggregation_schema": "iris-synthetic-session-v1",
                               # IRIS EXPLAIN: Continue the current record with features, context; each value comes from the
                               # IRIS EXPLAIN: expression shown on this unchanged line.
                               "features": features, "context": context,
                               # IRIS EXPLAIN: Set/describe these existing record fields: evidence_refs: source-file/line
                               # IRIS EXPLAIN: references retained for traceability.
                               "evidence_refs": ["synthetic fixture; no actual telemetry"]}
                # IRIS EXPLAIN: Store ['SC005', 'SC007'] when label == 'credential_access'; otherwise ['SC012', 'SC029'] when
                # IRIS EXPLAIN: label == 'reconnaissance'; otherwise [] in controls; later lines use this named result.
                controls = ["SC005", "SC007"] if label == "credential_access" else ["SC012", "SC029"] if label == "reconnaissance" else []
                # IRIS EXPLAIN: Enter this branch only when label == 'credential_access' and failed > 20.
                if label == "credential_access" and failed > 20:
                    # IRIS EXPLAIN: Call controls.append('SC006'): append one item to the working list.
                    controls.append("SC006")
                # IRIS EXPLAIN: Enter this branch only when label != 'benign' and context['asset_criticality'] >= 4.
                if label != "benign" and context["asset_criticality"] >= 4:
                    # IRIS EXPLAIN: Call controls.append('SC026'): append one item to the working list.
                    controls.append("SC026")
                # IRIS EXPLAIN: Call sessions.append(observation): append one item to the working list.
                sessions.append(observation)
                # IRIS EXPLAIN: Call reviews.append({'session_id': sid, 'run_id': observation['run_id'], 'campaign_id':
                # IRIS EXPLAIN: observation['campaign_id'], 'template_group': f'{label}-variant-{campaign ...: append one item
                # IRIS EXPLAIN: to the working list.
                reviews.append({"session_id": sid, "run_id": observation["run_id"],
                                # IRIS EXPLAIN: Set/describe these existing record fields: campaign_id: group provenance
                                # IRIS EXPLAIN: retained for split/session identity; not a telemetry predictor.
                                "campaign_id": observation["campaign_id"], "template_group": f"{label}-variant-{campaign % 5}",
                                # IRIS EXPLAIN: Set/describe these existing record fields: scenario_class: a reviewed training
                                # IRIS EXPLAIN: target or the explicitly identified prediction field; never silently added to
                                # IRIS EXPLAIN: telemetry predictors.
                                "scenario_class": label, "label_verified": True,
                                # IRIS EXPLAIN: Continue the current record with reviewer; each value comes from the expression
                                # IRIS EXPLAIN: shown on this unchanged line.
                                "reviewer": "SYNTHETIC_GENERATOR_NOT_AN_EXPERT",
                                # IRIS EXPLAIN: Continue the current record with recommended_control_ids, controls_reviewed;
                                # IRIS EXPLAIN: each value comes from the expression shown on this unchanged line.
                                "recommended_control_ids": controls, "controls_reviewed": True,
                                # IRIS EXPLAIN: Continue the current record with control_reviewer; each value comes from the
                                # IRIS EXPLAIN: expression shown on this unchanged line.
                                "control_reviewer": "SYNTHETIC_GENERATOR_NOT_AN_EXPERT"})
                # IRIS EXPLAIN: Enter this branch only when sample is None and label == 'credential_access'.
                if sample is None and label == "credential_access":
                    # IRIS EXPLAIN: Store observation in sample; later lines use this named result.
                    sample = observation
    # IRIS EXPLAIN: Store (destination / 'sessions.jsonl', destination / 'reviews.jsonl') in (sessions_path, reviews_path);
    # IRIS EXPLAIN: later lines use this named result.
    sessions_path, reviews_path = destination / "sessions.jsonl", destination / "reviews.jsonl"
    # IRIS EXPLAIN: Call write_jsonl(sessions_path, sessions) using the existing explicit arguments.
    write_jsonl(sessions_path, sessions)
    # IRIS EXPLAIN: Call write_jsonl(reviews_path, reviews) using the existing explicit arguments.
    write_jsonl(reviews_path, reviews)
    # IRIS EXPLAIN: Call write_json(destination / 'sample_session.json', sample) using the existing explicit arguments.
    write_json(destination / "sample_session.json", sample)
    # IRIS EXPLAIN: Return (sessions_path, reviews_path, sample) to the caller; this ends the current function path.
    return sessions_path, reviews_path, sample
