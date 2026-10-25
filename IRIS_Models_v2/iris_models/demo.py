"""Artificial fixtures only: do not report these scores as detection evidence."""
from __future__ import annotations

from pathlib import Path

import numpy as np

from .contracts import CLASSES, validate_features, write_json, write_jsonl


def generate(destination: Path, seed: int = 123) -> tuple[Path, Path, dict]:
    if (destination / "sessions.jsonl").exists():
        raise ValueError("Demo output exists. Choose a fresh output directory.")
    rng = np.random.default_rng(seed)
    sessions, reviews = [], []
    sample = None
    for campaign in range(20):
        for label in CLASSES:
            for replicate in range(3):
                sid = f"DEMO-{campaign:02d}-{label}-{replicate}"
                family = "network" if label == "reconnaissance" or (label == "benign" and rng.random() < .2) else "authentication"
                if family == "authentication":
                    failed = int(rng.integers(8, 65)) if label == "credential_access" else int(rng.integers(0, 7))
                    success = int(rng.integers(0, 3)) if label == "credential_access" else int(rng.integers(1, 4))
                    n = failed + success + int(rng.integers(0, 5))
                    rules = min(n, int(rng.integers(1, 5)))
                    max_level = int(rng.integers(4, 12)) if label == "credential_access" else int(rng.integers(2, 8))
                else:
                    failed, success = 0, 0
                    n = int(rng.integers(15, 160)) if label == "reconnaissance" else int(rng.integers(10, 90))
                    rules = int(rng.integers(1, 8))
                    max_level = int(rng.choice([4, 7, 10]))
                duration = float(rng.uniform(5, 90))
                features = validate_features({
                    "event_family": family, "primary_protocol": "SSH" if family == "authentication" else "TCP",
                    "event_count": n, "duration_seconds": duration,
                    "max_rule_level": max_level, "mean_rule_level": max_level * float(rng.uniform(.5, 1)),
                    "distinct_rules": rules, "distinct_sources": 1, "distinct_accounts": 1 if family == "authentication" else 0,
                    "failed_count": failed, "success_count": success,
                    "failure_ratio": failed / (failed+success) if failed+success else 0,
                    "success_after_failures": int(failed > 0 and success > 0),
                    "max_events_in_10s": max(1, min(n, int(n*float(rng.uniform(.1, .8))))),
                    "external_source_fraction": 0, "event_rate_per_minute": n*60/max(duration, 1),
                })
                context = {"asset_type": str(rng.choice(["workstation", "server"])),
                           "asset_criticality": int(rng.integers(1, 6)), "current_likelihood": int(rng.integers(1, 6)),
                           "impact": int(rng.integers(1, 6)), "previous_similar_24h": int(rng.integers(0, 4)),
                           "controls": {"SC005": "implemented", "SC012": "partial", "SC029": "missing"},
                           "active_exception_control_ids": ["SC006"]}
                observation = {"session_id": sid, "run_id": f"run-{label}-{replicate}",
                               "campaign_id": f"synthetic-campaign-{campaign:02d}",
                               "data_provenance": "synthetic", "sensor_healthy": True,
                               "aggregation_schema": "iris-synthetic-session-v1",
                               "features": features, "context": context,
                               "evidence_refs": ["synthetic fixture; no actual telemetry"]}
                controls = ["SC005", "SC007"] if label == "credential_access" else ["SC012", "SC029"] if label == "reconnaissance" else []
                if label == "credential_access" and failed > 20:
                    controls.append("SC006")
                if label != "benign" and context["asset_criticality"] >= 4:
                    controls.append("SC026")
                sessions.append(observation)
                reviews.append({"session_id": sid, "run_id": observation["run_id"],
                                "campaign_id": observation["campaign_id"], "template_group": f"{label}-variant-{campaign % 5}",
                                "scenario_class": label, "label_verified": True,
                                "reviewer": "SYNTHETIC_GENERATOR_NOT_AN_EXPERT",
                                "recommended_control_ids": controls, "controls_reviewed": True,
                                "control_reviewer": "SYNTHETIC_GENERATOR_NOT_AN_EXPERT"})
                if sample is None and label == "credential_access":
                    sample = observation
    sessions_path, reviews_path = destination / "sessions.jsonl", destination / "reviews.jsonl"
    write_jsonl(sessions_path, sessions)
    write_jsonl(reviews_path, reviews)
    write_json(destination / "sample_session.json", sample)
    return sessions_path, reviews_path, sample
