"""Offline-only training labels and end-to-end three-input workflows."""
from __future__ import annotations

from pathlib import Path

from .contracts import read_jsonl, write_json, write_jsonl
from .runtime import ModelService
from .three_sources import prepare_three
from .training import train


def attach_reviews(sessions_path: Path, labels_path: Path, out: Path, *, synthetic: bool) -> dict:
    sessions, labels = read_jsonl(sessions_path), read_jsonl(labels_path)
    if not labels:
        raise ValueError("Training labels are required; three unlabeled operational sources are not supervised targets")
    if all("session_id" in label for label in labels):
        # Existing reviewed-session format; the training loader verifies identity,
        # provenance, named reviewer, campaign/run alignment and supported labels.
        known = {session["session_id"] for session in sessions}
        if any(label["session_id"] not in known for label in labels):
            raise ValueError("Reviewed label references a session absent from this integration")
        write_jsonl(out, labels)
        return {"labels_written": len(labels), "format": "reviewed_session_labels"}
    if not synthetic:
        raise ValueError("Event-level generator annotations are synthetic-only. Real data requires individually reviewed session_id labels after preparation.")
    event_case = {}
    for label in labels:
        ids = label.get("event_ids")
        if not isinstance(ids, list) or not ids or any(not isinstance(eid, str) or not eid for eid in ids):
            raise ValueError("Synthetic labels need explicit event_ids")
        for eid in ids:
            if eid in event_case:
                raise ValueError("An event appears in more than one label annotation")
            event_case[eid] = label
    reviews, omitted = [], []
    for session in sessions:
        members = session["source_event_ids"]
        found = [event_case.get(eid) for eid in members]
        if any(label is None for label in found):
            omitted.append({"session_id": session["session_id"], "reason": "Some observed events have no label annotation"})
            continue
        first = found[0]
        if any(label is not first for label in found):
            raise ValueError("A session crosses distinct labeled activities; do not majority-vote hidden labels")
        if session["data_provenance"] != "synthetic":
            raise ValueError("Generator annotation cannot be attached to real data")
        for key in ("campaign_id", "run_id"):
            if first.get(key) != session[key]:
                raise ValueError("Annotation and observed session disagree on campaign/run")
        fields = {k: first[k] for k in ("template_group", "scenario_class", "label_verified", "reviewer",
                                        "recommended_control_ids", "controls_reviewed", "control_reviewer")}
        reviews.append({"session_id": session["session_id"], "campaign_id": session["campaign_id"],
                        "run_id": session["run_id"], **fields})
    write_jsonl(out, reviews)
    return {"labels_written": len(reviews), "format": "synthetic_explicit_event_membership", "omitted": omitted}


def train_three(assets: Path, risks: Path, alerts: Path, labels: Path, catalog: Path, out: Path,
                *, synthetic=False, group_by="campaign_id", seed=42, window_seconds=60) -> dict:
    report = prepare_three(assets, risks, alerts, out / "prepared", window_seconds=window_seconds)
    if (report["data_provenance"] == "synthetic") != synthetic:
        raise ValueError("Synthetic sources require --synthetic; real sources must not be called synthetic")
    reviews = out / "prepared/reviews.jsonl"
    annotations = attach_reviews(out / "prepared/model_sessions.jsonl", labels, reviews, synthetic=synthetic)
    metadata = train(out / "prepared/model_sessions.jsonl", reviews, catalog, out / "models",
                     synthetic=synthetic, group_by=group_by, seed=seed)
    clean_integration = not (report["quarantine"] or report["conflicting_event_ids_excluded"] or report["unresolved_asset_events"])
    metadata["three_source_integration"] = {"report": report, "annotation_join": annotations,
                                            "source_files_used": 3, "labels_are_runtime_inputs": False}
    metadata["model1"]["checks"]["three_source_exclusions_need_review"] = clean_integration
    metadata["model1"]["eligible_for_reviewed_advisory_release"] &= clean_integration
    metadata["model2"]["eligible_for_reviewed_advisory_release"] &= clean_integration
    write_json(out / "models/metadata.json", metadata)
    return metadata


def predict_three(assets: Path, risks: Path, alerts: Path, catalog: Path, out: Path,
                  *, models: Path | None = None, mode="shadow", window_seconds=60, limit=None) -> dict:
    report = prepare_three(assets, risks, alerts, out / "prepared", window_seconds=window_seconds)
    sessions = read_jsonl(out / "prepared/model_sessions.jsonl")
    if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int) or limit < 1):
        raise ValueError("limit must be a positive integer")
    chosen = sessions if limit is None else sessions[:limit]
    service = ModelService(models, catalog)
    predictions = [service.predict(session, mode=mode) for session in chosen]
    write_jsonl(out / "predictions.jsonl", predictions)
    summary = {"integrated_sources": 3, "total_sessions": len(sessions), "predictions_written": len(predictions),
               "limited_preview": len(chosen) != len(sessions), "mode": mode,
               "training_labels_read": False, "automatic_execution": False,
               "integration_report": report}
    write_json(out / "prediction_report.json", summary)
    return summary
