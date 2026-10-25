# IRIS EXPLAIN: File purpose: End-to-end three-source training/prediction wrappers; labels are opened only for offline
# IRIS EXPLAIN: supervised training.
# IRIS EXPLAIN: Existing documentation/literal text below is kept exactly as written; the explanation is outside the string so
# IRIS EXPLAIN: its value does not change.
"""Offline-only training labels and end-to-end three-input workflows."""
# IRIS EXPLAIN: Keep type annotations unevaluated at definition time; this does not add a model feature or change runtime
# IRIS EXPLAIN: settings.
from __future__ import annotations

# IRIS EXPLAIN: Import Path from pathlib to resolve server-owned paths without trusting uploaded filenames.
from pathlib import Path

# IRIS EXPLAIN: Import read_jsonl, write_json, write_jsonl from .contracts to reuse the shared project contract/implementation
# IRIS EXPLAIN: rather than duplicate it.
from .contracts import read_jsonl, write_json, write_jsonl
# IRIS EXPLAIN: Import ModelService from .runtime to reuse the shared project contract/implementation rather than duplicate it.
from .runtime import ModelService
# IRIS EXPLAIN: Import prepare_three from .three_sources to reuse the shared project contract/implementation rather than
# IRIS EXPLAIN: duplicate it.
from .three_sources import prepare_three
# IRIS EXPLAIN: Import train from .training to reuse the shared project contract/implementation rather than duplicate it.
from .training import train


# IRIS EXPLAIN: Function attach_reviews: Attach reviewed session labels or synthetic-only explicit event-membership annotations
# IRIS EXPLAIN: to prepared sessions; never manufacture labels during runtime inference.
# IRIS EXPLAIN: Inputs: sessions_path: prepared observed sessions, not labels; labels_path: offline reviewed annotations; not a
# IRIS EXPLAIN: runtime input; out: the destination path; existing safety checks govern overwrite behavior; synthetic: whether
# IRIS EXPLAIN: this offline experiment explicitly uses artificial data.
# IRIS EXPLAIN: Declared return type: dict; the return statements below show each actual result/fallback.
def attach_reviews(sessions_path: Path, labels_path: Path, out: Path, *, synthetic: bool) -> dict:
    # IRIS EXPLAIN: Store (read_jsonl(sessions_path), read_jsonl(labels_path)) in (sessions, labels); later lines use this named
    # IRIS EXPLAIN: result.
    sessions, labels = read_jsonl(sessions_path), read_jsonl(labels_path)
    # IRIS EXPLAIN: Enter this branch only when not labels.
    if not labels:
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Training labels are required; three
        # IRIS EXPLAIN: unlabeled operational sources are not supervised targets'); the caller's existing boundary determines
        # IRIS EXPLAIN: rollback or the HTTP diagnostic.
        raise ValueError("Training labels are required; three unlabeled operational sources are not supervised targets")
    # IRIS EXPLAIN: Enter this branch only when all(('session_id' in label for label in labels)).
    if all("session_id" in label for label in labels):
        # Existing reviewed-session format; the training loader verifies identity,
        # provenance, named reviewer, campaign/run alignment and supported labels.
        # IRIS EXPLAIN: Store the comprehension {session['session_id'] for session in sessions} in known; later lines use this
        # IRIS EXPLAIN: named result.
        known = {session["session_id"] for session in sessions}
        # IRIS EXPLAIN: Enter this branch only when any((label['session_id'] not in known for label in labels)).
        if any(label["session_id"] not in known for label in labels):
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Reviewed label references a session
            # IRIS EXPLAIN: absent from this integration'); the caller's existing boundary determines rollback or the HTTP
            # IRIS EXPLAIN: diagnostic.
            raise ValueError("Reviewed label references a session absent from this integration")
        # IRIS EXPLAIN: Call write_jsonl(out, labels) using the existing explicit arguments.
        write_jsonl(out, labels)
        # IRIS EXPLAIN: Return a mapping containing labels_written, format to the caller; this ends the current function path.
        return {"labels_written": len(labels), "format": "reviewed_session_labels"}
    # IRIS EXPLAIN: Enter this branch only when not synthetic.
    if not synthetic:
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Event-level generator annotations are
        # IRIS EXPLAIN: synthetic-only. Real data requires individually reviewed session_id labels after preparation.'); the
        # IRIS EXPLAIN: caller's existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError("Event-level generator annotations are synthetic-only. Real data requires individually reviewed session_id labels after preparation.")
    # IRIS EXPLAIN: Store a mapping containing  in event_case; later lines use this named result.
    event_case = {}
    # IRIS EXPLAIN: Iterate labels, binding each item to label; process only the existing observed/fixture collection.
    for label in labels:
        # IRIS EXPLAIN: Store the result of label.get('event_ids') (read an optional mapping field using its stated fallback) in
        # IRIS EXPLAIN: ids; later lines use this named result.
        ids = label.get("event_ids")
        # IRIS EXPLAIN: Enter this branch only when not isinstance(ids, list) or not ids or any((not isinstance(eid, str) or not
        # IRIS EXPLAIN: eid for eid in ids)).
        if not isinstance(ids, list) or not ids or any(not isinstance(eid, str) or not eid for eid in ids):
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Synthetic labels need explicit
            # IRIS EXPLAIN: event_ids'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError("Synthetic labels need explicit event_ids")
        # IRIS EXPLAIN: Iterate ids, binding each item to eid; process only the existing observed/fixture collection.
        for eid in ids:
            # IRIS EXPLAIN: Enter this branch only when eid in event_case.
            if eid in event_case:
                # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('An event appears in more than
                # IRIS EXPLAIN: one label annotation'); the caller's existing boundary determines rollback or the HTTP
                # IRIS EXPLAIN: diagnostic.
                raise ValueError("An event appears in more than one label annotation")
            # IRIS EXPLAIN: Store label in event_case[eid]; later lines use this named result.
            event_case[eid] = label
    # IRIS EXPLAIN: Store ([], []) in (reviews, omitted); later lines use this named result.
    reviews, omitted = [], []
    # IRIS EXPLAIN: Iterate sessions, binding each item to session; process only the existing observed/fixture collection.
    for session in sessions:
        # IRIS EXPLAIN: Store session['source_event_ids'] in members; later lines use this named result.
        members = session["source_event_ids"]
        # IRIS EXPLAIN: Store the comprehension [event_case.get(eid) for eid in members] in found; later lines use this named
        # IRIS EXPLAIN: result.
        found = [event_case.get(eid) for eid in members]
        # IRIS EXPLAIN: Enter this branch only when any((label is None for label in found)).
        if any(label is None for label in found):
            # IRIS EXPLAIN: Call omitted.append({'session_id': session['session_id'], 'reason': 'Some observed events have no
            # IRIS EXPLAIN: label annotation'}): append one item to the working list.
            omitted.append({"session_id": session["session_id"], "reason": "Some observed events have no label annotation"})
            # IRIS EXPLAIN: Skip the remainder of this iteration and move to the next item; do not fabricate an accepted result
            # IRIS EXPLAIN: for this skipped input.
            continue
        # IRIS EXPLAIN: Store found[0] in first; later lines use this named result.
        first = found[0]
        # IRIS EXPLAIN: Enter this branch only when any((label is not first for label in found)).
        if any(label is not first for label in found):
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('A session crosses distinct labeled
            # IRIS EXPLAIN: activities; do not majority-vote hidden labels'); the caller's existing boundary determines rollback
            # IRIS EXPLAIN: or the HTTP diagnostic.
            raise ValueError("A session crosses distinct labeled activities; do not majority-vote hidden labels")
        # IRIS EXPLAIN: Enter this branch only when session['data_provenance'] != 'synthetic'.
        if session["data_provenance"] != "synthetic":
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Generator annotation cannot be
            # IRIS EXPLAIN: attached to real data'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError("Generator annotation cannot be attached to real data")
        # IRIS EXPLAIN: Iterate ('campaign_id', 'run_id'), binding each item to key; process only the existing observed/fixture
        # IRIS EXPLAIN: collection.
        for key in ("campaign_id", "run_id"):
            # IRIS EXPLAIN: Enter this branch only when first.get(key) != session[key].
            if first.get(key) != session[key]:
                # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Annotation and observed session
                # IRIS EXPLAIN: disagree on campaign/run'); the caller's existing boundary determines rollback or the HTTP
                # IRIS EXPLAIN: diagnostic.
                raise ValueError("Annotation and observed session disagree on campaign/run")
        # IRIS EXPLAIN: Store the comprehension {k: first[k] for k in ('template_group', 'scenario_class', 'label_verified',
        # IRIS EXPLAIN: 'reviewer', 'recommended_control_ids', 'controls_reviewed', 'control_reviewer')} in fields; later lines
        # IRIS EXPLAIN: use this named result.
        fields = {k: first[k] for k in ("template_group", "scenario_class", "label_verified", "reviewer",
                                        # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these
                                        # IRIS EXPLAIN: existing arguments/items: "recommended_control_ids",
                                        # IRIS EXPLAIN: "controls_reviewed", "control_reviewer")}.
                                        "recommended_control_ids", "controls_reviewed", "control_reviewer")}
        # IRIS EXPLAIN: Call reviews.append({'session_id': session['session_id'], 'campaign_id': session['campaign_id'],
        # IRIS EXPLAIN: 'run_id': session['run_id'], **fields}): append one item to the working list.
        reviews.append({"session_id": session["session_id"], "campaign_id": session["campaign_id"],
                        # IRIS EXPLAIN: Set/describe these existing record fields: run_id: run/batch provenance retained for
                        # IRIS EXPLAIN: traceability; not a hidden attack-label feature.
                        "run_id": session["run_id"], **fields})
    # IRIS EXPLAIN: Call write_jsonl(out, reviews) using the existing explicit arguments.
    write_jsonl(out, reviews)
    # IRIS EXPLAIN: Return a mapping containing labels_written, format, omitted to the caller; this ends the current function
    # IRIS EXPLAIN: path.
    return {"labels_written": len(reviews), "format": "synthetic_explicit_event_membership", "omitted": omitted}


# IRIS EXPLAIN: Function train_three: Prepare the three sources, attach offline reviews, train both components, and retain
# IRIS EXPLAIN: integration-exclusion review as an additional release gate.
# IRIS EXPLAIN: Inputs: assets: the explicit assets input used by the unchanged statements below; risks: the time-valid
# IRIS EXPLAIN: registered risk snapshots; alerts: the explicit alerts input used by the unchanged statements below; labels: the
# IRIS EXPLAIN: supported catalogue/control or scenario identities for this calculation; catalog: the validated control
# IRIS EXPLAIN: catalogue; out: the destination path; existing safety checks govern overwrite behavior; synthetic: whether this
# IRIS EXPLAIN: offline experiment explicitly uses artificial data; group_by: the experiment independence unit: campaign,
# IRIS EXPLAIN: template family or run; seed: the reproducible random seed; window_seconds: the allowed inactivity window;
# IRIS EXPLAIN: serving must match the trained aggregation schema.
# IRIS EXPLAIN: Declared return type: dict; the return statements below show each actual result/fallback.
def train_three(assets: Path, risks: Path, alerts: Path, labels: Path, catalog: Path, out: Path,
                # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                # IRIS EXPLAIN: arguments/items: *, synthetic=False, group_by="campaign_id", seed=42, window_seconds=60) ->
                # IRIS EXPLAIN: dict:.
                *, synthetic=False, group_by="campaign_id", seed=42, window_seconds=60) -> dict:
    # IRIS EXPLAIN: Store the result of prepare_three(assets, risks, alerts, out / 'prepared', window_seconds=window_seconds) in
    # IRIS EXPLAIN: report; later lines use this named result.
    report = prepare_three(assets, risks, alerts, out / "prepared", window_seconds=window_seconds)
    # IRIS EXPLAIN: Enter this branch only when (report['data_provenance'] == 'synthetic') != synthetic.
    if (report["data_provenance"] == "synthetic") != synthetic:
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Synthetic sources require --synthetic;
        # IRIS EXPLAIN: real sources must not be called synthetic'); the caller's existing boundary determines rollback or the
        # IRIS EXPLAIN: HTTP diagnostic.
        raise ValueError("Synthetic sources require --synthetic; real sources must not be called synthetic")
    # IRIS EXPLAIN: Store the computed value out / 'prepared/reviews.jsonl' in reviews; later lines use this named result.
    reviews = out / "prepared/reviews.jsonl"
    # IRIS EXPLAIN: Store the result of attach_reviews(out / 'prepared/model_sessions.jsonl', labels, reviews,
    # IRIS EXPLAIN: synthetic=synthetic) in annotations; later lines use this named result.
    annotations = attach_reviews(out / "prepared/model_sessions.jsonl", labels, reviews, synthetic=synthetic)
    # IRIS EXPLAIN: Store the result of train(out / 'prepared/model_sessions.jsonl', reviews, catalog, out / 'models',
    # IRIS EXPLAIN: synthetic=synthetic, group_b... in metadata; later lines use this named result.
    metadata = train(out / "prepared/model_sessions.jsonl", reviews, catalog, out / "models",
                     # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                     # IRIS EXPLAIN: arguments/items: synthetic=synthetic, group_by=group_by, seed=seed).
                     synthetic=synthetic, group_by=group_by, seed=seed)
    # IRIS EXPLAIN: Store not (report['quarantine'] or report['conflicting_event_ids_excluded'] or
    # IRIS EXPLAIN: report['unresolved_asset_events']) in clean_integration; later lines use this named result.
    clean_integration = not (report["quarantine"] or report["conflicting_event_ids_excluded"] or report["unresolved_asset_events"])
    # IRIS EXPLAIN: Store a mapping containing report, annotation_join, source_files_used, labels_are_runtime_inputs in
    # IRIS EXPLAIN: metadata['three_source_integration']; later lines use this named result.
    metadata["three_source_integration"] = {"report": report, "annotation_join": annotations,
                                            # IRIS EXPLAIN: Continue the current record with source_files_used,
                                            # IRIS EXPLAIN: labels_are_runtime_inputs; each value comes from the expression
                                            # IRIS EXPLAIN: shown on this unchanged line.
                                            "source_files_used": 3, "labels_are_runtime_inputs": False}
    # IRIS EXPLAIN: Store clean_integration in metadata['model1']['checks']['three_source_exclusions_need_review']; later lines
    # IRIS EXPLAIN: use this named result.
    metadata["model1"]["checks"]["three_source_exclusions_need_review"] = clean_integration
    # IRIS EXPLAIN: Update metadata['model1']['eligible_for_reviewed_advisory_release'] using the existing BitAnd operation and
    # IRIS EXPLAIN: clean_integration.
    metadata["model1"]["eligible_for_reviewed_advisory_release"] &= clean_integration
    # IRIS EXPLAIN: Update metadata['model2']['eligible_for_reviewed_advisory_release'] using the existing BitAnd operation and
    # IRIS EXPLAIN: clean_integration.
    metadata["model2"]["eligible_for_reviewed_advisory_release"] &= clean_integration
    # IRIS EXPLAIN: Call write_json(out / 'models/metadata.json', metadata) using the existing explicit arguments.
    write_json(out / "models/metadata.json", metadata)
    # IRIS EXPLAIN: Return metadata to the caller; this ends the current function path.
    return metadata


# IRIS EXPLAIN: Function predict_three: Prepare only the three operational inputs, run a configured model service in the
# IRIS EXPLAIN: requested mode, and write predictions plus an honest full/limited-preview report.
# IRIS EXPLAIN: Inputs: assets: the explicit assets input used by the unchanged statements below; risks: the time-valid
# IRIS EXPLAIN: registered risk snapshots; alerts: the explicit alerts input used by the unchanged statements below; catalog:
# IRIS EXPLAIN: the validated control catalogue; out: the destination path; existing safety checks govern overwrite behavior;
# IRIS EXPLAIN: models: the explicit models input used by the unchanged statements below; mode: the existing
# IRIS EXPLAIN: rules/shadow/advisory choice, still governed by release checks; window_seconds: the allowed inactivity window;
# IRIS EXPLAIN: serving must match the trained aggregation schema; limit: the bounded maximum result/preview count.
# IRIS EXPLAIN: Declared return type: dict; the return statements below show each actual result/fallback.
def predict_three(assets: Path, risks: Path, alerts: Path, catalog: Path, out: Path,
                  # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                  # IRIS EXPLAIN: arguments/items: *, models: Path | None = None, mode="shadow", window_seconds=60, limit=None)
                  # IRIS EXPLAIN: -> dict:.
                  *, models: Path | None = None, mode="shadow", window_seconds=60, limit=None) -> dict:
    # IRIS EXPLAIN: Store the result of prepare_three(assets, risks, alerts, out / 'prepared', window_seconds=window_seconds) in
    # IRIS EXPLAIN: report; later lines use this named result.
    report = prepare_three(assets, risks, alerts, out / "prepared", window_seconds=window_seconds)
    # IRIS EXPLAIN: Store the result of read_jsonl(out / 'prepared/model_sessions.jsonl') in sessions; later lines use this
    # IRIS EXPLAIN: named result.
    sessions = read_jsonl(out / "prepared/model_sessions.jsonl")
    # IRIS EXPLAIN: Enter this branch only when limit is not None and (isinstance(limit, bool) or not isinstance(limit, int) or
    # IRIS EXPLAIN: limit < 1).
    if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int) or limit < 1):
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('limit must be a positive integer'); the
        # IRIS EXPLAIN: caller's existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError("limit must be a positive integer")
    # IRIS EXPLAIN: Store sessions when limit is None; otherwise sessions[:limit] in chosen; later lines use this named result.
    chosen = sessions if limit is None else sessions[:limit]
    # IRIS EXPLAIN: Store the result of ModelService(models, catalog) in service; later lines use this named result.
    service = ModelService(models, catalog)
    # IRIS EXPLAIN: Store the comprehension [service.predict(session, mode=mode) for session in chosen] in predictions; later
    # IRIS EXPLAIN: lines use this named result.
    predictions = [service.predict(session, mode=mode) for session in chosen]
    # IRIS EXPLAIN: Call write_jsonl(out / 'predictions.jsonl', predictions) using the existing explicit arguments.
    write_jsonl(out / "predictions.jsonl", predictions)
    # IRIS EXPLAIN: Store a mapping containing integrated_sources, total_sessions, predictions_written, limited_preview, mode,
    # IRIS EXPLAIN: training_labels_read, automatic_execution and additional fields in summary; later lines use this named
    # IRIS EXPLAIN: result.
    summary = {"integrated_sources": 3, "total_sessions": len(sessions), "predictions_written": len(predictions),
               # IRIS EXPLAIN: Continue the current record with limited_preview, mode; each value comes from the expression
               # IRIS EXPLAIN: shown on this unchanged line.
               "limited_preview": len(chosen) != len(sessions), "mode": mode,
               # IRIS EXPLAIN: Set/describe these existing record fields: training_labels_read: runtime provenance flag proving
               # IRIS EXPLAIN: labels are not operational inputs; automatic_execution: safety flag separating recommendations
               # IRIS EXPLAIN: from automatic control execution.
               "training_labels_read": False, "automatic_execution": False,
               # IRIS EXPLAIN: Continue the current record with integration_report; each value comes from the expression shown
               # IRIS EXPLAIN: on this unchanged line.
               "integration_report": report}
    # IRIS EXPLAIN: Call write_json(out / 'prediction_report.json', summary) using the existing explicit arguments.
    write_json(out / "prediction_report.json", summary)
    # IRIS EXPLAIN: Return summary to the caller; this ends the current function path.
    return summary
