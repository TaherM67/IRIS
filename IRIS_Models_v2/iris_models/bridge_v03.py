# IRIS EXPLAIN: File purpose: Optional compatibility adapters for the separate legacy v0.3 engine; preserve its
# IRIS EXPLAIN: assessment/recommendation interfaces without rewriting its core.
# IRIS EXPLAIN: Existing documentation/literal text below is kept exactly as written; the explanation is outside the string so
# IRIS EXPLAIN: its value does not change.
"""Optional adapters to the existing IRIS v0.3 Python engine; no core edits."""
# IRIS EXPLAIN: Keep type annotations unevaluated at definition time; this does not add a model feature or change runtime
# IRIS EXPLAIN: settings.
from __future__ import annotations

# IRIS EXPLAIN: Import FEATURES from .contracts to reuse the shared project contract/implementation rather than duplicate it.
from .contracts import FEATURES
# IRIS EXPLAIN: Import ModelService from .runtime to reuse the shared project contract/implementation rather than duplicate it.
from .runtime import ModelService
# IRIS EXPLAIN: Import __version__ from . to reuse the shared project contract/implementation rather than duplicate it.
from . import __version__


# IRIS EXPLAIN: Function observation_from_context: Adapt the legacy engine context into telemetry features and optional
# IRIS EXPLAIN: time-valid risk context; the caller must establish health and provenance.
# IRIS EXPLAIN: Inputs: context: existing pre-decision business/control context; likelihood: the explicit likelihood input used
# IRIS EXPLAIN: by the unchanged statements below; impact: the explicit impact input used by the unchanged statements below;
# IRIS EXPLAIN: previous_similar: the explicit previous similar input used by the unchanged statements below; sensor_healthy:
# IRIS EXPLAIN: the explicit sensor healthy input used by the unchanged statements below.
# IRIS EXPLAIN: Declared return type: dict; the return statements below show each actual result/fallback.
def observation_from_context(context, *, likelihood=None, impact=None, previous_similar=0, sensor_healthy=False) -> dict:
    # IRIS EXPLAIN: Existing documentation/literal text below is kept exactly as written; the explanation is outside the string
    # IRIS EXPLAIN: so its value does not change.
    """Requires the caller to establish sensor health and time-valid GRC context."""
    # IRIS EXPLAIN: Store context.session in session; later lines use this named result.
    session = context.session
    # IRIS EXPLAIN: Store the comprehension {key: getattr(session, key) for key in FEATURES} in features; later lines use this
    # IRIS EXPLAIN: named result.
    features = {key: getattr(session, key) for key in FEATURES}
    # IRIS EXPLAIN: Store the comprehension {c.control_id: c.implementation_state for c in context.controls} in states; later
    # IRIS EXPLAIN: lines use this named result.
    states = {c.control_id: c.implementation_state for c in context.controls}
    # IRIS EXPLAIN: Store None (no result/value) in model_context; later lines use this named result.
    model_context = None
    # IRIS EXPLAIN: Enter this branch only when likelihood is not None and impact is not None.
    if likelihood is not None and impact is not None:
        # IRIS EXPLAIN: Store a mapping containing asset_type, asset_criticality, current_likelihood, impact,
        # IRIS EXPLAIN: previous_similar_24h, controls, active_exception_control_ids in model_context; later lines use this
        # IRIS EXPLAIN: named result.
        model_context = {"asset_type": context.asset.asset_type,
                         # IRIS EXPLAIN: Set/describe these existing record fields: asset_criticality: pre-decision business
                         # IRIS EXPLAIN: criticality on the existing 1-5 scale; not a Model 1 telemetry input.
                         "asset_criticality": context.asset.criticality,
                         # IRIS EXPLAIN: Set/describe these existing record fields: current_likelihood: current working or
                         # IRIS EXPLAIN: pre-decision likelihood, according to this record's context; impact: the same
                         # IRIS EXPLAIN: registered risk's impact; it must not be independently maximized across risks.
                         "current_likelihood": likelihood, "impact": impact,
                         # IRIS EXPLAIN: Set/describe these existing record fields: previous_similar_24h: count of earlier
                         # IRIS EXPLAIN: completed similar sessions available inside this batch; controls: control
                         # IRIS EXPLAIN: implementation context or separately identified recommendations; labels remain
                         # IRIS EXPLAIN: offline-only targets.
                         "previous_similar_24h": previous_similar, "controls": states,
                         # IRIS EXPLAIN: Set/describe these existing record fields: active_exception_control_ids: controls
                         # IRIS EXPLAIN: requiring exception/compensating-control review before a response.
                         "active_exception_control_ids": [e.control_id for e in context.active_exceptions]}
    # IRIS EXPLAIN: Return a mapping containing session_id, run_id, features, aggregation_schema, sensor_healthy, evidence_refs,
    # IRIS EXPLAIN: context to the caller; this ends the current function path.
    return {"session_id": session.session_id, "run_id": session.run_id, "features": features,
            # IRIS EXPLAIN: Set/describe these existing record fields: aggregation_schema: the exact
            # IRIS EXPLAIN: normalization/session-window contract used for training and inference.
            "aggregation_schema": "iris-v03-wazuh-session-v1",
            # IRIS EXPLAIN: Set/describe these existing record fields: sensor_healthy: explicit health evidence; a missing/false
            # IRIS EXPLAIN: value must not be treated as benign; evidence_refs: source-file/line references retained for
            # IRIS EXPLAIN: traceability.
            "sensor_healthy": sensor_healthy, "evidence_refs": list(session.member_raw_refs),
            # IRIS EXPLAIN: Continue the current record with context; each value comes from the expression shown on this
            # IRIS EXPLAIN: unchanged line.
            "context": model_context}


# IRIS EXPLAIN: Class ScenarioAssessorV1: Compatibility wrapper exposing the legacy scenario-assessment interface.
class ScenarioAssessorV1:
    # IRIS EXPLAIN: Existing documentation/literal text below is kept exactly as written; the explanation is outside the string
    # IRIS EXPLAIN: so its value does not change.
    """Implements assess(context), version and sha256 used by IRISEngine."""
    # IRIS EXPLAIN: Function ScenarioAssessorV1.__init__: Keep the shared model service, explicit health-check callback and
    # IRIS EXPLAIN: selected inference mode for the legacy assessment interface.
    # IRIS EXPLAIN: Inputs: service: the explicit service input used by the unchanged statements below; health_check: the
    # IRIS EXPLAIN: explicit health check input used by the unchanged statements below; mode: the existing rules/shadow/advisory
    # IRIS EXPLAIN: choice, still governed by release checks.
    def __init__(self, service: ModelService, *, health_check, mode="shadow"):
        # IRIS EXPLAIN: Store (service, health_check, mode) in (self.service, self.health_check, self.mode); later lines use
        # IRIS EXPLAIN: this named result.
        self.service, self.health_check, self.mode = service, health_check, mode

    # IRIS EXPLAIN: Expose the following read-only method as a computed attribute rather than a caller-invoked command.
    @property
    # IRIS EXPLAIN: Function ScenarioAssessorV1.version: Expose the adapter/package version for traceability rather than a
    # IRIS EXPLAIN: learned feature.
    def version(self):
        # IRIS EXPLAIN: Return the formatted text f'iris-models-{__version__}' to the caller; this ends the current function
        # IRIS EXPLAIN: path.
        return f"iris-models-{__version__}"

    # IRIS EXPLAIN: Expose the following read-only method as a computed attribute rather than a caller-invoked command.
    @property
    # IRIS EXPLAIN: Function ScenarioAssessorV1.sha256: Expose the loaded model content hash when metadata is available,
    # IRIS EXPLAIN: otherwise None.
    def sha256(self):
        # IRIS EXPLAIN: Return self.service.metadata['model_sha256'] when self.service.metadata; otherwise None (no
        # IRIS EXPLAIN: result/value) to the caller; this ends the current function path.
        return self.service.metadata["model_sha256"] if self.service.metadata else None

    # IRIS EXPLAIN: Function ScenarioAssessorV1.assess: Build a health-checked observation, call the shared model service, and
    # IRIS EXPLAIN: translate its primary result to the legacy Assessment schema.
    # IRIS EXPLAIN: Inputs: context: existing pre-decision business/control context.
    def assess(self, context):
        # IRIS EXPLAIN: Import Assessment from iris_engine.schemas to reuse the shared project contract/implementation rather
        # IRIS EXPLAIN: than duplicate it.
        from iris_engine.schemas import Assessment
        # IRIS EXPLAIN: Store the result of observation_from_context(context, sensor_healthy=self.health_check(context) is True)
        # IRIS EXPLAIN: in observation; later lines use this named result.
        observation = observation_from_context(context, sensor_healthy=self.health_check(context) is True)
        # IRIS EXPLAIN: Store the result of self.service.predict(observation, mode=self.mode) (obtain the configured prediction
        # IRIS EXPLAIN: result without training on this call) in output; later lines use this named result.
        output = self.service.predict(observation, mode=self.mode)
        # IRIS EXPLAIN: Store output['soc_assessment'] in primary; later lines use this named result.
        primary = output["soc_assessment"]
        # IRIS EXPLAIN: Return the result of Assessment(scenario_class=primary['scenario_class'],
        # IRIS EXPLAIN: confidence=primary.get('confidence'), status=primary['... to the caller; this ends the current function
        # IRIS EXPLAIN: path.
        return Assessment(
            # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
            # IRIS EXPLAIN: scenario_class=primary["scenario_class"], confidence=primary.get("confidence"),.
            scenario_class=primary["scenario_class"], confidence=primary.get("confidence"),
            # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
            # IRIS EXPLAIN: status=primary["status"], method=primary["method"], model_version=self.version,.
            status=primary["status"], method=primary["method"], model_version=self.version,
            # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
            # IRIS EXPLAIN: class_probabilities=primary.get("class_probabilities", {}),.
            class_probabilities=primary.get("class_probabilities", {}),
            # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
            # IRIS EXPLAIN: evidence_event_ids=context.session.member_event_ids,.
            evidence_event_ids=context.session.member_event_ids,
            # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
            # IRIS EXPLAIN: evidence_features=output["evidence_features"],.
            evidence_features=output["evidence_features"],
            # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
            # IRIS EXPLAIN: warning="; ".join(output["warnings"]) or None,.
            warning="; ".join(output["warnings"]) or None,
        # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain
        # IRIS EXPLAIN: unchanged.
        )


# IRIS EXPLAIN: Class ControlRecommenderV1: Compatibility wrapper exposing the legacy control-recommendation interface.
class ControlRecommenderV1:
    # IRIS EXPLAIN: Existing documentation/literal text below is kept exactly as written; the explanation is outside the string
    # IRIS EXPLAIN: so its value does not change.
    """Preserves the engine's recommend(...) call and explicit state policy."""
    # IRIS EXPLAIN: Function ControlRecommenderV1.__init__: Keep the shared model service and health/mode settings for the
    # IRIS EXPLAIN: legacy recommendation interface.
    # IRIS EXPLAIN: Inputs: service: the explicit service input used by the unchanged statements below; health_check: the
    # IRIS EXPLAIN: explicit health check input used by the unchanged statements below; mode: the existing rules/shadow/advisory
    # IRIS EXPLAIN: choice, still governed by release checks.
    def __init__(self, service: ModelService, *, health_check, mode="shadow"):
        # IRIS EXPLAIN: Store (service, health_check, mode) in (self.service, self.health_check, self.mode); later lines use
        # IRIS EXPLAIN: this named result.
        self.service, self.health_check, self.mode = service, health_check, mode

    # IRIS EXPLAIN: Expose the following read-only method as a computed attribute rather than a caller-invoked command.
    @property
    # IRIS EXPLAIN: Function ControlRecommenderV1.version: Expose the adapter/package version for traceability rather than a
    # IRIS EXPLAIN: learned feature.
    def version(self):
        # IRIS EXPLAIN: Return the formatted text f'iris-models-{__version__}-controls' to the caller; this ends the current
        # IRIS EXPLAIN: function path.
        return f"iris-models-{__version__}-controls"

    # IRIS EXPLAIN: Function ControlRecommenderV1.recommend: Require an assessed, healthy legacy case and compatible released
    # IRIS EXPLAIN: models before learned advice; return control recommendations with explicit current-state/exception handling.
    # IRIS EXPLAIN: Inputs: context: existing pre-decision business/control context; assessment: the explicit assessment input
    # IRIS EXPLAIN: used by the unchanged statements below; current_likelihood: the explicit current likelihood input used by
    # IRIS EXPLAIN: the unchanged statements below; impact: the explicit impact input used by the unchanged statements below;
    # IRIS EXPLAIN: previous_similar_sessions: the explicit previous similar sessions input used by the unchanged statements
    # IRIS EXPLAIN: below.
    def recommend(self, context, assessment, current_likelihood, impact, previous_similar_sessions):
        # IRIS EXPLAIN: Import ControlRecommendation from iris_engine.schemas to reuse the shared project
        # IRIS EXPLAIN: contract/implementation rather than duplicate it.
        from iris_engine.schemas import ControlRecommendation
        # IRIS EXPLAIN: Enter this branch only when assessment.status != 'ASSESSED' or self.health_check(context) is not True.
        if assessment.status != "ASSESSED" or self.health_check(context) is not True:
            # IRIS EXPLAIN: Return ([], {'status': 'not_run', 'source': 'none', 'reason': 'No usable scenario/health evidence'})
            # IRIS EXPLAIN: to the caller; this ends the current function path.
            return [], {"status": "not_run", "source": "none", "reason": "No usable scenario/health evidence"}
        # IRIS EXPLAIN: Store the result of observation_from_context(context, likelihood=current_likelihood, impact=impact,
        # IRIS EXPLAIN: previous_similar=previous_s... in observation; later lines use this named result.
        observation = observation_from_context(context, likelihood=current_likelihood, impact=impact,
                                               # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with
                                               # IRIS EXPLAIN: these existing arguments/items:
                                               # IRIS EXPLAIN: previous_similar=previous_similar_sessions, sensor_healthy=True).
                                               previous_similar=previous_similar_sessions, sensor_healthy=True)
        # IRIS EXPLAIN: Store self.service.metadata is not None and self.service.metadata.get('aggregation_schema') ==
        # IRIS EXPLAIN: observation['aggregation_schema'] in matching_contract; later lines use this named result.
        matching_contract = (self.service.metadata is not None and self.service.metadata.get("aggregation_schema") == observation["aggregation_schema"])
        # IRIS EXPLAIN: Store self.mode == 'advisory' and assessment.method == 'calibrated_model1' and matching_contract and
        # IRIS EXPLAIN: self.service.released('model1') and self.service.rel... in use_learned; later lines use this named
        # IRIS EXPLAIN: result.
        use_learned = (self.mode == "advisory" and assessment.method == "calibrated_model1"
                       # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                       # IRIS EXPLAIN: arguments/items: and matching_contract and self.service.released("model1") and
                       # IRIS EXPLAIN: self.service.released("model2")).
                       and matching_contract and self.service.released("model1") and self.service.released("model2"))
        # IRIS EXPLAIN: Store the result of self.service._controls(assessment.scenario_class, observation['features'],
        # IRIS EXPLAIN: observation['context'], learned=... in result; later lines use this named result.
        result = self.service._controls(assessment.scenario_class, observation["features"], observation["context"], learned=use_learned)
        # IRIS EXPLAIN: Store the comprehension [ControlRecommendation(control_id=r['control_id'], control_name=r['name'],
        # IRIS EXPLAIN: score=r['model_score'] or 0, current_state=r['current_state'], action_type=r['action_type'], reco... in
        # IRIS EXPLAIN: recommendations; later lines use this named result.
        recommendations = [ControlRecommendation(
            # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
            # IRIS EXPLAIN: control_id=r["control_id"], control_name=r["name"], score=r["model_score"] or 0,.
            control_id=r["control_id"], control_name=r["name"], score=r["model_score"] or 0,
            # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
            # IRIS EXPLAIN: current_state=r["current_state"], action_type=r["action_type"],.
            current_state=r["current_state"], action_type=r["action_type"],
            # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
            # IRIS EXPLAIN: recommended_action=r["catalogue_action"], source=result["source"], warnings=r["warnings"],.
            recommended_action=r["catalogue_action"], source=result["source"], warnings=r["warnings"],
        # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain
        # IRIS EXPLAIN: unchanged.
        ) for r in result["recommendations"]]
        # IRIS EXPLAIN: Return (recommendations, {'status': 'advisory', 'source': result['source'], 'model_version':
        # IRIS EXPLAIN: self.version, 'warnings': result.get('warnings', [])}) to the caller; this ends the current function
        # IRIS EXPLAIN: path.
        return recommendations, {"status": "advisory", "source": result["source"],
                                 # IRIS EXPLAIN: Continue the current record with model_version, warnings; each value comes from
                                 # IRIS EXPLAIN: the expression shown on this unchanged line.
                                 "model_version": self.version, "warnings": result.get("warnings", [])}
