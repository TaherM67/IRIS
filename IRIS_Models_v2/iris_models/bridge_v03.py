"""Optional adapters to the existing IRIS v0.3 Python engine; no core edits."""
from __future__ import annotations

from .contracts import FEATURES
from .runtime import ModelService
from . import __version__


def observation_from_context(context, *, likelihood=None, impact=None, previous_similar=0, sensor_healthy=False) -> dict:
    """Requires the caller to establish sensor health and time-valid GRC context."""
    session = context.session
    features = {key: getattr(session, key) for key in FEATURES}
    states = {c.control_id: c.implementation_state for c in context.controls}
    model_context = None
    if likelihood is not None and impact is not None:
        model_context = {"asset_type": context.asset.asset_type,
                         "asset_criticality": context.asset.criticality,
                         "current_likelihood": likelihood, "impact": impact,
                         "previous_similar_24h": previous_similar, "controls": states,
                         "active_exception_control_ids": [e.control_id for e in context.active_exceptions]}
    return {"session_id": session.session_id, "run_id": session.run_id, "features": features,
            "aggregation_schema": "iris-v03-wazuh-session-v1",
            "sensor_healthy": sensor_healthy, "evidence_refs": list(session.member_raw_refs),
            "context": model_context}


class ScenarioAssessorV1:
    """Implements assess(context), version and sha256 used by IRISEngine."""
    def __init__(self, service: ModelService, *, health_check, mode="shadow"):
        self.service, self.health_check, self.mode = service, health_check, mode

    @property
    def version(self):
        return f"iris-models-{__version__}"

    @property
    def sha256(self):
        return self.service.metadata["model_sha256"] if self.service.metadata else None

    def assess(self, context):
        from iris_engine.schemas import Assessment
        observation = observation_from_context(context, sensor_healthy=self.health_check(context) is True)
        output = self.service.predict(observation, mode=self.mode)
        primary = output["soc_assessment"]
        return Assessment(
            scenario_class=primary["scenario_class"], confidence=primary.get("confidence"),
            status=primary["status"], method=primary["method"], model_version=self.version,
            class_probabilities=primary.get("class_probabilities", {}),
            evidence_event_ids=context.session.member_event_ids,
            evidence_features=output["evidence_features"],
            warning="; ".join(output["warnings"]) or None,
        )


class ControlRecommenderV1:
    """Preserves the engine's recommend(...) call and explicit state policy."""
    def __init__(self, service: ModelService, *, health_check, mode="shadow"):
        self.service, self.health_check, self.mode = service, health_check, mode

    @property
    def version(self):
        return f"iris-models-{__version__}-controls"

    def recommend(self, context, assessment, current_likelihood, impact, previous_similar_sessions):
        from iris_engine.schemas import ControlRecommendation
        if assessment.status != "ASSESSED" or self.health_check(context) is not True:
            return [], {"status": "not_run", "source": "none", "reason": "No usable scenario/health evidence"}
        observation = observation_from_context(context, likelihood=current_likelihood, impact=impact,
                                               previous_similar=previous_similar_sessions, sensor_healthy=True)
        matching_contract = (self.service.metadata is not None and self.service.metadata.get("aggregation_schema") == observation["aggregation_schema"])
        use_learned = (self.mode == "advisory" and assessment.method == "calibrated_model1"
                       and matching_contract and self.service.released("model1") and self.service.released("model2"))
        result = self.service._controls(assessment.scenario_class, observation["features"], observation["context"], learned=use_learned)
        recommendations = [ControlRecommendation(
            control_id=r["control_id"], control_name=r["name"], score=r["model_score"] or 0,
            current_state=r["current_state"], action_type=r["action_type"],
            recommended_action=r["catalogue_action"], source=result["source"], warnings=r["warnings"],
        ) for r in result["recommendations"]]
        return recommendations, {"status": "advisory", "source": result["source"],
                                 "model_version": self.version, "warnings": result.get("warnings", [])}
