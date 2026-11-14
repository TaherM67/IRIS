"""Grounding gates may withhold a score; they must never invent support."""
import copy
import types
import unittest
from backend.grounded_adapter import GroundedModelAdapter,public_review,GROUNDING_POLICY
from backend.grounded_context import SCHEMA

def match(a,b):
    return bool(a and b and (a==b or a.split(".")[0]==b.split(".")[0]))

class GroundingGateTests(unittest.TestCase):
    def fixture(self):
        adapter=GroundedModelAdapter.__new__(GroundedModelAdapter)
        adapter.metadata={"aggregation_schema":"iris-three-source-session-v1-window60"}
        adapter.reference=types.SimpleNamespace(technique_match=match)
        controls=[
          {"control_id":"C1","name":"Supported","applies_to":["server"],"mitigates_attack_techniques":["T1110"]},
          {"control_id":"C2","name":"Unregistered","applies_to":["server"],"mitigates_attack_techniques":["T1110"]},
          {"control_id":"C3","name":"Wrong technique","applies_to":["server"],"mitigates_attack_techniques":["T1046"]},
          {"control_id":"C4","name":"Wrong asset","applies_to":["cloud"],"mitigates_attack_techniques":["T1110"]}]
        adapter.catalogue=controls;adapter.controls={r["control_id"]:r for r in controls}
        rows=[{"control_id":r["control_id"],"name":r["name"],"model_score":.99} for r in controls]
        adapter.grounded=types.SimpleNamespace(recommend=lambda *args:{"source":"experimental_grounded_candidate_model","recommendations":copy.deepcopy(rows)})
        risk={"asset_id":"A1","risk_id":"R1","risk_version_id":"R1V1","existing_control_ids":["C1","C3","C4"],
              "planned_control_ids":[],"mitre_attack_techniques":["T1110"]}
        session={"asset_id":"A1","data_provenance":"synthetic","sensor_healthy":True,
                 "aggregation_schema":adapter.metadata["aggregation_schema"],"source_event_ids":["E1"],
                 "features":{"event_count":1},"risk_snapshots":[{"risk_id":"R1","risk_version_id":"R1V1","control_states":{"C1":"partial"}}],
                 "context":{"asset_criticality":3,"current_likelihood":2,"impact":4},
                 "model2_context":{"schema":SCHEMA,"asset":{"asset_id":"A1","control_groups":["server"]},
                   "alerts":[{"alert_id":"E1","mitre_technique":"T1110"}],"registered_risks":[risk],
                   "missing_fields":[],"membership_basis":"versioned_runtime_risk_snapshots"}}
        return adapter,session

    def test_unregistered_unrelated_and_inapplicable_high_scores_are_withheld(self):
        adapter,s=self.fixture()
        r=adapter._review(s)
        self.assertEqual([c["control_id"] for c in r["recommendations"]],["C1"])
        self.assertEqual(r["withheld_candidate_count"],3)
        self.assertEqual(r["grounding_policy"],GROUNDING_POLICY)
        reasons={reason for row in r["withheld_candidates"] for reason in row["reason_codes"]}
        self.assertEqual(reasons,{"no_registered_risk_link_matching_observed_technique","catalogue_technique_mismatch","asset_applicability_mismatch"})

    def test_accepted_advice_has_real_event_and_risk_links_and_retains_known_state(self):
        adapter,s=self.fixture();r=adapter._review(s)["recommendations"][0]
        self.assertEqual(r["matched_risk_ids"],["R1"])
        self.assertEqual(r["supporting_event_ids"],["E1"])
        self.assertEqual(r["current_state"],"partial")
        self.assertEqual(r["action_type"],"review")

    def test_business_projection_does_not_leak_raw_event_ids_or_scores(self):
        adapter,s=self.fixture();review=adapter._review(s);public=public_review(review)
        text=str(public)
        self.assertNotIn("model_score",text)
        self.assertNotIn("supporting_event_ids",text)
        self.assertNotIn("withheld_candidates",text)
        self.assertEqual(public["withheld_candidate_count"],3)

    def test_separate_techniques_cannot_fabricate_one_evidence_chain(self):
        adapter,s=self.fixture()
        s["source_event_ids"].append("E2")
        s["features"]["event_count"]=2
        s["model2_context"]["alerts"].append({"alert_id":"E2","mitre_technique":"T1046"})
        review=adapter._review(s)
        self.assertEqual([r["control_id"] for r in review["recommendations"]],["C1"])
        withheld=next(r for r in review["withheld_candidates"] if r["control_id"]=="C3")
        self.assertIn("no_shared_observed_technique_for_risk_and_control",withheld["reason_codes"])
