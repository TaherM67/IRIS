"""Acceptance cases for the expanded generation agreement and ambiguity reports."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from backend.input_contract import CONTRACT, FILES, validate_inputs
from backend.coverage import probability_diagnostics, session_outcome, summarize

class ContractTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory=Path(self.temp.name)
        self.data={}
        for key,name in FILES.items():
            p=CONTRACT/"example"/name
            self.data[key]=([json.loads(s) for s in p.read_text().splitlines()] if key=="siem_alerts"
                            else json.loads(p.read_text()))
    def check(self):
        paths={}
        for key,name in FILES.items():
            p=self.directory/name
            p.write_text("".join(json.dumps(x)+"\n" for x in self.data[key]) if key=="siem_alerts"
                         else json.dumps(self.data[key]))
            paths[key]=p
        return validate_inputs(paths)
    def test_clean_example_conserves_events_without_loading_weights(self):
        with mock.patch("joblib.load",side_effect=AssertionError("no weight loading")):
            r=self.check()
        self.assertTrue(r["valid"],r["errors"])
        self.assertEqual(r["counts"]["prepared_sessions"],7)
        self.assertEqual(r["readiness"]["model1_input_ready_sessions"],7)
        self.assertTrue(r["readiness"]["all_events_accounted_for"])
        self.assertFalse(r["model_weights_loaded"])
    def test_missing_technique_is_explained_without_fabrication(self):
        r=self.check()
        self.assertEqual(r["readiness"]["model2_complete_context_sessions"],6)
        self.assertEqual(r["readiness"]["model2_missing_field_counts"],{"alerts.mitre_technique":1})
    def test_unsupported_protocol_reports_exact_line(self):
        self.data["siem_alerts"][0]["protocol"]="UDP"
        r=self.check()
        self.assertFalse(r["valid"])
        self.assertTrue(any(e["path"]=="siem_alerts.jsonl#L1.protocol" for e in r["errors"]))
    def test_runtime_ground_truth_is_rejected(self):
        self.data["siem_alerts"][0]["scenario_class"]="benign"
        self.assertTrue(any("scenario_class" in e["path"] for e in self.check()["errors"]))
    def test_missing_measurement_is_not_replaced_with_zero(self):
        del self.data["siem_alerts"][0]["process_unsigned"]
        self.assertFalse(self.check()["valid"])
    def test_unknown_asset_is_not_silently_excluded(self):
        self.data["siem_alerts"][0]["asset_id"]="ABSENT-ASSET"
        self.assertFalse(self.check()["valid"])
    def test_unknown_control_is_rejected(self):
        self.data["risk_register"]["records"][0]["planned_control_ids"]=["CTL-FAKE-999"]
        self.assertFalse(self.check()["valid"])
    def test_state_keys_must_match_registered_membership(self):
        self.data["risk_register"]["records"][0]["control_states"]["CTL-IAM-999"]="implemented"
        self.assertTrue(any("control_states" in e["path"] for e in self.check()["errors"]))
    def test_duplicate_event_is_rejected(self):
        self.data["siem_alerts"].append(copy.deepcopy(self.data["siem_alerts"][0]))
        self.assertFalse(self.check()["valid"])
    def test_boolean_business_score_is_not_integer(self):
        self.data["risk_register"]["records"][0]["impact"]=True
        self.assertFalse(self.check()["valid"])
    def test_oversized_integer_is_a_validation_error_not_a_crash(self):
        self.data["risk_register"]["records"][0]["impact"]=10**1000
        self.assertFalse(self.check()["valid"])
    def test_future_inventory_cannot_explain_earlier_events(self):
        for r in self.data["asset_inventory"]["records"]:
            r["valid_from"]=r["recorded_at"]="2027-01-01T00:00:00Z"
        self.assertFalse(self.check()["valid"])
    def test_late_recorded_inventory_is_not_available_in_the_past(self):
        for r in self.data["asset_inventory"]["records"]:r["recorded_at"]="2027-01-01T00:00:00Z"
        self.assertFalse(self.check()["valid"])
    def test_outbound_remote_ip_cannot_become_monitored_destination(self):
        row=next(r for r in self.data["siem_alerts"] if r["network_direction"]=="outbound")
        row["destination_ip"]=row["remote_destination_ip"]
        self.assertFalse(self.check()["valid"])
    def test_unhealthy_sensor_is_retained_with_explicit_limitation(self):
        self.data["siem_alerts"][0]["sensor_healthy"]=False
        r=self.check()
        self.assertTrue(r["valid"],r["errors"])
        self.assertLess(r["readiness"]["model1_input_ready_sessions"],r["counts"]["prepared_sessions"])
    def test_duplicate_json_keys_cannot_silently_change_meaning(self):
        self.check()
        (self.directory/FILES["asset_inventory"]).write_text('{"records":[],"records":[]}')
        r=validate_inputs({k:self.directory/n for k,n in FILES.items()})
        self.assertTrue(any("Duplicate JSON" in e["message"] for e in r["errors"]))
    def test_invalid_ip_is_rejected(self):
        self.data["siem_alerts"][0]["source_ip"]="replace-with-ip"
        self.assertFalse(self.check()["valid"])
    def test_multiple_active_risks_in_same_category_are_rejected(self):
        r=copy.deepcopy(self.data["risk_register"]["records"][0])
        r["risk_id"]="OTHER-RISK";r["risk_version_id"]="OTHER-RISK-V1"
        self.data["risk_register"]["records"].append(r)
        self.assertFalse(self.check()["valid"])

class AmbiguityTests(unittest.TestCase):
    def test_diagnostic_probability_map_does_not_alias_model_output(self):
        candidate={"class_probabilities":{"a":.7,"b":.3}}
        result=probability_diagnostics(candidate)
        result["class_probabilities"]["a"]=0
        self.assertEqual(candidate["class_probabilities"]["a"],.7)
    def test_uniform_and_concentrated_probability_meanings(self):
        d=probability_diagnostics({"class_probabilities":{"a":.5,"b":.5}})
        self.assertAlmostEqual(d["normalized_entropy"],1)
        self.assertEqual(d["top_two_probability_margin"],0)
        d=probability_diagnostics({"class_probabilities":{"a":1.,"b":0.}})
        self.assertEqual(d["normalized_entropy"],0)
        self.assertEqual(d["top_two_probability_margin"],1)
    def test_missing_or_invalid_vectors_do_not_look_confident(self):
        self.assertIsNone(probability_diagnostics({}))
        self.assertFalse(probability_diagnostics({"class_probabilities":{"a":float("nan"),"b":.2}})["valid"])
        self.assertFalse(probability_diagnostics({"class_probabilities":{"a":.3,"b":.3}})["valid"])
    def test_diagnostics_cannot_promote_an_abstained_candidate(self):
        candidate={"status":"ABSTAINED","scenario_class":None,"confidence":.49,"threshold":.5,
                   "class_probabilities":{"benign":.49,"reconnaissance":.26,"credential_access":.25}}
        before=copy.deepcopy(candidate)
        s={"session_id":"S1","asset_id":"A1","source_event_ids":["E1"],"features":{}}
        p={"shadow_candidate":candidate,"soc_assessment":{"status":"ASSESSED","method":"rule_baseline","scenario_class":"benign"}}
        out=session_outcome(s,p,{})
        self.assertEqual(candidate,before)
        self.assertEqual(out["model1"]["status"],"ABSTAINED")
        self.assertIsNone(out["rule_model_disagreement"])
        self.assertEqual(summarize([out])["probability_diagnostics_available"],1)

