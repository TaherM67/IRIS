from __future__ import annotations

import copy
import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from iris_models.contracts import FEATURES, read_jsonl, write_json, write_jsonl
from iris_models.sample_sources import generate_samples
from iris_models.telemetry import timestamp
from iris_models.three_sources import ASSET_SCHEMA, RISK_SCHEMA, integrate, load_sources, prepare_three
from iris_models.three_training import attach_reviews, predict_three, train_three

CATALOG = Path(__file__).resolve().parents[1]/"iris_models/data/control_catalog.csv"


class ThreeSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root_tmp = tempfile.TemporaryDirectory()
        cls.base = Path(cls.root_tmp.name)
        cls.manifest = generate_samples(cls.base/"source", campaigns=10, runs_per_class=3, asset_count=6)
        cls.asset_template = json.loads((cls.base/"source/asset_inventory.json").read_text())
        cls.risk_template = json.loads((cls.base/"source/risk_register.json").read_text())
        cls.alert_template = read_jsonl(cls.base/"source/siem_alerts.jsonl")
        cls.example = next(r for r in cls.alert_template if r["event_id"].startswith("EVT-"))

    @classmethod
    def tearDownClass(cls):
        cls.root_tmp.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.assets = copy.deepcopy(self.asset_template)
        self.risks = copy.deepcopy(self.risk_template)
        self.alerts = copy.deepcopy(self.alert_template)
        self.ap, self.rp, self.ep = [self.root/name for name in ("asset_inventory.json", "risk_register.json", "siem_alerts.jsonl")]

    def tearDown(self):
        self.temp.cleanup()

    def save(self):
        write_json(self.ap, self.assets)
        write_json(self.rp, self.risks)
        write_jsonl(self.ep, self.alerts)

    def run_join(self):
        self.save()
        return integrate(self.ap, self.rp, self.ep)

    def only_example(self):
        self.alerts = [copy.deepcopy(self.example)]
        return self.alerts[0]

    def test_three_sources_join_without_multiplying_alerts(self):
        unified, sessions, report = self.run_join()
        self.assertEqual(len(unified), report["deduplicated_alerts"])
        self.assertTrue(report["join_does_not_multiply_alerts"])
        self.assertEqual(len(sessions), 90)
        self.assertTrue(all(len(row["risks"]) == 2 for row in unified if row["asset"]))
        self.assertEqual(report["unresolved_asset_events"], 2)

    def test_duplicate_rows_removed_and_bad_row_quarantined(self):
        _, _, report = self.run_join()
        self.assertEqual(report["exact_duplicate_rows_removed"], 12)
        self.assertEqual(len(report["quarantine"]), 1)

    def test_merged_model_features_remain_allowlisted(self):
        _, sessions, _ = self.run_join()
        self.assertTrue(all(set(s["features"]) == set(FEATURES) for s in sessions))
        self.assertNotIn("asset_id", sessions[0]["features"])
        self.assertNotIn("risk_id", sessions[0]["features"])
        self.assertEqual(sessions[0]["asset_snapshot"]["asset_id"], sessions[0]["asset_id"])

    def test_labels_are_not_runtime_inputs(self):
        _, sessions, report = self.run_join()
        self.assertFalse(report["training_labels_read"])
        self.assertTrue(all("scenario_class" not in session for session in sessions))

    def test_destination_ip_fallback(self):
        row = self.only_example()
        row.pop("asset_id")
        unified, _, _ = self.run_join()
        self.assertEqual(unified[0]["asset_match_method"], "exact_destination_ip")

    def test_hostname_fallback(self):
        row = self.only_example()
        row.pop("asset_id")
        row.pop("destination_ip")
        unified, _, _ = self.run_join()
        self.assertEqual(unified[0]["asset_match_method"], "exact_agent_hostname")

    def test_indexer_source_wrapper_preserves_collector_metadata(self):
        row = self.only_example()
        metadata = {key: row.pop(key) for key in ("sensor_healthy", "campaign_id", "run_id", "data_provenance")}
        eid = row.pop("event_id")
        self.alerts = [{"_source": row, "_id": eid, **metadata}]
        unified, sessions, _ = self.run_join()
        self.assertEqual(unified[0]["event_id"], eid)
        self.assertTrue(sessions[0]["sensor_healthy"])

    def test_attacker_source_ip_is_not_a_victim_lookup(self):
        row = self.only_example()
        row["source_ip"] = row.pop("destination_ip")
        row.pop("asset_id")
        row.pop("agent_name")
        unified, sessions, _ = self.run_join()
        self.assertIsNone(unified[0]["asset"])
        self.assertFalse(sessions)

    def test_conflicting_asset_id_and_ip_not_silently_joined(self):
        row = self.only_example()
        other = next(a for a in self.assets["records"] if a["asset_id"] != row["asset_id"] and a["valid_to"])
        row["destination_ip"] = other["ip_addresses"][0]
        unified, _, report = self.run_join()
        self.assertIsNone(unified[0]["asset"])
        self.assertEqual(report["unresolved_asset_events"], 1)

    def test_ambiguous_ip_not_first_match(self):
        row = self.only_example()
        other = next(a for a in self.assets["records"] if a["asset_id"] != row["asset_id"] and a["valid_to"])
        other["ip_addresses"] = [row["destination_ip"]]
        row.pop("asset_id")
        unified, _, _ = self.run_join()
        self.assertIsNone(unified[0]["asset"])

    def test_null_keys_do_not_match_each_other(self):
        row = self.only_example()
        row.update({"asset_id": None, "destination_ip": None, "agent_name": None})
        unified, sessions, _ = self.run_join()
        self.assertIsNone(unified[0]["asset"])
        self.assertFalse(sessions)

    def test_future_asset_version_not_applied_to_past(self):
        row = self.only_example()
        versions = [a for a in self.assets["records"] if a["asset_id"] == row["asset_id"]]
        old = next(a for a in versions if a["valid_to"])
        new = next(a for a in versions if not a["valid_to"])
        old["criticality"], new["criticality"] = 1, 5
        unified, _, _ = self.run_join()
        self.assertEqual(unified[0]["asset"]["criticality"], 1)

    def test_current_version_and_rotated_ip_used_after_boundary(self):
        row = self.only_example()
        new = next(a for a in self.assets["records"] if a["asset_id"] == row["asset_id"] and not a["valid_to"])
        row["timestamp"], row["destination_ip"] = new["valid_from"], new["ip_addresses"][0]
        unified, _, _ = self.run_join()
        self.assertEqual(unified[0]["asset"]["asset_version_id"], new["asset_version_id"])

    def test_recorded_later_asset_cannot_leak_backward(self):
        row = self.only_example()
        for asset in self.assets["records"]:
            if asset["asset_id"] == row["asset_id"]:
                asset["recorded_at"] = "2027-01-01T00:00:00Z"
        unified, _, _ = self.run_join()
        self.assertIsNone(unified[0]["asset"])

    def test_future_risk_context_not_fabricated(self):
        row = self.only_example()
        for risk in self.risks["records"]:
            if risk["asset_id"] == row["asset_id"]:
                risk["recorded_at"] = "2027-01-01T00:00:00Z"
        unified, sessions, report = self.run_join()
        self.assertEqual(unified[0]["risks"], [])
        self.assertEqual(len(sessions), 1)
        self.assertIsNone(sessions[0]["context"])
        self.assertEqual(report["matched_events_without_risk_context"], 1)

    def test_overlapping_asset_history_rejected(self):
        self.assets["records"][0]["valid_to"] = None
        self.save()
        with self.assertRaisesRegex(ValueError, "Overlapping"):
            load_sources(self.ap, self.rp)

    def test_overlapping_risk_history_rejected(self):
        self.risks["records"][0]["valid_to"] = None
        self.save()
        with self.assertRaisesRegex(ValueError, "Overlapping"):
            load_sources(self.ap, self.rp)

    def test_risk_referencing_unknown_asset_rejected(self):
        self.risks["records"][0]["asset_id"] = "AST-UNKNOWN"
        self.save()
        with self.assertRaisesRegex(ValueError, "absent from inventory"):
            load_sources(self.ap, self.rp)

    def test_context_version_change_splits_a_session(self):
        row = self.only_example()
        new = next(a for a in self.assets["records"] if a["asset_id"] == row["asset_id"] and not a["valid_to"])
        boundary = timestamp(new["valid_from"])
        row.update({"timestamp": (boundary-timedelta(seconds=5)).isoformat(), "event_id": "boundary-before"})
        later = {**row, "timestamp": (boundary+timedelta(seconds=5)).isoformat(),
                 "event_id": "boundary-after", "destination_ip": new["ip_addresses"][0]}
        self.alerts = [row, later]
        _, sessions, _ = self.run_join()
        self.assertEqual(len(sessions), 2)
        self.assertNotEqual(sessions[0]["asset_snapshot"]["asset_version_id"], sessions[1]["asset_snapshot"]["asset_version_id"])

    def test_duplicate_snapshot_id_rejected(self):
        self.assets["records"].append(copy.deepcopy(self.assets["records"][0]))
        self.save()
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            load_sources(self.ap, self.rp)

    def test_missing_business_criticality_not_imputed(self):
        self.assets["records"][0].pop("criticality")
        self.save()
        with self.assertRaises(ValueError):
            load_sources(self.ap, self.rp)

    def test_mixed_synthetic_and_real_provenance_rejected(self):
        self.risks["data_provenance"] = "operational"
        self.save()
        with self.assertRaisesRegex(ValueError, "provenance"):
            load_sources(self.ap, self.rp)

    def test_conflicting_event_id_excludes_both_versions(self):
        row = self.only_example()
        other = copy.deepcopy(row)
        other["rule_level"] = (row["rule_level"] + 1) % 16
        self.alerts.append(other)
        unified, sessions, report = self.run_join()
        self.assertFalse(unified)
        self.assertFalse(sessions)
        self.assertIn(row["event_id"], report["conflicting_event_ids_excluded"])

    def test_shuffle_does_not_change_sessions(self):
        _, first, _ = self.run_join()
        self.alerts.reverse()
        _, second, _ = self.run_join()
        def values(sessions):
            return {s["session_id"]: (s["features"], s["context"]) for s in sessions}
        self.assertEqual(values(first), values(second))

    def test_sensor_gap_marks_session_unhealthy(self):
        row = self.only_example()
        row["sensor_healthy"] = False
        _, sessions, _ = self.run_join()
        self.assertFalse(sessions[0]["sensor_healthy"])

    def test_risk_context_uses_a_real_pair_not_independent_maxima(self):
        row = self.only_example()
        candidates = [r for r in self.risks["records"] if r["asset_id"] == row["asset_id"] and r["valid_to"]]
        candidates[0].update({"likelihood": 5, "impact": 1})
        candidates[1].update({"likelihood": 3, "impact": 5})
        _, sessions, _ = self.run_join()
        context = sessions[0]["context"]
        self.assertEqual((context["current_likelihood"], context["impact"]), (3, 5))
        self.assertEqual(context["context_risk_id"], candidates[1]["risk_id"])

    def test_recent_count_never_uses_future_or_incomplete_sessions(self):
        row = self.only_example()
        start = timestamp(row["timestamp"])
        row.update({"run_id": "first", "event_id": "first-1", "timestamp": start.isoformat()})
        first_end = {**row, "event_id": "first-2", "timestamp": (start+timedelta(seconds=20)).isoformat()}
        overlapping = {**row, "run_id": "overlap", "event_id": "overlap-1", "timestamp": (start+timedelta(seconds=5)).isoformat()}
        later = {**row, "run_id": "later", "event_id": "later-1", "timestamp": (start+timedelta(seconds=30)).isoformat()}
        self.alerts = [later, row, overlapping, first_end]
        _, sessions, _ = self.run_join()
        by_run = {s["run_id"]: s for s in sessions}
        self.assertEqual(by_run["first"]["context"]["previous_similar_24h"], 0)
        self.assertEqual(by_run["overlap"]["context"]["previous_similar_24h"], 0)
        self.assertEqual(by_run["later"]["context"]["previous_similar_24h"], 2)

    def test_synthetic_event_labels_join_to_observed_sessions(self):
        self.save()
        prepare_three(self.ap, self.rp, self.ep, self.root/"prepared")
        report = attach_reviews(self.root/"prepared/model_sessions.jsonl", self.base/"source/training_labels.jsonl", self.root/"reviews.jsonl", synthetic=True)
        self.assertEqual(report["labels_written"], 90)

    def test_real_data_cannot_use_generator_case_labels(self):
        self.save()
        prepare_three(self.ap, self.rp, self.ep, self.root/"prepared")
        with self.assertRaisesRegex(ValueError, "synthetic-only"):
            attach_reviews(self.root/"prepared/model_sessions.jsonl", self.base/"source/training_labels.jsonl", self.root/"reviews.jsonl", synthetic=False)

    def test_existing_output_not_overwritten(self):
        self.save()
        prepare_three(self.ap, self.rp, self.ep, self.root/"prepared")
        with self.assertRaises(ValueError):
            prepare_three(self.ap, self.rp, self.ep, self.root/"prepared")

    def test_three_input_prediction_needs_no_labels(self):
        self.only_example()
        self.save()
        report = predict_three(self.ap, self.rp, self.ep, CATALOG, self.root/"prediction", mode="rules")
        self.assertEqual(report["integrated_sources"], 3)
        self.assertFalse(report["training_labels_read"])
        self.assertEqual(report["predictions_written"], 1)
        prediction = read_jsonl(self.root/"prediction/predictions.jsonl")[0]
        self.assertFalse(prediction["automatic_execution"])

    def test_full_three_input_training(self):
        self.save()
        metadata = train_three(self.ap, self.rp, self.ep, self.base/"source/training_labels.jsonl", CATALOG, self.root/"training", synthetic=True)
        self.assertEqual(metadata["data_quality"]["accepted_sessions"], 90)
        self.assertEqual(metadata["model2"]["status"], "trained_shadow")
        self.assertFalse(metadata["model1"]["eligible_for_reviewed_advisory_release"])
        self.assertFalse(metadata["three_source_integration"]["labels_are_runtime_inputs"])


if __name__ == "__main__":
    unittest.main()
