from __future__ import annotations

import copy
import json
import shutil
import tempfile
import unittest
import sys
import types
from pathlib import Path
from unittest.mock import patch

import numpy as np

from iris_models.contracts import CLASSES, FEATURES, digest, read_jsonl, validate_features, write_json, write_jsonl
from iris_models.dataset import load_dataset, split_groups
from iris_models.demo import generate
from iris_models.runtime import ModelService, promote
from iris_models.telemetry import extract_campaign, extract_run, normalize_event, timestamp
from iris_models.training import scenario_metrics, train
from iris_models.bridge_v03 import observation_from_context, ScenarioAssessorV1, ControlRecommenderV1

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "iris_models/data/control_catalog.csv"


class ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temp.name)
        cls.sessions, cls.reviews, cls.sample = generate(cls.directory / "fixtures")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_valid_features(self):
        self.assertEqual(set(validate_features(self.sample["features"])), set(FEATURES))

    def test_truth_feature_rejected(self):
        for key in ("scenario_class", "template_name", "run_id", "source_ip", "risk_level"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_features({**self.sample["features"], key: "leak"})

    def test_missing_feature_rejected(self):
        row = self.sample["features"].copy()
        row.pop("event_count")
        with self.assertRaises(ValueError):
            validate_features(row)

    def test_nonfinite_feature_rejected(self):
        for value in (float("nan"), float("inf"), -1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_features({**self.sample["features"], "event_count": value})

    def test_inconsistent_counts_rejected(self):
        with self.assertRaises(ValueError):
            validate_features({**self.sample["features"], "failed_count": 1e6})

    def test_fractional_count_rejected(self):
        with self.assertRaises(ValueError):
            validate_features({**self.sample["features"], "distinct_sources": 1.5})

    def test_bad_failure_ratio_rejected(self):
        with self.assertRaises(ValueError):
            validate_features({**self.sample["features"], "failure_ratio": .123456789})

    def test_bad_rate_rejected(self):
        with self.assertRaises(ValueError):
            validate_features({**self.sample["features"], "event_rate_per_minute": 1e7})

    def test_synthetic_cannot_be_called_real(self):
        with self.assertRaises(ValueError):
            load_dataset(self.sessions, self.reviews, synthetic=False)

    def test_group_splits_disjoint(self):
        data, _ = load_dataset(self.sessions, self.reviews, synthetic=True)
        indexes, manifest = split_groups(data)
        all_rows = np.concatenate(list(indexes.values()))
        self.assertEqual(len(set(all_rows)), len(data))
        for left, groups in manifest["groups"].items():
            for right, other in manifest["groups"].items():
                if left != right:
                    self.assertFalse(set(groups) & set(other))

    def test_reproducible_split(self):
        data, _ = load_dataset(self.sessions, self.reviews, synthetic=True)
        self.assertEqual(split_groups(data)[1], split_groups(data)[1])

    def test_single_campaign_is_not_campaign_validation(self):
        data, _ = load_dataset(self.sessions, self.reviews, synthetic=True)
        data["campaign_id"] = "one-campaign"
        with self.assertRaisesRegex(ValueError, "at least 5"):
            split_groups(data)

    def test_sensor_down_and_unreviewed_rows_quarantined(self):
        observations, reviews = read_jsonl(self.sessions), read_jsonl(self.reviews)
        observations[0]["sensor_healthy"] = False
        reviews[1]["label_verified"] = False
        with tempfile.TemporaryDirectory() as tmp:
            p, q = Path(tmp)/"s.jsonl", Path(tmp)/"r.jsonl"
            write_jsonl(p, observations)
            write_jsonl(q, reviews)
            data, quality = load_dataset(p, q, synthetic=True)
        self.assertEqual(len(quality["quarantined"]), 2)
        self.assertEqual(len(data), 178)

    def test_25_rows_not_25_runs(self):
        observations, reviews = read_jsonl(self.sessions), read_jsonl(self.reviews)
        for row in observations + reviews:
            row["campaign_id"] = "one-campaign"
            row["run_id"] = "one-run"
        with tempfile.TemporaryDirectory() as tmp:
            p, q = Path(tmp)/"s.jsonl", Path(tmp)/"r.jsonl"
            write_jsonl(p, observations)
            write_jsonl(q, reviews)
            with self.assertRaises(ValueError):
                load_dataset(p, q, synthetic=True)

    def test_duplicate_review_rejected(self):
        reviews = read_jsonl(self.reviews)
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/"r.jsonl"
            write_jsonl(p, reviews + [reviews[0]])
            with self.assertRaises(ValueError):
                load_dataset(self.sessions, p, synthetic=True)

    def test_model1_does_not_require_fabricated_grc_context(self):
        observations = read_jsonl(self.sessions)
        for row in observations:
            row["context"] = None
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/"s.jsonl"
            write_jsonl(p, observations)
            data, _ = load_dataset(p, self.reviews, synthetic=True)
        self.assertEqual(len(data), 180)
        self.assertFalse(data.controls_reviewed.any())

    def test_abstentions_reduce_attack_recall(self):
        metrics = scenario_metrics(["credential_access", "credential_access", "benign", "reconnaissance"],
                                   ["credential_access", "ABSTAINED", "benign", "reconnaissance"])
        self.assertEqual(metrics["per_class"]["credential_access"]["recall"], .5)
        self.assertEqual(metrics["coverage"], .75)


class ModelIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.sessions, cls.reviews, cls.sample = generate(cls.root / "fixtures")
        cls.model_dir = cls.root / "models"
        cls.metadata = train(cls.sessions, cls.reviews, CATALOG, cls.model_dir, synthetic=True)
        cls.service = ModelService(cls.model_dir, CATALOG)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_three_candidates_compared(self):
        self.assertEqual(set(self.metadata["model1"]["selection_scores"]),
                         {"logistic_regression", "random_forest", "hist_gradient_boosting"})

    def test_calibration_does_not_refit_base_preprocessing(self):
        from iris_models.contracts import NUMERIC
        data, _ = load_dataset(self.sessions, self.reviews, synthetic=True)
        groups = self.metadata["split"]["groups"]
        fit_groups = set(groups["train"]) | set(groups["selection"])
        expected = data[data.campaign_id.isin(fit_groups)][NUMERIC].mean().to_numpy()
        actual = self.service.bundle["scenario_base_pipeline"].named_steps["features"].named_transformers_["numeric"].mean_
        np.testing.assert_allclose(actual, expected)

    def test_artifact_loads(self):
        self.assertIsNone(self.service.load_error)
        self.assertIsNotNone(self.service.bundle)

    def test_shadow_default_does_not_replace_rules(self):
        output = self.service.predict(self.sample)
        self.assertEqual(output["soc_assessment"]["method"], "rule_baseline")
        self.assertIsNotNone(output["shadow_candidate"])
        self.assertTrue(output["requires_human_review"])
        self.assertFalse(output["automatic_execution"])
        self.assertFalse(output["official_risk_register_write"])

    def test_synthetic_release_blocked(self):
        for component in ("model1", "model2"):
            with self.subTest(component=component), self.assertRaisesRegex(ValueError, "blocked"):
                promote(self.model_dir, component, "project-reviewer")

    def test_advisory_without_approval_stays_fallback(self):
        output = self.service.predict(self.sample, mode="advisory")
        self.assertEqual(output["soc_assessment"]["method"], "rule_baseline")
        self.assertFalse(output["model1_released"])

    def test_rules_mode_does_not_infer_ml(self):
        with patch.object(self.service.bundle["scenario_model"], "predict_proba", side_effect=AssertionError("No ML expected")):
            self.assertIsNone(self.service.predict(self.sample, mode="rules")["shadow_candidate"])

    def test_prediction_failure_retains_rules(self):
        with patch.object(self.service.bundle["scenario_model"], "predict_proba", side_effect=RuntimeError("simulated failure")):
            result = self.service.predict(self.sample)
        self.assertEqual(result["soc_assessment"]["method"], "rule_baseline")
        self.assertTrue(any("inference failed" in w for w in result["warnings"]))

    def test_malformed_policy_context_does_not_recommend_actions(self):
        row = copy.deepcopy(self.sample)
        row["context"]["controls"] = None
        result = self.service.predict(row)
        self.assertEqual(result["grc_control_review"]["recommendations"], [])

    def test_sensor_gap_never_assessed_benign(self):
        row = {**self.sample, "sensor_healthy": False}
        result = self.service.predict(row)
        self.assertEqual(result["soc_assessment"]["status"], "ABSTAINED")
        self.assertEqual(result["grc_control_review"]["recommendations"], [])

    def test_unseen_category_abstains_ml(self):
        row = copy.deepcopy(self.sample)
        row["features"]["event_family"] = "endpoint_compromise"
        result = self.service.predict(row)
        self.assertIsNone(result["shadow_candidate"])
        self.assertIsNone(result["soc_assessment"]["scenario_class"])

    def test_catalogue_state_and_exception_policy(self):
        result = self.service.predict(self.sample)
        by_id = {r["control_id"]: r for r in result["grc_control_review"]["recommendations"]}
        self.assertEqual(by_id["SC005"]["action_type"], "verify")
        self.assertEqual(by_id["SC006"]["action_type"], "review")
        self.assertIsNone(by_id["SC005"]["model_score"])

    def test_missing_artifact_uses_rules(self):
        result = ModelService(None, CATALOG).predict(self.sample)
        self.assertEqual(result["soc_assessment"]["method"], "rule_baseline")
        self.assertIsNone(result["shadow_candidate"])

    def test_tamper_rejected_before_unpickle(self):
        with tempfile.TemporaryDirectory() as tmp:
            copied = Path(tmp)/"copied"
            shutil.copytree(self.model_dir, copied)
            with (copied/"models.joblib").open("ab") as stream:
                stream.write(b"tamper")
            with patch("iris_models.runtime.joblib.load", side_effect=AssertionError("Must not unpickle")):
                service = ModelService(copied, CATALOG)
        self.assertIn("checksum mismatch", service.load_error)
        self.assertIsNone(service.bundle)

    def test_version_mismatch_rejected_before_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            copied = Path(tmp)/"copied"
            shutil.copytree(self.model_dir, copied)
            metadata = copy.deepcopy(self.metadata)
            metadata["scikit_learn_version"] = "incompatible"
            write_json(copied/"metadata.json", metadata)
            with patch("iris_models.runtime.joblib.load", side_effect=AssertionError("Must not load")):
                service = ModelService(copied, CATALOG)
        self.assertIn("version mismatch", service.load_error)

    def test_train_serve_sessionizer_mismatch_disables_ml(self):
        row = copy.deepcopy(self.sample)
        row["aggregation_schema"] = "different-sessionizer"
        result = self.service.predict(row)
        self.assertIsNone(result["shadow_candidate"])
        self.assertTrue(any("contract differs" in w for w in result["warnings"]))

    def test_model2_uses_crossfit_predictions(self):
        report = self.metadata["model2"]
        self.assertEqual(report["status"], "trained_shadow")
        self.assertIn("never oracle", report["scenario_inputs"])
        self.assertIn("SC001", report["unsupported_controls"])

    def test_no_overwrite_of_existing_experiment(self):
        with self.assertRaisesRegex(ValueError, "already contains"):
            train(self.sessions, self.reviews, CATALOG, self.model_dir, synthetic=True)

    def test_grc_criticality_does_not_change_scenario(self):
        a, b = copy.deepcopy(self.sample), copy.deepcopy(self.sample)
        a["context"]["asset_criticality"], b["context"]["asset_criticality"] = 1, 5
        self.assertEqual(self.service.predict(a)["shadow_candidate"]["class_probabilities"],
                         self.service.predict(b)["shadow_candidate"]["class_probabilities"])

    def test_bridge_builds_telemetry_only_features(self):
        s = types.SimpleNamespace(**self.sample["features"], session_id="S", run_id="R", member_raw_refs=["ref"], member_event_ids=["e"])
        c = types.SimpleNamespace(session=s, asset=types.SimpleNamespace(asset_type="server", criticality=5), controls=[], active_exceptions=[])
        observation = observation_from_context(c, sensor_healthy=True)
        self.assertEqual(set(observation["features"]), set(FEATURES))
        self.assertIsNone(observation["context"])
        self.assertEqual(observation["aggregation_schema"], "iris-v03-wazuh-session-v1")

    def test_bridge_assessment_and_recommender_interfaces(self):
        s = types.SimpleNamespace(**self.sample["features"], session_id="S", run_id="R", member_raw_refs=["ref"], member_event_ids=["e"])
        c = types.SimpleNamespace(session=s, asset=types.SimpleNamespace(asset_type="server", criticality=5), controls=[], active_exceptions=[])
        fake_schemas = types.ModuleType("iris_engine.schemas")
        fake_schemas.Assessment = types.SimpleNamespace
        fake_schemas.ControlRecommendation = types.SimpleNamespace
        with patch.dict(sys.modules, {"iris_engine": types.ModuleType("iris_engine"), "iris_engine.schemas": fake_schemas}):
            assessor = ScenarioAssessorV1(self.service, health_check=lambda _: True)
            assessment = assessor.assess(c)
            self.assertEqual(assessment.status, "ASSESSED")
            recommender = ControlRecommenderV1(self.service, health_check=lambda _: True)
            recommendations, metadata = recommender.recommend(c, assessment, 3, 5, 0)
            self.assertTrue(recommendations)
            self.assertEqual(metadata["source"], "catalogue_fallback")

    def test_bridge_missing_health_fails_closed(self):
        s = types.SimpleNamespace(**self.sample["features"], session_id="S", run_id="R", member_raw_refs=[], member_event_ids=[])
        c = types.SimpleNamespace(session=s, asset=types.SimpleNamespace(asset_type="server", criticality=5), controls=[], active_exceptions=[])
        fake_schemas = types.ModuleType("iris_engine.schemas")
        fake_schemas.Assessment = types.SimpleNamespace
        with patch.dict(sys.modules, {"iris_engine": types.ModuleType("iris_engine"), "iris_engine.schemas": fake_schemas}):
            result = ScenarioAssessorV1(self.service, health_check=lambda _: None).assess(c)
        self.assertEqual(result.status, "ABSTAINED")


class RangeAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.campaign = Path(self.temp.name)/"campaign-test"
        self.run = self.campaign/"runs/run-0001-ssh_bruteforce"
        topology = {"assets": [
            {"asset_id": "A", "ip": "10.77.0.201", "hostname": "workstation01", "role": "workstation"},
            {"asset_id": "M", "ip": "10.77.0.10", "hostname": "wazuh-manager", "role": "wazuh_manager"},
            {"asset_id": "S", "ip": "10.77.0.11", "hostname": "suricata-sensor", "role": "network_sensor"},
        ]}
        write_json(self.run/"topology.json", topology)
        write_json(self.run/"identity_data.json", {"accounts": [{"username": "alice"}]})
        write_json(self.run/"quality/sensor_health.json", {
            "action_error": None, "telemetry_errors": [],
            "health": {"wazuh-manager": {"status": "ok", "active_agents": ["workstation01", "suricata-sensor"]},
                       "suricata-sensor": {"status": "ok"}, "workstation01": {"status": "ok"}}})
        self.eve = {"timestamp": "2026-10-24T10:00:00+00:00", "event_type": "alert", "flow_id": 123,
                    "src_ip": "10.77.0.101", "dest_ip": "10.77.0.201", "src_port": 40000, "dest_port": 22,
                    "proto": "TCP", "alert": {"severity": 2, "signature_id": 1001}}
        self.wazuh = [{"timestamp": f"2026-10-24T10:00:0{i}+00:00", "agent": {"name": "workstation01"},
                       "rule": {"id": "5710", "level": 5, "groups": ["sshd"], "description": "Failed password" if i < 2 else "Accepted password"},
                       "data": {"srcip": "10.77.0.101", "dstuser": "alice"}}
                      for i in range(3)]
        write_jsonl(self.run/"wazuh_stuff/alerts.jsonl", self.wazuh + [{"timestamp": self.eve["timestamp"], "full_log": json.dumps(self.eve)}])
        write_jsonl(self.run/"suricata_stuff/eve.json", [self.eve])
        # Invalid truth JSON proves extraction does not parse/use truth or scenario labels.
        (self.run/"activity_ground_truth.jsonl").write_text("NOT JSON, MUST NOT BE READ", encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def test_suricata_severity_mapping(self):
        for severity, expected in [(1, 10), (2, 7), (3, 4)]:
            event = copy.deepcopy(self.eve)
            event["alert"]["severity"] = severity
            self.assertEqual(normalize_event(event, "suricata", "ref")["level"], expected)

    def test_timezone_required(self):
        with self.assertRaises(ValueError):
            timestamp("2026-10-24T10:00:00")

    def test_truth_independent_import_and_dedup(self):
        rows, quarantine = extract_run(self.run, self.campaign.name)
        self.assertFalse(quarantine)
        self.assertEqual(len(rows), 2)
        self.assertEqual(sum(r["features"]["event_count"] for r in rows), 4)
        self.assertTrue(all(r["sensor_healthy"] for r in rows))
        for row in rows:
            self.assertIsNone(row["context"])
            self.assertNotIn("scenario_class", row["features"])

    def test_benign_success_after_failures_feature(self):
        rows, _ = extract_run(self.run, self.campaign.name)
        auth = next(r for r in rows if r["features"]["event_family"] == "authentication")
        self.assertEqual(auth["features"]["success_after_failures"], 1)
        self.assertAlmostEqual(auth["features"]["failure_ratio"], 2/3)

    def test_missing_manifest_blocks_training_health(self):
        rows, report = extract_campaign(self.campaign)
        self.assertFalse(any(r["sensor_healthy"] for r in rows))
        self.assertFalse(report["truth_files_read"])

    def test_complete_runtime_hashes_allow_import_without_truth(self):
        files = []
        for relative in ("topology.json", "identity_data.json", "wazuh_stuff/alerts.jsonl", "suricata_stuff/eve.json", "quality/sensor_health.json"):
            p = self.run/relative
            files.append({"path": str(p.relative_to(self.campaign)), "sha256": digest(p), "bytes": p.stat().st_size})
        files.append({"path": str((self.run/"activity_ground_truth.jsonl").relative_to(self.campaign)), "sha256": "not-read", "bytes": 0})
        write_json(self.campaign/"campaign_manifest.json", {"files": files})
        rows, report = extract_campaign(self.campaign)
        self.assertTrue(rows)
        self.assertTrue(all(r["sensor_healthy"] for r in rows))
        self.assertFalse(report["warnings"])

    def test_hash_tamper_blocks_import(self):
        p = self.run/"topology.json"
        write_json(self.campaign/"campaign_manifest.json", {"files": [{"path": str(p.relative_to(self.campaign)), "sha256": "bad-hash", "bytes": p.stat().st_size}]})
        with self.assertRaisesRegex(ValueError, "integrity mismatch"):
            extract_campaign(self.campaign)

    def test_bad_time_quarantined(self):
        self.wazuh[0]["timestamp"] = "bad-time"
        write_jsonl(self.run/"wazuh_stuff/alerts.jsonl", self.wazuh)
        rows, quarantine = extract_run(self.run, self.campaign.name)
        self.assertTrue(quarantine)
        self.assertFalse(any(r["sensor_healthy"] for r in rows))


if __name__ == "__main__":
    unittest.main()
