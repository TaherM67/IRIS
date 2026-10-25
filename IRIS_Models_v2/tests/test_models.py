# IRIS EXPLAIN: File purpose: Regression tests for feature contracts, grouped ML evaluation, artifact integrity, fallback
# IRIS EXPLAIN: behavior, and cyber-range normalization.
# IRIS EXPLAIN: Keep type annotations unevaluated at definition time; this does not add a model feature or change runtime
# IRIS EXPLAIN: settings.
from __future__ import annotations

# IRIS EXPLAIN: Import copy to create independent fixtures or estimators without mutating the original.
import copy
# IRIS EXPLAIN: Import json to encode and decode structured finite JSON payloads.
import json
# IRIS EXPLAIN: Import shutil to copy immutable inputs or clean test-owned temporary directories.
import shutil
# IRIS EXPLAIN: Import tempfile to create fresh isolated run/upload/test directories.
import tempfile
# IRIS EXPLAIN: Import unittest to define regression assertions and controlled test mocks.
import unittest
# IRIS EXPLAIN: Import sys to inspect the Python version or select the same executable/import path.
import sys
# IRIS EXPLAIN: Import types to use the types support module.
import types
# IRIS EXPLAIN: Import Path from pathlib to resolve server-owned paths without trusting uploaded filenames.
from pathlib import Path
# IRIS EXPLAIN: Import patch from unittest.mock to define regression assertions and controlled test mocks.
from unittest.mock import patch

# IRIS EXPLAIN: Import numpy as np to perform reproducible numeric sampling, vectorized predictions and array calculations.
import numpy as np

# IRIS EXPLAIN: Import CLASSES, FEATURES, digest, read_jsonl, validate_features, write_json, write_jsonl from
# IRIS EXPLAIN: iris_models.contracts to reuse the shared project contract/implementation rather than duplicate it.
from iris_models.contracts import CLASSES, FEATURES, digest, read_jsonl, validate_features, write_json, write_jsonl
# IRIS EXPLAIN: Import load_dataset, split_groups from iris_models.dataset to reuse the shared project contract/implementation
# IRIS EXPLAIN: rather than duplicate it.
from iris_models.dataset import load_dataset, split_groups
# IRIS EXPLAIN: Import generate from iris_models.demo to reuse the shared project contract/implementation rather than duplicate
# IRIS EXPLAIN: it.
from iris_models.demo import generate
# IRIS EXPLAIN: Import ModelService, promote from iris_models.runtime to reuse the shared project contract/implementation rather
# IRIS EXPLAIN: than duplicate it.
from iris_models.runtime import ModelService, promote
# IRIS EXPLAIN: Import extract_campaign, extract_run, normalize_event, timestamp from iris_models.telemetry to reuse the shared
# IRIS EXPLAIN: project contract/implementation rather than duplicate it.
from iris_models.telemetry import extract_campaign, extract_run, normalize_event, timestamp
# IRIS EXPLAIN: Import scenario_metrics, train from iris_models.training to reuse the shared project contract/implementation
# IRIS EXPLAIN: rather than duplicate it.
from iris_models.training import scenario_metrics, train
# IRIS EXPLAIN: Import observation_from_context, ScenarioAssessorV1, ControlRecommenderV1 from iris_models.bridge_v03 to reuse
# IRIS EXPLAIN: the shared project contract/implementation rather than duplicate it.
from iris_models.bridge_v03 import observation_from_context, ScenarioAssessorV1, ControlRecommenderV1

# IRIS EXPLAIN: Store Path(__file__).resolve().parents[1] in ROOT; later lines use this named result.
ROOT = Path(__file__).resolve().parents[1]
# IRIS EXPLAIN: Store the computed value ROOT / 'iris_models/data/control_catalog.csv' in CATALOG; later lines use this named
# IRIS EXPLAIN: result.
CATALOG = ROOT / "iris_models/data/control_catalog.csv"


# IRIS EXPLAIN: Class ContractTests: Groups regression checks and their isolated synthetic fixtures; unittest invokes test_
# IRIS EXPLAIN: methods independently.
class ContractTests(unittest.TestCase):
    # IRIS EXPLAIN: Bind the following helper to the class (cls), used here for shared setup/construction behavior.
    @classmethod
    # IRIS EXPLAIN: Function ContractTests.setUpClass: Prepare shared trusted-model/synthetic test fixtures once for this class.
    def setUpClass(cls):
        # IRIS EXPLAIN: Store the result of tempfile.TemporaryDirectory() in cls.temp; later lines use this named result.
        cls.temp = tempfile.TemporaryDirectory()
        # IRIS EXPLAIN: Store the result of Path(cls.temp.name) in cls.directory; later lines use this named result.
        cls.directory = Path(cls.temp.name)
        # IRIS EXPLAIN: Store the result of generate(cls.directory / 'fixtures') in (cls.sessions, cls.reviews, cls.sample);
        # IRIS EXPLAIN: later lines use this named result.
        cls.sessions, cls.reviews, cls.sample = generate(cls.directory / "fixtures")

    # IRIS EXPLAIN: Bind the following helper to the class (cls), used here for shared setup/construction behavior.
    @classmethod
    # IRIS EXPLAIN: Function ContractTests.tearDownClass: Close test-owned clients/servers or temporary fixtures so no resources
    # IRIS EXPLAIN: or mutable test state leak to later tests.
    def tearDownClass(cls):
        # IRIS EXPLAIN: Call cls.temp.cleanup(): remove only this fixture-owned temporary directory.
        cls.temp.cleanup()

    # IRIS EXPLAIN: Function ContractTests.test_valid_features: Regression test: verify that valid features; the assertions
    # IRIS EXPLAIN: below define the exact expected behavior.
    def test_valid_features(self):
        # IRIS EXPLAIN: Call self.assertEqual(set(validate_features(self.sample['features'])), set(FEATURES)): assert that the
        # IRIS EXPLAIN: actual and expected values are equal.
        self.assertEqual(set(validate_features(self.sample["features"])), set(FEATURES))

    # IRIS EXPLAIN: Function ContractTests.test_truth_feature_rejected: Regression test: verify that truth feature rejected; the
    # IRIS EXPLAIN: assertions below define the exact expected behavior.
    def test_truth_feature_rejected(self):
        # IRIS EXPLAIN: Iterate ('scenario_class', 'template_name', 'run_id', 'source_ip', 'risk_level'), binding each item to
        # IRIS EXPLAIN: key; process only the existing observed/fixture collection.
        for key in ("scenario_class", "template_name", "run_id", "source_ip", "risk_level"):
            # IRIS EXPLAIN: Enter self.subTest(key=key); self.assertRaises(ValueError); its context manager supplies the
            # IRIS EXPLAIN: existing cleanup/transaction/expected-exception behavior.
            with self.subTest(key=key), self.assertRaises(ValueError):
                # IRIS EXPLAIN: Call validate_features({**self.sample['features'], key: 'leak'}) using the existing explicit
                # IRIS EXPLAIN: arguments.
                validate_features({**self.sample["features"], key: "leak"})

    # IRIS EXPLAIN: Function ContractTests.test_missing_feature_rejected: Regression test: verify that missing feature rejected;
    # IRIS EXPLAIN: the assertions below define the exact expected behavior.
    def test_missing_feature_rejected(self):
        # IRIS EXPLAIN: Store the result of self.sample['features'].copy() (make an independent shallow copy) in row; later
        # IRIS EXPLAIN: lines use this named result.
        row = self.sample["features"].copy()
        # IRIS EXPLAIN: Call row.pop('event_count'): remove and return the selected item.
        row.pop("event_count")
        # IRIS EXPLAIN: Enter self.assertRaises(ValueError); its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.assertRaises(ValueError):
            # IRIS EXPLAIN: Call validate_features(row) using the existing explicit arguments.
            validate_features(row)

    # IRIS EXPLAIN: Function ContractTests.test_nonfinite_feature_rejected: Regression test: verify that nonfinite feature
    # IRIS EXPLAIN: rejected; the assertions below define the exact expected behavior.
    def test_nonfinite_feature_rejected(self):
        # IRIS EXPLAIN: Iterate (float('nan'), float('inf'), -1), binding each item to value; process only the existing
        # IRIS EXPLAIN: observed/fixture collection.
        for value in (float("nan"), float("inf"), -1):
            # IRIS EXPLAIN: Enter self.subTest(value=value); self.assertRaises(ValueError); its context manager supplies the
            # IRIS EXPLAIN: existing cleanup/transaction/expected-exception behavior.
            with self.subTest(value=value), self.assertRaises(ValueError):
                # IRIS EXPLAIN: Call validate_features({**self.sample['features'], 'event_count': value}) using the existing
                # IRIS EXPLAIN: explicit arguments.
                validate_features({**self.sample["features"], "event_count": value})

    # IRIS EXPLAIN: Function ContractTests.test_inconsistent_counts_rejected: Regression test: verify that inconsistent counts
    # IRIS EXPLAIN: rejected; the assertions below define the exact expected behavior.
    def test_inconsistent_counts_rejected(self):
        # IRIS EXPLAIN: Enter self.assertRaises(ValueError); its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.assertRaises(ValueError):
            # IRIS EXPLAIN: Call validate_features({**self.sample['features'], 'failed_count': 1000000.0}) using the existing
            # IRIS EXPLAIN: explicit arguments.
            validate_features({**self.sample["features"], "failed_count": 1e6})

    # IRIS EXPLAIN: Function ContractTests.test_fractional_count_rejected: Regression test: verify that fractional count
    # IRIS EXPLAIN: rejected; the assertions below define the exact expected behavior.
    def test_fractional_count_rejected(self):
        # IRIS EXPLAIN: Enter self.assertRaises(ValueError); its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.assertRaises(ValueError):
            # IRIS EXPLAIN: Call validate_features({**self.sample['features'], 'distinct_sources': 1.5}) using the existing
            # IRIS EXPLAIN: explicit arguments.
            validate_features({**self.sample["features"], "distinct_sources": 1.5})

    # IRIS EXPLAIN: Function ContractTests.test_bad_failure_ratio_rejected: Regression test: verify that bad failure ratio
    # IRIS EXPLAIN: rejected; the assertions below define the exact expected behavior.
    def test_bad_failure_ratio_rejected(self):
        # IRIS EXPLAIN: Enter self.assertRaises(ValueError); its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.assertRaises(ValueError):
            # IRIS EXPLAIN: Call validate_features({**self.sample['features'], 'failure_ratio': 0.123456789}) using the existing
            # IRIS EXPLAIN: explicit arguments.
            validate_features({**self.sample["features"], "failure_ratio": .123456789})

    # IRIS EXPLAIN: Function ContractTests.test_bad_rate_rejected: Regression test: verify that bad rate rejected; the
    # IRIS EXPLAIN: assertions below define the exact expected behavior.
    def test_bad_rate_rejected(self):
        # IRIS EXPLAIN: Enter self.assertRaises(ValueError); its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.assertRaises(ValueError):
            # IRIS EXPLAIN: Call validate_features({**self.sample['features'], 'event_rate_per_minute': 10000000.0}) using the
            # IRIS EXPLAIN: existing explicit arguments.
            validate_features({**self.sample["features"], "event_rate_per_minute": 1e7})

    # IRIS EXPLAIN: Function ContractTests.test_synthetic_cannot_be_called_real: Regression test: verify that synthetic cannot
    # IRIS EXPLAIN: be called real; the assertions below define the exact expected behavior.
    def test_synthetic_cannot_be_called_real(self):
        # IRIS EXPLAIN: Enter self.assertRaises(ValueError); its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.assertRaises(ValueError):
            # IRIS EXPLAIN: Call load_dataset(self.sessions, self.reviews, synthetic=False) using the existing explicit
            # IRIS EXPLAIN: arguments.
            load_dataset(self.sessions, self.reviews, synthetic=False)

    # IRIS EXPLAIN: Function ContractTests.test_group_splits_disjoint: Regression test: verify that group splits disjoint; the
    # IRIS EXPLAIN: assertions below define the exact expected behavior.
    def test_group_splits_disjoint(self):
        # IRIS EXPLAIN: Store the result of load_dataset(self.sessions, self.reviews, synthetic=True) in (data, _); later lines
        # IRIS EXPLAIN: use this named result.
        data, _ = load_dataset(self.sessions, self.reviews, synthetic=True)
        # IRIS EXPLAIN: Store the result of split_groups(data) in (indexes, manifest); later lines use this named result.
        indexes, manifest = split_groups(data)
        # IRIS EXPLAIN: Store the result of np.concatenate(list(indexes.values())) in all_rows; later lines use this named
        # IRIS EXPLAIN: result.
        all_rows = np.concatenate(list(indexes.values()))
        # IRIS EXPLAIN: Call self.assertEqual(len(set(all_rows)), len(data)): assert that the actual and expected values are
        # IRIS EXPLAIN: equal.
        self.assertEqual(len(set(all_rows)), len(data))
        # IRIS EXPLAIN: Iterate manifest['groups'].items(), binding each item to (left, groups); process only the existing
        # IRIS EXPLAIN: observed/fixture collection.
        for left, groups in manifest["groups"].items():
            # IRIS EXPLAIN: Iterate manifest['groups'].items(), binding each item to (right, other); process only the existing
            # IRIS EXPLAIN: observed/fixture collection.
            for right, other in manifest["groups"].items():
                # IRIS EXPLAIN: Enter this branch only when left != right.
                if left != right:
                    # IRIS EXPLAIN: Call self.assertFalse(set(groups) & set(other)): assert that the stated condition is false.
                    self.assertFalse(set(groups) & set(other))

    # IRIS EXPLAIN: Function ContractTests.test_reproducible_split: Regression test: verify that reproducible split; the
    # IRIS EXPLAIN: assertions below define the exact expected behavior.
    def test_reproducible_split(self):
        # IRIS EXPLAIN: Store the result of load_dataset(self.sessions, self.reviews, synthetic=True) in (data, _); later lines
        # IRIS EXPLAIN: use this named result.
        data, _ = load_dataset(self.sessions, self.reviews, synthetic=True)
        # IRIS EXPLAIN: Call self.assertEqual(split_groups(data)[1], split_groups(data)[1]): assert that the actual and expected
        # IRIS EXPLAIN: values are equal.
        self.assertEqual(split_groups(data)[1], split_groups(data)[1])

    # IRIS EXPLAIN: Function ContractTests.test_single_campaign_is_not_campaign_validation: Regression test: verify that single
    # IRIS EXPLAIN: campaign is not campaign validation; the assertions below define the exact expected behavior.
    def test_single_campaign_is_not_campaign_validation(self):
        # IRIS EXPLAIN: Store the result of load_dataset(self.sessions, self.reviews, synthetic=True) in (data, _); later lines
        # IRIS EXPLAIN: use this named result.
        data, _ = load_dataset(self.sessions, self.reviews, synthetic=True)
        # IRIS EXPLAIN: Store 'one-campaign' in data['campaign_id']; later lines use this named result.
        data["campaign_id"] = "one-campaign"
        # IRIS EXPLAIN: Enter self.assertRaisesRegex(ValueError, 'at least 5'); its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.assertRaisesRegex(ValueError, "at least 5"):
            # IRIS EXPLAIN: Call split_groups(data) using the existing explicit arguments.
            split_groups(data)

    # IRIS EXPLAIN: Function ContractTests.test_sensor_down_and_unreviewed_rows_quarantined: Regression test: verify that sensor
    # IRIS EXPLAIN: down and unreviewed rows quarantined; the assertions below define the exact expected behavior.
    def test_sensor_down_and_unreviewed_rows_quarantined(self):
        # IRIS EXPLAIN: Store (read_jsonl(self.sessions), read_jsonl(self.reviews)) in (observations, reviews); later lines use
        # IRIS EXPLAIN: this named result.
        observations, reviews = read_jsonl(self.sessions), read_jsonl(self.reviews)
        # IRIS EXPLAIN: Store False in observations[0]['sensor_healthy']; later lines use this named result.
        observations[0]["sensor_healthy"] = False
        # IRIS EXPLAIN: Store False in reviews[1]['label_verified']; later lines use this named result.
        reviews[1]["label_verified"] = False
        # IRIS EXPLAIN: Enter tempfile.TemporaryDirectory() as tmp; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with tempfile.TemporaryDirectory() as tmp:
            # IRIS EXPLAIN: Store (Path(tmp) / 's.jsonl', Path(tmp) / 'r.jsonl') in (p, q); later lines use this named result.
            p, q = Path(tmp)/"s.jsonl", Path(tmp)/"r.jsonl"
            # IRIS EXPLAIN: Call write_jsonl(p, observations) using the existing explicit arguments.
            write_jsonl(p, observations)
            # IRIS EXPLAIN: Call write_jsonl(q, reviews) using the existing explicit arguments.
            write_jsonl(q, reviews)
            # IRIS EXPLAIN: Store the result of load_dataset(p, q, synthetic=True) in (data, quality); later lines use this
            # IRIS EXPLAIN: named result.
            data, quality = load_dataset(p, q, synthetic=True)
        # IRIS EXPLAIN: Call self.assertEqual(len(quality['quarantined']), 2): assert that the actual and expected values are
        # IRIS EXPLAIN: equal.
        self.assertEqual(len(quality["quarantined"]), 2)
        # IRIS EXPLAIN: Call self.assertEqual(len(data), 178): assert that the actual and expected values are equal.
        self.assertEqual(len(data), 178)

    # IRIS EXPLAIN: Function ContractTests.test_25_rows_not_25_runs: Regression test: verify that 25 rows not 25 runs; the
    # IRIS EXPLAIN: assertions below define the exact expected behavior.
    def test_25_rows_not_25_runs(self):
        # IRIS EXPLAIN: Store (read_jsonl(self.sessions), read_jsonl(self.reviews)) in (observations, reviews); later lines use
        # IRIS EXPLAIN: this named result.
        observations, reviews = read_jsonl(self.sessions), read_jsonl(self.reviews)
        # IRIS EXPLAIN: Iterate observations + reviews, binding each item to row; process only the existing observed/fixture
        # IRIS EXPLAIN: collection.
        for row in observations + reviews:
            # IRIS EXPLAIN: Store 'one-campaign' in row['campaign_id']; later lines use this named result.
            row["campaign_id"] = "one-campaign"
            # IRIS EXPLAIN: Store 'one-run' in row['run_id']; later lines use this named result.
            row["run_id"] = "one-run"
        # IRIS EXPLAIN: Enter tempfile.TemporaryDirectory() as tmp; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with tempfile.TemporaryDirectory() as tmp:
            # IRIS EXPLAIN: Store (Path(tmp) / 's.jsonl', Path(tmp) / 'r.jsonl') in (p, q); later lines use this named result.
            p, q = Path(tmp)/"s.jsonl", Path(tmp)/"r.jsonl"
            # IRIS EXPLAIN: Call write_jsonl(p, observations) using the existing explicit arguments.
            write_jsonl(p, observations)
            # IRIS EXPLAIN: Call write_jsonl(q, reviews) using the existing explicit arguments.
            write_jsonl(q, reviews)
            # IRIS EXPLAIN: Enter self.assertRaises(ValueError); its context manager supplies the existing
            # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
            with self.assertRaises(ValueError):
                # IRIS EXPLAIN: Call load_dataset(p, q, synthetic=True) using the existing explicit arguments.
                load_dataset(p, q, synthetic=True)

    # IRIS EXPLAIN: Function ContractTests.test_duplicate_review_rejected: Regression test: verify that duplicate review
    # IRIS EXPLAIN: rejected; the assertions below define the exact expected behavior.
    def test_duplicate_review_rejected(self):
        # IRIS EXPLAIN: Store the result of read_jsonl(self.reviews) in reviews; later lines use this named result.
        reviews = read_jsonl(self.reviews)
        # IRIS EXPLAIN: Enter tempfile.TemporaryDirectory() as tmp; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with tempfile.TemporaryDirectory() as tmp:
            # IRIS EXPLAIN: Store the computed value Path(tmp) / 'r.jsonl' in p; later lines use this named result.
            p = Path(tmp)/"r.jsonl"
            # IRIS EXPLAIN: Call write_jsonl(p, reviews + [reviews[0]]) using the existing explicit arguments.
            write_jsonl(p, reviews + [reviews[0]])
            # IRIS EXPLAIN: Enter self.assertRaises(ValueError); its context manager supplies the existing
            # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
            with self.assertRaises(ValueError):
                # IRIS EXPLAIN: Call load_dataset(self.sessions, p, synthetic=True) using the existing explicit arguments.
                load_dataset(self.sessions, p, synthetic=True)

    # IRIS EXPLAIN: Function ContractTests.test_model1_does_not_require_fabricated_grc_context: Regression test: verify that
    # IRIS EXPLAIN: model1 does not require fabricated grc context; the assertions below define the exact expected behavior.
    def test_model1_does_not_require_fabricated_grc_context(self):
        # IRIS EXPLAIN: Store the result of read_jsonl(self.sessions) in observations; later lines use this named result.
        observations = read_jsonl(self.sessions)
        # IRIS EXPLAIN: Iterate observations, binding each item to row; process only the existing observed/fixture collection.
        for row in observations:
            # IRIS EXPLAIN: Store None (no result/value) in row['context']; later lines use this named result.
            row["context"] = None
        # IRIS EXPLAIN: Enter tempfile.TemporaryDirectory() as tmp; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with tempfile.TemporaryDirectory() as tmp:
            # IRIS EXPLAIN: Store the computed value Path(tmp) / 's.jsonl' in p; later lines use this named result.
            p = Path(tmp)/"s.jsonl"
            # IRIS EXPLAIN: Call write_jsonl(p, observations) using the existing explicit arguments.
            write_jsonl(p, observations)
            # IRIS EXPLAIN: Store the result of load_dataset(p, self.reviews, synthetic=True) in (data, _); later lines use this
            # IRIS EXPLAIN: named result.
            data, _ = load_dataset(p, self.reviews, synthetic=True)
        # IRIS EXPLAIN: Call self.assertEqual(len(data), 180): assert that the actual and expected values are equal.
        self.assertEqual(len(data), 180)
        # IRIS EXPLAIN: Call self.assertFalse(data.controls_reviewed.any()): assert that the stated condition is false.
        self.assertFalse(data.controls_reviewed.any())

    # IRIS EXPLAIN: Function ContractTests.test_abstentions_reduce_attack_recall: Regression test: verify that abstentions
    # IRIS EXPLAIN: reduce attack recall; the assertions below define the exact expected behavior.
    def test_abstentions_reduce_attack_recall(self):
        # IRIS EXPLAIN: Store the result of scenario_metrics(['credential_access', 'credential_access', 'benign',
        # IRIS EXPLAIN: 'reconnaissance'], ['credential_acces... in metrics; later lines use this named result.
        metrics = scenario_metrics(["credential_access", "credential_access", "benign", "reconnaissance"],
                                   # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these
                                   # IRIS EXPLAIN: existing arguments/items: ["credential_access", "ABSTAINED", "benign",
                                   # IRIS EXPLAIN: "reconnaissance"]).
                                   ["credential_access", "ABSTAINED", "benign", "reconnaissance"])
        # IRIS EXPLAIN: Call self.assertEqual(metrics['per_class']['credential_access']['recall'], 0.5): assert that the actual
        # IRIS EXPLAIN: and expected values are equal.
        self.assertEqual(metrics["per_class"]["credential_access"]["recall"], .5)
        # IRIS EXPLAIN: Call self.assertEqual(metrics['coverage'], 0.75): assert that the actual and expected values are equal.
        self.assertEqual(metrics["coverage"], .75)


# IRIS EXPLAIN: Class ModelIntegrationTests: Groups regression checks and their isolated synthetic fixtures; unittest invokes
# IRIS EXPLAIN: test_ methods independently.
class ModelIntegrationTests(unittest.TestCase):
    # IRIS EXPLAIN: Bind the following helper to the class (cls), used here for shared setup/construction behavior.
    @classmethod
    # IRIS EXPLAIN: Function ModelIntegrationTests.setUpClass: Prepare shared trusted-model/synthetic test fixtures once for
    # IRIS EXPLAIN: this class.
    def setUpClass(cls):
        # IRIS EXPLAIN: Store the result of tempfile.TemporaryDirectory() in cls.temp; later lines use this named result.
        cls.temp = tempfile.TemporaryDirectory()
        # IRIS EXPLAIN: Store the result of Path(cls.temp.name) in cls.root; later lines use this named result.
        cls.root = Path(cls.temp.name)
        # IRIS EXPLAIN: Store the result of generate(cls.root / 'fixtures') in (cls.sessions, cls.reviews, cls.sample); later
        # IRIS EXPLAIN: lines use this named result.
        cls.sessions, cls.reviews, cls.sample = generate(cls.root / "fixtures")
        # IRIS EXPLAIN: Store the computed value cls.root / 'models' in cls.model_dir; later lines use this named result.
        cls.model_dir = cls.root / "models"
        # IRIS EXPLAIN: Store the result of train(cls.sessions, cls.reviews, CATALOG, cls.model_dir, synthetic=True) in
        # IRIS EXPLAIN: cls.metadata; later lines use this named result.
        cls.metadata = train(cls.sessions, cls.reviews, CATALOG, cls.model_dir, synthetic=True)
        # IRIS EXPLAIN: Store the result of ModelService(cls.model_dir, CATALOG) in cls.service; later lines use this named
        # IRIS EXPLAIN: result.
        cls.service = ModelService(cls.model_dir, CATALOG)

    # IRIS EXPLAIN: Bind the following helper to the class (cls), used here for shared setup/construction behavior.
    @classmethod
    # IRIS EXPLAIN: Function ModelIntegrationTests.tearDownClass: Close test-owned clients/servers or temporary fixtures so no
    # IRIS EXPLAIN: resources or mutable test state leak to later tests.
    def tearDownClass(cls):
        # IRIS EXPLAIN: Call cls.temp.cleanup(): remove only this fixture-owned temporary directory.
        cls.temp.cleanup()

    # IRIS EXPLAIN: Function ModelIntegrationTests.test_three_candidates_compared: Regression test: verify that three candidates
    # IRIS EXPLAIN: compared; the assertions below define the exact expected behavior.
    def test_three_candidates_compared(self):
        # IRIS EXPLAIN: Call self.assertEqual(set(self.metadata['model1']['selection_scores']), {'logistic_regression',
        # IRIS EXPLAIN: 'random_forest', 'hist_gradient_boosting'}): assert that the actual and expected values are equal.
        self.assertEqual(set(self.metadata["model1"]["selection_scores"]),
                         # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                         # IRIS EXPLAIN: arguments/items: {"logistic_regression", "random_forest", "hist_gradient_boosting"}).
                         {"logistic_regression", "random_forest", "hist_gradient_boosting"})

    # IRIS EXPLAIN: Function ModelIntegrationTests.test_calibration_does_not_refit_base_preprocessing: Regression test: verify
    # IRIS EXPLAIN: that calibration does not refit base preprocessing; the assertions below define the exact expected behavior.
    def test_calibration_does_not_refit_base_preprocessing(self):
        # IRIS EXPLAIN: Import NUMERIC from iris_models.contracts to reuse the shared project contract/implementation rather
        # IRIS EXPLAIN: than duplicate it.
        from iris_models.contracts import NUMERIC
        # IRIS EXPLAIN: Store the result of load_dataset(self.sessions, self.reviews, synthetic=True) in (data, _); later lines
        # IRIS EXPLAIN: use this named result.
        data, _ = load_dataset(self.sessions, self.reviews, synthetic=True)
        # IRIS EXPLAIN: Store self.metadata['split']['groups'] in groups; later lines use this named result.
        groups = self.metadata["split"]["groups"]
        # IRIS EXPLAIN: Store the computed value set(groups['train']) | set(groups['selection']) in fit_groups; later lines use
        # IRIS EXPLAIN: this named result.
        fit_groups = set(groups["train"]) | set(groups["selection"])
        # IRIS EXPLAIN: Store the result of data[data.campaign_id.isin(fit_groups)][NUMERIC].mean().to_numpy() (convert this
        # IRIS EXPLAIN: existing table/series to a numeric array) in expected; later lines use this named result.
        expected = data[data.campaign_id.isin(fit_groups)][NUMERIC].mean().to_numpy()
        # IRIS EXPLAIN: Store
        # IRIS EXPLAIN: self.service.bundle['scenario_base_pipeline'].named_steps['features'].named_transformers_['numeric'].mean_
        # IRIS EXPLAIN: in actual; later lines use this named result.
        actual = self.service.bundle["scenario_base_pipeline"].named_steps["features"].named_transformers_["numeric"].mean_
        # IRIS EXPLAIN: Call np.testing.assert_allclose(actual, expected) using the existing explicit arguments.
        np.testing.assert_allclose(actual, expected)

    # IRIS EXPLAIN: Function ModelIntegrationTests.test_artifact_loads: Regression test: verify that artifact loads; the
    # IRIS EXPLAIN: assertions below define the exact expected behavior.
    def test_artifact_loads(self):
        # IRIS EXPLAIN: Call self.assertIsNone(self.service.load_error): assert that the value is exactly None.
        self.assertIsNone(self.service.load_error)
        # IRIS EXPLAIN: Call self.assertIsNotNone(self.service.bundle): assert that the value is available rather than None.
        self.assertIsNotNone(self.service.bundle)

    # IRIS EXPLAIN: Function ModelIntegrationTests.test_shadow_default_does_not_replace_rules: Regression test: verify that
    # IRIS EXPLAIN: shadow default does not replace rules; the assertions below define the exact expected behavior.
    def test_shadow_default_does_not_replace_rules(self):
        # IRIS EXPLAIN: Store the result of self.service.predict(self.sample) (obtain the configured prediction result without
        # IRIS EXPLAIN: training on this call) in output; later lines use this named result.
        output = self.service.predict(self.sample)
        # IRIS EXPLAIN: Call self.assertEqual(output['soc_assessment']['method'], 'rule_baseline'): assert that the actual and
        # IRIS EXPLAIN: expected values are equal.
        self.assertEqual(output["soc_assessment"]["method"], "rule_baseline")
        # IRIS EXPLAIN: Call self.assertIsNotNone(output['shadow_candidate']): assert that the value is available rather than
        # IRIS EXPLAIN: None.
        self.assertIsNotNone(output["shadow_candidate"])
        # IRIS EXPLAIN: Call self.assertTrue(output['requires_human_review']): assert that the stated condition is true.
        self.assertTrue(output["requires_human_review"])
        # IRIS EXPLAIN: Call self.assertFalse(output['automatic_execution']): assert that the stated condition is false.
        self.assertFalse(output["automatic_execution"])
        # IRIS EXPLAIN: Call self.assertFalse(output['official_risk_register_write']): assert that the stated condition is
        # IRIS EXPLAIN: false.
        self.assertFalse(output["official_risk_register_write"])

    # IRIS EXPLAIN: Function ModelIntegrationTests.test_synthetic_release_blocked: Regression test: verify that synthetic
    # IRIS EXPLAIN: release blocked; the assertions below define the exact expected behavior.
    def test_synthetic_release_blocked(self):
        # IRIS EXPLAIN: Iterate ('model1', 'model2'), binding each item to component; process only the existing observed/fixture
        # IRIS EXPLAIN: collection.
        for component in ("model1", "model2"):
            # IRIS EXPLAIN: Enter self.subTest(component=component); self.assertRaisesRegex(ValueError, 'blocked'); its context
            # IRIS EXPLAIN: manager supplies the existing cleanup/transaction/expected-exception behavior.
            with self.subTest(component=component), self.assertRaisesRegex(ValueError, "blocked"):
                # IRIS EXPLAIN: Call promote(self.model_dir, component, 'project-reviewer'): attempt guarded advisory release;
                # IRIS EXPLAIN: existing evidence gates still decide whether it is allowed.
                promote(self.model_dir, component, "project-reviewer")

    # IRIS EXPLAIN: Function ModelIntegrationTests.test_advisory_without_approval_stays_fallback: Regression test: verify that
    # IRIS EXPLAIN: advisory without approval stays fallback; the assertions below define the exact expected behavior.
    def test_advisory_without_approval_stays_fallback(self):
        # IRIS EXPLAIN: Store the result of self.service.predict(self.sample, mode='advisory') (obtain the configured prediction
        # IRIS EXPLAIN: result without training on this call) in output; later lines use this named result.
        output = self.service.predict(self.sample, mode="advisory")
        # IRIS EXPLAIN: Call self.assertEqual(output['soc_assessment']['method'], 'rule_baseline'): assert that the actual and
        # IRIS EXPLAIN: expected values are equal.
        self.assertEqual(output["soc_assessment"]["method"], "rule_baseline")
        # IRIS EXPLAIN: Call self.assertFalse(output['model1_released']): assert that the stated condition is false.
        self.assertFalse(output["model1_released"])

    # IRIS EXPLAIN: Function ModelIntegrationTests.test_rules_mode_does_not_infer_ml: Regression test: verify that rules mode
    # IRIS EXPLAIN: does not infer ml; the assertions below define the exact expected behavior.
    def test_rules_mode_does_not_infer_ml(self):
        # IRIS EXPLAIN: Enter patch.object(self.service.bundle['scenario_model'], 'predict_proba',
        # IRIS EXPLAIN: side_effect=AssertionError('No ML expected')); its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with patch.object(self.service.bundle["scenario_model"], "predict_proba", side_effect=AssertionError("No ML expected")):
            # IRIS EXPLAIN: Call self.assertIsNone(self.service.predict(self.sample, mode='rules')['shadow_candidate']): assert
            # IRIS EXPLAIN: that the value is exactly None.
            self.assertIsNone(self.service.predict(self.sample, mode="rules")["shadow_candidate"])

    # IRIS EXPLAIN: Function ModelIntegrationTests.test_prediction_failure_retains_rules: Regression test: verify that
    # IRIS EXPLAIN: prediction failure retains rules; the assertions below define the exact expected behavior.
    def test_prediction_failure_retains_rules(self):
        # IRIS EXPLAIN: Enter patch.object(self.service.bundle['scenario_model'], 'predict_proba',
        # IRIS EXPLAIN: side_effect=RuntimeError('simulated failure')); its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with patch.object(self.service.bundle["scenario_model"], "predict_proba", side_effect=RuntimeError("simulated failure")):
            # IRIS EXPLAIN: Store the result of self.service.predict(self.sample) (obtain the configured prediction result
            # IRIS EXPLAIN: without training on this call) in result; later lines use this named result.
            result = self.service.predict(self.sample)
        # IRIS EXPLAIN: Call self.assertEqual(result['soc_assessment']['method'], 'rule_baseline'): assert that the actual and
        # IRIS EXPLAIN: expected values are equal.
        self.assertEqual(result["soc_assessment"]["method"], "rule_baseline")
        # IRIS EXPLAIN: Call self.assertTrue(any(('inference failed' in w for w in result['warnings']))): assert that the stated
        # IRIS EXPLAIN: condition is true.
        self.assertTrue(any("inference failed" in w for w in result["warnings"]))

    # IRIS EXPLAIN: Function ModelIntegrationTests.test_malformed_policy_context_does_not_recommend_actions: Regression test:
    # IRIS EXPLAIN: verify that malformed policy context does not recommend actions; the assertions below define the exact
    # IRIS EXPLAIN: expected behavior.
    def test_malformed_policy_context_does_not_recommend_actions(self):
        # IRIS EXPLAIN: Store the result of copy.deepcopy(self.sample) (make an independent nested copy for this fixture) in
        # IRIS EXPLAIN: row; later lines use this named result.
        row = copy.deepcopy(self.sample)
        # IRIS EXPLAIN: Store None (no result/value) in row['context']['controls']; later lines use this named result.
        row["context"]["controls"] = None
        # IRIS EXPLAIN: Store the result of self.service.predict(row) (obtain the configured prediction result without training
        # IRIS EXPLAIN: on this call) in result; later lines use this named result.
        result = self.service.predict(row)
        # IRIS EXPLAIN: Call self.assertEqual(result['grc_control_review']['recommendations'], []): assert that the actual and
        # IRIS EXPLAIN: expected values are equal.
        self.assertEqual(result["grc_control_review"]["recommendations"], [])

    # IRIS EXPLAIN: Function ModelIntegrationTests.test_sensor_gap_never_assessed_benign: Regression test: verify that sensor
    # IRIS EXPLAIN: gap never assessed benign; the assertions below define the exact expected behavior.
    def test_sensor_gap_never_assessed_benign(self):
        # IRIS EXPLAIN: Store a mapping containing sensor_healthy in row; later lines use this named result.
        row = {**self.sample, "sensor_healthy": False}
        # IRIS EXPLAIN: Store the result of self.service.predict(row) (obtain the configured prediction result without training
        # IRIS EXPLAIN: on this call) in result; later lines use this named result.
        result = self.service.predict(row)
        # IRIS EXPLAIN: Call self.assertEqual(result['soc_assessment']['status'], 'ABSTAINED'): assert that the actual and
        # IRIS EXPLAIN: expected values are equal.
        self.assertEqual(result["soc_assessment"]["status"], "ABSTAINED")
        # IRIS EXPLAIN: Call self.assertEqual(result['grc_control_review']['recommendations'], []): assert that the actual and
        # IRIS EXPLAIN: expected values are equal.
        self.assertEqual(result["grc_control_review"]["recommendations"], [])

    # IRIS EXPLAIN: Function ModelIntegrationTests.test_unseen_category_abstains_ml: Regression test: verify that unseen
    # IRIS EXPLAIN: category abstains ml; the assertions below define the exact expected behavior.
    def test_unseen_category_abstains_ml(self):
        # IRIS EXPLAIN: Store the result of copy.deepcopy(self.sample) (make an independent nested copy for this fixture) in
        # IRIS EXPLAIN: row; later lines use this named result.
        row = copy.deepcopy(self.sample)
        # IRIS EXPLAIN: Store 'endpoint_compromise' in row['features']['event_family']; later lines use this named result.
        row["features"]["event_family"] = "endpoint_compromise"
        # IRIS EXPLAIN: Store the result of self.service.predict(row) (obtain the configured prediction result without training
        # IRIS EXPLAIN: on this call) in result; later lines use this named result.
        result = self.service.predict(row)
        # IRIS EXPLAIN: Call self.assertIsNone(result['shadow_candidate']): assert that the value is exactly None.
        self.assertIsNone(result["shadow_candidate"])
        # IRIS EXPLAIN: Call self.assertIsNone(result['soc_assessment']['scenario_class']): assert that the value is exactly
        # IRIS EXPLAIN: None.
        self.assertIsNone(result["soc_assessment"]["scenario_class"])

    # IRIS EXPLAIN: Function ModelIntegrationTests.test_catalogue_state_and_exception_policy: Regression test: verify that
    # IRIS EXPLAIN: catalogue state and exception policy; the assertions below define the exact expected behavior.
    def test_catalogue_state_and_exception_policy(self):
        # IRIS EXPLAIN: Store the result of self.service.predict(self.sample) (obtain the configured prediction result without
        # IRIS EXPLAIN: training on this call) in result; later lines use this named result.
        result = self.service.predict(self.sample)
        # IRIS EXPLAIN: Store the comprehension {r['control_id']: r for r in result['grc_control_review']['recommendations']} in
        # IRIS EXPLAIN: by_id; later lines use this named result.
        by_id = {r["control_id"]: r for r in result["grc_control_review"]["recommendations"]}
        # IRIS EXPLAIN: Call self.assertEqual(by_id['SC005']['action_type'], 'verify'): assert that the actual and expected
        # IRIS EXPLAIN: values are equal.
        self.assertEqual(by_id["SC005"]["action_type"], "verify")
        # IRIS EXPLAIN: Call self.assertEqual(by_id['SC006']['action_type'], 'review'): assert that the actual and expected
        # IRIS EXPLAIN: values are equal.
        self.assertEqual(by_id["SC006"]["action_type"], "review")
        # IRIS EXPLAIN: Call self.assertIsNone(by_id['SC005']['model_score']): assert that the value is exactly None.
        self.assertIsNone(by_id["SC005"]["model_score"])

    # IRIS EXPLAIN: Function ModelIntegrationTests.test_missing_artifact_uses_rules: Regression test: verify that missing
    # IRIS EXPLAIN: artifact uses rules; the assertions below define the exact expected behavior.
    def test_missing_artifact_uses_rules(self):
        # IRIS EXPLAIN: Store the result of ModelService(None, CATALOG).predict(self.sample) (obtain the configured prediction
        # IRIS EXPLAIN: result without training on this call) in result; later lines use this named result.
        result = ModelService(None, CATALOG).predict(self.sample)
        # IRIS EXPLAIN: Call self.assertEqual(result['soc_assessment']['method'], 'rule_baseline'): assert that the actual and
        # IRIS EXPLAIN: expected values are equal.
        self.assertEqual(result["soc_assessment"]["method"], "rule_baseline")
        # IRIS EXPLAIN: Call self.assertIsNone(result['shadow_candidate']): assert that the value is exactly None.
        self.assertIsNone(result["shadow_candidate"])

    # IRIS EXPLAIN: Function ModelIntegrationTests.test_tamper_rejected_before_unpickle: Regression test: verify that tamper
    # IRIS EXPLAIN: rejected before unpickle; the assertions below define the exact expected behavior.
    def test_tamper_rejected_before_unpickle(self):
        # IRIS EXPLAIN: Enter tempfile.TemporaryDirectory() as tmp; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with tempfile.TemporaryDirectory() as tmp:
            # IRIS EXPLAIN: Store the computed value Path(tmp) / 'copied' in copied; later lines use this named result.
            copied = Path(tmp)/"copied"
            # IRIS EXPLAIN: Call shutil.copytree(self.model_dir, copied) using the existing explicit arguments.
            shutil.copytree(self.model_dir, copied)
            # IRIS EXPLAIN: Enter (copied / 'models.joblib').open('ab') as stream; its context manager supplies the existing
            # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
            with (copied/"models.joblib").open("ab") as stream:
                # IRIS EXPLAIN: Call stream.write(b'tamper'): write the already prepared payload.
                stream.write(b"tamper")
            # IRIS EXPLAIN: Enter patch('iris_models.runtime.joblib.load', side_effect=AssertionError('Must not unpickle')); its
            # IRIS EXPLAIN: context manager supplies the existing cleanup/transaction/expected-exception behavior.
            with patch("iris_models.runtime.joblib.load", side_effect=AssertionError("Must not unpickle")):
                # IRIS EXPLAIN: Store the result of ModelService(copied, CATALOG) in service; later lines use this named result.
                service = ModelService(copied, CATALOG)
        # IRIS EXPLAIN: Call self.assertIn('checksum mismatch', service.load_error): assert that the item belongs to the
        # IRIS EXPLAIN: expected collection.
        self.assertIn("checksum mismatch", service.load_error)
        # IRIS EXPLAIN: Call self.assertIsNone(service.bundle): assert that the value is exactly None.
        self.assertIsNone(service.bundle)

    # IRIS EXPLAIN: Function ModelIntegrationTests.test_version_mismatch_rejected_before_load: Regression test: verify that
    # IRIS EXPLAIN: version mismatch rejected before load; the assertions below define the exact expected behavior.
    def test_version_mismatch_rejected_before_load(self):
        # IRIS EXPLAIN: Enter tempfile.TemporaryDirectory() as tmp; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with tempfile.TemporaryDirectory() as tmp:
            # IRIS EXPLAIN: Store the computed value Path(tmp) / 'copied' in copied; later lines use this named result.
            copied = Path(tmp)/"copied"
            # IRIS EXPLAIN: Call shutil.copytree(self.model_dir, copied) using the existing explicit arguments.
            shutil.copytree(self.model_dir, copied)
            # IRIS EXPLAIN: Store the result of copy.deepcopy(self.metadata) (make an independent nested copy for this fixture)
            # IRIS EXPLAIN: in metadata; later lines use this named result.
            metadata = copy.deepcopy(self.metadata)
            # IRIS EXPLAIN: Store 'incompatible' in metadata['scikit_learn_version']; later lines use this named result.
            metadata["scikit_learn_version"] = "incompatible"
            # IRIS EXPLAIN: Call write_json(copied / 'metadata.json', metadata) using the existing explicit arguments.
            write_json(copied/"metadata.json", metadata)
            # IRIS EXPLAIN: Enter patch('iris_models.runtime.joblib.load', side_effect=AssertionError('Must not load')); its
            # IRIS EXPLAIN: context manager supplies the existing cleanup/transaction/expected-exception behavior.
            with patch("iris_models.runtime.joblib.load", side_effect=AssertionError("Must not load")):
                # IRIS EXPLAIN: Store the result of ModelService(copied, CATALOG) in service; later lines use this named result.
                service = ModelService(copied, CATALOG)
        # IRIS EXPLAIN: Call self.assertIn('version mismatch', service.load_error): assert that the item belongs to the expected
        # IRIS EXPLAIN: collection.
        self.assertIn("version mismatch", service.load_error)

    # IRIS EXPLAIN: Function ModelIntegrationTests.test_train_serve_sessionizer_mismatch_disables_ml: Regression test: verify
    # IRIS EXPLAIN: that train serve sessionizer mismatch disables ml; the assertions below define the exact expected behavior.
    def test_train_serve_sessionizer_mismatch_disables_ml(self):
        # IRIS EXPLAIN: Store the result of copy.deepcopy(self.sample) (make an independent nested copy for this fixture) in
        # IRIS EXPLAIN: row; later lines use this named result.
        row = copy.deepcopy(self.sample)
        # IRIS EXPLAIN: Store 'different-sessionizer' in row['aggregation_schema']; later lines use this named result.
        row["aggregation_schema"] = "different-sessionizer"
        # IRIS EXPLAIN: Store the result of self.service.predict(row) (obtain the configured prediction result without training
        # IRIS EXPLAIN: on this call) in result; later lines use this named result.
        result = self.service.predict(row)
        # IRIS EXPLAIN: Call self.assertIsNone(result['shadow_candidate']): assert that the value is exactly None.
        self.assertIsNone(result["shadow_candidate"])
        # IRIS EXPLAIN: Call self.assertTrue(any(('contract differs' in w for w in result['warnings']))): assert that the stated
        # IRIS EXPLAIN: condition is true.
        self.assertTrue(any("contract differs" in w for w in result["warnings"]))

    # IRIS EXPLAIN: Function ModelIntegrationTests.test_model2_uses_crossfit_predictions: Regression test: verify that model2
    # IRIS EXPLAIN: uses crossfit predictions; the assertions below define the exact expected behavior.
    def test_model2_uses_crossfit_predictions(self):
        # IRIS EXPLAIN: Store self.metadata['model2'] in report; later lines use this named result.
        report = self.metadata["model2"]
        # IRIS EXPLAIN: Call self.assertEqual(report['status'], 'trained_shadow'): assert that the actual and expected values
        # IRIS EXPLAIN: are equal.
        self.assertEqual(report["status"], "trained_shadow")
        # IRIS EXPLAIN: Call self.assertIn('never oracle', report['scenario_inputs']): assert that the item belongs to the
        # IRIS EXPLAIN: expected collection.
        self.assertIn("never oracle", report["scenario_inputs"])
        # IRIS EXPLAIN: Call self.assertIn('SC001', report['unsupported_controls']): assert that the item belongs to the
        # IRIS EXPLAIN: expected collection.
        self.assertIn("SC001", report["unsupported_controls"])

    # IRIS EXPLAIN: Function ModelIntegrationTests.test_no_overwrite_of_existing_experiment: Regression test: verify that no
    # IRIS EXPLAIN: overwrite of existing experiment; the assertions below define the exact expected behavior.
    def test_no_overwrite_of_existing_experiment(self):
        # IRIS EXPLAIN: Enter self.assertRaisesRegex(ValueError, 'already contains'); its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.assertRaisesRegex(ValueError, "already contains"):
            # IRIS EXPLAIN: Call train(self.sessions, self.reviews, CATALOG, self.model_dir, synthetic=True) using the existing
            # IRIS EXPLAIN: explicit arguments.
            train(self.sessions, self.reviews, CATALOG, self.model_dir, synthetic=True)

    # IRIS EXPLAIN: Function ModelIntegrationTests.test_grc_criticality_does_not_change_scenario: Regression test: verify that
    # IRIS EXPLAIN: grc criticality does not change scenario; the assertions below define the exact expected behavior.
    def test_grc_criticality_does_not_change_scenario(self):
        # IRIS EXPLAIN: Store (copy.deepcopy(self.sample), copy.deepcopy(self.sample)) in (a, b); later lines use this named
        # IRIS EXPLAIN: result.
        a, b = copy.deepcopy(self.sample), copy.deepcopy(self.sample)
        # IRIS EXPLAIN: Store (1, 5) in (a['context']['asset_criticality'], b['context']['asset_criticality']); later lines use
        # IRIS EXPLAIN: this named result.
        a["context"]["asset_criticality"], b["context"]["asset_criticality"] = 1, 5
        # IRIS EXPLAIN: Call self.assertEqual(self.service.predict(a)['shadow_candidate']['class_probabilities'],
        # IRIS EXPLAIN: self.service.predict(b)['shadow_candidate']['class_probabilities']): assert that the actual and expected
        # IRIS EXPLAIN: values are equal.
        self.assertEqual(self.service.predict(a)["shadow_candidate"]["class_probabilities"],
                         # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                         # IRIS EXPLAIN: arguments/items: self.service.predict(b)["shadow_candidate"]["class_probabilities"]).
                         self.service.predict(b)["shadow_candidate"]["class_probabilities"])

    # IRIS EXPLAIN: Function ModelIntegrationTests.test_bridge_builds_telemetry_only_features: Regression test: verify that
    # IRIS EXPLAIN: bridge builds telemetry only features; the assertions below define the exact expected behavior.
    def test_bridge_builds_telemetry_only_features(self):
        # IRIS EXPLAIN: Store the result of types.SimpleNamespace(**self.sample['features'], session_id='S', run_id='R',
        # IRIS EXPLAIN: member_raw_refs=['ref'], membe... in s; later lines use this named result.
        s = types.SimpleNamespace(**self.sample["features"], session_id="S", run_id="R", member_raw_refs=["ref"], member_event_ids=["e"])
        # IRIS EXPLAIN: Store the result of types.SimpleNamespace(session=s, asset=types.SimpleNamespace(asset_type='server',
        # IRIS EXPLAIN: criticality=5), controls=... in c; later lines use this named result.
        c = types.SimpleNamespace(session=s, asset=types.SimpleNamespace(asset_type="server", criticality=5), controls=[], active_exceptions=[])
        # IRIS EXPLAIN: Store the result of observation_from_context(c, sensor_healthy=True) in observation; later lines use
        # IRIS EXPLAIN: this named result.
        observation = observation_from_context(c, sensor_healthy=True)
        # IRIS EXPLAIN: Call self.assertEqual(set(observation['features']), set(FEATURES)): assert that the actual and expected
        # IRIS EXPLAIN: values are equal.
        self.assertEqual(set(observation["features"]), set(FEATURES))
        # IRIS EXPLAIN: Call self.assertIsNone(observation['context']): assert that the value is exactly None.
        self.assertIsNone(observation["context"])
        # IRIS EXPLAIN: Call self.assertEqual(observation['aggregation_schema'], 'iris-v03-wazuh-session-v1'): assert that the
        # IRIS EXPLAIN: actual and expected values are equal.
        self.assertEqual(observation["aggregation_schema"], "iris-v03-wazuh-session-v1")

    # IRIS EXPLAIN: Function ModelIntegrationTests.test_bridge_assessment_and_recommender_interfaces: Regression test: verify
    # IRIS EXPLAIN: that bridge assessment and recommender interfaces; the assertions below define the exact expected behavior.
    def test_bridge_assessment_and_recommender_interfaces(self):
        # IRIS EXPLAIN: Store the result of types.SimpleNamespace(**self.sample['features'], session_id='S', run_id='R',
        # IRIS EXPLAIN: member_raw_refs=['ref'], membe... in s; later lines use this named result.
        s = types.SimpleNamespace(**self.sample["features"], session_id="S", run_id="R", member_raw_refs=["ref"], member_event_ids=["e"])
        # IRIS EXPLAIN: Store the result of types.SimpleNamespace(session=s, asset=types.SimpleNamespace(asset_type='server',
        # IRIS EXPLAIN: criticality=5), controls=... in c; later lines use this named result.
        c = types.SimpleNamespace(session=s, asset=types.SimpleNamespace(asset_type="server", criticality=5), controls=[], active_exceptions=[])
        # IRIS EXPLAIN: Store the result of types.ModuleType('iris_engine.schemas') in fake_schemas; later lines use this named
        # IRIS EXPLAIN: result.
        fake_schemas = types.ModuleType("iris_engine.schemas")
        # IRIS EXPLAIN: Store types.SimpleNamespace in fake_schemas.Assessment; later lines use this named result.
        fake_schemas.Assessment = types.SimpleNamespace
        # IRIS EXPLAIN: Store types.SimpleNamespace in fake_schemas.ControlRecommendation; later lines use this named result.
        fake_schemas.ControlRecommendation = types.SimpleNamespace
        # IRIS EXPLAIN: Enter patch.dict(sys.modules, {'iris_engine': types.ModuleType('iris_engine'), 'iris_engine.schemas':
        # IRIS EXPLAIN: fake_schemas}); its context manager supplies the existing cleanup/transaction/expected-exception
        # IRIS EXPLAIN: behavior.
        with patch.dict(sys.modules, {"iris_engine": types.ModuleType("iris_engine"), "iris_engine.schemas": fake_schemas}):
            # IRIS EXPLAIN: Store the result of ScenarioAssessorV1(self.service, health_check=lambda _: True) in assessor; later
            # IRIS EXPLAIN: lines use this named result.
            assessor = ScenarioAssessorV1(self.service, health_check=lambda _: True)
            # IRIS EXPLAIN: Store the result of assessor.assess(c) in assessment; later lines use this named result.
            assessment = assessor.assess(c)
            # IRIS EXPLAIN: Call self.assertEqual(assessment.status, 'ASSESSED'): assert that the actual and expected values are
            # IRIS EXPLAIN: equal.
            self.assertEqual(assessment.status, "ASSESSED")
            # IRIS EXPLAIN: Store the result of ControlRecommenderV1(self.service, health_check=lambda _: True) in recommender;
            # IRIS EXPLAIN: later lines use this named result.
            recommender = ControlRecommenderV1(self.service, health_check=lambda _: True)
            # IRIS EXPLAIN: Store the result of recommender.recommend(c, assessment, 3, 5, 0) in (recommendations, metadata);
            # IRIS EXPLAIN: later lines use this named result.
            recommendations, metadata = recommender.recommend(c, assessment, 3, 5, 0)
            # IRIS EXPLAIN: Call self.assertTrue(recommendations): assert that the stated condition is true.
            self.assertTrue(recommendations)
            # IRIS EXPLAIN: Call self.assertEqual(metadata['source'], 'catalogue_fallback'): assert that the actual and expected
            # IRIS EXPLAIN: values are equal.
            self.assertEqual(metadata["source"], "catalogue_fallback")

    # IRIS EXPLAIN: Function ModelIntegrationTests.test_bridge_missing_health_fails_closed: Regression test: verify that bridge
    # IRIS EXPLAIN: missing health fails closed; the assertions below define the exact expected behavior.
    def test_bridge_missing_health_fails_closed(self):
        # IRIS EXPLAIN: Store the result of types.SimpleNamespace(**self.sample['features'], session_id='S', run_id='R',
        # IRIS EXPLAIN: member_raw_refs=[], member_eve... in s; later lines use this named result.
        s = types.SimpleNamespace(**self.sample["features"], session_id="S", run_id="R", member_raw_refs=[], member_event_ids=[])
        # IRIS EXPLAIN: Store the result of types.SimpleNamespace(session=s, asset=types.SimpleNamespace(asset_type='server',
        # IRIS EXPLAIN: criticality=5), controls=... in c; later lines use this named result.
        c = types.SimpleNamespace(session=s, asset=types.SimpleNamespace(asset_type="server", criticality=5), controls=[], active_exceptions=[])
        # IRIS EXPLAIN: Store the result of types.ModuleType('iris_engine.schemas') in fake_schemas; later lines use this named
        # IRIS EXPLAIN: result.
        fake_schemas = types.ModuleType("iris_engine.schemas")
        # IRIS EXPLAIN: Store types.SimpleNamespace in fake_schemas.Assessment; later lines use this named result.
        fake_schemas.Assessment = types.SimpleNamespace
        # IRIS EXPLAIN: Enter patch.dict(sys.modules, {'iris_engine': types.ModuleType('iris_engine'), 'iris_engine.schemas':
        # IRIS EXPLAIN: fake_schemas}); its context manager supplies the existing cleanup/transaction/expected-exception
        # IRIS EXPLAIN: behavior.
        with patch.dict(sys.modules, {"iris_engine": types.ModuleType("iris_engine"), "iris_engine.schemas": fake_schemas}):
            # IRIS EXPLAIN: Store the result of ScenarioAssessorV1(self.service, health_check=lambda _: None).assess(c) in
            # IRIS EXPLAIN: result; later lines use this named result.
            result = ScenarioAssessorV1(self.service, health_check=lambda _: None).assess(c)
        # IRIS EXPLAIN: Call self.assertEqual(result.status, 'ABSTAINED'): assert that the actual and expected values are equal.
        self.assertEqual(result.status, "ABSTAINED")


# IRIS EXPLAIN: Class RangeAdapterTests: Groups regression checks and their isolated synthetic fixtures; unittest invokes test_
# IRIS EXPLAIN: methods independently.
class RangeAdapterTests(unittest.TestCase):
    # IRIS EXPLAIN: Function RangeAdapterTests.setUp: Prepare an isolated synthetic fixture for this test and register cleanup;
    # IRIS EXPLAIN: do not modify user data.
    def setUp(self):
        # IRIS EXPLAIN: Store the result of tempfile.TemporaryDirectory() in self.temp; later lines use this named result.
        self.temp = tempfile.TemporaryDirectory()
        # IRIS EXPLAIN: Store the computed value Path(self.temp.name) / 'campaign-test' in self.campaign; later lines use this
        # IRIS EXPLAIN: named result.
        self.campaign = Path(self.temp.name)/"campaign-test"
        # IRIS EXPLAIN: Store the computed value self.campaign / 'runs/run-0001-ssh_bruteforce' in self.run; later lines use
        # IRIS EXPLAIN: this named result.
        self.run = self.campaign/"runs/run-0001-ssh_bruteforce"
        # IRIS EXPLAIN: Store a mapping containing assets in topology; later lines use this named result.
        topology = {"assets": [
            # IRIS EXPLAIN: Set/describe these existing record fields: asset_id: exact target-asset identity; not an attacker
            # IRIS EXPLAIN: source-IP guess.
            {"asset_id": "A", "ip": "10.77.0.201", "hostname": "workstation01", "role": "workstation"},
            # IRIS EXPLAIN: Set/describe these existing record fields: asset_id: exact target-asset identity; not an attacker
            # IRIS EXPLAIN: source-IP guess.
            {"asset_id": "M", "ip": "10.77.0.10", "hostname": "wazuh-manager", "role": "wazuh_manager"},
            # IRIS EXPLAIN: Set/describe these existing record fields: asset_id: exact target-asset identity; not an attacker
            # IRIS EXPLAIN: source-IP guess.
            {"asset_id": "S", "ip": "10.77.0.11", "hostname": "suricata-sensor", "role": "network_sensor"},
        # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain
        # IRIS EXPLAIN: unchanged.
        ]}
        # IRIS EXPLAIN: Call write_json(self.run / 'topology.json', topology) using the existing explicit arguments.
        write_json(self.run/"topology.json", topology)
        # IRIS EXPLAIN: Call write_json(self.run / 'identity_data.json', {'accounts': [{'username': 'alice'}]}) using the
        # IRIS EXPLAIN: existing explicit arguments.
        write_json(self.run/"identity_data.json", {"accounts": [{"username": "alice"}]})
        # IRIS EXPLAIN: Call write_json(self.run / 'quality/sensor_health.json', {'action_error': None, 'telemetry_errors': [],
        # IRIS EXPLAIN: 'health': {'wazuh-manager': {'status': 'ok', 'active_agent... using the existing explicit arguments.
        write_json(self.run/"quality/sensor_health.json", {
            # IRIS EXPLAIN: Continue the current record with action_error, telemetry_errors; each value comes from the
            # IRIS EXPLAIN: expression shown on this unchanged line.
            "action_error": None, "telemetry_errors": [],
            # IRIS EXPLAIN: Set/describe these existing record fields: status: the stated assessment/proposal/run state; an
            # IRIS EXPLAIN: abstention must not be relabeled benign.
            "health": {"wazuh-manager": {"status": "ok", "active_agents": ["workstation01", "suricata-sensor"]},
                       # IRIS EXPLAIN: Set/describe these existing record fields: status: the stated assessment/proposal/run
                       # IRIS EXPLAIN: state; an abstention must not be relabeled benign; status: the stated
                       # IRIS EXPLAIN: assessment/proposal/run state; an abstention must not be relabeled benign.
                       "suricata-sensor": {"status": "ok"}, "workstation01": {"status": "ok"}}})
        # IRIS EXPLAIN: Store a mapping containing timestamp, event_type, flow_id, src_ip, dest_ip, src_port, dest_port and
        # IRIS EXPLAIN: additional fields in self.eve; later lines use this named result.
        self.eve = {"timestamp": "2026-10-24T10:00:00+00:00", "event_type": "alert", "flow_id": 123,
                    # IRIS EXPLAIN: Continue the current record with src_ip, dest_ip, src_port, dest_port; each value comes from
                    # IRIS EXPLAIN: the expression shown on this unchanged line.
                    "src_ip": "10.77.0.101", "dest_ip": "10.77.0.201", "src_port": 40000, "dest_port": 22,
                    # IRIS EXPLAIN: Continue the current record with proto, alert, severity, signature_id; each value comes from
                    # IRIS EXPLAIN: the expression shown on this unchanged line.
                    "proto": "TCP", "alert": {"severity": 2, "signature_id": 1001}}
        # IRIS EXPLAIN: Store the comprehension [{'timestamp': f'2026-10-24T10:00:0{i}+00:00', 'agent': {'name':
        # IRIS EXPLAIN: 'workstation01'}, 'rule': {'id': '5710', 'level': 5, 'groups': ['sshd'], 'description': 'Failed
        # IRIS EXPLAIN: password' i... in self.wazuh; later lines use this named result.
        self.wazuh = [{"timestamp": f"2026-10-24T10:00:0{i}+00:00", "agent": {"name": "workstation01"},
                       # IRIS EXPLAIN: Continue the current record with rule, id, level, groups, description; each value comes
                       # IRIS EXPLAIN: from the expression shown on this unchanged line.
                       "rule": {"id": "5710", "level": 5, "groups": ["sshd"], "description": "Failed password" if i < 2 else "Accepted password"},
                       # IRIS EXPLAIN: Continue the current record with data, srcip, dstuser; each value comes from the
                       # IRIS EXPLAIN: expression shown on this unchanged line.
                       "data": {"srcip": "10.77.0.101", "dstuser": "alice"}}
                      # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                      # IRIS EXPLAIN: arguments/items: for i in range(3)].
                      for i in range(3)]
        # IRIS EXPLAIN: Call write_jsonl(self.run / 'wazuh_stuff/alerts.jsonl', self.wazuh + [{'timestamp':
        # IRIS EXPLAIN: self.eve['timestamp'], 'full_log': json.dumps(self.eve)}]) using the existing explicit arguments.
        write_jsonl(self.run/"wazuh_stuff/alerts.jsonl", self.wazuh + [{"timestamp": self.eve["timestamp"], "full_log": json.dumps(self.eve)}])
        # IRIS EXPLAIN: Call write_jsonl(self.run / 'suricata_stuff/eve.json', [self.eve]) using the existing explicit
        # IRIS EXPLAIN: arguments.
        write_jsonl(self.run/"suricata_stuff/eve.json", [self.eve])
        # Invalid truth JSON proves extraction does not parse/use truth or scenario labels.
        # IRIS EXPLAIN: Call (self.run / 'activity_ground_truth.jsonl').write_text('NOT JSON, MUST NOT BE READ',
        # IRIS EXPLAIN: encoding='utf-8'): write the existing text payload.
        (self.run/"activity_ground_truth.jsonl").write_text("NOT JSON, MUST NOT BE READ", encoding="utf-8")

    # IRIS EXPLAIN: Function RangeAdapterTests.tearDown: Close test-owned clients/servers or temporary fixtures so no resources
    # IRIS EXPLAIN: or mutable test state leak to later tests.
    def tearDown(self):
        # IRIS EXPLAIN: Call self.temp.cleanup(): remove only this fixture-owned temporary directory.
        self.temp.cleanup()

    # IRIS EXPLAIN: Function RangeAdapterTests.test_suricata_severity_mapping: Regression test: verify that suricata severity
    # IRIS EXPLAIN: mapping; the assertions below define the exact expected behavior.
    def test_suricata_severity_mapping(self):
        # IRIS EXPLAIN: Iterate [(1, 10), (2, 7), (3, 4)], binding each item to (severity, expected); process only the existing
        # IRIS EXPLAIN: observed/fixture collection.
        for severity, expected in [(1, 10), (2, 7), (3, 4)]:
            # IRIS EXPLAIN: Store the result of copy.deepcopy(self.eve) (make an independent nested copy for this fixture) in
            # IRIS EXPLAIN: event; later lines use this named result.
            event = copy.deepcopy(self.eve)
            # IRIS EXPLAIN: Store severity in event['alert']['severity']; later lines use this named result.
            event["alert"]["severity"] = severity
            # IRIS EXPLAIN: Call self.assertEqual(normalize_event(event, 'suricata', 'ref')['level'], expected): assert that the
            # IRIS EXPLAIN: actual and expected values are equal.
            self.assertEqual(normalize_event(event, "suricata", "ref")["level"], expected)

    # IRIS EXPLAIN: Function RangeAdapterTests.test_timezone_required: Regression test: verify that timezone required; the
    # IRIS EXPLAIN: assertions below define the exact expected behavior.
    def test_timezone_required(self):
        # IRIS EXPLAIN: Enter self.assertRaises(ValueError); its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.assertRaises(ValueError):
            # IRIS EXPLAIN: Call timestamp('2026-10-24T10:00:00') using the existing explicit arguments.
            timestamp("2026-10-24T10:00:00")

    # IRIS EXPLAIN: Function RangeAdapterTests.test_truth_independent_import_and_dedup: Regression test: verify that truth
    # IRIS EXPLAIN: independent import and dedup; the assertions below define the exact expected behavior.
    def test_truth_independent_import_and_dedup(self):
        # IRIS EXPLAIN: Store the result of extract_run(self.run, self.campaign.name) in (rows, quarantine); later lines use
        # IRIS EXPLAIN: this named result.
        rows, quarantine = extract_run(self.run, self.campaign.name)
        # IRIS EXPLAIN: Call self.assertFalse(quarantine): assert that the stated condition is false.
        self.assertFalse(quarantine)
        # IRIS EXPLAIN: Call self.assertEqual(len(rows), 2): assert that the actual and expected values are equal.
        self.assertEqual(len(rows), 2)
        # IRIS EXPLAIN: Call self.assertEqual(sum((r['features']['event_count'] for r in rows)), 4): assert that the actual and
        # IRIS EXPLAIN: expected values are equal.
        self.assertEqual(sum(r["features"]["event_count"] for r in rows), 4)
        # IRIS EXPLAIN: Call self.assertTrue(all((r['sensor_healthy'] for r in rows))): assert that the stated condition is
        # IRIS EXPLAIN: true.
        self.assertTrue(all(r["sensor_healthy"] for r in rows))
        # IRIS EXPLAIN: Iterate rows, binding each item to row; process only the existing observed/fixture collection.
        for row in rows:
            # IRIS EXPLAIN: Call self.assertIsNone(row['context']): assert that the value is exactly None.
            self.assertIsNone(row["context"])
            # IRIS EXPLAIN: Call self.assertNotIn('scenario_class', row['features']): assert that the item is absent.
            self.assertNotIn("scenario_class", row["features"])

    # IRIS EXPLAIN: Function RangeAdapterTests.test_benign_success_after_failures_feature: Regression test: verify that benign
    # IRIS EXPLAIN: success after failures feature; the assertions below define the exact expected behavior.
    def test_benign_success_after_failures_feature(self):
        # IRIS EXPLAIN: Store the result of extract_run(self.run, self.campaign.name) in (rows, _); later lines use this named
        # IRIS EXPLAIN: result.
        rows, _ = extract_run(self.run, self.campaign.name)
        # IRIS EXPLAIN: Store the result of next((r for r in rows if r['features']['event_family'] == 'authentication')) in
        # IRIS EXPLAIN: auth; later lines use this named result.
        auth = next(r for r in rows if r["features"]["event_family"] == "authentication")
        # IRIS EXPLAIN: Call self.assertEqual(auth['features']['success_after_failures'], 1): assert that the actual and
        # IRIS EXPLAIN: expected values are equal.
        self.assertEqual(auth["features"]["success_after_failures"], 1)
        # IRIS EXPLAIN: Call self.assertAlmostEqual(auth['features']['failure_ratio'], 2 / 3) using the existing explicit
        # IRIS EXPLAIN: arguments.
        self.assertAlmostEqual(auth["features"]["failure_ratio"], 2/3)

    # IRIS EXPLAIN: Function RangeAdapterTests.test_missing_manifest_blocks_training_health: Regression test: verify that
    # IRIS EXPLAIN: missing manifest blocks training health; the assertions below define the exact expected behavior.
    def test_missing_manifest_blocks_training_health(self):
        # IRIS EXPLAIN: Store the result of extract_campaign(self.campaign) in (rows, report); later lines use this named
        # IRIS EXPLAIN: result.
        rows, report = extract_campaign(self.campaign)
        # IRIS EXPLAIN: Call self.assertFalse(any((r['sensor_healthy'] for r in rows))): assert that the stated condition is
        # IRIS EXPLAIN: false.
        self.assertFalse(any(r["sensor_healthy"] for r in rows))
        # IRIS EXPLAIN: Call self.assertFalse(report['truth_files_read']): assert that the stated condition is false.
        self.assertFalse(report["truth_files_read"])

    # IRIS EXPLAIN: Function RangeAdapterTests.test_complete_runtime_hashes_allow_import_without_truth: Regression test: verify
    # IRIS EXPLAIN: that complete runtime hashes allow import without truth; the assertions below define the exact expected
    # IRIS EXPLAIN: behavior.
    def test_complete_runtime_hashes_allow_import_without_truth(self):
        # IRIS EXPLAIN: Store [] in files; later lines use this named result.
        files = []
        # IRIS EXPLAIN: Iterate ('topology.json', 'identity_data.json', 'wazuh_stuff/alerts.jsonl', 'suricata_stuff/eve.json',
        # IRIS EXPLAIN: 'quality/sensor_health.json'), binding each item to relative; process only the existing observed/fixture
        # IRIS EXPLAIN: collection.
        for relative in ("topology.json", "identity_data.json", "wazuh_stuff/alerts.jsonl", "suricata_stuff/eve.json", "quality/sensor_health.json"):
            # IRIS EXPLAIN: Store the computed value self.run / relative in p; later lines use this named result.
            p = self.run/relative
            # IRIS EXPLAIN: Call files.append({'path': str(p.relative_to(self.campaign)), 'sha256': digest(p), 'bytes':
            # IRIS EXPLAIN: p.stat().st_size}): append one item to the working list.
            files.append({"path": str(p.relative_to(self.campaign)), "sha256": digest(p), "bytes": p.stat().st_size})
        # IRIS EXPLAIN: Call files.append({'path': str((self.run / 'activity_ground_truth.jsonl').relative_to(self.campaign)),
        # IRIS EXPLAIN: 'sha256': 'not-read', 'bytes': 0}): append one item to the working list.
        files.append({"path": str((self.run/"activity_ground_truth.jsonl").relative_to(self.campaign)), "sha256": "not-read", "bytes": 0})
        # IRIS EXPLAIN: Call write_json(self.campaign / 'campaign_manifest.json', {'files': files}) using the existing explicit
        # IRIS EXPLAIN: arguments.
        write_json(self.campaign/"campaign_manifest.json", {"files": files})
        # IRIS EXPLAIN: Store the result of extract_campaign(self.campaign) in (rows, report); later lines use this named
        # IRIS EXPLAIN: result.
        rows, report = extract_campaign(self.campaign)
        # IRIS EXPLAIN: Call self.assertTrue(rows): assert that the stated condition is true.
        self.assertTrue(rows)
        # IRIS EXPLAIN: Call self.assertTrue(all((r['sensor_healthy'] for r in rows))): assert that the stated condition is
        # IRIS EXPLAIN: true.
        self.assertTrue(all(r["sensor_healthy"] for r in rows))
        # IRIS EXPLAIN: Call self.assertFalse(report['warnings']): assert that the stated condition is false.
        self.assertFalse(report["warnings"])

    # IRIS EXPLAIN: Function RangeAdapterTests.test_hash_tamper_blocks_import: Regression test: verify that hash tamper blocks
    # IRIS EXPLAIN: import; the assertions below define the exact expected behavior.
    def test_hash_tamper_blocks_import(self):
        # IRIS EXPLAIN: Store the computed value self.run / 'topology.json' in p; later lines use this named result.
        p = self.run/"topology.json"
        # IRIS EXPLAIN: Call write_json(self.campaign / 'campaign_manifest.json', {'files': [{'path':
        # IRIS EXPLAIN: str(p.relative_to(self.campaign)), 'sha256': 'bad-hash', 'bytes': p.stat().st_size}]}) using the
        # IRIS EXPLAIN: existing explicit arguments.
        write_json(self.campaign/"campaign_manifest.json", {"files": [{"path": str(p.relative_to(self.campaign)), "sha256": "bad-hash", "bytes": p.stat().st_size}]})
        # IRIS EXPLAIN: Enter self.assertRaisesRegex(ValueError, 'integrity mismatch'); its context manager supplies the
        # IRIS EXPLAIN: existing cleanup/transaction/expected-exception behavior.
        with self.assertRaisesRegex(ValueError, "integrity mismatch"):
            # IRIS EXPLAIN: Call extract_campaign(self.campaign) using the existing explicit arguments.
            extract_campaign(self.campaign)

    # IRIS EXPLAIN: Function RangeAdapterTests.test_bad_time_quarantined: Regression test: verify that bad time quarantined; the
    # IRIS EXPLAIN: assertions below define the exact expected behavior.
    def test_bad_time_quarantined(self):
        # IRIS EXPLAIN: Store 'bad-time' in self.wazuh[0]['timestamp']; later lines use this named result.
        self.wazuh[0]["timestamp"] = "bad-time"
        # IRIS EXPLAIN: Call write_jsonl(self.run / 'wazuh_stuff/alerts.jsonl', self.wazuh) using the existing explicit
        # IRIS EXPLAIN: arguments.
        write_jsonl(self.run/"wazuh_stuff/alerts.jsonl", self.wazuh)
        # IRIS EXPLAIN: Store the result of extract_run(self.run, self.campaign.name) in (rows, quarantine); later lines use
        # IRIS EXPLAIN: this named result.
        rows, quarantine = extract_run(self.run, self.campaign.name)
        # IRIS EXPLAIN: Call self.assertTrue(quarantine): assert that the stated condition is true.
        self.assertTrue(quarantine)
        # IRIS EXPLAIN: Call self.assertFalse(any((r['sensor_healthy'] for r in rows))): assert that the stated condition is
        # IRIS EXPLAIN: false.
        self.assertFalse(any(r["sensor_healthy"] for r in rows))


# IRIS EXPLAIN: Run the CLI/test entry point only when this file is executed directly, not when another module imports it.
if __name__ == "__main__":
    # IRIS EXPLAIN: Call unittest.main() using the existing explicit arguments.
    unittest.main()
