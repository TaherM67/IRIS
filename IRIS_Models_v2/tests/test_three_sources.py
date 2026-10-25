# IRIS EXPLAIN: File purpose: Regression tests for exact asset resolution, historical context, deduplication, label separation,
# IRIS EXPLAIN: and full three-input workflows.
# IRIS EXPLAIN: Keep type annotations unevaluated at definition time; this does not add a model feature or change runtime
# IRIS EXPLAIN: settings.
from __future__ import annotations

# IRIS EXPLAIN: Import copy to create independent fixtures or estimators without mutating the original.
import copy
# IRIS EXPLAIN: Import json to encode and decode structured finite JSON payloads.
import json
# IRIS EXPLAIN: Import tempfile to create fresh isolated run/upload/test directories.
import tempfile
# IRIS EXPLAIN: Import unittest to define regression assertions and controlled test mocks.
import unittest
# IRIS EXPLAIN: Import timedelta from datetime to represent timezone-aware timestamps and elapsed-time windows.
from datetime import timedelta
# IRIS EXPLAIN: Import Path from pathlib to resolve server-owned paths without trusting uploaded filenames.
from pathlib import Path

# IRIS EXPLAIN: Import FEATURES, read_jsonl, write_json, write_jsonl from iris_models.contracts to reuse the shared project
# IRIS EXPLAIN: contract/implementation rather than duplicate it.
from iris_models.contracts import FEATURES, read_jsonl, write_json, write_jsonl
# IRIS EXPLAIN: Import generate_samples from iris_models.sample_sources to reuse the shared project contract/implementation
# IRIS EXPLAIN: rather than duplicate it.
from iris_models.sample_sources import generate_samples
# IRIS EXPLAIN: Import timestamp from iris_models.telemetry to reuse the shared project contract/implementation rather than
# IRIS EXPLAIN: duplicate it.
from iris_models.telemetry import timestamp
# IRIS EXPLAIN: Import ASSET_SCHEMA, RISK_SCHEMA, integrate, load_sources, prepare_three from iris_models.three_sources to reuse
# IRIS EXPLAIN: the shared project contract/implementation rather than duplicate it.
from iris_models.three_sources import ASSET_SCHEMA, RISK_SCHEMA, integrate, load_sources, prepare_three
# IRIS EXPLAIN: Import attach_reviews, predict_three, train_three from iris_models.three_training to reuse the shared project
# IRIS EXPLAIN: contract/implementation rather than duplicate it.
from iris_models.three_training import attach_reviews, predict_three, train_three

# IRIS EXPLAIN: Store the computed value Path(__file__).resolve().parents[1] / 'iris_models/data/control_catalog.csv' in
# IRIS EXPLAIN: CATALOG; later lines use this named result.
CATALOG = Path(__file__).resolve().parents[1]/"iris_models/data/control_catalog.csv"


# IRIS EXPLAIN: Class ThreeSourceTests: Groups regression checks and their isolated synthetic fixtures; unittest invokes test_
# IRIS EXPLAIN: methods independently.
class ThreeSourceTests(unittest.TestCase):
    # IRIS EXPLAIN: Bind the following helper to the class (cls), used here for shared setup/construction behavior.
    @classmethod
    # IRIS EXPLAIN: Function ThreeSourceTests.setUpClass: Prepare shared trusted-model/synthetic test fixtures once for this
    # IRIS EXPLAIN: class.
    def setUpClass(cls):
        # IRIS EXPLAIN: Store the result of tempfile.TemporaryDirectory() in cls.root_tmp; later lines use this named result.
        cls.root_tmp = tempfile.TemporaryDirectory()
        # IRIS EXPLAIN: Store the result of Path(cls.root_tmp.name) in cls.base; later lines use this named result.
        cls.base = Path(cls.root_tmp.name)
        # IRIS EXPLAIN: Store the result of generate_samples(cls.base / 'source', campaigns=10, runs_per_class=3, asset_count=6)
        # IRIS EXPLAIN: in cls.manifest; later lines use this named result.
        cls.manifest = generate_samples(cls.base/"source", campaigns=10, runs_per_class=3, asset_count=6)
        # IRIS EXPLAIN: Store the result of json.loads((cls.base / 'source/asset_inventory.json').read_text()) (decode the
        # IRIS EXPLAIN: existing JSON text) in cls.asset_template; later lines use this named result.
        cls.asset_template = json.loads((cls.base/"source/asset_inventory.json").read_text())
        # IRIS EXPLAIN: Store the result of json.loads((cls.base / 'source/risk_register.json').read_text()) (decode the
        # IRIS EXPLAIN: existing JSON text) in cls.risk_template; later lines use this named result.
        cls.risk_template = json.loads((cls.base/"source/risk_register.json").read_text())
        # IRIS EXPLAIN: Store the result of read_jsonl(cls.base / 'source/siem_alerts.jsonl') in cls.alert_template; later lines
        # IRIS EXPLAIN: use this named result.
        cls.alert_template = read_jsonl(cls.base/"source/siem_alerts.jsonl")
        # IRIS EXPLAIN: Store the result of next((r for r in cls.alert_template if r['event_id'].startswith('EVT-'))) in
        # IRIS EXPLAIN: cls.example; later lines use this named result.
        cls.example = next(r for r in cls.alert_template if r["event_id"].startswith("EVT-"))

    # IRIS EXPLAIN: Bind the following helper to the class (cls), used here for shared setup/construction behavior.
    @classmethod
    # IRIS EXPLAIN: Function ThreeSourceTests.tearDownClass: Close test-owned clients/servers or temporary fixtures so no
    # IRIS EXPLAIN: resources or mutable test state leak to later tests.
    def tearDownClass(cls):
        # IRIS EXPLAIN: Call cls.root_tmp.cleanup(): remove only this fixture-owned temporary directory.
        cls.root_tmp.cleanup()

    # IRIS EXPLAIN: Function ThreeSourceTests.setUp: Prepare an isolated synthetic fixture for this test and register cleanup;
    # IRIS EXPLAIN: do not modify user data.
    def setUp(self):
        # IRIS EXPLAIN: Store the result of tempfile.TemporaryDirectory() in self.temp; later lines use this named result.
        self.temp = tempfile.TemporaryDirectory()
        # IRIS EXPLAIN: Store the result of Path(self.temp.name) in self.root; later lines use this named result.
        self.root = Path(self.temp.name)
        # IRIS EXPLAIN: Store the result of copy.deepcopy(self.asset_template) (make an independent nested copy for this
        # IRIS EXPLAIN: fixture) in self.assets; later lines use this named result.
        self.assets = copy.deepcopy(self.asset_template)
        # IRIS EXPLAIN: Store the result of copy.deepcopy(self.risk_template) (make an independent nested copy for this fixture)
        # IRIS EXPLAIN: in self.risks; later lines use this named result.
        self.risks = copy.deepcopy(self.risk_template)
        # IRIS EXPLAIN: Store the result of copy.deepcopy(self.alert_template) (make an independent nested copy for this
        # IRIS EXPLAIN: fixture) in self.alerts; later lines use this named result.
        self.alerts = copy.deepcopy(self.alert_template)
        # IRIS EXPLAIN: Store the comprehension [self.root / name for name in ('asset_inventory.json', 'risk_register.json',
        # IRIS EXPLAIN: 'siem_alerts.jsonl')] in (self.ap, self.rp, self.ep); later lines use this named result.
        self.ap, self.rp, self.ep = [self.root/name for name in ("asset_inventory.json", "risk_register.json", "siem_alerts.jsonl")]

    # IRIS EXPLAIN: Function ThreeSourceTests.tearDown: Close test-owned clients/servers or temporary fixtures so no resources
    # IRIS EXPLAIN: or mutable test state leak to later tests.
    def tearDown(self):
        # IRIS EXPLAIN: Call self.temp.cleanup(): remove only this fixture-owned temporary directory.
        self.temp.cleanup()

    # IRIS EXPLAIN: Function ThreeSourceTests.save: Write the test-owned inventory/register/alert fixture with the intended
    # IRIS EXPLAIN: schema.
    def save(self):
        # IRIS EXPLAIN: Call write_json(self.ap, self.assets) using the existing explicit arguments.
        write_json(self.ap, self.assets)
        # IRIS EXPLAIN: Call write_json(self.rp, self.risks) using the existing explicit arguments.
        write_json(self.rp, self.risks)
        # IRIS EXPLAIN: Call write_jsonl(self.ep, self.alerts) using the existing explicit arguments.
        write_jsonl(self.ep, self.alerts)

    # IRIS EXPLAIN: Function ThreeSourceTests.run_join: Call the actual three-source integration on this test's isolated fixture
    # IRIS EXPLAIN: files.
    def run_join(self):
        # IRIS EXPLAIN: Call self.save() using the existing explicit arguments.
        self.save()
        # IRIS EXPLAIN: Return the result of integrate(self.ap, self.rp, self.ep) to the caller; this ends the current function
        # IRIS EXPLAIN: path.
        return integrate(self.ap, self.rp, self.ep)

    # IRIS EXPLAIN: Function ThreeSourceTests.only_example: Select an isolated existing example snapshot/event fixture for
    # IRIS EXPLAIN: targeted source-join tests.
    def only_example(self):
        # IRIS EXPLAIN: Store [copy.deepcopy(self.example)] in self.alerts; later lines use this named result.
        self.alerts = [copy.deepcopy(self.example)]
        # IRIS EXPLAIN: Return self.alerts[0] to the caller; this ends the current function path.
        return self.alerts[0]

    # IRIS EXPLAIN: Function ThreeSourceTests.test_three_sources_join_without_multiplying_alerts: Regression test: verify that
    # IRIS EXPLAIN: three sources join without multiplying alerts; the assertions below define the exact expected behavior.
    def test_three_sources_join_without_multiplying_alerts(self):
        # IRIS EXPLAIN: Store the result of self.run_join() in (unified, sessions, report); later lines use this named result.
        unified, sessions, report = self.run_join()
        # IRIS EXPLAIN: Call self.assertEqual(len(unified), report['deduplicated_alerts']): assert that the actual and expected
        # IRIS EXPLAIN: values are equal.
        self.assertEqual(len(unified), report["deduplicated_alerts"])
        # IRIS EXPLAIN: Call self.assertTrue(report['join_does_not_multiply_alerts']): assert that the stated condition is true.
        self.assertTrue(report["join_does_not_multiply_alerts"])
        # IRIS EXPLAIN: Call self.assertEqual(len(sessions), 90): assert that the actual and expected values are equal.
        self.assertEqual(len(sessions), 90)
        # IRIS EXPLAIN: Call self.assertTrue(all((len(row['risks']) == 2 for row in unified if row['asset']))): assert that the
        # IRIS EXPLAIN: stated condition is true.
        self.assertTrue(all(len(row["risks"]) == 2 for row in unified if row["asset"]))
        # IRIS EXPLAIN: Call self.assertEqual(report['unresolved_asset_events'], 2): assert that the actual and expected values
        # IRIS EXPLAIN: are equal.
        self.assertEqual(report["unresolved_asset_events"], 2)

    # IRIS EXPLAIN: Function ThreeSourceTests.test_duplicate_rows_removed_and_bad_row_quarantined: Regression test: verify that
    # IRIS EXPLAIN: duplicate rows removed and bad row quarantined; the assertions below define the exact expected behavior.
    def test_duplicate_rows_removed_and_bad_row_quarantined(self):
        # IRIS EXPLAIN: Store the result of self.run_join() in (_, _, report); later lines use this named result.
        _, _, report = self.run_join()
        # IRIS EXPLAIN: Call self.assertEqual(report['exact_duplicate_rows_removed'], 12): assert that the actual and expected
        # IRIS EXPLAIN: values are equal.
        self.assertEqual(report["exact_duplicate_rows_removed"], 12)
        # IRIS EXPLAIN: Call self.assertEqual(len(report['quarantine']), 1): assert that the actual and expected values are
        # IRIS EXPLAIN: equal.
        self.assertEqual(len(report["quarantine"]), 1)

    # IRIS EXPLAIN: Function ThreeSourceTests.test_merged_model_features_remain_allowlisted: Regression test: verify that merged
    # IRIS EXPLAIN: model features remain allowlisted; the assertions below define the exact expected behavior.
    def test_merged_model_features_remain_allowlisted(self):
        # IRIS EXPLAIN: Store the result of self.run_join() in (_, sessions, _); later lines use this named result.
        _, sessions, _ = self.run_join()
        # IRIS EXPLAIN: Call self.assertTrue(all((set(s['features']) == set(FEATURES) for s in sessions))): assert that the
        # IRIS EXPLAIN: stated condition is true.
        self.assertTrue(all(set(s["features"]) == set(FEATURES) for s in sessions))
        # IRIS EXPLAIN: Call self.assertNotIn('asset_id', sessions[0]['features']): assert that the item is absent.
        self.assertNotIn("asset_id", sessions[0]["features"])
        # IRIS EXPLAIN: Call self.assertNotIn('risk_id', sessions[0]['features']): assert that the item is absent.
        self.assertNotIn("risk_id", sessions[0]["features"])
        # IRIS EXPLAIN: Call self.assertEqual(sessions[0]['asset_snapshot']['asset_id'], sessions[0]['asset_id']): assert that
        # IRIS EXPLAIN: the actual and expected values are equal.
        self.assertEqual(sessions[0]["asset_snapshot"]["asset_id"], sessions[0]["asset_id"])

    # IRIS EXPLAIN: Function ThreeSourceTests.test_labels_are_not_runtime_inputs: Regression test: verify that labels are not
    # IRIS EXPLAIN: runtime inputs; the assertions below define the exact expected behavior.
    def test_labels_are_not_runtime_inputs(self):
        # IRIS EXPLAIN: Store the result of self.run_join() in (_, sessions, report); later lines use this named result.
        _, sessions, report = self.run_join()
        # IRIS EXPLAIN: Call self.assertFalse(report['training_labels_read']): assert that the stated condition is false.
        self.assertFalse(report["training_labels_read"])
        # IRIS EXPLAIN: Call self.assertTrue(all(('scenario_class' not in session for session in sessions))): assert that the
        # IRIS EXPLAIN: stated condition is true.
        self.assertTrue(all("scenario_class" not in session for session in sessions))

    # IRIS EXPLAIN: Function ThreeSourceTests.test_destination_ip_fallback: Regression test: verify that destination ip
    # IRIS EXPLAIN: fallback; the assertions below define the exact expected behavior.
    def test_destination_ip_fallback(self):
        # IRIS EXPLAIN: Store the result of self.only_example() in row; later lines use this named result.
        row = self.only_example()
        # IRIS EXPLAIN: Call row.pop('asset_id'): remove and return the selected item.
        row.pop("asset_id")
        # IRIS EXPLAIN: Store the result of self.run_join() in (unified, _, _); later lines use this named result.
        unified, _, _ = self.run_join()
        # IRIS EXPLAIN: Call self.assertEqual(unified[0]['asset_match_method'], 'exact_destination_ip'): assert that the actual
        # IRIS EXPLAIN: and expected values are equal.
        self.assertEqual(unified[0]["asset_match_method"], "exact_destination_ip")

    # IRIS EXPLAIN: Function ThreeSourceTests.test_hostname_fallback: Regression test: verify that hostname fallback; the
    # IRIS EXPLAIN: assertions below define the exact expected behavior.
    def test_hostname_fallback(self):
        # IRIS EXPLAIN: Store the result of self.only_example() in row; later lines use this named result.
        row = self.only_example()
        # IRIS EXPLAIN: Call row.pop('asset_id'): remove and return the selected item.
        row.pop("asset_id")
        # IRIS EXPLAIN: Call row.pop('destination_ip'): remove and return the selected item.
        row.pop("destination_ip")
        # IRIS EXPLAIN: Store the result of self.run_join() in (unified, _, _); later lines use this named result.
        unified, _, _ = self.run_join()
        # IRIS EXPLAIN: Call self.assertEqual(unified[0]['asset_match_method'], 'exact_agent_hostname'): assert that the actual
        # IRIS EXPLAIN: and expected values are equal.
        self.assertEqual(unified[0]["asset_match_method"], "exact_agent_hostname")

    # IRIS EXPLAIN: Function ThreeSourceTests.test_indexer_source_wrapper_preserves_collector_metadata: Regression test: verify
    # IRIS EXPLAIN: that indexer source wrapper preserves collector metadata; the assertions below define the exact expected
    # IRIS EXPLAIN: behavior.
    def test_indexer_source_wrapper_preserves_collector_metadata(self):
        # IRIS EXPLAIN: Store the result of self.only_example() in row; later lines use this named result.
        row = self.only_example()
        # IRIS EXPLAIN: Store the comprehension {key: row.pop(key) for key in ('sensor_healthy', 'campaign_id', 'run_id',
        # IRIS EXPLAIN: 'data_provenance')} in metadata; later lines use this named result.
        metadata = {key: row.pop(key) for key in ("sensor_healthy", "campaign_id", "run_id", "data_provenance")}
        # IRIS EXPLAIN: Store the result of row.pop('event_id') (remove and return the selected item) in eid; later lines use
        # IRIS EXPLAIN: this named result.
        eid = row.pop("event_id")
        # IRIS EXPLAIN: Store [{'_source': row, '_id': eid, **metadata}] in self.alerts; later lines use this named result.
        self.alerts = [{"_source": row, "_id": eid, **metadata}]
        # IRIS EXPLAIN: Store the result of self.run_join() in (unified, sessions, _); later lines use this named result.
        unified, sessions, _ = self.run_join()
        # IRIS EXPLAIN: Call self.assertEqual(unified[0]['event_id'], eid): assert that the actual and expected values are
        # IRIS EXPLAIN: equal.
        self.assertEqual(unified[0]["event_id"], eid)
        # IRIS EXPLAIN: Call self.assertTrue(sessions[0]['sensor_healthy']): assert that the stated condition is true.
        self.assertTrue(sessions[0]["sensor_healthy"])

    # IRIS EXPLAIN: Function ThreeSourceTests.test_attacker_source_ip_is_not_a_victim_lookup: Regression test: verify that
    # IRIS EXPLAIN: attacker source ip is not a victim lookup; the assertions below define the exact expected behavior.
    def test_attacker_source_ip_is_not_a_victim_lookup(self):
        # IRIS EXPLAIN: Store the result of self.only_example() in row; later lines use this named result.
        row = self.only_example()
        # IRIS EXPLAIN: Store the result of row.pop('destination_ip') (remove and return the selected item) in row['source_ip'];
        # IRIS EXPLAIN: later lines use this named result.
        row["source_ip"] = row.pop("destination_ip")
        # IRIS EXPLAIN: Call row.pop('asset_id'): remove and return the selected item.
        row.pop("asset_id")
        # IRIS EXPLAIN: Call row.pop('agent_name'): remove and return the selected item.
        row.pop("agent_name")
        # IRIS EXPLAIN: Store the result of self.run_join() in (unified, sessions, _); later lines use this named result.
        unified, sessions, _ = self.run_join()
        # IRIS EXPLAIN: Call self.assertIsNone(unified[0]['asset']): assert that the value is exactly None.
        self.assertIsNone(unified[0]["asset"])
        # IRIS EXPLAIN: Call self.assertFalse(sessions): assert that the stated condition is false.
        self.assertFalse(sessions)

    # IRIS EXPLAIN: Function ThreeSourceTests.test_conflicting_asset_id_and_ip_not_silently_joined: Regression test: verify that
    # IRIS EXPLAIN: conflicting asset id and ip not silently joined; the assertions below define the exact expected behavior.
    def test_conflicting_asset_id_and_ip_not_silently_joined(self):
        # IRIS EXPLAIN: Store the result of self.only_example() in row; later lines use this named result.
        row = self.only_example()
        # IRIS EXPLAIN: Store the result of next((a for a in self.assets['records'] if a['asset_id'] != row['asset_id'] and
        # IRIS EXPLAIN: a['valid_to'])) in other; later lines use this named result.
        other = next(a for a in self.assets["records"] if a["asset_id"] != row["asset_id"] and a["valid_to"])
        # IRIS EXPLAIN: Store other['ip_addresses'][0] in row['destination_ip']; later lines use this named result.
        row["destination_ip"] = other["ip_addresses"][0]
        # IRIS EXPLAIN: Store the result of self.run_join() in (unified, _, report); later lines use this named result.
        unified, _, report = self.run_join()
        # IRIS EXPLAIN: Call self.assertIsNone(unified[0]['asset']): assert that the value is exactly None.
        self.assertIsNone(unified[0]["asset"])
        # IRIS EXPLAIN: Call self.assertEqual(report['unresolved_asset_events'], 1): assert that the actual and expected values
        # IRIS EXPLAIN: are equal.
        self.assertEqual(report["unresolved_asset_events"], 1)

    # IRIS EXPLAIN: Function ThreeSourceTests.test_ambiguous_ip_not_first_match: Regression test: verify that ambiguous ip not
    # IRIS EXPLAIN: first match; the assertions below define the exact expected behavior.
    def test_ambiguous_ip_not_first_match(self):
        # IRIS EXPLAIN: Store the result of self.only_example() in row; later lines use this named result.
        row = self.only_example()
        # IRIS EXPLAIN: Store the result of next((a for a in self.assets['records'] if a['asset_id'] != row['asset_id'] and
        # IRIS EXPLAIN: a['valid_to'])) in other; later lines use this named result.
        other = next(a for a in self.assets["records"] if a["asset_id"] != row["asset_id"] and a["valid_to"])
        # IRIS EXPLAIN: Store [row['destination_ip']] in other['ip_addresses']; later lines use this named result.
        other["ip_addresses"] = [row["destination_ip"]]
        # IRIS EXPLAIN: Call row.pop('asset_id'): remove and return the selected item.
        row.pop("asset_id")
        # IRIS EXPLAIN: Store the result of self.run_join() in (unified, _, _); later lines use this named result.
        unified, _, _ = self.run_join()
        # IRIS EXPLAIN: Call self.assertIsNone(unified[0]['asset']): assert that the value is exactly None.
        self.assertIsNone(unified[0]["asset"])

    # IRIS EXPLAIN: Function ThreeSourceTests.test_null_keys_do_not_match_each_other: Regression test: verify that null keys do
    # IRIS EXPLAIN: not match each other; the assertions below define the exact expected behavior.
    def test_null_keys_do_not_match_each_other(self):
        # IRIS EXPLAIN: Store the result of self.only_example() in row; later lines use this named result.
        row = self.only_example()
        # IRIS EXPLAIN: Call row.update({'asset_id': None, 'destination_ip': None, 'agent_name': None}): merge the supplied
        # IRIS EXPLAIN: fields into this existing mapping.
        row.update({"asset_id": None, "destination_ip": None, "agent_name": None})
        # IRIS EXPLAIN: Store the result of self.run_join() in (unified, sessions, _); later lines use this named result.
        unified, sessions, _ = self.run_join()
        # IRIS EXPLAIN: Call self.assertIsNone(unified[0]['asset']): assert that the value is exactly None.
        self.assertIsNone(unified[0]["asset"])
        # IRIS EXPLAIN: Call self.assertFalse(sessions): assert that the stated condition is false.
        self.assertFalse(sessions)

    # IRIS EXPLAIN: Function ThreeSourceTests.test_future_asset_version_not_applied_to_past: Regression test: verify that future
    # IRIS EXPLAIN: asset version not applied to past; the assertions below define the exact expected behavior.
    def test_future_asset_version_not_applied_to_past(self):
        # IRIS EXPLAIN: Store the result of self.only_example() in row; later lines use this named result.
        row = self.only_example()
        # IRIS EXPLAIN: Store the comprehension [a for a in self.assets['records'] if a['asset_id'] == row['asset_id']] in
        # IRIS EXPLAIN: versions; later lines use this named result.
        versions = [a for a in self.assets["records"] if a["asset_id"] == row["asset_id"]]
        # IRIS EXPLAIN: Store the result of next((a for a in versions if a['valid_to'])) in old; later lines use this named
        # IRIS EXPLAIN: result.
        old = next(a for a in versions if a["valid_to"])
        # IRIS EXPLAIN: Store the result of next((a for a in versions if not a['valid_to'])) in new; later lines use this named
        # IRIS EXPLAIN: result.
        new = next(a for a in versions if not a["valid_to"])
        # IRIS EXPLAIN: Store (1, 5) in (old['criticality'], new['criticality']); later lines use this named result.
        old["criticality"], new["criticality"] = 1, 5
        # IRIS EXPLAIN: Store the result of self.run_join() in (unified, _, _); later lines use this named result.
        unified, _, _ = self.run_join()
        # IRIS EXPLAIN: Call self.assertEqual(unified[0]['asset']['criticality'], 1): assert that the actual and expected values
        # IRIS EXPLAIN: are equal.
        self.assertEqual(unified[0]["asset"]["criticality"], 1)

    # IRIS EXPLAIN: Function ThreeSourceTests.test_current_version_and_rotated_ip_used_after_boundary: Regression test: verify
    # IRIS EXPLAIN: that current version and rotated ip used after boundary; the assertions below define the exact expected
    # IRIS EXPLAIN: behavior.
    def test_current_version_and_rotated_ip_used_after_boundary(self):
        # IRIS EXPLAIN: Store the result of self.only_example() in row; later lines use this named result.
        row = self.only_example()
        # IRIS EXPLAIN: Store the result of next((a for a in self.assets['records'] if a['asset_id'] == row['asset_id'] and (not
        # IRIS EXPLAIN: a['valid_to']))) in new; later lines use this named result.
        new = next(a for a in self.assets["records"] if a["asset_id"] == row["asset_id"] and not a["valid_to"])
        # IRIS EXPLAIN: Store (new['valid_from'], new['ip_addresses'][0]) in (row['timestamp'], row['destination_ip']); later
        # IRIS EXPLAIN: lines use this named result.
        row["timestamp"], row["destination_ip"] = new["valid_from"], new["ip_addresses"][0]
        # IRIS EXPLAIN: Store the result of self.run_join() in (unified, _, _); later lines use this named result.
        unified, _, _ = self.run_join()
        # IRIS EXPLAIN: Call self.assertEqual(unified[0]['asset']['asset_version_id'], new['asset_version_id']): assert that the
        # IRIS EXPLAIN: actual and expected values are equal.
        self.assertEqual(unified[0]["asset"]["asset_version_id"], new["asset_version_id"])

    # IRIS EXPLAIN: Function ThreeSourceTests.test_recorded_later_asset_cannot_leak_backward: Regression test: verify that
    # IRIS EXPLAIN: recorded later asset cannot leak backward; the assertions below define the exact expected behavior.
    def test_recorded_later_asset_cannot_leak_backward(self):
        # IRIS EXPLAIN: Store the result of self.only_example() in row; later lines use this named result.
        row = self.only_example()
        # IRIS EXPLAIN: Iterate self.assets['records'], binding each item to asset; process only the existing observed/fixture
        # IRIS EXPLAIN: collection.
        for asset in self.assets["records"]:
            # IRIS EXPLAIN: Enter this branch only when asset['asset_id'] == row['asset_id'].
            if asset["asset_id"] == row["asset_id"]:
                # IRIS EXPLAIN: Store '2027-01-01T00:00:00Z' in asset['recorded_at']; later lines use this named result.
                asset["recorded_at"] = "2027-01-01T00:00:00Z"
        # IRIS EXPLAIN: Store the result of self.run_join() in (unified, _, _); later lines use this named result.
        unified, _, _ = self.run_join()
        # IRIS EXPLAIN: Call self.assertIsNone(unified[0]['asset']): assert that the value is exactly None.
        self.assertIsNone(unified[0]["asset"])

    # IRIS EXPLAIN: Function ThreeSourceTests.test_future_risk_context_not_fabricated: Regression test: verify that future risk
    # IRIS EXPLAIN: context not fabricated; the assertions below define the exact expected behavior.
    def test_future_risk_context_not_fabricated(self):
        # IRIS EXPLAIN: Store the result of self.only_example() in row; later lines use this named result.
        row = self.only_example()
        # IRIS EXPLAIN: Iterate self.risks['records'], binding each item to risk; process only the existing observed/fixture
        # IRIS EXPLAIN: collection.
        for risk in self.risks["records"]:
            # IRIS EXPLAIN: Enter this branch only when risk['asset_id'] == row['asset_id'].
            if risk["asset_id"] == row["asset_id"]:
                # IRIS EXPLAIN: Store '2027-01-01T00:00:00Z' in risk['recorded_at']; later lines use this named result.
                risk["recorded_at"] = "2027-01-01T00:00:00Z"
        # IRIS EXPLAIN: Store the result of self.run_join() in (unified, sessions, report); later lines use this named result.
        unified, sessions, report = self.run_join()
        # IRIS EXPLAIN: Call self.assertEqual(unified[0]['risks'], []): assert that the actual and expected values are equal.
        self.assertEqual(unified[0]["risks"], [])
        # IRIS EXPLAIN: Call self.assertEqual(len(sessions), 1): assert that the actual and expected values are equal.
        self.assertEqual(len(sessions), 1)
        # IRIS EXPLAIN: Call self.assertIsNone(sessions[0]['context']): assert that the value is exactly None.
        self.assertIsNone(sessions[0]["context"])
        # IRIS EXPLAIN: Call self.assertEqual(report['matched_events_without_risk_context'], 1): assert that the actual and
        # IRIS EXPLAIN: expected values are equal.
        self.assertEqual(report["matched_events_without_risk_context"], 1)

    # IRIS EXPLAIN: Function ThreeSourceTests.test_overlapping_asset_history_rejected: Regression test: verify that overlapping
    # IRIS EXPLAIN: asset history rejected; the assertions below define the exact expected behavior.
    def test_overlapping_asset_history_rejected(self):
        # IRIS EXPLAIN: Store None (no result/value) in self.assets['records'][0]['valid_to']; later lines use this named
        # IRIS EXPLAIN: result.
        self.assets["records"][0]["valid_to"] = None
        # IRIS EXPLAIN: Call self.save() using the existing explicit arguments.
        self.save()
        # IRIS EXPLAIN: Enter self.assertRaisesRegex(ValueError, 'Overlapping'); its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.assertRaisesRegex(ValueError, "Overlapping"):
            # IRIS EXPLAIN: Call load_sources(self.ap, self.rp) using the existing explicit arguments.
            load_sources(self.ap, self.rp)

    # IRIS EXPLAIN: Function ThreeSourceTests.test_overlapping_risk_history_rejected: Regression test: verify that overlapping
    # IRIS EXPLAIN: risk history rejected; the assertions below define the exact expected behavior.
    def test_overlapping_risk_history_rejected(self):
        # IRIS EXPLAIN: Store None (no result/value) in self.risks['records'][0]['valid_to']; later lines use this named result.
        self.risks["records"][0]["valid_to"] = None
        # IRIS EXPLAIN: Call self.save() using the existing explicit arguments.
        self.save()
        # IRIS EXPLAIN: Enter self.assertRaisesRegex(ValueError, 'Overlapping'); its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.assertRaisesRegex(ValueError, "Overlapping"):
            # IRIS EXPLAIN: Call load_sources(self.ap, self.rp) using the existing explicit arguments.
            load_sources(self.ap, self.rp)

    # IRIS EXPLAIN: Function ThreeSourceTests.test_risk_referencing_unknown_asset_rejected: Regression test: verify that risk
    # IRIS EXPLAIN: referencing unknown asset rejected; the assertions below define the exact expected behavior.
    def test_risk_referencing_unknown_asset_rejected(self):
        # IRIS EXPLAIN: Store 'AST-UNKNOWN' in self.risks['records'][0]['asset_id']; later lines use this named result.
        self.risks["records"][0]["asset_id"] = "AST-UNKNOWN"
        # IRIS EXPLAIN: Call self.save() using the existing explicit arguments.
        self.save()
        # IRIS EXPLAIN: Enter self.assertRaisesRegex(ValueError, 'absent from inventory'); its context manager supplies the
        # IRIS EXPLAIN: existing cleanup/transaction/expected-exception behavior.
        with self.assertRaisesRegex(ValueError, "absent from inventory"):
            # IRIS EXPLAIN: Call load_sources(self.ap, self.rp) using the existing explicit arguments.
            load_sources(self.ap, self.rp)

    # IRIS EXPLAIN: Function ThreeSourceTests.test_context_version_change_splits_a_session: Regression test: verify that context
    # IRIS EXPLAIN: version change splits a session; the assertions below define the exact expected behavior.
    def test_context_version_change_splits_a_session(self):
        # IRIS EXPLAIN: Store the result of self.only_example() in row; later lines use this named result.
        row = self.only_example()
        # IRIS EXPLAIN: Store the result of next((a for a in self.assets['records'] if a['asset_id'] == row['asset_id'] and (not
        # IRIS EXPLAIN: a['valid_to']))) in new; later lines use this named result.
        new = next(a for a in self.assets["records"] if a["asset_id"] == row["asset_id"] and not a["valid_to"])
        # IRIS EXPLAIN: Store the result of timestamp(new['valid_from']) in boundary; later lines use this named result.
        boundary = timestamp(new["valid_from"])
        # IRIS EXPLAIN: Call row.update({'timestamp': (boundary - timedelta(seconds=5)).isoformat(), 'event_id':
        # IRIS EXPLAIN: 'boundary-before'}): merge the supplied fields into this existing mapping.
        row.update({"timestamp": (boundary-timedelta(seconds=5)).isoformat(), "event_id": "boundary-before"})
        # IRIS EXPLAIN: Store a mapping containing timestamp, event_id, destination_ip in later; later lines use this named
        # IRIS EXPLAIN: result.
        later = {**row, "timestamp": (boundary+timedelta(seconds=5)).isoformat(),
                 # IRIS EXPLAIN: Continue the current record with event_id, destination_ip; each value comes from the expression
                 # IRIS EXPLAIN: shown on this unchanged line.
                 "event_id": "boundary-after", "destination_ip": new["ip_addresses"][0]}
        # IRIS EXPLAIN: Store [row, later] in self.alerts; later lines use this named result.
        self.alerts = [row, later]
        # IRIS EXPLAIN: Store the result of self.run_join() in (_, sessions, _); later lines use this named result.
        _, sessions, _ = self.run_join()
        # IRIS EXPLAIN: Call self.assertEqual(len(sessions), 2): assert that the actual and expected values are equal.
        self.assertEqual(len(sessions), 2)
        # IRIS EXPLAIN: Call self.assertNotEqual(sessions[0]['asset_snapshot']['asset_version_id'],
        # IRIS EXPLAIN: sessions[1]['asset_snapshot']['asset_version_id']): assert that the values differ.
        self.assertNotEqual(sessions[0]["asset_snapshot"]["asset_version_id"], sessions[1]["asset_snapshot"]["asset_version_id"])

    # IRIS EXPLAIN: Function ThreeSourceTests.test_duplicate_snapshot_id_rejected: Regression test: verify that duplicate
    # IRIS EXPLAIN: snapshot id rejected; the assertions below define the exact expected behavior.
    def test_duplicate_snapshot_id_rejected(self):
        # IRIS EXPLAIN: Call self.assets['records'].append(copy.deepcopy(self.assets['records'][0])): append one item to the
        # IRIS EXPLAIN: working list.
        self.assets["records"].append(copy.deepcopy(self.assets["records"][0]))
        # IRIS EXPLAIN: Call self.save() using the existing explicit arguments.
        self.save()
        # IRIS EXPLAIN: Enter self.assertRaisesRegex(ValueError, 'Duplicate'); its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            # IRIS EXPLAIN: Call load_sources(self.ap, self.rp) using the existing explicit arguments.
            load_sources(self.ap, self.rp)

    # IRIS EXPLAIN: Function ThreeSourceTests.test_missing_business_criticality_not_imputed: Regression test: verify that
    # IRIS EXPLAIN: missing business criticality not imputed; the assertions below define the exact expected behavior.
    def test_missing_business_criticality_not_imputed(self):
        # IRIS EXPLAIN: Call self.assets['records'][0].pop('criticality'): remove and return the selected item.
        self.assets["records"][0].pop("criticality")
        # IRIS EXPLAIN: Call self.save() using the existing explicit arguments.
        self.save()
        # IRIS EXPLAIN: Enter self.assertRaises(ValueError); its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.assertRaises(ValueError):
            # IRIS EXPLAIN: Call load_sources(self.ap, self.rp) using the existing explicit arguments.
            load_sources(self.ap, self.rp)

    # IRIS EXPLAIN: Function ThreeSourceTests.test_mixed_synthetic_and_real_provenance_rejected: Regression test: verify that
    # IRIS EXPLAIN: mixed synthetic and real provenance rejected; the assertions below define the exact expected behavior.
    def test_mixed_synthetic_and_real_provenance_rejected(self):
        # IRIS EXPLAIN: Store 'operational' in self.risks['data_provenance']; later lines use this named result.
        self.risks["data_provenance"] = "operational"
        # IRIS EXPLAIN: Call self.save() using the existing explicit arguments.
        self.save()
        # IRIS EXPLAIN: Enter self.assertRaisesRegex(ValueError, 'provenance'); its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.assertRaisesRegex(ValueError, "provenance"):
            # IRIS EXPLAIN: Call load_sources(self.ap, self.rp) using the existing explicit arguments.
            load_sources(self.ap, self.rp)

    # IRIS EXPLAIN: Function ThreeSourceTests.test_conflicting_event_id_excludes_both_versions: Regression test: verify that
    # IRIS EXPLAIN: conflicting event id excludes both versions; the assertions below define the exact expected behavior.
    def test_conflicting_event_id_excludes_both_versions(self):
        # IRIS EXPLAIN: Store the result of self.only_example() in row; later lines use this named result.
        row = self.only_example()
        # IRIS EXPLAIN: Store the result of copy.deepcopy(row) (make an independent nested copy for this fixture) in other;
        # IRIS EXPLAIN: later lines use this named result.
        other = copy.deepcopy(row)
        # IRIS EXPLAIN: Store the computed value (row['rule_level'] + 1) % 16 in other['rule_level']; later lines use this named
        # IRIS EXPLAIN: result.
        other["rule_level"] = (row["rule_level"] + 1) % 16
        # IRIS EXPLAIN: Call self.alerts.append(other): append one item to the working list.
        self.alerts.append(other)
        # IRIS EXPLAIN: Store the result of self.run_join() in (unified, sessions, report); later lines use this named result.
        unified, sessions, report = self.run_join()
        # IRIS EXPLAIN: Call self.assertFalse(unified): assert that the stated condition is false.
        self.assertFalse(unified)
        # IRIS EXPLAIN: Call self.assertFalse(sessions): assert that the stated condition is false.
        self.assertFalse(sessions)
        # IRIS EXPLAIN: Call self.assertIn(row['event_id'], report['conflicting_event_ids_excluded']): assert that the item
        # IRIS EXPLAIN: belongs to the expected collection.
        self.assertIn(row["event_id"], report["conflicting_event_ids_excluded"])

    # IRIS EXPLAIN: Function ThreeSourceTests.test_shuffle_does_not_change_sessions: Regression test: verify that shuffle does
    # IRIS EXPLAIN: not change sessions; the assertions below define the exact expected behavior.
    def test_shuffle_does_not_change_sessions(self):
        # IRIS EXPLAIN: Store the result of self.run_join() in (_, first, _); later lines use this named result.
        _, first, _ = self.run_join()
        # IRIS EXPLAIN: Call self.alerts.reverse() using the existing explicit arguments.
        self.alerts.reverse()
        # IRIS EXPLAIN: Store the result of self.run_join() in (_, second, _); later lines use this named result.
        _, second, _ = self.run_join()
        # IRIS EXPLAIN: Function ThreeSourceTests.values: Extract the deterministic observed session content used to compare
        # IRIS EXPLAIN: shuffled input orders.
        # IRIS EXPLAIN: Inputs: sessions: observed prepared sessions, not automatically reviewed labels.
        def values(sessions):
            # IRIS EXPLAIN: Return the comprehension {s['session_id']: (s['features'], s['context']) for s in sessions} to the
            # IRIS EXPLAIN: caller; this ends the current function path.
            return {s["session_id"]: (s["features"], s["context"]) for s in sessions}
        # IRIS EXPLAIN: Call self.assertEqual(values(first), values(second)): assert that the actual and expected values are
        # IRIS EXPLAIN: equal.
        self.assertEqual(values(first), values(second))

    # IRIS EXPLAIN: Function ThreeSourceTests.test_sensor_gap_marks_session_unhealthy: Regression test: verify that sensor gap
    # IRIS EXPLAIN: marks session unhealthy; the assertions below define the exact expected behavior.
    def test_sensor_gap_marks_session_unhealthy(self):
        # IRIS EXPLAIN: Store the result of self.only_example() in row; later lines use this named result.
        row = self.only_example()
        # IRIS EXPLAIN: Store False in row['sensor_healthy']; later lines use this named result.
        row["sensor_healthy"] = False
        # IRIS EXPLAIN: Store the result of self.run_join() in (_, sessions, _); later lines use this named result.
        _, sessions, _ = self.run_join()
        # IRIS EXPLAIN: Call self.assertFalse(sessions[0]['sensor_healthy']): assert that the stated condition is false.
        self.assertFalse(sessions[0]["sensor_healthy"])

    # IRIS EXPLAIN: Function ThreeSourceTests.test_risk_context_uses_a_real_pair_not_independent_maxima: Regression test: verify
    # IRIS EXPLAIN: that risk context uses a real pair not independent maxima; the assertions below define the exact expected
    # IRIS EXPLAIN: behavior.
    def test_risk_context_uses_a_real_pair_not_independent_maxima(self):
        # IRIS EXPLAIN: Store the result of self.only_example() in row; later lines use this named result.
        row = self.only_example()
        # IRIS EXPLAIN: Store the comprehension [r for r in self.risks['records'] if r['asset_id'] == row['asset_id'] and
        # IRIS EXPLAIN: r['valid_to']] in candidates; later lines use this named result.
        candidates = [r for r in self.risks["records"] if r["asset_id"] == row["asset_id"] and r["valid_to"]]
        # IRIS EXPLAIN: Call candidates[0].update({'likelihood': 5, 'impact': 1}): merge the supplied fields into this existing
        # IRIS EXPLAIN: mapping.
        candidates[0].update({"likelihood": 5, "impact": 1})
        # IRIS EXPLAIN: Call candidates[1].update({'likelihood': 3, 'impact': 5}): merge the supplied fields into this existing
        # IRIS EXPLAIN: mapping.
        candidates[1].update({"likelihood": 3, "impact": 5})
        # IRIS EXPLAIN: Store the result of self.run_join() in (_, sessions, _); later lines use this named result.
        _, sessions, _ = self.run_join()
        # IRIS EXPLAIN: Store sessions[0]['context'] in context; later lines use this named result.
        context = sessions[0]["context"]
        # IRIS EXPLAIN: Call self.assertEqual((context['current_likelihood'], context['impact']), (3, 5)): assert that the
        # IRIS EXPLAIN: actual and expected values are equal.
        self.assertEqual((context["current_likelihood"], context["impact"]), (3, 5))
        # IRIS EXPLAIN: Call self.assertEqual(context['context_risk_id'], candidates[1]['risk_id']): assert that the actual and
        # IRIS EXPLAIN: expected values are equal.
        self.assertEqual(context["context_risk_id"], candidates[1]["risk_id"])

    # IRIS EXPLAIN: Function ThreeSourceTests.test_recent_count_never_uses_future_or_incomplete_sessions: Regression test:
    # IRIS EXPLAIN: verify that recent count never uses future or incomplete sessions; the assertions below define the exact
    # IRIS EXPLAIN: expected behavior.
    def test_recent_count_never_uses_future_or_incomplete_sessions(self):
        # IRIS EXPLAIN: Store the result of self.only_example() in row; later lines use this named result.
        row = self.only_example()
        # IRIS EXPLAIN: Store the result of timestamp(row['timestamp']) in start; later lines use this named result.
        start = timestamp(row["timestamp"])
        # IRIS EXPLAIN: Call row.update({'run_id': 'first', 'event_id': 'first-1', 'timestamp': start.isoformat()}): merge the
        # IRIS EXPLAIN: supplied fields into this existing mapping.
        row.update({"run_id": "first", "event_id": "first-1", "timestamp": start.isoformat()})
        # IRIS EXPLAIN: Store a mapping containing event_id, timestamp in first_end; later lines use this named result.
        first_end = {**row, "event_id": "first-2", "timestamp": (start+timedelta(seconds=20)).isoformat()}
        # IRIS EXPLAIN: Store a mapping containing run_id, event_id, timestamp in overlapping; later lines use this named
        # IRIS EXPLAIN: result.
        overlapping = {**row, "run_id": "overlap", "event_id": "overlap-1", "timestamp": (start+timedelta(seconds=5)).isoformat()}
        # IRIS EXPLAIN: Store a mapping containing run_id, event_id, timestamp in later; later lines use this named result.
        later = {**row, "run_id": "later", "event_id": "later-1", "timestamp": (start+timedelta(seconds=30)).isoformat()}
        # IRIS EXPLAIN: Store [later, row, overlapping, first_end] in self.alerts; later lines use this named result.
        self.alerts = [later, row, overlapping, first_end]
        # IRIS EXPLAIN: Store the result of self.run_join() in (_, sessions, _); later lines use this named result.
        _, sessions, _ = self.run_join()
        # IRIS EXPLAIN: Store the comprehension {s['run_id']: s for s in sessions} in by_run; later lines use this named result.
        by_run = {s["run_id"]: s for s in sessions}
        # IRIS EXPLAIN: Call self.assertEqual(by_run['first']['context']['previous_similar_24h'], 0): assert that the actual and
        # IRIS EXPLAIN: expected values are equal.
        self.assertEqual(by_run["first"]["context"]["previous_similar_24h"], 0)
        # IRIS EXPLAIN: Call self.assertEqual(by_run['overlap']['context']['previous_similar_24h'], 0): assert that the actual
        # IRIS EXPLAIN: and expected values are equal.
        self.assertEqual(by_run["overlap"]["context"]["previous_similar_24h"], 0)
        # IRIS EXPLAIN: Call self.assertEqual(by_run['later']['context']['previous_similar_24h'], 2): assert that the actual and
        # IRIS EXPLAIN: expected values are equal.
        self.assertEqual(by_run["later"]["context"]["previous_similar_24h"], 2)

    # IRIS EXPLAIN: Function ThreeSourceTests.test_synthetic_event_labels_join_to_observed_sessions: Regression test: verify
    # IRIS EXPLAIN: that synthetic event labels join to observed sessions; the assertions below define the exact expected
    # IRIS EXPLAIN: behavior.
    def test_synthetic_event_labels_join_to_observed_sessions(self):
        # IRIS EXPLAIN: Call self.save() using the existing explicit arguments.
        self.save()
        # IRIS EXPLAIN: Call prepare_three(self.ap, self.rp, self.ep, self.root / 'prepared') using the existing explicit
        # IRIS EXPLAIN: arguments.
        prepare_three(self.ap, self.rp, self.ep, self.root/"prepared")
        # IRIS EXPLAIN: Store the result of attach_reviews(self.root / 'prepared/model_sessions.jsonl', self.base /
        # IRIS EXPLAIN: 'source/training_labels.jsonl', sel... in report; later lines use this named result.
        report = attach_reviews(self.root/"prepared/model_sessions.jsonl", self.base/"source/training_labels.jsonl", self.root/"reviews.jsonl", synthetic=True)
        # IRIS EXPLAIN: Call self.assertEqual(report['labels_written'], 90): assert that the actual and expected values are
        # IRIS EXPLAIN: equal.
        self.assertEqual(report["labels_written"], 90)

    # IRIS EXPLAIN: Function ThreeSourceTests.test_real_data_cannot_use_generator_case_labels: Regression test: verify that real
    # IRIS EXPLAIN: data cannot use generator case labels; the assertions below define the exact expected behavior.
    def test_real_data_cannot_use_generator_case_labels(self):
        # IRIS EXPLAIN: Call self.save() using the existing explicit arguments.
        self.save()
        # IRIS EXPLAIN: Call prepare_three(self.ap, self.rp, self.ep, self.root / 'prepared') using the existing explicit
        # IRIS EXPLAIN: arguments.
        prepare_three(self.ap, self.rp, self.ep, self.root/"prepared")
        # IRIS EXPLAIN: Enter self.assertRaisesRegex(ValueError, 'synthetic-only'); its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.assertRaisesRegex(ValueError, "synthetic-only"):
            # IRIS EXPLAIN: Call attach_reviews(self.root / 'prepared/model_sessions.jsonl', self.base /
            # IRIS EXPLAIN: 'source/training_labels.jsonl', self.root / 'reviews.jsonl', synthetic=False) using the existing
            # IRIS EXPLAIN: explicit arguments.
            attach_reviews(self.root/"prepared/model_sessions.jsonl", self.base/"source/training_labels.jsonl", self.root/"reviews.jsonl", synthetic=False)

    # IRIS EXPLAIN: Function ThreeSourceTests.test_existing_output_not_overwritten: Regression test: verify that existing output
    # IRIS EXPLAIN: not overwritten; the assertions below define the exact expected behavior.
    def test_existing_output_not_overwritten(self):
        # IRIS EXPLAIN: Call self.save() using the existing explicit arguments.
        self.save()
        # IRIS EXPLAIN: Call prepare_three(self.ap, self.rp, self.ep, self.root / 'prepared') using the existing explicit
        # IRIS EXPLAIN: arguments.
        prepare_three(self.ap, self.rp, self.ep, self.root/"prepared")
        # IRIS EXPLAIN: Enter self.assertRaises(ValueError); its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.assertRaises(ValueError):
            # IRIS EXPLAIN: Call prepare_three(self.ap, self.rp, self.ep, self.root / 'prepared') using the existing explicit
            # IRIS EXPLAIN: arguments.
            prepare_three(self.ap, self.rp, self.ep, self.root/"prepared")

    # IRIS EXPLAIN: Function ThreeSourceTests.test_three_input_prediction_needs_no_labels: Regression test: verify that three
    # IRIS EXPLAIN: input prediction needs no labels; the assertions below define the exact expected behavior.
    def test_three_input_prediction_needs_no_labels(self):
        # IRIS EXPLAIN: Call self.only_example() using the existing explicit arguments.
        self.only_example()
        # IRIS EXPLAIN: Call self.save() using the existing explicit arguments.
        self.save()
        # IRIS EXPLAIN: Store the result of predict_three(self.ap, self.rp, self.ep, CATALOG, self.root / 'prediction',
        # IRIS EXPLAIN: mode='rules') in report; later lines use this named result.
        report = predict_three(self.ap, self.rp, self.ep, CATALOG, self.root/"prediction", mode="rules")
        # IRIS EXPLAIN: Call self.assertEqual(report['integrated_sources'], 3): assert that the actual and expected values are
        # IRIS EXPLAIN: equal.
        self.assertEqual(report["integrated_sources"], 3)
        # IRIS EXPLAIN: Call self.assertFalse(report['training_labels_read']): assert that the stated condition is false.
        self.assertFalse(report["training_labels_read"])
        # IRIS EXPLAIN: Call self.assertEqual(report['predictions_written'], 1): assert that the actual and expected values are
        # IRIS EXPLAIN: equal.
        self.assertEqual(report["predictions_written"], 1)
        # IRIS EXPLAIN: Store read_jsonl(self.root / 'prediction/predictions.jsonl')[0] in prediction; later lines use this
        # IRIS EXPLAIN: named result.
        prediction = read_jsonl(self.root/"prediction/predictions.jsonl")[0]
        # IRIS EXPLAIN: Call self.assertFalse(prediction['automatic_execution']): assert that the stated condition is false.
        self.assertFalse(prediction["automatic_execution"])

    # IRIS EXPLAIN: Function ThreeSourceTests.test_full_three_input_training: Regression test: verify that full three input
    # IRIS EXPLAIN: training; the assertions below define the exact expected behavior.
    def test_full_three_input_training(self):
        # IRIS EXPLAIN: Call self.save() using the existing explicit arguments.
        self.save()
        # IRIS EXPLAIN: Store the result of train_three(self.ap, self.rp, self.ep, self.base / 'source/training_labels.jsonl',
        # IRIS EXPLAIN: CATALOG, self.root / 'tr... in metadata; later lines use this named result.
        metadata = train_three(self.ap, self.rp, self.ep, self.base/"source/training_labels.jsonl", CATALOG, self.root/"training", synthetic=True)
        # IRIS EXPLAIN: Call self.assertEqual(metadata['data_quality']['accepted_sessions'], 90): assert that the actual and
        # IRIS EXPLAIN: expected values are equal.
        self.assertEqual(metadata["data_quality"]["accepted_sessions"], 90)
        # IRIS EXPLAIN: Call self.assertEqual(metadata['model2']['status'], 'trained_shadow'): assert that the actual and
        # IRIS EXPLAIN: expected values are equal.
        self.assertEqual(metadata["model2"]["status"], "trained_shadow")
        # IRIS EXPLAIN: Call self.assertFalse(metadata['model1']['eligible_for_reviewed_advisory_release']): assert that the
        # IRIS EXPLAIN: stated condition is false.
        self.assertFalse(metadata["model1"]["eligible_for_reviewed_advisory_release"])
        # IRIS EXPLAIN: Call self.assertFalse(metadata['three_source_integration']['labels_are_runtime_inputs']): assert that
        # IRIS EXPLAIN: the stated condition is false.
        self.assertFalse(metadata["three_source_integration"]["labels_are_runtime_inputs"])


# IRIS EXPLAIN: Run the CLI/test entry point only when this file is executed directly, not when another module imports it.
if __name__ == "__main__":
    # IRIS EXPLAIN: Call unittest.main() using the existing explicit arguments.
    unittest.main()
