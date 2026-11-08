"""Regression checks for the isolated synthetic training adapter."""
from copy import deepcopy
from pathlib import Path
import os
import unittest
from tools.retrain_dataset_v2 import load_upload, normalize_alert, attach_synthetic_targets


class AdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        candidates = ([Path(os.environ['IRIS_V2_DATASET'])] if os.environ.get('IRIS_V2_DATASET') else [
            root / 'IRIS_dataset_v2.zip',
            root / 'artifacts/dataset_v2_run_20261029/source_dataset.zip',
            root / 'artifacts/dataset_v2_run_20261028/source_dataset.zip'])
        archive = next((path for path in candidates if path.is_file()), None)
        if archive is None:
            raise FileNotFoundError('Provide IRIS_dataset_v2.zip in the repository root or set IRIS_V2_DATASET')
        cls.data = load_upload(archive)

    def test_dataset_checksums_and_counts(self):
        self.assertEqual(len(self.data['security_controls']['controls']), 120)
        self.assertEqual(len(self.data['training_labels']['labels']), 1340)

    def test_target_fields_do_not_enter_telemetry(self):
        row = deepcopy(self.data['siem_alerts']['alerts'][0])
        first = normalize_alert(row)
        row['associations']['control_ids'] = ['LEAK-SENTINEL']
        row['associations']['risk_ids'] = ['LEAK-SENTINEL']
        row['mitre_technique'] = 'LEAK-SENTINEL'
        row['mitre_tactic'] = 'LEAK-SENTINEL'
        self.assertEqual(normalize_alert(row), first)
        self.assertNotIn('LEAK-SENTINEL', str(first))

    def test_suricata_severity_is_not_reversed(self):
        row = next(deepcopy(x) for x in self.data['siem_alerts']['alerts'] if x['source'] == 'suricata')
        for original, canonical in [(1, 10), (2, 7), (3, 4)]:
            row['source_severity'] = original
            self.assertEqual(normalize_alert(row)['rule_level'], canonical)

    def test_only_supported_outcomes(self):
        row = deepcopy(self.data['siem_alerts']['alerts'][0])
        for category, outcome in [('authentication_success', 'success'), ('authentication_failed', 'failed'),
                                  ('brute_force', 'failed'), ('network_scan', 'unknown')]:
            row['category'] = category
            self.assertEqual(normalize_alert(row)['outcome'], outcome)

    def test_associations_are_weak_targets_not_features(self):
        row = self.data['siem_alerts']['alerts'][0]
        sid = row['session_id']
        label = next(x for x in self.data['training_labels']['labels'] if x['session_id'] == sid)
        observation = {'session_id': 'prepared-example', 'source_event_ids': [row['alert_id']],
                       'asset_id': row['associations']['asset_id'], 'run_id': sid,
                       'features': {'example': 1}}
        observed, targets, excluded = attach_synthetic_targets([observation], {row['alert_id']: row}, [label],
                                                              set(row['associations']['control_ids']))
        self.assertEqual(targets[0]['recommended_control_ids'], sorted(set(row['associations']['control_ids'])))
        self.assertEqual(observed[0]['features'], {'example': 1})
        self.assertIn('not-human-reviewed', targets[0]['control_reviewer'])


if __name__ == '__main__':
    unittest.main()
