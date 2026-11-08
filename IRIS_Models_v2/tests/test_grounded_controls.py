"""Safety and target-isolation tests for the repaired experimental service."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

import numpy as np

from iris_models.grounded_controls import (
    GroundedControlRecommender, PAIR_FEATURES, candidate_features, technique_match,
)

RUN = Path(__file__).resolve().parents[2] / 'artifacts/model2_fix_20261029'


class GroundedControlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.request = json.loads((RUN / 'example_request.json').read_text())
        cls.service = GroundedControlRecommender.load(RUN / 'grounded_model2.joblib')

    def test_named_controls_are_returned_without_execution(self):
        result = self.service.recommend(**deepcopy(self.request))
        self.assertTrue(result['recommendations'])
        self.assertFalse(result['automatic_execution'])
        self.assertFalse(result['release_eligible'])
        for control in result['recommendations']:
            self.assertTrue(control['name'])
            self.assertEqual(control['action_type'], 'review')
            self.assertEqual(control['current_state'], 'unknown')
            self.assertTrue(control['requires_human_approval'])

    def test_association_truth_cannot_change_predictors(self):
        request = deepcopy(self.request)
        first = candidate_features(**request)
        for alert in request['alerts']:
            alert['associations'] = {'control_ids': ['SECRET-TARGET'], 'risk_ids': ['SECRET-TARGET']}
            alert['scenario'] = 'SECRET-TARGET'
        for control in request['catalogue']:
            control['model2_held_out_positive'] = 'SECRET-TARGET'
            control['effectiveness'] = 1.0
        second = candidate_features(**request)
        self.assertEqual(first[0], second[0])
        np.testing.assert_array_equal(first[1], second[1])
        self.assertEqual(first[2], second[2])

    def test_risk_membership_actually_changes_context(self):
        request = deepcopy(self.request)
        first = candidate_features(**request)
        for risk in request['registered_risks']:
            risk['existing_control_ids'] = []
            risk['planned_control_ids'] = []
        second = candidate_features(**request)
        self.assertNotEqual(first[2], second[2])
        self.assertFalse(second[2])
        self.assertFalse(np.array_equal(first[1], second[1]))

    def test_wrong_asset_is_rejected(self):
        request = deepcopy(self.request)
        request['asset']['asset_id'] = 'WRONG'
        with self.assertRaisesRegex(ValueError, 'different asset'):
            self.service.recommend(**request)

    def test_wrong_risk_owner_is_rejected(self):
        request = deepcopy(self.request)
        request['registered_risks'][0]['asset_id'] = 'WRONG'
        with self.assertRaisesRegex(ValueError, 'different asset'):
            self.service.recommend(**request)

    def test_wrong_event_membership_is_rejected(self):
        request = deepcopy(self.request)
        request['alerts'][0]['alert_id'] = 'WRONG'
        with self.assertRaisesRegex(ValueError, 'membership'):
            self.service.recommend(**request)

    def test_missing_technique_requires_review(self):
        request = deepcopy(self.request)
        for alert in request['alerts']:
            alert['mitre_technique'] = None
        result = self.service.recommend(**request)
        self.assertEqual(result['source'], 'not_run')
        self.assertFalse(result['recommendations'])

    def test_real_data_release_remains_blocked(self):
        request = deepcopy(self.request)
        request['session']['data_provenance'] = 'operational'
        with self.assertRaisesRegex(ValueError, 'release is blocked'):
            self.service.recommend(**request)

    def test_empty_events_are_rejected(self):
        request = deepcopy(self.request)
        request['alerts'] = []
        with self.assertRaisesRegex(ValueError, 'events are required'):
            self.service.recommend(**request)

    def test_catalogue_change_is_rejected(self):
        request = deepcopy(self.request)
        request['catalogue'][0]['name'] += ' modified'
        with self.assertRaisesRegex(ValueError, 'catalogue changed'):
            self.service.recommend(**request)

    def test_checksum_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'model.joblib'
            path.write_bytes((RUN / 'grounded_model2.joblib').read_bytes() + b'bad')
            path.with_suffix('.json').write_text((RUN / 'grounded_model2.json').read_text())
            with self.assertRaisesRegex(ValueError, 'checksum'):
                GroundedControlRecommender.load(path)

    def test_technique_parents_are_explicit(self):
        self.assertTrue(technique_match('T1110.001', 'T1110'))
        self.assertFalse(technique_match('T1110', 'T1046'))
        self.assertFalse(technique_match(None, 'T1110'))

    def test_inputs_are_not_mutated(self):
        request = deepcopy(self.request)
        before = deepcopy(request)
        self.service.recommend(**request)
        self.assertEqual(request, before)


if __name__ == '__main__':
    unittest.main()
