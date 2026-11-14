"""Protect hospital experiment isolation, provenance and runtime selection."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from backend.config import ROOT
from backend.core import INPUTS
from backend.model_adapter import ModelAdapter
from backend.scenarios import CLASSES
from backend.source_inputs import select_profile
from tools.train_hospital import grouped_holdout, train


class HospitalTrainingTests(unittest.TestCase):
    def test_whole_groups_are_split_deterministically_with_all_classes(self):
        rows = [dict(experimental_group=f'G{g}', campaign_id=f'C{g}', template_group=f'T{g}',
                     scenario_class=c, features={'observed': g * 1000 + ci * 10 + n})
                for g in range(4) for ci, c in enumerate(CLASSES) for n in range(10)]
        assignments, _ = grouped_holdout(rows)
        self.assertEqual(assignments, grouped_holdout(list(reversed(rows)))[0])
        self.assertEqual(set(assignments.values()), {'fit', 'test'})
        for role in ('fit', 'test'):
            self.assertEqual({r['scenario_class'] for r in rows if assignments[r['experimental_group']] == role}, set(CLASSES))
        # A caller cannot lie about an existing template's connected group.
        corrupt = copy.deepcopy(rows)
        for row in corrupt:
            row['template_group'] = 'ONE-COPIED-TEMPLATE'
        with self.assertRaisesRegex(ValueError, 'template_group crosses'):
            grouped_holdout(corrupt)

    def test_unreviewed_fitting_requires_explicit_experimental_opt_in(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'output'
            with self.assertRaisesRegex(ValueError, 'experimental-synthetic'):
                train(Path(directory), out)
            self.assertFalse(out.exists())

    def test_saved_holdout_has_no_campaign_template_feature_or_event_overlap(self):
        out = ROOT / 'artifacts/model_versions/iris_hospital_20261114'
        manifest = json.loads((out / 'split_manifest.json').read_text())
        rows = [json.loads(s) for s in (out / 'prepared/supervised_records.jsonl').read_text().splitlines()]
        self.assertEqual(sum(manifest['rows'].values()), 2490)
        fit = [r for r in rows if manifest['assignments'][r['experimental_group']] == 'fit']
        test = [r for r in rows if manifest['assignments'][r['experimental_group']] == 'test']
        for key in ('campaign_id', 'template_group', 'session_id'):
            self.assertFalse({r[key] for r in fit} & {r[key] for r in test})
        self.assertFalse({e for r in fit for e in r['source_event_ids']} & {e for r in test for e in r['source_event_ids']})
        self.assertFalse({json.dumps(r['features'], sort_keys=True) for r in fit} &
                         {json.dumps(r['features'], sort_keys=True) for r in test})
        self.assertFalse(any(r['label_verified'] for r in rows))

    def test_original_profiles_remain_available_and_hospital_is_hash_selected(self):
        paths = {k: ROOT / 'datasets/iris_general_hospital_20261114/data' / n for k, n in INPUTS.items()}
        self.assertEqual(select_profile(paths), 'iris_hospital_20261114')
        self.assertEqual(select_profile({k: ROOT / 'demo/scenarios_v2' / n for k, n in INPUTS.items()}), 'iris_scenarios_20261109')
        adapter = ModelAdapter(profile='iris_hospital_20261114')
        self.assertFalse(adapter.status()['model1_released'])
        self.assertFalse(adapter.status()['model2_released'])
        metadata = adapter.metadata['model1']
        self.assertEqual(metadata['prediction_method'], 'uncalibrated_experimental_model1')
        self.assertFalse(metadata['eligible_for_reviewed_advisory_release'])
        self.assertNotIn('scenario_class', metadata['features'])
        self.assertNotIn('asset_criticality', metadata['features'])
