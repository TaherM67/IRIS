"""Runtime schema/profile fixes: complete enumeration, no labels or fake context."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from backend.config import ROOT, Settings
from backend.coverage import session_outcome
from backend.grounded_context import GroundedContext
from backend.model_adapter import ModelAdapter
from backend.source_inputs import normalize_inputs, read_alerts, select_profile
from tools.check_input_coverage import run_check


def supplied_v2():
    """A tiny supplied-format fixture; no offline labels are provided."""
    asset = dict(asset_id='AST-TEST', hostname='host-test', ip_address='10.10.1.1',
                 asset_type='server', criticality='High', network_zone='lab', owner='Test team',
                 valid_from='2026-01-01T00:00:00Z', valid_to=None, control_groups=['server'])
    risk = dict(risk_id='RISK-TEST', asset_id='AST-TEST', category='Unauthorized Access',
                history=[dict(valid_from='2026-01-01T00:00:00Z',likelihood=3,impact=4)],
                existing_control_ids=['CTL-IAM-002'], planned_control_ids=[],
                mitre_attack_techniques=['T1110'])
    alert = dict(alert_id='EVENT-TEST', timestamp='2026-10-01T00:00:00Z',
                 source='wazuh', source_severity=7, category='authentication_failed',
                 dst_ip='10.10.1.1', src_ip='192.0.2.5', hostname='host-test', user='example',
                 protocol='tcp', rule_id='100001', session_id='SOURCE-SESSION', mitre_technique='T1110',
                 associations={'asset_id':'AST-TEST','risk_ids':['ORACLE-RISK'], 'control_ids':['ORACLE-CONTROL']})
    return {'asset_inventory':{'metadata':{'synthetic':True}, 'assets':[asset]},
            'risk_register':{'metadata':{'synthetic':True}, 'risks':[risk]},
            'siem_alerts':{'metadata':{'synthetic':True}, 'alerts':[alert]}}


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='iris-source-test-')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def paths(self, data):
        result = {}
        for key,value in data.items():
            result[key] = self.directory/(key+'.json')
            result[key].write_text(json.dumps(value), encoding='utf-8')
        return result

    def test_profiles_follow_input_contract_not_labels(self):
        from backend.core import INPUTS
        for folder,expected in [('demo/scenarios_v2','iris_scenarios_20261109'), ('demo/data','legacy')]:
            self.assertEqual(select_profile({k:ROOT/folder/name for k,name in INPUTS.items()}),expected)
        self.assertEqual(select_profile(self.paths(supplied_v2())), 'iris_models_20261030')

    def test_byte_count_alone_does_not_require_the_seven_extra_measurements(self):
        path=self.directory/'alerts.jsonl'
        path.write_text(json.dumps({'protocol':'TCP','bytes_sent':100})+'\n')
        assets=self.directory/'assets.json';assets.write_text(json.dumps({'records':[]}))
        self.assertEqual(select_profile({'asset_inventory':assets,'siem_alerts':path}), 'iris_models_20261030')

    def test_normalizer_keeps_context_but_never_oracle_targets(self):
        paths = self.paths(supplied_v2())
        before = {k:p.read_bytes() for k,p in paths.items()}
        converted,report = normalize_inputs(paths,self.directory/'normalized')
        self.assertFalse(report['training_labels_read'])
        all_text = ''.join(p.read_text() for p in converted.values())
        self.assertNotIn('ORACLE', all_text)
        risk = json.loads(converted['risk_register'].read_text())
        self.assertEqual(risk['control_membership_basis'], 'explicit_synthetic_static_membership')
        self.assertEqual(risk['records'][0]['existing_control_ids'], ['CTL-IAM-002'])
        self.assertEqual(risk['records'][0]['control_states'], {})
        alert = read_alerts(converted['siem_alerts'])[0]
        self.assertEqual((alert['mitre_technique'], alert['protocol']), ('T1110','tcp'))
        self.assertEqual({k:p.read_bytes() for k,p in paths.items()},before)

    def test_only_declared_synthetic_exports_receive_assumptions(self):
        data = supplied_v2(); data['asset_inventory']['metadata']['synthetic'] = False
        with self.assertRaisesRegex(ValueError,'real or undeclared'):
            normalize_inputs(self.paths(data),self.directory/'normalized')

    def test_real_alert_export_cannot_inherit_synthetic_asset_provenance(self):
        data=supplied_v2();data['siem_alerts']['metadata']['synthetic']=False
        with self.assertRaisesRegex(ValueError,'declare synthetic provenance'):
            normalize_inputs(self.paths(data),self.directory/'normalized')

    def test_canonical_json_alert_export_is_converted_without_dropping_events(self):
        from backend.core import INPUTS
        paths={k:ROOT/'demo/scenarios_v2'/name for k,name in INPUTS.items()}
        rows=read_alerts(paths['siem_alerts'])[:3]
        wrapped=self.directory/'alerts.json'
        wrapped.write_text(json.dumps({'alerts':rows}))
        converted,report=normalize_inputs({**paths,'siem_alerts':wrapped},self.directory/'normalized')
        self.assertEqual(read_alerts(converted['siem_alerts']),rows)
        self.assertEqual(report['format'],'canonical_json_alert_export')

    def test_explicit_profile_environment_is_respected(self):
        from backend.core import Engine
        keys={r:('CONFIG-TEST-'+r).ljust(48,'0') for r in ('admin','soc','grc')}
        with mock.patch.dict(os.environ,{'IRIS_MODEL_PROFILE':'legacy'}):
            engine=Engine(Settings(self.directory,keys))
        self.assertFalse(engine.auto_profile)
        self.assertIsNone(engine.adapter._active)

    def test_history_and_suricata_mapping_match_the_training_contract(self):
        data = supplied_v2(); data['risk_register']['risks'][0]['history'].append(
            dict(valid_from='2026-09-01T00:00:00Z',likelihood=4,impact=5))
        data['siem_alerts']['alerts'][0].update(source='suricata', source_severity=1)
        converted,_ = normalize_inputs(self.paths(data),self.directory/'normalized')
        rows = json.loads(converted['risk_register'].read_text())['records']
        self.assertEqual(rows[0]['valid_to'],rows[1]['valid_from'])
        self.assertEqual((rows[0]['likelihood'],rows[1]['likelihood']),(3,4))
        self.assertEqual(read_alerts(converted['siem_alerts'])[0]['rule_level'],10)

    def test_duplicate_redelivery_removed_but_distinct_event_retained(self):
        data = supplied_v2(); original=data['siem_alerts']['alerts'][0]
        data['siem_alerts']['alerts'] += [dict(original,alert_id='REDELIVERY'),
            dict(original,alert_id='LATER-EVENT',timestamp='2026-10-01T00:00:01Z')]
        converted,report = normalize_inputs(self.paths(data),self.directory/'normalized')
        self.assertEqual(report['redelivery_duplicates_removed'],1)
        self.assertEqual(len(read_alerts(converted['siem_alerts'])),2)

    def test_canonical_sources_are_not_rewritten(self):
        from backend.core import INPUTS
        paths = {k:ROOT/'demo/scenarios_v2'/name for k,name in INPUTS.items()}
        self.assertEqual(normalize_inputs(paths,self.directory/'unused')[0],paths)
        self.assertFalse((self.directory/'unused').exists())

    def test_static_control_membership_is_never_claimed_as_historical(self):
        from iris_models.three_sources import integrate
        converted,_ = normalize_inputs(self.paths(supplied_v2()),self.directory/'normalized')
        _,sessions,_ = integrate(converted['asset_inventory'],converted['risk_register'],converted['siem_alerts'])
        session=GroundedContext(converted).attach(sessions[0])
        self.assertEqual(session['model2_context']['membership_basis'],'explicit_synthetic_static_membership')
        self.assertEqual(session['model2_context']['missing_fields'],[])

    def test_missing_control_context_is_not_filled(self):
        data=supplied_v2();del data['asset_inventory']['assets'][0]['control_groups']
        del data['risk_register']['risks'][0]['planned_control_ids']
        converted,_=normalize_inputs(self.paths(data),self.directory/'normalized')
        from iris_models.three_sources import integrate
        _,ss,_=integrate(converted['asset_inventory'],converted['risk_register'],converted['siem_alerts'])
        missing=GroundedContext(converted).attach(ss[0])['model2_context']['missing_fields']
        self.assertIn('asset.control_groups',missing)
        self.assertIn('registered_risks.planned_control_ids',missing)

    def test_v2_runs_in_actual_backend_without_label_files(self):
        report,rows=run_check(self.paths(supplied_v2()))
        self.assertEqual(report['selected_profile'],'iris_models_20261030')
        self.assertEqual(report['model_coverage']['sessions_checked'],1)
        self.assertEqual(rows[0]['model1']['status'],'ASSESSED')
        self.assertEqual(rows[0]['model2']['status'],'ASSESSED')
        self.assertTrue(report['source_files_unchanged'])

    def test_config_bound_supports_full_v2_but_is_still_enforced(self):
        keys={r:('CONFIG-TEST-'+r).ljust(48,'0') for r in ('admin','soc','grc')}
        self.assertEqual(Settings(self.directory,keys).max_sessions,5000)
        with self.assertRaises(ValueError): Settings(self.directory,keys,max_sessions=5001)

    def test_v2_telemetry_mapping_is_identical_to_the_existing_training_adapter(self):
        from tools.retrain_dataset_v2 import normalize_alert
        data=supplied_v2()
        converted,_=normalize_inputs(self.paths(data),self.directory/'normalized')
        actual=read_alerts(converted['siem_alerts'])[0]
        actual.pop('mitre_technique')  # Retained separately for grounded control review, not Model 1.
        self.assertEqual(actual,normalize_alert(data['siem_alerts']['alerts'][0]))


class FullCoverageTests(unittest.TestCase):
    def test_all_expanded_sessions_and_no_technique_cases_are_accounted_for(self):
        from backend.core import INPUTS
        paths={k:ROOT/'demo/scenarios_v2'/name for k,name in INPUTS.items()}
        report,rows=run_check(paths)
        self.assertEqual(report['selected_profile'],'iris_scenarios_20261109')
        self.assertEqual(report['model_coverage']['model1']['status_counts'],{'ASSESSED':84})
        self.assertEqual(report['model_coverage']['model2']['status_counts'],
                         {'NO_OBSERVED_TECHNIQUE':12,'ASSESSED':72})
        self.assertEqual(len({r['session_id'] for r in rows}),84)
        self.assertFalse(report['accuracy_evaluated'])

    def test_legacy_selects_ssh_model_and_retains_sensor_health_guard(self):
        from backend.core import INPUTS
        paths={k:ROOT/'demo/data'/name for k,name in INPUTS.items()}
        report,rows=run_check(paths)
        self.assertEqual(report['model_coverage']['model1']['status_counts'],{'ASSESSED':131,'NOT_RUN':1})
        blocked=[r for r in rows if r['model1']['status']=='NOT_RUN']
        self.assertIn('sensor_health_unavailable_or_unhealthy',blocked[0]['model1']['reasons'])

    def test_wrong_explicit_profile_reports_the_exact_unsupported_protocol(self):
        from backend.core import INPUTS
        paths={k:ROOT/'demo/data'/name for k,name in INPUTS.items()}
        _,rows=run_check(paths,'iris_models_20261030')
        blocked=[r for r in rows if 'unseen_category' in r['model1']['reasons']]
        self.assertEqual(len(blocked),98)
        self.assertTrue(all(r['model1']['unsupported_categories']['primary_protocol']=='SSH' for r in blocked))


if __name__=='__main__':
    unittest.main()
