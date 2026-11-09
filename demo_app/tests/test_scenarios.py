"""Expanded artifact, evidence correlation, review revisions and preservation."""
import copy
import hashlib
import http.client
import json
from pathlib import Path
import shutil
import tempfile
import threading
import unittest
from unittest import mock
import uuid

from backend.config import ROOT, Settings
from backend.model_adapter import ModelAdapter
from backend.scenarios import CLASSES, EXTRA_FEATURES, evidence_from_alerts, rule_scenario
from backend.storage import encoded
from demo_app.engine import DemoEngine, DATA
from demo_app.server import DemoServer

EXPANDED = ROOT / 'demo/scenarios_v2'
KEYS = {r: ('EXPANDED-TEST-ONLY-' + r).ljust(48, '0') for r in ('admin','soc','grc')}


class ExpandedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = tempfile.TemporaryDirectory(prefix='iris-expanded-template-')
        cls.addClassCleanup(cls.base.cleanup)
        cls.adapter = ModelAdapter(profile='iris_scenarios_20261109')
        cls.template = DemoEngine(Settings(Path(cls.base.name),KEYS),data_dir=EXPANDED,adapter=cls.adapter)
        cls.summary = cls.template.analyze('admin')
        cls.cases = cls.template.store.cases(run_id=cls.summary['run_id'],limit=100)['items']

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='iris-expanded-test-')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        shutil.copyfile(self.template.store.path,self.directory/'iris.sqlite3')
        self.settings = Settings(self.directory,KEYS)
        self.engine = DemoEngine(self.settings,data_dir=EXPANDED,adapter=self.adapter)

    def test_all_seven_classes_are_fitted_and_available_in_demo(self):
        self.assertEqual(set(self.adapter.status()['supported_scenarios']),set(CLASSES))
        self.assertEqual(self.summary['sessions'],84)
        self.assertEqual({c['prediction']['soc_assessment']['scenario_class'] for c in self.cases},set(CLASSES))
        self.assertEqual({c['prediction']['shadow_candidate']['scenario_class'] for c in self.cases},set(CLASSES))
        self.assertFalse(self.adapter.status()['model1_released'])
        self.assertEqual(self.adapter.status()['scenario_feature_count'],23)

    def test_campaigns_and_sessions_do_not_cross_training_roles(self):
        manifest=json.loads((ROOT/'artifacts/model_versions/iris_scenarios_20261109/split_manifest.json').read_text())
        for name in ('campaigns','session_ids'):
            roles=list(manifest[name].values())
            for i,left in enumerate(roles):
                for right in roles[i+1:]: self.assertFalse(set(left)&set(right))

    def test_new_scenarios_require_observed_signals_and_healthy_sensors(self):
        for label in ('malicious_execution','privilege_escalation','web_exploitation','data_exfiltration'):
            session=copy.deepcopy(next(c['session'] for c in self.cases if c['prediction']['soc_assessment']['scenario_class']==label))
            self.assertEqual(rule_scenario(session),label)
            session['sensor_healthy']=False
            self.assertIsNone(rule_scenario(session))
            self.assertIsNone(self.adapter.predict(session)['shadow_candidate'])
            session['sensor_healthy']=True
            session['scenario_evidence']=dict.fromkeys(EXTRA_FEATURES,0)
            self.assertNotEqual(rule_scenario(session),label)

    def test_labels_and_association_fields_are_not_evidence_features(self):
        row=dict(bytes_sent=10,process_unsigned=True)
        clean=evidence_from_alerts([row])
        row.update(scenario='data_exfiltration',scenario_class='privilege_escalation',training_label='malicious_execution',
                   associations={'control_ids':['SPOOFED']},risk_score=1,asset_criticality=5)
        self.assertEqual(evidence_from_alerts([row]),clean)
        with self.assertRaises(ValueError): evidence_from_alerts([dict(bytes_sent=float('nan'))])
        with self.assertRaises(ValueError): evidence_from_alerts([dict(process_unsigned='true')])

    def test_unreleased_model_abstains_on_real_or_unfamiliar_inputs(self):
        source=copy.deepcopy(self.cases[0]['session'])
        for change in ({'data_provenance':'cyber_range'}, {'aggregation_schema':'different-window'},
                       {'scenario_evidence_complete':False}):
            session={**source,**change}
            self.assertIsNone(self.adapter.predict(session)['shadow_candidate'])
        source['features']['event_family']='unfamiliar_sensor_family'
        self.assertIsNone(self.adapter.predict(source)['shadow_candidate'])

    def test_invalid_measurements_do_not_become_an_assessment(self):
        source=copy.deepcopy(self.cases[0]['session'])
        source['scenario_evidence']['known_indicator_count']=source['features']['event_count']+1
        result=self.adapter.predict(source)
        self.assertEqual(result['soc_assessment']['status'],'ABSTAINED')
        self.assertIsNone(result['shadow_candidate'])

    def test_one_incident_per_session_and_every_source_alert_retained_once(self):
        result=self.engine.incidents('soc',100)
        self.assertEqual(result['total'],84)
        self.assertEqual(result['scenario_counts'],dict.fromkeys(CLASSES,12))
        ids=[a['event_id'] for item in result['items'] for a in item['alerts']]
        self.assertEqual(len(ids),result['source_alerts'])
        self.assertEqual(len(ids),len(set(ids)))
        self.assertEqual(len({item['incident_id'] for item in result['items']}),84)
        self.assertGreater(min(item['alert_count'] for item in result['items']),1)

    def test_incident_filters_and_pagination_apply_after_correlation(self):
        filtered=self.engine.incidents('soc',5,scenario='data_exfiltration')
        self.assertEqual((filtered['total'],len(filtered['items'])),(12,5))
        self.assertTrue(all(item['scenario']=='data_exfiltration' for item in filtered['items']))
        first=self.engine.incidents('soc',50); second=self.engine.incidents('soc',50,50)
        self.assertEqual(len(first['items'])+len(second['items']),84)
        self.assertFalse({r['incident_id'] for r in first['items']} & {r['incident_id'] for r in second['items']})
        with self.assertRaises(ValueError): self.engine.incidents('soc',scenario='arbitrary')
        with self.assertRaises(PermissionError): self.engine.incidents('grc')

    def test_changed_filter_keeps_unchanged_supporting_alerts_in_incident(self):
        proposal=self.engine.proposals('soc')['items'][0]
        sid=proposal['payload']['evidence']['session_id']
        before=next(item for item in self.engine.incidents('soc',100)['items'] if item['incident_id']==sid)
        self.engine.review('soc',proposal['proposal_id'],'approve','Reviewed the correlated synthetic incident evidence.')
        after=self.engine.incidents('soc',100,changed_only=True)
        self.assertEqual(after['total'],1)
        self.assertEqual(after['items'][0]['alert_count'],before['alert_count'])
        self.assertEqual(after['items'][0]['changed_alerts'],proposal['payload']['changed_alerts'])

    def test_all_attack_families_have_distinct_risks_and_named_controls(self):
        proposals=self.engine.proposals('grc')['items']
        self.assertEqual(len(proposals),72)
        self.assertEqual({p['payload']['evidence']['observed_activity'] for p in proposals},set(CLASSES)-{'benign'})
        for proposal in proposals:
            evidence=proposal['payload']['evidence']
            self.assertTrue(evidence['controls'])
            self.assertTrue(evidence['model2_review']['recommendations'])
            self.assertNotIn('features',evidence)
            self.assertNotIn('ml_shadow',evidence)

    def test_reanalysis_does_not_duplicate_pending_reviews(self):
        before=self.engine.status('admin')['counts']
        summary=self.engine.analyze('admin')
        self.assertTrue(summary['reused_existing_run'])
        self.assertEqual(self.engine.status('admin')['counts'],before)

    def test_old_model_review_for_same_session_is_superseded_not_deleted(self):
        original=self.engine.proposals('soc')['items'][0]
        old_case=self.engine.store.case(original['case_id'])
        old_case['case_id']='CASE-'+uuid.uuid4().hex[:24]
        old_case['run_id']='RUN-'+uuid.uuid4().hex
        old_id='PROP-'+uuid.uuid4().hex
        with self.engine.store.connection() as db:
            db.execute('INSERT INTO runs VALUES (?,?,?,?,?,?,NULL)',(old_case['run_id'],uuid.uuid4().hex,'completed','2026-01-01','admin','{}'))
            db.execute('INSERT INTO cases VALUES (?,?,?,?)',(old_case['case_id'],old_case['run_id'],old_case['session']['session_id'],encoded(old_case)))
            db.execute('INSERT INTO demo_proposals(proposal_id,exercise_id,case_id,kind,payload_json,status) VALUES (?,?,?,?,?,?)',
                       (old_id,original['exercise_id'],old_case['case_id'],'soc',encoded(original['payload']),'pending'))
        self.assertEqual(self.engine.proposals('soc')['total'],85)
        self.engine.analyze('admin')
        self.assertEqual(self.engine.proposals('soc')['total'],84)
        stale=self.engine.proposals('soc',status='stale')['items']
        self.assertEqual(stale[0]['proposal_id'],old_id)
        self.assertIn('Superseded',stale[0]['reason'])
        self.assertEqual(self.engine.store.case(old_case['case_id'])['session'],old_case['session'])

    def test_dataset_change_starts_new_exercise_preserving_prior_approvals(self):
        p=self.engine.proposals('grc')['items'][0]
        self.engine.review('grc',p['proposal_id'],'approve','Preservation test of a synthetic risk change.')
        old_exercise=self.engine.status('admin')['exercise_id']
        with self.assertRaises(ValueError): DemoEngine(self.settings,data_dir=DATA,adapter=self.adapter)
        legacy=DemoEngine(self.settings,data_dir=DATA,adapter=self.adapter,allow_dataset_change=True)
        self.assertNotEqual(old_exercise,legacy.status('admin')['exercise_id'])
        with legacy.store.connection() as db:
            self.assertEqual(db.execute('SELECT status FROM demo_proposals WHERE proposal_id=?',(p['proposal_id'],)).fetchone()[0],'approved')
            self.assertEqual(db.execute('SELECT COUNT(*) FROM demo_changes WHERE exercise_id=?',(old_exercise,)).fetchone()[0],1)

    def test_grouped_http_contract_role_guard_and_validation(self):
        with DemoServer(('127.0.0.1',0),self.engine) as server:
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                def request(path,role='soc'):
                    connection=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=20)
                    connection.request('GET',path,headers={'X-IRIS-Key':KEYS[role]})
                    response=connection.getresponse(); status=response.status; payload=json.loads(response.read());connection.close()
                    return status,payload
                status,data=request('/api/demo/alerts?group_by=incident&scenario=web_exploitation&limit=5')
                self.assertEqual((status,data['total'],len(data['items'])),(200,12,5))
                self.assertEqual(request('/api/demo/alerts?group_by=incident','grc')[0],403)
                self.assertEqual(request('/api/demo/alerts?group_by=invalid')[0],422)
                self.assertEqual(request('/api/demo/alerts?group_by=incident&scenario=invalid')[0],422)
            finally:
                server.shutdown();thread.join(timeout=5)


if __name__=='__main__':
    unittest.main()
