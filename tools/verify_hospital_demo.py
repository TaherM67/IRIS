"""Check all hospital sessions and real HTTPS approvals using temporary state.

Needs an existing localhost certificate/key (passed explicitly). Passwords,
tokens, private keys and the temporary database are never saved in results.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import http.client
import json
from pathlib import Path
import secrets
import ssl
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'IRIS_Models_v2')]
from backend.config import Settings
from backend.coverage import session_outcome, summarize
from backend.model_adapter import ModelAdapter, digest
from demo_app.auth import AccountAuth, account_record
from demo_app.engine import DemoEngine
from demo_app.server import DemoServer
from demo_app.tls import server_context


def verify(out, cert, key):
    if out.exists():
        raise ValueError('Use a fresh output directory')
    out.mkdir(parents=True)
    data = ROOT / 'datasets/iris_general_hospital_20261114/data'
    names = ('asset_inventory.json', 'risk_register.json', 'siem_alerts.jsonl')
    hashes = {name: digest(data / name) for name in names}
    adapter = ModelAdapter(profile='iris_hospital_20261114')
    checks = []
    def check(condition, name):
        if not condition:
            raise AssertionError(name)
        checks.append(name)
    with tempfile.TemporaryDirectory(prefix='iris-hospital-workflow-') as directory:
        keys = {role: secrets.token_urlsafe(36) for role in ('admin', 'soc', 'grc')}
        settings = Settings(Path(directory), keys)
        engine = DemoEngine(settings, data_dir=data, adapter=adapter)
        passwords = {role: secrets.token_urlsafe(24) for role in keys}
        auth = AccountAuth([account_record('verify-' + role, passwords[role], role) for role in keys])
        server = DemoServer(('127.0.0.1', 0), engine,
                            tls_context=server_context(cert, key), auth=auth)
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
        thread.start()
        context = ssl.create_default_context(cafile=str(cert))
        def request(path, token=None, method='GET', payload=None):
            headers = {'Authorization': 'Bearer ' + token} if token else {}
            body = None
            if payload is not None:
                body = json.dumps(payload)
                headers['Content-Type'] = 'application/json'
            connection = http.client.HTTPSConnection('127.0.0.1', server.server_port, context=context, timeout=300)
            try:
                connection.request(method, path, body, headers)
                response = connection.getresponse()
                raw = response.read()
                value = json.loads(raw) if response.getheader('Content-Type', '').startswith('application/json') else raw
                return response.status, value
            finally:
                connection.close()
        try:
            for page in ('/admin', '/soc', '/grc', '/demo-static/app.js', '/health'):
                check(request(page)[0] == 200, 'HTTPS ' + page)
            check(request('/api/demo/state')[0] == 401, 'unauthenticated requests rejected')
            tokens = {}
            for role in keys:
                status, value = request('/api/demo/auth/login', method='POST', payload={
                    'username': 'verify-' + role, 'password': passwords[role], 'workspace': role})
                check(status == 200 and value['role'] == role, role + ' account sign-in')
                tokens[role] = value['access_token']
            check(request('/api/demo/risks', tokens['soc'])[0] == 403, 'SOC cannot read GRC register')
            check(request('/api/demo/alerts', tokens['grc'])[0] == 403, 'GRC cannot read SOC queue')
            status, run = request('/api/demo/analyze', tokens['admin'], 'POST', {})
            check(status == 200, 'authenticated full hospital analysis')
            check(run['sessions'] == 2490, 'all 2490 sessions persisted')
            cases = engine.store.cases(run_id=run['run_id'], limit=5000)['items']
            check(len(cases) == 2490, 'all cases read beyond former 2000 limit')
            events = [e for case in cases for e in case['session']['source_event_ids']]
            check(len(events) == len(set(events)) == 15000, 'all 15000 source events accounted for exactly once')
            outcomes = [session_outcome(c['session'], c['prediction'], adapter.metadata) for c in cases]
            coverage = summarize(outcomes)
            before = engine.status('admin')['counts']
            check(before['alerts'] == 15000 and before['risks'] == 1860, 'full working alert and risk tables')
            for role in ('grc', 'soc'):
                proposals = engine.proposals(role)['items']
                check(bool(proposals), role + ' proposals available')
                applied = None
                stale = 0
                for proposal in proposals:
                    path = '/api/demo/proposals/' + proposal['proposal_id'] + '/review'
                    check(request(path, tokens['admin'], 'POST', {'decision': 'approve', 'reason': 'Admin cannot approve for another role.'})[0] == 403,
                          'Admin cannot approve ' + role + ' proposal')
                    status, applied = request(path, tokens[role], 'POST', {
                        'decision': 'approve', 'reason': 'Reviewed the linked synthetic hospital evidence in isolated verification.'})
                    if status == 409:
                        stale += 1
                        continue
                    check(status == 200, role + ' authorized approval')
                    repeat_status, _ = request(path, tokens[role], 'POST', {
                        'decision': 'approve', 'reason': 'Reviewed the linked synthetic hospital evidence in isolated verification.'})
                    check(repeat_status == 200, role + ' approval retry is idempotent')
                    break
                else:
                    raise AssertionError('No current ' + role + ' proposal could be approved')
            after = engine.status('admin')['counts']
            check(after['changed_risks'] > 0, 'GRC approval changes saved register')
            check(after['reprioritized_alerts'] > 0, 'SOC approval changes saved alert priorities')
            for endpoint, role in (('/api/demo/export/risks', 'grc'), ('/api/demo/export/alerts', 'soc')):
                status, value = request(endpoint, tokens[role])
                check(status == 200 and bool(value), role + ' current-state export')
            status, replay = request('/api/demo/analyze', tokens['admin'], 'POST', {})
            check(status == 200 and replay['reused_existing_run'], 'reanalysis reuses immutable model evidence')
            check(engine.status('admin')['counts']['changed_risks'] == after['changed_risks'], 'reanalysis preserves approved risk changes')
            reopened = DemoEngine(settings, data_dir=data, adapter=adapter)
            check(reopened.status('admin')['counts'] == engine.status('admin')['counts'], 'restart preserves all working counts')
            check(all(not c['prediction']['automatic_execution'] and not c['prediction']['official_risk_register_write'] for c in cases),
                  'experimental models remain separate from approved writes')
            check(hashes == {name: digest(data / name) for name in names}, 'operational source files unchanged')
            with (out / 'session_outcomes.jsonl').open('w', encoding='utf-8') as stream:
                for row in outcomes:
                    stream.write(json.dumps(row, allow_nan=False) + '\n')
            report = dict(verified_at_utc=datetime.now(timezone.utc).isoformat(), status='PASS', checks=checks,
                          model_profile=adapter.profile, counts_before_approval=before, counts_after_approval=after,
                          events_accounted_for=len(events), sessions=len(cases), model_coverage=coverage,
                          source_sha256=hashes, existing_demo_state_opened=False,
                          browser_visual_check=False, private_lan_check=False, accuracy_evaluated=False)
            (out / 'workflow.json').write_text(json.dumps(report, indent=2) + '\n')
            print(json.dumps(report, indent=2))
            return report
        finally:
            server.shutdown()
            server.server_close()
            thread.join(5)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--cert-file', type=Path, required=True)
    parser.add_argument('--key-file', type=Path, required=True)
    args = parser.parse_args()
    verify(args.out, args.cert_file, args.key_file)
