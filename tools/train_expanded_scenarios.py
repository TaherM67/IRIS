"""Build and fit a reproducible, seven-class synthetic demonstration profile.

Uses the same three-source integration at fit and serving time. Entire campaigns
belong to one of fit, selection, calibration, threshold, or final audit. This is
a software demonstration, not independent attack-detection validation.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'IRIS_Models_v2'))

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.calibration import CalibratedClassifierCV
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.frozen import FrozenEstimator
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from backend.scenarios import CLASSES, EXTRA_FEATURES, OBSERVED_FLAGS, RISK_CATEGORIES, VERSION, attach_evidence, feature_row
from iris_models.contracts import CATEGORICAL, FEATURES, NUMERIC, digest, write_json, write_jsonl
from iris_models.three_sources import integrate

SEED = 20261109
TECHNIQUES = dict(credential_access='T1110', reconnaissance='T1046', malicious_execution='T1059',
                  privilege_escalation='T1068', web_exploitation='T1190', data_exfiltration='T1048')
CATALOGUE = ROOT / 'artifacts/model_versions/iris_models_20261030/control_catalogue.json'


def controls_for(catalogue, technique):
    return [r for r in catalogue if any(t.split('.')[0] == technique for t in r['mitigates_attack_techniques'])][:3]


def sources(directory, *, campaigns, repetitions, demo=False):
    rng = random.Random(SEED + int(demo))
    catalogue = json.loads(CATALOGUE.read_text())
    asset_count = 30
    assets, risks = [], []
    groups = sorted({g for r in catalogue for g in r['applies_to']})
    for i in range(asset_count):
        aid = f'DIVERSE-A{i+1:03d}'
        asset = dict(asset_id=aid, asset_version_id=aid+'-V1', hostname=f'{("identity", "web", "payroll", "engineering", "files", "workstation")[i%6]}-{i+1:02d}',
                     ip_addresses=[f'10.80.0.{i+10}'], asset_type='server', criticality=i%5+1,
                     zone='synthetic-lab', owner='Demonstration team', control_groups=groups,
                     valid_from='2026-09-01T00:00:00+00:00', valid_to=None, recorded_at='2026-09-01T00:00:00+00:00')
        assets.append(asset)
        for j, (scenario, categories) in enumerate(RISK_CATEGORIES.items()):
            controls = controls_for(catalogue, TECHNIQUES[scenario])
            if not controls:
                raise ValueError('No pinned catalogue coverage for ' + scenario)
            ids = [r['control_id'] for r in controls]
            rid = f'DIVERSE-R{i+1:03d}-{j+1}'
            risks.append(dict(risk_id=rid, risk_version_id=rid+'-V1', asset_id=aid,
                              risk_category=next(iter(categories)), likelihood=2+i%3, impact=1+i%5,
                              existing_control_ids=ids[:1], planned_control_ids=ids[1:],
                              mitre_attack_techniques=[TECHNIQUES[scenario]],
                              control_states={cid: 'partial' if k == 0 else 'missing' for k,cid in enumerate(ids)},
                              active_exception_control_ids=[], valid_from=asset['valid_from'], valid_to=None,
                              recorded_at=asset['recorded_at']))
    events, labels = [], {}
    start = datetime(2026, 11, 8, 6, tzinfo=timezone.utc) if demo else datetime(2026, 10, 1, 6, tzinfo=timezone.utc)
    for group in range(campaigns):
        campaign = f'{"SHOWCASE" if demo else "FIT"}-{group+1:03d}'
        for rep in range(repetitions):
            for c, scenario in enumerate(CLASSES):
                index = (group*repetitions+rep)*len(CLASSES)+c
                run = f'{"DEMO" if demo else "TRAIN"}-{index+1:05d}'
                labels[run] = scenario
                asset = assets[(group*7+rep*3+c)%asset_count]
                family, protocol, count_range = {
                    'benign': ('authentication','SSH',(5,12)), 'credential_access': ('authentication','SSH',(22,38)),
                    'reconnaissance': ('network','TCP',(18,32)), 'malicious_execution': ('process','LOCAL',(6,14)),
                    'privilege_escalation': ('privilege','LOCAL',(4,10)), 'web_exploitation': ('web','HTTPS',(6,18)),
                    'data_exfiltration': ('network','HTTPS',(5,12)),
                }[scenario]
                if scenario == 'benign' and rep%3:
                    family,protocol = [('process','LOCAL'),('web','HTTPS'),('network','HTTPS')][(group+rep)%3]
                n = rng.randint(*count_range)
                at = start + (timedelta(minutes=index*3) if demo else timedelta(days=group, minutes=(rep*7+c)*3))
                for k in range(n):
                    attack = scenario != 'benign'
                    outcome = ('failed' if k<n-1 else 'success') if family=='authentication' else 'unknown'
                    if scenario == 'benign' and family=='authentication':
                        outcome = 'failed' if k == 0 else 'success'
                    flags = dict.fromkeys(OBSERVED_FLAGS, False)
                    if scenario == 'malicious_execution': flags.update(process_unsigned=k%3!=0, malicious_indicator=k%4==0)
                    if scenario == 'privilege_escalation': flags.update(privilege_change=k%2==0, malicious_indicator=k%3==0)
                    if scenario == 'web_exploitation': flags.update(web_attack_signal=k%3!=0)
                    if scenario == 'data_exfiltration': flags.update(sensitive_data_access=k%2==0, destination_untrusted=True)
                    sent = (rng.randint(1_500_000,5_000_000) if scenario=='data_exfiltration' else
                            0 if family in {'process','privilege'} else rng.randint(100,30_000))
                    level = rng.randint(8,13) if attack else rng.randint(1,9)
                    outbound = scenario=='data_exfiltration' or (scenario=='benign' and family=='network')
                    local = outbound or family in {'process','privilege'}
                    events.append(dict(event_id=f'{run}-E{k+1:03d}', timestamp=(at+timedelta(seconds=k*rng.uniform(.5,1.2))).isoformat(),
                                       asset_id=asset['asset_id'], agent_name=asset['hostname'],
                                       destination_ip=None if outbound else asset['ip_addresses'][0],
                                       remote_destination_ip=f'198.51.100.{group%200+1}' if outbound else None,
                                       network_direction='outbound' if outbound else 'local' if local else 'inbound',
                                       source_ip=asset['ip_addresses'][0] if local else f'198.51.100.{group%200+1}',
                                       account=f'lab_user_{rep%4}', event_family=family,
                                       protocol=protocol, rule_id=f'OBS-{100+c if attack else 200}-{k%(5 if scenario=="reconnaissance" else 2)}',
                                       rule_level=level, outcome=outcome, bytes_sent=sent, **flags,
                                       mitre_technique=TECHNIQUES.get(scenario), sensor_healthy=True,
                                       campaign_id=campaign, run_id=run, data_provenance='synthetic'))
    directory.mkdir(parents=True, exist_ok=True)
    write_json(directory/'asset_inventory.json', dict(schema_version='iris-asset-inventory-v1',data_provenance='synthetic',records=assets))
    write_json(directory/'risk_register.json', dict(schema_version='iris-risk-register-v1',data_provenance='synthetic',records=risks))
    rng.shuffle(events)
    write_jsonl(directory/'siem_alerts.jsonl', events)
    paths = {key:directory/name for key,name in dict(asset_inventory='asset_inventory.json',risk_register='risk_register.json',siem_alerts='siem_alerts.jsonl').items()}
    _, sessions, report = integrate(paths['asset_inventory'],paths['risk_register'],paths['siem_alerts'],window_seconds=60)
    sessions = attach_evidence(sessions, paths)
    if len(sessions) != len(labels):
        raise ValueError('Generator produced fragmented or merged source sessions')
    write_json(directory/'demo_manifest.json', dict(name='IRIS diverse scenario demonstration', version='2.0',data_provenance='synthetic',
        seed=SEED, unique_assets=asset_count, unique_risks=len(risks),expected_sessions=len(sessions),siem_alert_rows=len(events),
        expected_scenario_counts=dict(Counter(labels.values())),training_labels_included=False,
        inputs=[dict(upload_field=k,filename=p.name,sha256=digest(p)) for k,p in paths.items()],
        purpose='Synthetic software demonstration only; distinct sessions with correlated evidence, not independent real attacks.'))
    return sessions, labels, report


def train(out, demo_out):
    if (out/'model1_metadata.json').exists():
        raise ValueError('Use a fresh version directory; trained artifacts are not overwritten')
    sessions, labels, report = sources(out/'training_sources', campaigns=30, repetitions=5)
    rows = [feature_row(s,FEATURES) for s in sessions]
    X = pd.DataFrame(rows,columns=FEATURES+EXTRA_FEATURES)
    y = np.array([labels[s['run_id']] for s in sessions])
    campaign_ids = sorted({s['campaign_id'] for s in sessions})
    random.Random(SEED).shuffle(campaign_ids)
    boundaries = dict(fit=(0,18), selection=(18,21), calibration=(21,24), threshold=(24,27), test=(27,30))
    groups = {k:campaign_ids[a:b] for k,(a,b) in boundaries.items()}
    indexes = {k:np.array([i for i,s in enumerate(sessions) if s['campaign_id'] in ids]) for k,ids in groups.items()}
    def pipeline(classifier):
        return Pipeline([('features',ColumnTransformer([
            ('categorical',OneHotEncoder(handle_unknown='ignore',sparse_output=False),CATEGORICAL),
            ('numeric',StandardScaler(),NUMERIC+EXTRA_FEATURES)])),('classifier',classifier)])
    candidates = {
        'logistic_regression':LogisticRegression(max_iter=1500,random_state=SEED),
        'random_forest':RandomForestClassifier(n_estimators=150,max_depth=12,min_samples_leaf=2,n_jobs=2,random_state=SEED),
        'hist_gradient_boosting':HistGradientBoostingClassifier(max_iter=80,max_leaf_nodes=15,random_state=SEED),
    }
    fitted, scores = {}, {}
    for name, classifier in candidates.items():
        fitted[name]=pipeline(classifier).fit(X.iloc[indexes['fit']],y[indexes['fit']])
        scores[name]=float(f1_score(y[indexes['selection']],fitted[name].predict(X.iloc[indexes['selection']]),average='macro'))
    selected=max(scores,key=scores.get)
    calibrated=CalibratedClassifierCV(FrozenEstimator(fitted[selected]),method='sigmoid').fit(X.iloc[indexes['calibration']],y[indexes['calibration']])
    tune_probs=calibrated.predict_proba(X.iloc[indexes['threshold']]); tune_y=y[indexes['threshold']]
    choices=[]
    for threshold in (.5,.55,.6,.65,.7,.75,.8,.85,.9,.95):
        accepted=tune_probs.max(axis=1)>=threshold; predicted=calibrated.classes_[tune_probs.argmax(axis=1)]
        fpr=float(np.sum(accepted & (predicted!='benign') & (tune_y=='benign'))/max(1,np.sum(tune_y=='benign')))
        precision=float(np.mean(predicted[accepted]==tune_y[accepted])) if accepted.any() else 0
        if fpr<=.05 and precision>=.9: choices.append((float(accepted.mean()),-threshold,threshold))
    threshold=max(choices)[2] if choices else 1.0
    probs=calibrated.predict_proba(X.iloc[indexes['test']]); truth=y[indexes['test']]
    accepted=probs.max(axis=1)>=threshold
    predictions=np.where(accepted,calibrated.classes_[probs.argmax(axis=1)],'ABSTAINED')
    metrics=dict(n=len(truth),coverage=float(accepted.mean()),accuracy_all_sessions=float(accuracy_score(truth,predictions)),
                 accepted_accuracy=float(accuracy_score(truth[accepted],predictions[accepted])) if accepted.any() else None,
                 macro_f1=float(f1_score(truth,predictions,labels=list(CLASSES),average='macro',zero_division=0)),
                 per_class=classification_report(truth,predictions,labels=list(CLASSES),output_dict=True,zero_division=0),
                 confusion_labels=[*CLASSES,'ABSTAINED'],confusion_matrix=confusion_matrix(truth,predictions,labels=[*CLASSES,'ABSTAINED']).tolist(),
                 validation_scope='Synthetic campaign holdout; no real-world performance claim')
    out.mkdir(parents=True,exist_ok=True)
    joblib.dump(calibrated,out/'model1_scenario.joblib',compress=3)
    metadata=dict(profile='iris_scenarios_20261109',schema=VERSION,features=FEATURES+EXTRA_FEATURES,
                  aggregation_schema='iris-three-source-session-v1-window60',sklearn_version=sklearn.__version__,
                  model_sha256=digest(out/'model1_scenario.joblib'),classes=list(calibrated.classes_),algorithm=selected,
                  selection_scores=scores,threshold=threshold,metrics=metrics,synthetic=True,
                  categorical_vocab={k:sorted(X.iloc[indexes['fit']][k].unique().tolist()) for k in CATEGORICAL},
                  numeric_train_ranges={k:[float(X.iloc[indexes['fit']][k].min()),float(X.iloc[indexes['fit']][k].max())] for k in NUMERIC+EXTRA_FEATURES},
                  checks=dict(disjoint_campaigns=len(set(sum(groups.values(),[])))==30,all_classes_in_every_split=all(set(y[ix])==set(CLASSES) for ix in indexes.values()),
                              real_reviewed_data=False),eligible_for_reviewed_advisory_release=False,
                  calibration='Frozen selected fit pipeline; disjoint calibration campaigns; no refit',
                  source_identity_features_used=False,training_labels_read_at_runtime=False)
    write_json(out/'model1_metadata.json',metadata)
    write_json(out/'split_manifest.json',dict(seed=SEED,campaigns=groups,rows={k:len(ix) for k,ix in indexes.items()},
        session_ids={k:[sessions[i]['session_id'] for i in ix] for k,ix in indexes.items()}))
    write_jsonl(out/'training_labels.jsonl',[dict(session_id=s['session_id'],campaign_id=s['campaign_id'],scenario_class=labels[s['run_id']],label_source='synthetic_generator') for s in sessions])
    write_jsonl(out/'audit_predictions.jsonl',[dict(session_id=sessions[i]['session_id'],campaign_id=sessions[i]['campaign_id'],truth=str(t),prediction=str(p)) for i,t,p in zip(indexes['test'],truth,predictions)])
    demo_sessions, _, _=sources(demo_out,campaigns=12,repetitions=1,demo=True)
    write_json(ROOT/'backend/model_profile_scenarios.json',dict(profile=metadata['profile'],directory=str(out.relative_to(ROOT)).replace('\\','/'),
        metadata_sha256=digest(out/'model1_metadata.json'),model_sha256=metadata['model_sha256'],evidence_schema=VERSION,
        mode='shadow_only',production_validated=False))
    print(json.dumps(dict(algorithm=selected,classes=metadata['classes'],audit=metrics,demo_sessions=len(demo_sessions)),indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,default=ROOT/'artifacts/model_versions/iris_scenarios_20261109')
    parser.add_argument('--demo-out',type=Path,default=ROOT/'demo/scenarios_v2')
    args=parser.parse_args()
    train(args.out.resolve(),args.demo_out.resolve())
