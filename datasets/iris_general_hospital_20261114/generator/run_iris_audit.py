#!/usr/bin/env python3
"""Run the supplied IRIS coverage function and retain actual review evidence.

The capture subclass only reads every persisted case before the official
temporary store is removed. It changes no inference, thresholds, policies,
source files, approval state or model weights. Offline joins happen afterwards.
"""
from __future__ import annotations
import argparse
from collections import Counter
from datetime import datetime,timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

for name in ['OMP_NUM_THREADS','OPENBLAS_NUM_THREADS','MKL_NUM_THREADS']:
    os.environ.setdefault(name,'1')


def load(path):return json.loads(path.read_text(encoding='utf-8'))
def rows(path):return [json.loads(s) for s in path.read_text(encoding='utf-8').splitlines()]
def dump(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,allow_nan=False)+'\n',encoding='utf-8')
def dump_lines(path,items):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('w',encoding='utf-8') as f:
        for row in items:f.write(json.dumps(row,separators=(',',':'),allow_nan=False)+'\n')
def band(score):return 'Low' if score<=4 else 'Medium' if score<=9 else 'High' if score<=16 else 'Critical'
def detector(level):return 'Low' if level*10/16<3 else 'Medium' if level*10/16<6 else 'High' if level*10/16<8 else 'Critical'


def review_queue(audits):
    """Keep unresolved cases in an explicit review segment, never default Low."""
    order={'Needs Review':-1,'Critical':0,'High':1,'Medium':2,'Low':3}
    ordered=sorted(audits,key=lambda a:(order.get(a['primary_response_priority'],-1),-(a['registered_risk_score'] or 0),-a['source_rule_level'],a['case_id']))
    counts=Counter();result=[]
    for i,a in enumerate(ordered):
        segment='mapping_review_required' if a['primary_response_priority']=='Needs Review' else 'risk_prioritized'
        counts[segment]+=1
        result.append(dict(queue_position=i+1,queue_segment=segment,position_in_segment=counts[segment],
            case_id=a['case_id'],asset_id=a['asset_id'],hostname=a['hostname'],
            source_detector_severity=a['source_detector_severity'],iris_proposed_priority=a['primary_response_priority'],
            proposed_hospital_reference_priority=a['hospital_review_reference_priority'],registered_risk_score=a['registered_risk_score'],
            sorting_basis='Unresolved cases have a separate review segment; mapped cases sort by IRIS response priority, registered risk score and detector level. All writes await actual approval.',
            update_status=a['update_status']))
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--iris-root',type=Path,required=True)
    p.add_argument('--dataset-dir',type=Path,default=Path(__file__).resolve().parents[1])
    args=p.parse_args();root=args.dataset_dir.resolve();iris=args.iris_root.resolve()
    qualification=load(root/'validation/qualification.json')
    if not qualification['valid']:raise ValueError('Official qualification must pass before inference')
    directory=root/'validation/inference'
    if directory.exists():raise ValueError('Choose a new output bundle; previous inference is preserved')
    sys.path.insert(0,str(iris))
    spec=importlib.util.spec_from_file_location('official_iris_coverage',iris/'tools/check_input_coverage.py')
    coverage=importlib.util.module_from_spec(spec);spec.loader.exec_module(coverage)
    OriginalEngine=coverage.Engine;captured=[]
    class CaptureEngine(OriginalEngine):
        def run(self,*a,**kw):
            summary=super().run(*a,**kw)
            result=self.store.cases(run_id=summary['run_id'],limit=self.settings.max_sessions)
            assert result['total']==len(result['items'])==summary['sessions']
            captured.extend(result['items'])
            return summary
    coverage.Engine=CaptureEngine
    paths={key:root/'data'/filename for key,filename in coverage.INPUTS.items()}
    try:report,outcomes=coverage.run_check(paths,'auto')
    finally:coverage.Engine=OriginalEngine
    directory.mkdir(parents=True,exist_ok=False)
    dump(directory/'coverage.json',report);dump_lines(directory/'session_outcomes.jsonl',outcomes)
    # These annotations are loaded after inference, only for offline trace joins.
    labels=rows(root/'offline/training_labels.jsonl')
    annotations={frozenset(l['event_ids']):l for l in labels}
    contexts={a['asset_id']:a for a in load(root/'offline/asset_contexts.json')}
    asset_source=load(root/'data/asset_inventory.json')['records']
    raw_assets={a['asset_version_id']:a for a in asset_source}
    risk_source=load(root/'data/risk_register.json')['records']
    raw_risks={r['risk_version_id']:r for r in risk_source}
    audits=[]
    for case in captured:
        s=case['session'];prediction=case['prediction'];risk=case['risk_review']
        l=annotations[frozenset(s['source_event_ids'])]
        a=raw_assets[s['asset_snapshot']['asset_version_id']]
        r=raw_risks.get(risk.get('matched_risk_version_id'))
        score=r['likelihood']*r['impact'] if r else None
        raw_level=max(s['features']['max_rule_level'],0)
        raw_priority=detector(raw_level);response=risk['priority']
        hospital_reference=response
        reason='Retain the actual IRIS policy proposal and its mapping status.'
        # This is an explicitly proposed hospital review rule, outside runtime.
        # It cannot silently change the supplied primary policy or model output.
        if r and score>=20 and a['criticality']>=4 and raw_level>=8 and risk['mapping_status']=='MATCHED':
            hospital_reference='Critical'
            reason='Proposed hospital review floor: corroborated rule evidence on a care-critical asset with registered likelihood x impact >= 20. Requires approval of this separate hospital policy.'
        m2=prediction.get('model2_review') or {}
        audits.append(dict(case_id=l['case_id'],engine_case_id=case['case_id'],session_id=s['session_id'],asset_id=s['asset_id'],
            asset_version_id=a['asset_version_id'],hostname=a['hostname'],department=contexts[s['asset_id']]['department'],
            business_service=contexts[s['asset_id']]['business_service'],source_event_ids=s['source_event_ids'],
            source_rule_level=raw_level,source_detector_severity=raw_priority,asset_criticality=a['criticality'],
            primary_rule_assessment=prediction['soc_assessment'],risk_review=risk,
            registered_risk_score=score,registered_risk_level=band(score) if score is not None else None,
            primary_response_priority=response,primary_control_review=case['primary_controls'],
            experimental_model2_source=m2.get('source'),experimental_model2_recommendations=m2.get('recommendations',[]),
            experimental_model2_missing_fields=m2.get('missing_fields',[]),
            hospital_review_reference_priority=hospital_reference,hospital_review_reference_rationale=reason,
            hospital_review_reference_policy_status='proposed_synthetic_review_policy_not_installed_in_iris',
            update_status='proposal_only_requires_actual_soc_grc_approval',actual_human_approval=False,
            official_risk_register_written=False,training_labels_used_for_inference=False))
    by_case={r['case_id']:r for r in audits}
    comparisons=[]
    for t in load(root/'offline/temporal_comparisons.json'):
        phases=[]
        for original in t['phases']:
            a=by_case[original['case_id']]
            phases.append(dict(case_id=a['case_id'],phase=original['phase'],asset_version_id=a['asset_version_id'],
                risk_version_id=original['risk_version_id'],source_rule_level=a['source_rule_level'],
                source_detector_severity=a['source_detector_severity'],asset_criticality=a['asset_criticality'],
                primary_mapping_status=a['risk_review']['mapping_status'],primary_response_priority=a['primary_response_priority'],
                risk_score=a['registered_risk_score'],risk_level=a['registered_risk_level'],
                proposed_likelihood=a['risk_review']['proposed_likelihood'],
                hospital_review_reference_priority=a['hospital_review_reference_priority']))
        comparisons.append(dict(**t,observed_results=phases,
            original_detector_severity_held_constant=len({p['source_detector_severity'] for p in phases})==1,
            actual_iris_priority_changed=len({p['primary_response_priority'] for p in phases})>1,
            note='Actual IRIS priorities and the separate proposed hospital review priorities are distinguished. Historical approvals are fictional fixtures.'))
    dump_lines(root/'offline/actual_iris_reviews.jsonl',audits)
    dump(root/'offline/priority_change_walkthroughs.json',comparisons)
    dump_lines(root/'offline/review_queue.jsonl',review_queue(audits))
    summary=dict(official_coverage_function='tools/check_input_coverage.py:run_check',
        official_coverage_source_sha256=hashlib.sha256((iris/'tools/check_input_coverage.py').read_bytes()).hexdigest(),
        cases_retrieved=len(captured),all_cases_retrieved=len(captured)==len(labels),
        actual_iris_priorities=dict(Counter(a['primary_response_priority'] for a in audits)),
        actual_iris_mapping_statuses=dict(Counter(a['risk_review']['mapping_status'] for a in audits)),
        actual_model2_recommendations=sum(len(a['experimental_model2_recommendations']) for a in audits),
        sessions_with_actual_model2_recommendations=sum(bool(a['experimental_model2_recommendations']) for a in audits),
        actual_priority_changed_comparisons=sum(t['actual_iris_priority_changed'] for t in comparisons),
        comparisons_with_constant_detector_severity=sum(t['original_detector_severity_held_constant'] for t in comparisons),
        proposed_hospital_reference_priorities=dict(Counter(a['hospital_review_reference_priority'] for a in audits)),
        proposed_hospital_reference_differs_from_iris=sum(a['hospital_review_reference_priority']!=a['primary_response_priority'] for a in audits),
        hospital_reference_is_runtime_policy=False,source_files_unchanged=report['source_files_unchanged'],
        model_weights_changed=False,frozen_thresholds_changed=False,actual_approvals_created=False,
        labels_independently_reviewed=False,accuracy_evaluated=False)
    dump(root/'validation/workflow_audit.json',summary)
    print(json.dumps({'coverage':report['model_coverage'],'workflow':summary},indent=2))


if __name__=='__main__':main()
