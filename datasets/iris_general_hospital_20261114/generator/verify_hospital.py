#!/usr/bin/env python3
"""Independent schema, hospital-context and temporal checks; no model fitting."""
import argparse
from collections import Counter,defaultdict
from datetime import datetime
import hashlib
import json
from pathlib import Path
import tempfile
import subprocess
import sys


def read(path):return json.loads(path.read_text(encoding='utf-8'))
def lines(path):return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()]
def stamp(value):return datetime.fromisoformat(value.replace('Z','+00:00'))


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--dataset-dir',type=Path,default=Path(__file__).resolve().parents[1])
    ap.add_argument('--check-reproducibility',action='store_true')
    args=ap.parse_args();r=args.dataset_dir.resolve();ref=r/'reference/agreement'
    from jsonschema import Draft202012Validator,FormatChecker
    checks=Counter();errors=[]
    def check(ok,key,detail=''):
        checks[key]+=1
        if not ok:errors.append({'check':key,'detail':str(detail)})
    ae=read(r/'data/asset_inventory.json');re=read(r/'data/risk_register.json');events=lines(r/'data/siem_alerts.jsonl')
    labels=lines(r/'offline/training_labels.jsonl');scenarios=lines(r/'offline/scenario_details.jsonl')
    changes=lines(r/'offline/change_journal.jsonl');associations=lines(r/'offline/event_associations.jsonl')
    contexts=read(r/'offline/asset_contexts.json');risk_contexts=lines(r/'offline/risk_contexts.jsonl')
    catalogue=read(ref/'control_catalogue_reference.json');cat={c['control_id']:c for c in catalogue}
    contract=read(ref/'contract.json');assets=ae['records'];risks=re['records']
    check(hashlib.sha256((ref/'control_catalogue_reference.json').read_bytes()).hexdigest()==contract['catalogue_reference_sha256'],'fixed_catalogue_hash')
    for name,values in [('asset_inventory',[ae]),('risk_register',[re]),('siem_alert',events),('training_label',labels)]:
        validator=Draft202012Validator(read(ref/'schemas'/f'{name}.schema.json'),format_checker=FormatChecker())
        count=0
        for i,value in enumerate(values):
            for e in validator.iter_errors(value):
                count+=1;errors.append({'check':'normative_json_schema','detail':f'{name}[{i}] {e.json_path}: {e.message}'})
        checks['normative_schema_'+name]+=len(values)
    av=defaultdict(list);rv=defaultdict(list);ar=defaultdict(set)
    for a in assets:av[a['asset_id']].append(a)
    for x in risks:rv[x['risk_id']].append(x);ar[x['asset_id']].add(x['risk_id'])
    def selected(group,time):
        t=stamp(time)
        rows=[v for v in group if stamp(v['valid_from'])<=t and (v['valid_to'] is None or t<stamp(v['valid_to'])) and stamp(v['recorded_at'])<=t]
        check(len(rows)==1,'unique_valid_known_snapshot',time)
        return rows[0]
    check(len(av)==500 and len(rv)==1860 and len(events)==15000,'requested_counts')
    check(all(3<=len(ar[aid])<=4 for aid in av),'three_or_four_risks_each_asset')
    check(len(contexts)==500 and {a['asset_id'] for a in contexts}==set(av),'hospital_asset_context_coverage')
    check(len(risk_contexts)==1860 and {x['risk_id'] for x in risk_contexts}==set(rv),'hospital_risk_statements_coverage')
    for kind,groups,vkey in [('asset',av,'asset_version_id'),('risk',rv,'risk_version_id')]:
        ids=[v[vkey] for vs in groups.values() for v in vs]
        check(len(ids)==len(set(ids)),kind+'_unique_versions')
        for key,vs in groups.items():
            ordered=sorted(vs,key=lambda v:v['valid_from'])
            check(sum(v['valid_to'] is None for v in vs)==1,kind+'_single_current')
            for before,after in zip(ordered,ordered[1:]):
                check(before['valid_to'] is not None and stamp(before['valid_to'])<=stamp(after['valid_from']),kind+'_nonoverlap',key)
            if kind=='risk':check(len({v['asset_id'] for v in vs})==1,'stable_risk_asset')
    for risk in risks:
        a=selected(av[risk['asset_id']],risk['valid_from'])
        existing=set(risk['existing_control_ids']);planned=set(risk['planned_control_ids']);members=existing|planned
        check(bool(members) and not(existing&planned),'nonempty_registered_disjoint_control_memberships')
        check(set(risk['control_states'])==members and set(risk['active_exception_control_ids'])<=members,'control_state_membership')
        for cid in members:
            c=cat[cid]
            check('all' in c['applies_to'] or bool(set(c['applies_to'])&set(a['control_groups'])),'catalogue_asset_applicability',cid)
            check(any(t==u or t.startswith(u+'.') or u.startswith(t+'.') for t in risk['mitre_attack_techniques'] for u in c['mitigates_attack_techniques']),'catalogue_registered_technique_match',cid)
    ev={e['event_id']:e for e in events};by_run=defaultdict(list);version_events=Counter()
    check(len(ev)==15000,'unique_event_ids')
    for e in events:
        a=selected(av[e['asset_id']],e['timestamp']);version_events[a['asset_version_id']]+=1
        check(e['agent_name']==a['hostname'],'hostname_join')
        if e['network_direction']=='inbound':check(e['destination_ip'] in a['ip_addresses'] and e['remote_destination_ip'] is None,'inbound_endpoints')
        else:check(e['destination_ip'] is None and e['source_ip'] in a['ip_addresses'],'local_outbound_endpoints')
        if e['event_family'] in {'process','privilege'}:check(e['bytes_sent']==0 and e['network_direction']=='local','local_process_semantics')
        by_run[(e['campaign_id'],e['run_id'])].append(e)
    check({e['asset_id'] for e in events}==set(av),'every_asset_observed')
    for vs in av.values():
        if len(vs)>1:check(all(version_events[v['asset_version_id']]>0 for v in vs),'historical_assets_observed_each_side')
    for key,es in by_run.items():
        es.sort(key=lambda e:e['timestamp'])
        check(len({(e['asset_id'],e['account'],e['source_ip'],e['event_family'],e['protocol']) for e in es})==1,'constant_source_run')
        check(all(0<=(stamp(b['timestamp'])-stamp(a['timestamp'])).total_seconds()<=60 for a,b in zip(es,es[1:])),'session_gap')
        check(len({selected(av[e['asset_id']],e['timestamp'])['asset_version_id'] for e in es})==1,'no_inventory_boundary_crossing')
    membership=Counter();target_count=0
    for l in labels:
        membership.update(l['event_ids'])
        check(set(l['event_ids'])=={e['event_id'] for e in by_run[(l['campaign_id'],l['run_id'])]},'annotation_exact_prepared_session')
        check(l['review_status']=='unreviewed' and l['label_verified'] is False and l['reviewer'] is None and l['controls_reviewed'] is False and l['control_reviewer'] is None,'no_fabricated_label_review')
        target_count+=len(l['recommended_control_ids'])
    check(set(membership)==set(ev) and set(membership.values())=={1},'every_event_annotated_once')
    lbl={l['case_id']:l for l in labels};risk_links=Counter();variants=Counter()
    for s in scenarios:
        l=lbl[s['case_id']];es=[ev[eid] for eid in l['event_ids']];summary=s['observation_summary'];variants[(s['scenario_class'],s['variant_kind'])]+=1
        check(summary['event_count']==len(es) and summary['total_bytes_sent']==sum(e['bytes_sent'] for e in es) and summary['failed_count']==sum(e['outcome']=='failed' for e in es),'accurate_observation_summary')
        check(summary['observed_techniques']==sorted({e['mitre_technique'] for e in es if e['mitre_technique']}),'accurate_observed_techniques')
        for rid in s['related_risk_ids']:
            risk_links[rid]+=1
            versions={selected(rv[rid],e['timestamp'])['risk_version_id'] for e in es}
            check(len(versions)==1 and next(iter(versions))==s['risk_version_id'],'no_risk_boundary_crossing')
            rr=selected(rv[rid],es[0]['timestamp'])
            check(all(cid in set(rr['existing_control_ids']+rr['planned_control_ids']) for cid in l['recommended_control_ids']),'offline_targets_registered_and_supported')
    check(set(risk_links)==set(rv),'every_risk_has_linked_attack_observations')
    for cls,n in Counter(l['scenario_class'] for l in labels).items():
        special='benign_lookalike' if cls=='benign' else 'subtle_noisy'
        check(variants[(cls,special)]*5==n,'twenty_percent_difficult_per_class',cls)
    check(len(associations)==15000 and {a['event_id'] for a in associations}==set(ev),'offline_event_join_complete')
    for a in associations:
        check(a['case_id'] in lbl and a['event_id'] in lbl[a['case_id']]['event_ids'],'offline_event_annotation_join')
    update_count=0
    for c in changes:
        if c['change_type']!='incident_triggered_simulated_risk_review':continue
        update_count+=1
        check(stamp(c['trigger_observed_at'])<stamp(c['recorded_at'])<=stamp(c['effective_at']),'evidence_precedes_risk_update')
        check(all(stamp(ev[eid]['timestamp'])<stamp(c['recorded_at']) for eid in c['trigger_event_ids']),'no_future_alerts_in_risk_update')
        check(c['actual_human_approval'] is False and c['labels_independently_reviewed'] is False,'simulation_approval_status_honest')
        before=next(x for x in rv[c['risk_id']] if x['risk_version_id']==c['before_risk_version_id']);after=next(x for x in rv[c['risk_id']] if x['risk_version_id']==c['after_risk_version_id'])
        check(before['likelihood']==c['before_likelihood'] and after['likelihood']==c['after_likelihood'],'change_journal_matches_register')
    check(update_count==48,'incident_triggered_risk_update_count')
    provenance={}
    if args.check_reproducibility:
        with tempfile.TemporaryDirectory(prefix='iris-hospital-repro-') as t:
            subprocess.run([sys.executable,str(r/'generator/generate_hospital.py'),'--output-dir',t,'--seed','20261114'],check=True,stdout=subprocess.DEVNULL)
            generated=[p for d in ['data','offline'] for p in (Path(t)/d).glob('*') if p.is_file()]
            for p in generated:
                relative=p.relative_to(t);same=p.read_bytes()==(r/relative).read_bytes()
                check(same,'seed_reproducible_bytes',relative)
                provenance[str(relative)]={'identical':same,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
    report={'status':'PASS' if not errors else 'FAIL','scope':'Independent validation with the unmodified supplied JSON schemas plus hospital business links, historical integrity and reproducibility',
        'check_evaluations':sum(checks.values()),'checks':dict(checks),'errors':errors,'error_count':len(errors),
        'current_risks':len(rv),'events':len(events),'sessions':len(by_run),'all_risks_exercised':set(risk_links)==set(rv),
        'offline_unreviewed_control_target_count':target_count,'reproducibility':provenance,
        'labels_independently_reviewed':False,'model_accuracy_claimed':False}
    (r/'validation/independent_validation.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:report[k] for k in ['status','check_evaluations','error_count','current_risks','events','sessions','all_risks_exercised','offline_unreviewed_control_target_count']},indent=2))
    if errors:print(json.dumps(errors[:10],indent=2));raise SystemExit(1)


if __name__=='__main__':main()
