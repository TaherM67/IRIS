#!/usr/bin/env python3
"""Hospital fixtures for the supplied, unchanged IRIS expanded input contract.

Only the three data/ files are runtime inputs. All scenarios, associations,
clinical context, change explanations and review references remain offline.
No model or saved application state is read by this generator.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import random
import uuid

SEED=20261114
HOSPITAL='IRIS General Hospital'
CATEGORY_CLASS={
    'Unauthorized Access':'credential_access','Reconnaissance':'reconnaissance',
    'Malware Execution':'malicious_execution','Privilege Escalation':'privilege_escalation',
    'Web Application Compromise':'web_exploitation','Data Exfiltration':'data_exfiltration'}
TECHNIQUE={'Unauthorized Access':'T1110','Reconnaissance':'T1046',
    'Malware Execution':'T1059','Privilege Escalation':'T1068',
    'Web Application Compromise':'T1190','Data Exfiltration':'T1048'}
RISK_TEXT={
    'Unauthorized Access':('Unauthorized access to {role} using compromised or repeatedly guessed credentials',
        'Loss of authorized access boundaries, exposure of hospital information, or interruption of {service}'),
    'Reconnaissance':('Unauthorized discovery of reachable services on {role}',
        'Exposure of the service footprint supporting {service}, enabling follow-on intrusion attempts'),
    'Malware Execution':('Unauthorized program or command execution in the managed operating environment of {role}',
        'Disruption of {service} and possible loss of trust in the system used by hospital staff'),
    'Privilege Escalation':('Elevation beyond the approved account role on {role}',
        'Unauthorized administrative changes affecting the integrity or availability of {service}'),
    'Web Application Compromise':('Exploitation of the exposed HTTP application or administrative interface of {role}',
        'Unauthorized application actions or disclosure affecting {service}'),
    'Data Exfiltration':('Unauthorized transfer of information from {role} over a separate, unapproved outbound channel',
        'Disclosure of fictional patient, staff, operational or security information held for {service}')}

# role code, count, asset type, department, service, owner, groups, criticality
ROLES=[
 ('ward-nursing-ws',80,'workstation','Inpatient wards','bedside documentation','Clinical Workplace Team',['endpoint'],4),
 ('imaging-viewer-ws',40,'workstation','Radiology','diagnostic image review','Imaging Informatics Team',['endpoint'],4),
 ('laboratory-ws',30,'workstation','Laboratory','specimen workflow','Laboratory Informatics Team',['endpoint'],4),
 ('pharmacy-ws',20,'workstation','Pharmacy','medication verification','Pharmacy Informatics Team',['endpoint'],5),
 ('administration-ws',20,'workstation','Administration','staff scheduling and finance','Hospital Business Systems',['endpoint'],2),
 ('it-support-ws',20,'workstation','IT Operations','technical service support','Hospital IT Operations',['endpoint'],3),
 ('ehr-app',16,'server','Clinical Applications','electronic health record access','Clinical Applications Team',['server','web'],5),
 ('pacs-app',12,'server','Radiology','image archive access','Imaging Informatics Team',['server','web'],5),
 ('lis-app',8,'server','Laboratory','laboratory result distribution','Laboratory Informatics Team',['server','web'],5),
 ('pharmacy-app',8,'server','Pharmacy','medication administration support','Pharmacy Informatics Team',['server','web'],5),
 ('interface-engine',6,'server','Clinical Integration','clinical message routing','Clinical Integration Team',['server'],5),
 ('backup-server',6,'server','IT Operations','hospital recovery operations','Hospital Resilience Team',['server'],4),
 ('virtualization-host',8,'server','IT Operations','clinical virtual machine hosting','Hospital Infrastructure Team',['server'],5),
 ('file-print-server',6,'server','Administration','document and print services','Hospital Business Systems',['server'],3),
 ('ehr-db',16,'database','Clinical Applications','electronic health record storage','Clinical Database Team',['server','db'],5),
 ('pacs-index-db',10,'database','Radiology','image metadata storage','Imaging Database Team',['server','db'],5),
 ('lis-db',8,'database','Laboratory','laboratory result storage','Laboratory Database Team',['server','db'],5),
 ('pharmacy-db',6,'database','Pharmacy','medication catalogue storage','Pharmacy Database Team',['server','db'],5),
 ('finance-db',6,'database','Administration','billing and payroll records','Hospital Business Systems',['server','db'],3),
 ('reporting-db',4,'database','Administration','operational reporting','Hospital Analytics Team',['server','db'],3),
 ('directory-service',5,'identity_service','Identity and Access','clinical staff authentication','Hospital Identity Team',['server','identity'],5),
 ('clinical-sso',4,'identity_service','Identity and Access','clinical single sign on','Hospital Identity Team',['server','identity'],5),
 ('network-radius',3,'identity_service','Identity and Access','network access authentication','Hospital Identity Team',['server','identity'],4),
 ('privileged-access',3,'identity_service','Identity and Access','privileged access administration','Hospital Identity Team',['server','identity'],5),
 ('patient-portal',8,'web_application','Patient Services','patient portal access','Patient Digital Services',['web'],5),
 ('appointment-web',5,'web_application','Outpatient Clinics','appointment scheduling','Patient Digital Services',['web'],4),
 ('clinical-web',5,'web_application','Clinical Applications','clinical workflow access','Clinical Applications Team',['web'],5),
 ('vendor-support-web',4,'web_application','Biomedical Engineering','approved vendor service access','Biomedical Security Team',['web'],4),
 ('billing-web',3,'web_application','Administration','billing enquiries','Hospital Business Systems',['web'],3),
 ('clinical-core-switch',32,'network_device','Network Operations','clinical network transport','Hospital Network Team',['network'],4),
 ('segmentation-firewall',12,'network_device','Network Operations','clinical network segmentation','Hospital Network Team',['network'],5),
 ('remote-access-gateway',8,'network_device','Network Operations','approved remote access','Hospital Network Team',['network'],4),
 ('wireless-controller',8,'network_device','Network Operations','clinical wireless connectivity','Hospital Network Team',['network'],4),
 ('cloud-backup-vault',16,'cloud_resource','IT Operations','offsite recovery storage','Hospital Resilience Team',['cloud'],5),
 ('telemedicine-cloud',12,'cloud_resource','Outpatient Clinics','remote consultation support','Patient Digital Services',['cloud'],4),
 ('analytics-cloud',6,'cloud_resource','Administration','de-identified operational analytics','Hospital Analytics Team',['cloud'],3),
 ('integration-cloud',6,'cloud_resource','Clinical Integration','approved external data exchange','Clinical Integration Team',['cloud'],4),
 ('bedside-monitor-gateway',12,'iot_device','ICU and Emergency','bedside monitoring connectivity','Biomedical Engineering Team',['iot'],5),
 ('infusion-integration-gateway',8,'iot_device','ICU and Inpatient Wards','medication device connectivity','Biomedical Engineering Team',['iot'],5),
 ('imaging-acquisition-console',6,'iot_device','Radiology','diagnostic image acquisition','Imaging Engineering Team',['iot','endpoint'],5),
 ('laboratory-instrument-gateway',4,'iot_device','Laboratory','instrument result connectivity','Laboratory Engineering Team',['iot'],4),
]


def dump(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,ensure_ascii=False,allow_nan=False)+'\n',encoding='utf-8')


def dump_lines(path,rows):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('w',encoding='utf-8',newline='\n') as f:
        for row in rows:f.write(json.dumps(row,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n')


def stamp(t):return t.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
def when(s):return datetime.fromisoformat(s.replace('Z','+00:00'))
def matches(a,b):return a==b or a.startswith(b+'.') or b.startswith(a+'.')
def level(score):return 'Low' if score<=4 else 'Medium' if score<=9 else 'High' if score<=16 else 'Critical'


def categories(a):
    typ=a['asset_type']; u='Unauthorized Access'; p='Privilege Escalation'; d='Data Exfiltration'; r='Reconnaissance'; m='Malware Execution'; w='Web Application Compromise'
    if typ=='workstation':return [u,m,p,d]
    if typ=='server':return [u,w,m,d] if 'web' in a['control_groups'] else [u,r,m,p]
    return {'database':[u,p,d],'identity_service':[u,r,p,d],
        'web_application':[u,r,w,d],'network_device':[u,r,p],
        'cloud_resource':[u,r,p,d],'iot_device':[u,r,p]}[typ]


def active(versions,t):
    found=[r for r in versions if r['valid_from']<=t and (r['valid_to'] is None or t<r['valid_to']) and r['recorded_at']<=t]
    if len(found)!=1:raise ValueError('Expected exactly one valid, known snapshot')
    return found[0]


def generate(out,seed=SEED):
    rng=random.Random(seed)
    reference=Path(__file__).resolve().parents[1]/'reference/agreement'
    contract=json.loads((reference/'contract.json').read_text())
    raw_catalogue=(reference/'control_catalogue_reference.json').read_bytes()
    if hashlib.sha256(raw_catalogue).hexdigest()!=contract['catalogue_reference_sha256']:raise ValueError('Pinned catalogue changed')
    catalogue=json.loads(raw_catalogue); by_control={c['control_id']:c for c in catalogue}
    alert_schema=json.loads((reference/'schemas/siem_alert.schema.json').read_text())
    allowed_techniques=set(alert_schema['properties']['mitre_technique']['enum'])
    assert set(TECHNIQUE.values())<=allowed_techniques
    ns=uuid.uuid5(uuid.NAMESPACE_URL,'iris-hospital-v2/'+str(seed))
    def uid(kind,n):return uuid.uuid5(ns,kind+'/'+str(n)).hex
    def candidates(asset,category):
        tech=TECHNIQUE[category]
        return sorted(c['control_id'] for c in catalogue if ('all' in c['applies_to'] or set(c['applies_to'])&set(asset['control_groups'])) and any(matches(tech,t) for t in c['mitigates_attack_techniques']))
    def policy_control_rows(risk):
        return [{'control_id':cid,'name':by_control[cid]['name'],'registered_state':risk['control_states'].get(cid,'unknown')} for cid in risk['existing_control_ids']+risk['planned_control_ids']]

    asset_contexts=[]; asset_versions=defaultdict(list); assets=[]
    for code,count,typ,dept,service,owner,groups,criticality in ROLES:
        for number in range(1,count+1):
            i=len(assets); aid=uid('asset',i)
            a=dict(asset_id=aid,asset_version_id=uid('asset-version',f'{i}/0'),
                hostname=f'cvh-{code}-{number:03d}.hospital.test',ip_addresses=[f'10.68.{10+i//200}.{1+i%200}'],
                asset_type=typ,criticality=criticality,zone=dept.lower().replace(' ','-'),owner=owner,
                control_groups=groups[:],valid_from='2026-10-01T00:00:00Z',valid_to=None,recorded_at='2026-09-30T12:00:00Z')
            assets.append(a)
            asset_contexts.append(dict(asset_id=aid,hostname=a['hostname'],organization=HOSPITAL,
                role=code.replace('-',' '),department=dept,business_service=service,
                clinical_dependency=('Direct care support' if criticality>=4 else 'Hospital supporting operations'),
                data_scope=('Fictional clinical or device operational data' if criticality>=4 else 'Fictional staff or administrative records'),
                physical_context='Main hospital campus or explicitly named cloud tenancy',
                managed_execution_context=('Embedded or managed device command interpreter' if typ in {'iot_device','network_device'} else 'Managed host or application service execution context'),
                has_web_application=('web' in groups),data_provenance='synthetic'))
    assert len(assets)==500
    context_by_asset={r['asset_id']:r for r in asset_contexts}
    # Nine assets per type undergo a pre-scheduled clinical service activation.
    historical=[]
    for typ in sorted({a['asset_type'] for a in assets}):
        historical.extend([a['asset_id'] for a in assets if a['asset_type']==typ and a['criticality']>=4][:9])
    assert len(historical)==72
    history_set=set(historical)
    inventory_changes=[]
    for i,a in enumerate(assets):
        if a['asset_id'] in history_set:
            before=deepcopy(a);before.update(criticality=3,valid_to='2026-11-01T00:00:00Z')
            a.update(asset_version_id=uid('asset-version',f'{i}/1'),valid_from='2026-11-01T00:00:00Z',recorded_at='2026-10-31T12:00:00Z')
            asset_versions[a['asset_id']].append(before)
            inventory_changes.append(dict(change_id=uid('inventory-change',i),asset_id=a['asset_id'],
                effective_at=a['valid_from'],recorded_at=a['recorded_at'],change_type='scheduled_clinical_service_activation',
                before_asset_version_id=before['asset_version_id'],after_asset_version_id=a['asset_version_id'],
                before_criticality=3,after_criticality=a['criticality'],
                rationale=f"The {context_by_asset[a['asset_id']]['role']} moves from validated standby into the live care workflow for {context_by_asset[a['asset_id']]['business_service']}.",
                status='fictional_historical_inventory_change',data_provenance='synthetic'))
        asset_versions[a['asset_id']].append(deepcopy(a))

    risks=[]; risk_versions=defaultdict(list); risk_contexts=[]; by_asset_risks=defaultdict(list)
    for a in assets:
        for category in categories(a):
            i=len(risks); rid=uid('risk',i); pool=candidates(a,category)
            assert pool,(a['asset_type'],category)
            rng.shuffle(pool)
            ne=min(2,max(1,len(pool)-1)); np=min(2,len(pool)-ne)
            existing=pool[:ne];planned=pool[ne:ne+np]
            if not planned:planned=[existing.pop()]
            states={cid:rng.choices(['implemented','partial','unknown','compensating'],[50,30,15,5])[0] for cid in existing}
            states.update({cid:rng.choices(['missing','not_assessed','unknown'],[65,20,15])[0] for cid in planned})
            exceptions=[]
            if i%41==0 and planned:
                states[planned[-1]]='exception';exceptions=[planned[-1]]
            impact=min(5,max(1,a['criticality']+rng.choice([-1,0,0,0,1])))
            likelihood=rng.choices([1,2,3,4,5],[8,28,36,22,6])[0]
            r=dict(risk_id=rid,risk_version_id=uid('risk-version',f'{i}/0'),asset_id=a['asset_id'],risk_category=category,
                likelihood=likelihood,impact=impact,existing_control_ids=existing,planned_control_ids=planned,
                mitre_attack_techniques=[TECHNIQUE[category]],control_states=states,active_exception_control_ids=exceptions,
                valid_from='2026-10-01T00:00:00Z',valid_to=None,recorded_at='2026-09-30T12:00:00Z')
            if a['asset_id'] in history_set:
                before=deepcopy(r);before.update(impact=max(1,impact-1),valid_to='2026-11-01T00:00:00Z')
                risk_versions[rid].append(before)
                r.update(risk_version_id=uid('risk-version',f'{i}/1'),valid_from='2026-11-01T00:00:00Z',recorded_at='2026-10-31T12:00:00Z')
            risk_versions[rid].append(r);risks.append(r);by_asset_risks[a['asset_id']].append(r)
            c=context_by_asset[a['asset_id']]; statement,consequence=RISK_TEXT[category]
            risk_contexts.append(dict(risk_id=rid,asset_id=a['asset_id'],risk_category=category,
                risk_statement=statement.format(role=c['role']),hospital_consequence=consequence.format(service=c['business_service']),
                department=c['department'],business_service=c['business_service'],
                registration_basis='Fictional asset exposure and service assessment established before the first alert',data_provenance='synthetic'))
    assert len(risks)==1860
    asset_by_id={a['asset_id']:a for a in assets}
    risk_by_id={r['risk_id']:r for r in risks}
    # Each historical asset has an explicitly linked before/after evidence pair.
    chosen={}
    preference=['Web Application Compromise','Data Exfiltration','Privilege Escalation','Malware Execution','Reconnaissance','Unauthorized Access']
    for aid in historical:
        rr=by_asset_risks[aid]
        r=min(rr,key=lambda x:preference.index(x['risk_category'])); chosen[aid]=r['risk_id']
        risk_versions[r['risk_id']][0].update(likelihood=2,impact=3)
        r.update(likelihood=3,impact=asset_by_id[aid]['criticality'])
    reviewed=[]
    for typ in sorted({a['asset_type'] for a in assets}):
        reviewed.extend([chosen[aid] for aid in historical if asset_by_id[aid]['asset_type']==typ][:6])
    assert len(reviewed)==48
    review_set=set(reviewed)
    for rid in reviewed:
        r=risk_by_id[rid];before=deepcopy(r);r['valid_to']='2026-11-06T00:00:00Z'
        after=deepcopy(before);after.update(risk_version_id=uid('risk-review-version',rid),
            likelihood=min(5,before['likelihood']+1),valid_from='2026-11-06T00:00:00Z',valid_to=None,recorded_at='2026-11-05T12:00:00Z')
        available=[c for c in candidates(asset_by_id[r['asset_id']],r['risk_category']) if c not in set(r['existing_control_ids']+r['planned_control_ids'])]
        if available:
            cid=available[0];after['planned_control_ids'].append(cid);after['control_states'][cid]='missing'
        risk_versions[rid].append(after)

    plans=[]; pattern_groups={}; chosen_set=set(chosen.values())
    def add(risk,phase,pattern=None,kind='single_observation'):
        i=len(plans);aid=risk['asset_id'];cls=CATEGORY_CLASS[risk['risk_category']]
        plans.append(dict(index=i,asset_id=aid,risk_id=risk['risk_id'],scenario_class=cls,phase=phase,
            pattern=pattern or uid('pattern',i),history_kind=kind,protected=kind!='single_observation'))
    for r in risks:
        paired=r['risk_id'] in chosen_set
        add(r,'before' if paired else rng.choice(['early','current']),uid('paired-pattern',r['risk_id']) if paired else None,
            'inventory_context_pair' if paired else 'single_observation')
    for aid,rid in chosen.items():
        add(risk_by_id[rid],'after_inventory',uid('paired-pattern',rid),'inventory_context_pair')
    for rid in reviewed:
        add(risk_by_id[rid],'after_risk_review',uid('paired-pattern',rid),'risk_review_followup')
    # Round class counts to multiples of five for exact 20% difficult cases.
    for cls in CATEGORY_CLASS.values():
        choices=[r for r in risks if CATEGORY_CLASS[r['risk_category']]==cls]
        while sum(p['scenario_class']==cls for p in plans)%5:add(rng.choice(choices),'current')
    for a in assets:
        i=len(plans);plans.append(dict(index=i,asset_id=a['asset_id'],risk_id=None,scenario_class='benign',phase='current',
            pattern=uid('pattern',i),history_kind='routine_hospital_activity',protected=False))
    for cls in ['benign',*CATEGORY_CLASS.values()]:
        group=[p for p in plans if p['scenario_class']==cls]
        difficult=set(p['index'] for p in rng.sample([p for p in group if not p['protected']],len(group)//5))
        for p in group:p['variant_kind']='benign_lookalike' if cls=='benign' and p['index'] in difficult else 'subtle_noisy' if p['index'] in difficult else 'standard'
    for p in plans:pattern_groups.setdefault(p['pattern'],[]).append(p)
    n_by_pattern={}; max_by_pattern={}
    for key,group in pattern_groups.items():
        p=group[0];cls=p['scenario_class'];difficult=p['variant_kind']!='standard'
        n_by_pattern[key]=13 if cls=='credential_access' and not difficult else 15 if cls=='reconnaissance' and not difficult else 5 if cls in {'credential_access','reconnaissance'} else 3
        max_by_pattern[key]=20 if cls in {'credential_access','reconnaissance'} and not difficult else 8
    budget=15000-sum(n_by_pattern[k]*len(g) for k,g in pattern_groups.items())
    if budget<0:raise ValueError(f'Minimum observations exceed requested count by {-budget}')
    while budget:
        available=[k for k,g in pattern_groups.items() if n_by_pattern[k]<max_by_pattern[k] and len(g)<=budget]
        if not available:raise ValueError('Cannot allocate exact event budget')
        key=rng.choice(available);n_by_pattern[key]+=1;budget-=len(pattern_groups[key])

    # Patterns reuse observed measurements across matched context replays.
    patterns={}
    for key,group in pattern_groups.items():
        p=group[0];cls=p['scenario_class'];a=asset_by_id[p['asset_id']];difficult=p['variant_kind']!='standard'
        family={'credential_access':'authentication','reconnaissance':'network','malicious_execution':'process',
            'privilege_escalation':'privilege','web_exploitation':'web','data_exfiltration':'network'}.get(cls)
        if cls=='benign':family=rng.choice(['authentication','network','process','privilege']+(['web'] if 'web' in a['control_groups'] else []))
        direction='local' if family in {'process','privilege'} else 'outbound' if cls=='data_exfiltration' else 'inbound'
        if cls=='benign' and family=='network':direction=rng.choice(['inbound','outbound'])
        protocol='LOCAL' if direction=='local' else 'HTTPS' if family=='web' or a['asset_type'] in {'web_application','cloud_resource'} else rng.choice(['SSH','HTTPS']) if family=='authentication' else rng.choice(['TCP','HTTPS']) if direction=='outbound' else 'TCP'
        remote=f"{rng.choice(['192.0.2','198.51.100','203.0.113'])}.{rng.randint(1,254)}"
        account=None if family=='network' and rng.random()<.55 else f'cvh-service-{rng.randint(1,150):03d}' if a['asset_type']!='workstation' else f'cvh-staff-{rng.randint(1,250):03d}'
        n=n_by_pattern[key];rows=[];offset=0
        # Registered severity is not a desired response priority. The replay
        # examples deliberately preserve this detector measurement across time.
        max_level=8 if p['protected'] else rng.randint(3,9) if difficult else rng.randint(7,14) if cls!='benign' else rng.randint(1,7)
        tech=None if cls=='benign' else TECHNIQUE[risk_by_id[p['risk_id']]['risk_category']]
        if cls!='benign' and difficult and rng.random()<.2:tech=None
        for j in range(n):
            if j:offset+=rng.randint(2,20 if difficult else 12)
            unsigned=(family=='process' and (j<2 if cls=='malicious_execution' and not difficult else rng.random()<(.3 if difficult else .04)))
            privilege=(family=='privilege' and (j==0 if cls=='privilege_escalation' and not difficult else rng.random()<(.3 if difficult else .08)))
            web=(family=='web' and (j<2 if cls=='web_exploitation' and not difficult else rng.random()<(.35 if difficult else .04)))
            indicator=(j==0 and cls in {'malicious_execution','privilege_escalation'} and not difficult) or rng.random()<(.10 if difficult else .05 if cls!='benign' else .01)
            sensitive=(j==0 and cls=='data_exfiltration') or rng.random()<(.2 if cls=='benign' else .1)
            untrusted=direction=='outbound' and ((j==0 and cls=='data_exfiltration') or rng.random()<(.2 if difficult else .03))
            if direction=='outbound':
                byte_count=rng.randint(1800000,3200000) if cls=='data_exfiltration' and not difficult else rng.randint(15000,850000)
            else:byte_count=0
            if cls=='credential_access':outcome='failed' if difficult or j<n-1 or rng.random()<.75 else 'success'
            elif family=='authentication':outcome='failed' if j==0 or difficult and j<min(3,n-1) else 'success'
            else:outcome=rng.choices(['success','failed','unknown'],[70,20,10])[0]
            # Use one observed rule family across classes; rule IDs carry no truth.
            rule_n=j%rng.randint(4,6) if family=='network' else rng.randint(0,5)
            rows.append(dict(offset=offset,rule_id=uid('detector',f'{family}/{rule_n}'),rule_level=max_level if j==0 else rng.randint(max(0,max_level-3),max_level),
                outcome=outcome,bytes_sent=byte_count,process_unsigned=bool(unsigned),privilege_change=bool(privilege),web_attack_signal=bool(web),
                sensitive_data_access=bool(sensitive),destination_untrusted=bool(untrusted),malicious_indicator=bool(indicator),
                mitre_technique=tech if j==0 or rng.random()<.6 else None))
        patterns[key]=dict(rows=rows,event_family=family,network_direction=direction,protocol=protocol,remote=remote,account=account)

    events=[];labels=[];scenarios=[]; associations=[];pattern_cases=defaultdict(list)
    for p in plans:
        i=p['index'];a=asset_by_id[p['asset_id']];c=context_by_asset[a['asset_id']];cls=p['scenario_class'];pattern=patterns[p['pattern']]
        dates={'before':(10,24),'early':(10,rng.randint(15,29)),'current':(11,rng.randint(2,4)),'after_inventory':(11,3),'after_risk_review':(11,8)}
        month,day=dates[p['phase']];start=datetime(2026,month,day,(i*7)%22,(i*11)%55,0,tzinfo=timezone.utc)
        campaign=uid('campaign',assets.index(a)//5);run=uid('run',i);case=uid('case',i)
        # Shared procedural base variants retain one template identity; paired
        # replays also share a campaign and identical observed feature vector.
        template=uid('template',f"{cls}/{c['role']}/{p['variant_kind']}")
        this=[]
        for j,raw in enumerate(pattern['rows']):
            raw=raw.copy();offset=raw.pop('offset');time=stamp(start+timedelta(seconds=offset));eid=uid('event',len(events)+len(this))
            aa=active(asset_versions[a['asset_id']],time);d=pattern['network_direction']
            e=dict(event_id=eid,timestamp=time,asset_id=a['asset_id'],agent_name=aa['hostname'],
                destination_ip=aa['ip_addresses'][0] if d=='inbound' else None,
                remote_destination_ip=pattern['remote'] if d=='outbound' else None,
                network_direction=d,source_ip=pattern['remote'] if d=='inbound' else aa['ip_addresses'][0],
                account=pattern['account'],event_family=pattern['event_family'],protocol=pattern['protocol'],
                **raw,sensor_healthy=True,campaign_id=campaign,run_id=run,data_provenance='synthetic')
            this.append(e)
            rr=active(risk_versions[p['risk_id']],time) if p['risk_id'] else None
            associations.append(dict(event_id=eid,case_id=case,run_id=run,campaign_id=campaign,asset_id=a['asset_id'],
                asset_version_id=aa['asset_version_id'],risk_id=p['risk_id'],risk_version_id=rr['risk_version_id'] if rr else None,
                relation='attack_scenario_evidence' if rr else 'routine_comparison',scenario_class=cls,review_status='unreviewed'))
        events.extend(this);rr=active(risk_versions[p['risk_id']],this[0]['timestamp']) if p['risk_id'] else None
        targets=[] if rr is None else [cid for cid in rr['planned_control_ids'] if rr['control_states'].get(cid) in {'missing','partial'} and cid not in rr['active_exception_control_ids']][:2]
        labels.append(dict(case_id=case,event_ids=[e['event_id'] for e in this],campaign_id=campaign,run_id=run,template_group=template,
            scenario_class=cls,label_source='llm_synthetic',review_status='unreviewed',label_verified=False,reviewer=None,
            recommended_control_ids=targets,controls_reviewed=False,control_reviewer=None))
        summary=dict(event_count=len(this),event_family=pattern['event_family'],protocol=pattern['protocol'],network_direction=pattern['network_direction'],
            max_rule_level=max(e['rule_level'] for e in this),failed_count=sum(e['outcome']=='failed' for e in this),
            total_bytes_sent=sum(e['bytes_sent'] for e in this),observed_techniques=sorted({e['mitre_technique'] for e in this if e['mitre_technique']}))
        description=(f"At {HOSPITAL}, the {c['role']} supports {c['business_service']} in {c['department']}. "
            +(f"This fictional exercise observes {RISK_TEXT[rr['risk_category']][0].format(role=c['role']).lower()}. " if rr else 'Staff or approved service accounts perform routine hospital activity. ')
            +f"The sensor records {len(this)} events from {this[0]['timestamp']} to {this[-1]['timestamp']}. "
            +('The observed outbound transfer uses a recipient and channel outside the hospital approved data-exchange service. ' if cls=='data_exfiltration' else '')
            +'Scenario interpretation and control targets are unreviewed synthetic annotations.')
        scenarios.append(dict(case_id=case,run_id=run,campaign_id=campaign,asset_id=a['asset_id'],related_risk_ids=[p['risk_id']] if rr else [],
            scenario_class=cls,variant_kind=p['variant_kind'],template_group=template,pattern_group=p['pattern'],phase=p['phase'],
            history_kind=p['history_kind'],session_start=this[0]['timestamp'],session_end=this[-1]['timestamp'],
            department=c['department'],business_service=c['business_service'],narrative=description,observation_summary=summary,
            asset_version_id=active(asset_versions[a['asset_id']],this[0]['timestamp'])['asset_version_id'],risk_version_id=rr['risk_version_id'] if rr else None,
            control_reference_targets=targets,review_status='unreviewed'))
        pattern_cases[p['pattern']].append(case)
    assert len(events)==15000
    assert len({e['event_id'] for e in events})==15000
    assert len({rid for s in scenarios for rid in s['related_risk_ids']})==1860
    assert len(labels)<=contract['maximum_sessions']
    events.sort(key=lambda e:(e['timestamp'],e['event_id']))
    scenario_by_case={s['case_id']:s for s in scenarios}
    changes=inventory_changes[:]
    for rid in reviewed:
        group=pattern_cases[uid('paired-pattern',rid)]
        trigger=next(scenario_by_case[c] for c in group if scenario_by_case[c]['phase']=='after_inventory')
        before=active(risk_versions[rid],'2026-11-04T12:00:00Z');after=active(risk_versions[rid],'2026-11-08T12:00:00Z')
        changes.append(dict(change_id=uid('risk-change',rid),change_type='incident_triggered_simulated_risk_review',
            asset_id=after['asset_id'],risk_id=rid,trigger_case_id=trigger['case_id'],trigger_event_ids=next(l['event_ids'] for l in labels if l['case_id']==trigger['case_id']),
            trigger_observed_at=trigger['session_end'],recorded_at=after['recorded_at'],effective_at=after['valid_from'],
            before_risk_version_id=before['risk_version_id'],after_risk_version_id=after['risk_version_id'],
            before_likelihood=before['likelihood'],after_likelihood=after['likelihood'],impact=after['impact'],
            controls_added_to_plan=sorted(set(after['planned_control_ids'])-set(before['planned_control_ids'])),
            rationale='A fictional SOC escalation and GRC assessment after the linked observations raise the registered likelihood and extend the mitigation plan. No control is declared effective from an alert alone.',
            status='simulated_historical_update_only',actual_human_approval=False,labels_independently_reviewed=False,data_provenance='synthetic'))
    timeline=[]
    for aid,rid in chosen.items():
        group=pattern_cases[uid('paired-pattern',rid)]
        timeline.append(dict(comparison_id=uid('comparison',rid),asset_id=aid,risk_id=rid,
            phases=[dict(case_id=cid,phase=scenario_by_case[cid]['phase'],asset_version_id=scenario_by_case[cid]['asset_version_id'],risk_version_id=scenario_by_case[cid]['risk_version_id']) for cid in group],
            evidence_basis='Same measured pattern replayed in separate source runs under time-valid context versions',
            review_status='unreviewed_synthetic_reference',data_provenance='synthetic'))
    flat_assets=[v for a in assets for v in asset_versions[a['asset_id']]]
    flat_risks=[v for r in risks for v in risk_versions[r['risk_id']]]
    dump(out/'data/asset_inventory.json',dict(schema_version='iris-asset-inventory-v1',data_provenance='synthetic',records=flat_assets))
    dump(out/'data/risk_register.json',dict(schema_version='iris-risk-register-v1',data_provenance='synthetic',control_membership_basis='versioned_runtime_risk_snapshots',records=flat_risks))
    dump_lines(out/'data/siem_alerts.jsonl',events)
    dump_lines(out/'offline/training_labels.jsonl',labels)
    dump_lines(out/'offline/scenario_details.jsonl',scenarios)
    dump_lines(out/'offline/event_associations.jsonl',associations)
    dump_lines(out/'offline/risk_contexts.jsonl',risk_contexts)
    dump(out/'offline/asset_contexts.json',asset_contexts)
    dump_lines(out/'offline/change_journal.jsonl',changes)
    dump(out/'offline/temporal_comparisons.json',timeline)
    current=[active(vs,'2026-11-10T00:00:00Z') for vs in risk_versions.values()]
    dump(out/'offline/risk_levels.json',[dict(risk_id=r['risk_id'],asset_id=r['asset_id'],risk_score=r['likelihood']*r['impact'],severity=level(r['likelihood']*r['impact']),likelihood=r['likelihood'],impact=r['impact']) for r in current])
    context=dict(organization=HOSPITAL,organization_type='Fictional 350-bed general hospital',
        departments=['Emergency','ICU','Inpatient Wards','Radiology','Laboratory','Pharmacy','Outpatient Clinics','Administration','Hospital IT'],
        scope='500 selected monitored technology assets across one main hospital campus and its fictional cloud tenancy; not a complete medical-device inventory',
        data_provenance='synthetic',patient_records_included=False,clinical_performance_claimed=False,
        logical_assets=500,current_risks=1860,risks_per_asset=dict(Counter(len(v) for v in by_asset_risks.values())),
        asset_type_counts=dict(Counter(a['asset_type'] for a in assets)),
        roles=[dict(role=role,count=n,asset_type=typ,department=dept,service=svc,owner=owner,control_groups=groups,clinical_criticality=crit) for role,n,typ,dept,svc,owner,groups,crit in ROLES],
        time_basis='UTC October to early November 2026; inventory changes 1 November, 48 incident-triggered fictional risk updates effective 6 November',
        mutation_boundary='Historical changes are generated simulation fixtures. Live risk and priority updates remain proposals requiring actual SOC/GRC approval.',
        severity_convention=dict(formula='likelihood * impact',bands={'Low':[1,4],'Medium':[5,9],'High':[10,16],'Critical':[17,25]},runtime_field=False),
        reference_catalogue_sha256=contract['catalogue_reference_sha256'])
    dump(out/'offline/hospital_context.json',context)
    summary=dict(seed=seed,logical_assets=500,asset_snapshots=len(flat_assets),current_risks=1860,risk_snapshots=len(flat_risks),
        alerts=len(events),sessions=len(labels),class_counts=dict(Counter(l['scenario_class'] for l in labels)),
        variant_counts=dict(Counter(s['variant_kind'] for s in scenarios)),historical_assets=72,incident_driven_risk_updates=48,
        paired_context_comparisons=len(timeline),shared_template_groups=len({l['template_group'] for l in labels}),
        generated_control_memberships=sum(len(r['existing_control_ids'])+len(r['planned_control_ids']) for r in flat_risks),
        risk_level_counts=dict(Counter(level(r['likelihood']*r['impact']) for r in current)))
    dump(out/'offline/generation_summary.json',summary)
    return summary


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output-dir',type=Path,default=Path(__file__).resolve().parents[1])
    ap.add_argument('--seed',type=int,default=SEED)
    args=ap.parse_args()
    print(json.dumps(generate(args.output_dir.resolve(),args.seed),indent=2))
