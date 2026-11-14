#!/usr/bin/env python3
"""Build the hospital explanation, executed-results summary and hash manifest."""
import argparse
from collections import Counter
import hashlib
from html import escape
import importlib.util
import json
from pathlib import Path
import platform


def load(p):return json.loads(p.read_text(encoding='utf-8'))
def lines(p):return [json.loads(s) for s in p.read_text(encoding='utf-8').splitlines()]
def dump(p,x):p.write_text(json.dumps(x,indent=2,allow_nan=False)+'\n',encoding='utf-8')
def table(headers,rows):
    return '<table><thead><tr>'+''.join('<th>'+escape(str(v))+'</th>' for v in headers)+'</tr></thead><tbody>'+''.join('<tr>'+''.join('<td>'+escape(str(v))+'</td>' for v in row)+'</tr>' for row in rows)+'</tbody></table>'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--dataset-dir',type=Path,default=Path(__file__).resolve().parents[1])
    p.add_argument('--iris-root',type=Path,required=True)
    args=p.parse_args();root=args.dataset_dir.resolve();iris=args.iris_root.resolve()
    context=load(root/'offline/hospital_context.json');summary=load(root/'offline/generation_summary.json')
    qualification=load(root/'validation/qualification.json');independent=load(root/'validation/independent_validation.json')
    workflow=load(root/'validation/workflow_audit.json');coverage=load(root/'validation/inference/coverage.json')
    preparation=load(root/'validation/training_handoff/preparation.json')
    if not qualification['valid'] or independent['status']!='PASS':raise ValueError('Correct validation errors before packaging')
    roles=context['roles'];risks=lines(root/'offline/risk_contexts.jsonl')
    assets={a['asset_id']:a for a in load(root/'offline/asset_contexts.json')}
    examples=load(root/'offline/priority_change_walkthroughs.json')
    example=next(x for x in examples if assets[x['asset_id']]['role']=='ehr app' and len(x['observed_results'])==3)
    audits=lines(root/'offline/actual_iris_reviews.jsonl')
    audit_by_case={a['case_id']:a for a in audits}
    spec=importlib.util.spec_from_file_location('hospital_audit_helpers',root/'generator/run_iris_audit.py')
    helpers=importlib.util.module_from_spec(spec);spec.loader.exec_module(helpers)
    helpers.dump_lines(root/'offline/review_queue.jsonl',helpers.review_queue(audits))
    selected_audit=audit_by_case[example['observed_results'][1]['case_id']]
    controls=selected_audit['experimental_model2_recommendations']
    risk=next(r for r in risks if r['risk_id']==example['risk_id'])
    phases=[{'before':'Standby service before 1 November','after_inventory':'Live clinical service after 1 November','after_risk_review':'After the incident-triggered risk review on 6 November'}[r['phase']] for r in example['observed_results']]
    phase_rows=[(name,r['source_detector_severity'],r['asset_criticality'],r['risk_score'],r['primary_response_priority'],r['hospital_review_reference_priority']) for name,r in zip(phases,example['observed_results'])]
    types=Counter()
    for r in roles:types[r['asset_type']]+=r['count']
    dataset_notes=[
        'The user-selected hospital and 500 assets with three to four relevant risks replace the original generic 40-assets/six-risks generation example.',
        'The runtime schemas, allowed techniques/classes, fixed catalogue, source provenance, historical semantics, input limits and review boundaries are unchanged.',
        'Class frequencies follow the registered hospital risks; they are not balanced to the original 1,260-session example.',
        'Each of 1,860 risks has linked attack observations. There are 1,990 attack-scenario sessions plus 500 benign sessions, not 15,000 independent attack scenarios.',
        'Matched temporal examples reuse measured patterns and retain shared grouping identities; they do not count as independent experiments.',
        'The copied reference agreement is unchanged. This bundle documents the user scope overrides rather than editing the contract to make validation pass.'
    ]
    limitations=[
        'The qualifier is VALID_WITH_LIMITATIONS with zero errors. Its single warning concerns 593 sessions with no observed technique: 500 benign and 93 subtle/noisy attack sessions. No technique is invented for them.',
        'Model 1 assessed 2,091 sessions and explicitly abstained on 399 below its frozen threshold. These are coverage counts, not correctness or accuracy.',
        'There are 640 rule/model disagreements and 886 primary-policy UNMAPPED cases requiring review. They remain in the audit and queue; their priority is not guessed.',
        'Labels and control reference targets remain unreviewed. Official preparation found 14 connected independent groups and insufficient per-class support in some experimental roles. Both independent review and additional independent examples are required before fitting.',
        'No real patient data, real approvals, live hospital changes, fitting, threshold changes or performance claims are included.',
        'The current IRIS primary priority matrix combines detector severity with asset criticality. Registered likelihood and impact affect its risk review and the inspection queue tie-break; they do not directly raise its priority matrix output.',
        'A separate proposed hospital review floor demonstrates Medium-to-Critical escalation when care-critical assets have registered likelihood x impact >= 20 and corroborating rule evidence. It is clearly marked as a synthetic reference policy, is not installed in IRIS, and requires actual organizational policy approval before use.',
        'Forty-eight historical risk-register updates are simulation fixtures after synthetic SOC/GRC review. Actual label reviewers and real human approvals are not claimed. Control plans are not proof of implemented or effective safeguards.'
    ]
    readme=f'''IRIS HOSPITAL DATASET
{context['organization']}

PURPOSE AND ORGANIZATION

This is a fictional 350-bed general hospital with emergency, ICU, inpatient,
imaging, laboratory, pharmacy, outpatient and administrative services. The
dataset covers 500 selected monitored assets across the main hospital campus
and its fictional cloud tenancy. These are hospital technology assets, not
patient records and not a complete clinical device inventory.

500 assets; 1,860 logical current risks; 15,000 alerts; 2,490 prepared sessions.
Every asset has three or four relevant risks. Every risk has linked attack
observations. The 15,000 alert observations form 1,990 attack scenario sessions
and 500 routine hospital sessions. Of these, 398 attack sessions are subtle/noisy
and 100 routine sessions are benign lookalikes: exactly 20 percent per class.

Open HOSPITAL_CONTEXT_AND_RESULTS.html for the readable hospital role inventory,
risk examples, exact before/after example, control names and executed results.

RUNTIME INPUTS

Upload exactly these three files from data/:
  asset_inventory.json
  risk_register.json
  siem_alerts.jsonl

The file names, fields, enums and format follow the supplied unchanged schemas.
No scenario truth, desired priority, control recommendation target or result
is injected into these runtime inputs. Hostnames describe hospital functions;
IDs are opaque. Owners and addresses are fictional. Supported telemetry remains
authentication/network/process/privilege/web with the exact supported protocol
values. Clinical protocols are not silently relabeled as supported telemetry.

HOSPITAL ASSET TYPES

{chr(10).join(f'  {typ}: {count}' for typ,count in types.items())}

Asset-specific roles, departments, services, data scope and clinical dependence
are in offline/asset_contexts.json. The 41 role groups include EHR applications,
PACS image services, LIS laboratory systems, pharmacy systems, identity/SSO,
patient portals, clinical workstations, segmentation firewalls, backup vaults,
and bedside-monitor and infusion-integration gateways.

RELATED RISKS

Six supported categories are used selectively: Unauthorized Access,
Reconnaissance, Malware Execution, Privilege Escalation, Web Application
Compromise and Data Exfiltration. Workstations have four; databases, network
devices and monitored medical/IoT gateways have three; other selected roles
have four. Web exploitation is registered for assets with an actual application
surface. No blanket assignment of all six risks or all control groups is used.

offline/risk_contexts.jsonl explains the individual risk and hospital consequence
for all 1,860 risks. Existing/planned memberships and implementation states are
explicit in the runtime register, drawn only from the fixed catalogue and
matched to registered technique plus asset applicability. Some records have
only planned controls; a nonexistent installed control is not fabricated.

Risk-level inspection bands use likelihood x impact: Low 1-4, Medium 5-9,
High 10-16, Critical 17-25. These bands are documented inspection conventions,
not extra runtime fields or learned priorities.

WHAT CHANGES OVER TIME

72 assets move from validated standby into live clinical service on 1 Nov 2026.
Their inventory criticality and associated registered risk context have
non-overlapping before/after versions, all known by their effective timestamps.
The same observed pattern is replayed on both sides using separate source runs.
All 72 comparisons produce higher actual IRIS response priority.

For 48 of these risks, earlier November alerts trigger a fictional SOC/GRC risk
review recorded on 5 Nov, effective 6 Nov. It raises registered likelihood and
adds a planned control when an additional supported candidate exists. Follow-up
alerts on 8 Nov use that new historical risk version. Earlier alerts retain
their original context; later information is never used as an earlier feature.

For the EHR application cvh-ehr-app-001.hospital.test, the linked risk is:
  {risk['risk_statement']}
The detector remains Medium in all three measured replays:
  Before activation: criticality 3, registered risk 2 x 3 = 6 (Medium),
                     actual IRIS priority Medium.
  Live care service: criticality 5, registered risk 3 x 5 = 15 (High),
                     actual IRIS priority High.
  After risk review: criticality 5, registered risk 4 x 5 = 20 (Critical),
                     actual IRIS priority remains High under its existing matrix;
                     proposed hospital review reference priority is Critical.

The hospital reference floor is separate from actual IRIS policy and is not
silently presented as an engine result. Reviewing or installing a different
priority policy is a separate decision. All register/priority writes proposed
by the actual run remain pending real SOC/GRC approval.

offline/change_journal.jsonl retains causes, event IDs, version IDs, before/after
values and effective/knowledge times. offline/priority_change_walkthroughs.json
contains 72 fully joined comparisons. offline/actual_iris_reviews.jsonl contains
the actual primary policy and Model 2 results for all 2,490 sessions.
offline/review_queue.jsonl retains the original detector severity. Unresolved
cases have an explicit mapping-review segment. Mapped cases are ordered by
proposed response priority, then registered risk score, then detector level.

EXECUTED QUALIFICATION AND INFERENCE

Official contract qualification: valid true, zero errors, one explained warning.
All 15,000 source events reach exactly one of 2,490 prepared sessions.
Independent checks with the four supplied JSON Schemas: PASS.
Fresh generator rerun: every generated data/context/annotation file byte-identical.
Model 1: 2,091 assessed; 399 explicit confidence abstentions.
Model 2: 1,897 sessions assessed; 5,919 recommendation entries; 593 sessions lack
observed technique context. Those 593 comprise 500 benign and 93 attack sessions.
All accepted cases were read. Model weights and thresholds were unchanged.
Coverage is not model accuracy, review certification or control effectiveness.

The official preparation report is NOT fit-ready: unreviewed labels, only 14
connected independent groups, and insufficient per-class support in some roles.
No train-three, fitting, calibration or activation command was run.

DIRECTORY GUIDE

data/                         exactly three operational sources
offline/training_labels.jsonl exact seven-class annotation schema, unreviewed
offline/scenario_details.jsonl hospital narratives and measured evidence summaries
offline/event_associations.jsonl every event linked to case, asset and risk version
offline/asset_contexts.json    hospital asset roles and services
offline/risk_contexts.jsonl   risk statements and hospital consequences
offline/risk_levels.json      current likelihood/impact products and inspection bands
offline/change_journal.jsonl  inventory and incident-triggered historical changes
offline/temporal_comparisons.json source comparison identities
offline/actual_iris_reviews.jsonl actual engine decisions and recommendations
offline/review_queue.jsonl    source severity and proposed response priority
offline/priority_change_walkthroughs.json actual and reference priority comparisons
offline/hospital_context.json complete organization scope and role counts
offline/generation_summary.json generator counts and variation
reference/agreement/          unchanged contract, schemas, catalogue and original prompt
validation/qualification.json official contract result and every prepared session
validation/training_handoff/  actual official preparation records and split diagnostics
validation/inference/         actual frozen-model coverage and per-session outcomes
validation/workflow_audit.json counts of actual review and priority results
validation/independent_validation.json schema, joins, chronology and reproducibility
validation/source_provenance.json supplied source/model identities and tool hashes
generator/                    runnable generator, verifier, audit and report builder
manifest.json                 checksums and scope overrides for the complete bundle

The original reference prompt requests 40 assets, six risks each and a balanced
1,260-session example. Your later hospital instruction overrides those example
counts and requires three to four relevant risks per asset and 15,000 alerts.
The machine-readable schemas and catalogue are unchanged. All scope differences
are recorded in manifest.json.

REPRODUCE

Python 3.12 and jsonschema are used for independent schema checks. The supplied
IRIS runtime requires its pinned ML requirements and trusted frozen weights.
From this bundle directory, where IRIS_ROOT is the updated agreement checkout:

  python3 generator/generate_hospital.py --output-dir . --seed 20261114
  python3 generator/verify_hospital.py --check-reproducibility
  python3 IRIS_ROOT/tools/validate_inputs.py --input-dir data --out NEW_qualification.json
  python3 IRIS_ROOT/tools/prepare_expanded_training.py --input-dir data --labels offline/training_labels.jsonl --out NEW_TRAINING_REVIEW_DIRECTORY
  python3 IRIS_ROOT/tools/check_input_coverage.py --assets data/asset_inventory.json --risks data/risk_register.json --alerts data/siem_alerts.jsonl --model-profile auto --out NEW_COVERAGE_DIRECTORY

For a new bundle with validation/qualification.json but no existing inference/
directory, capture the actual case audit via:
  python3 generator/run_iris_audit.py --iris-root IRIS_ROOT
It calls the official run_check function unchanged and only adds a read of every
persisted case before its temporary store is removed. Offline labels are joined
after inference and never passed to the engine. Existing outputs are preserved.

Original base source: 4289c59cbea80c41f635c8893fe738de40e24c7f plus the agreement
pack's exact iris_refinement.patch, applied locally. No remote source was changed.
The expected agreement branch is iris-input-agreement-20261114, commit
cdd036e53337fc813fd5a7a672a4e374a591055c, as stated in the supplied pack.
'''
    (root/'README.txt').write_text(readme,encoding='utf-8')
    risks_by_type={
        'Clinical workstation':'Unauthorized access; malicious execution; privilege escalation; data exfiltration',
        'EHR / PACS / LIS / pharmacy application':'Unauthorized access; web application compromise; malicious execution; data exfiltration',
        'Clinical database':'Unauthorized access; privilege escalation; data exfiltration',
        'Identity service':'Unauthorized access; reconnaissance; privilege escalation; data exfiltration',
        'Patient or clinical web application':'Unauthorized access; reconnaissance; web exploitation; data exfiltration',
        'Network device':'Unauthorized access; reconnaissance; privilege escalation',
        'Cloud resource':'Unauthorized access; reconnaissance; privilege escalation; data exfiltration',
        'Medical / IoT gateway':'Unauthorized access; reconnaissance; privilege escalation'}
    control_rows=[(c.get('control_id'),c.get('name'),c.get('current_state','unknown'),c.get('action_type','review')) for c in selected_audit['primary_control_review']['recommendations']]
    cards=''.join(f'<div><b>{n}</b><span>{escape(label)}</span></div>' for n,label in [('500','hospital assets'),('1,860','registered risks'),('15,000','alerts'),('72','priority comparisons')])
    html=f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Hospital data context and executed IRIS results</title><style>
body{{font-family:Arial,sans-serif;color:#172b3a;line-height:1.55;margin:0;background:#f3f6f8}}main{{max-width:1120px;margin:auto;padding:44px 30px;background:white}}h1{{font-size:34px;line-height:1.15;margin-bottom:16px}}h2{{margin-top:38px;font-size:23px}}p{{max-width:1000px}}.eyebrow{{color:#265f67;font-size:13px;font-weight:bold;letter-spacing:.09em}}.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:18px;margin:28px 0}}.stats b{{display:block;font-size:30px;color:#16565f}}.stats span{{font-size:14px}}table{{border-collapse:collapse;width:100%;font-size:14px;margin:18px 0 28px}}th,td{{padding:11px 12px;text-align:left;border:1px solid #d8e1e5;vertical-align:top}}th{{background:#eaf1f3}}tr:nth-child(even) td{{background:#f8fafb}}small{{color:#506473}}code{{font-size:13px}}li{{margin-bottom:8px}}@media(max-width:700px){{main{{padding:24px 16px}}.stats{{grid-template-columns:repeat(2,1fr)}}table{{font-size:12px}}th,td{{padding:7px}}}}@media print{{body{{background:white}}main{{padding:0}}h2{{break-after:avoid}}tr{{break-inside:avoid}}}}</style><main>
<div class="eyebrow">IRIS · SYNTHETIC HOSPITAL EXERCISE · 14 NOVEMBER 2026</div>
<h1>{escape(context['organization'])}</h1>
<p>A fictional 350-bed general hospital with emergency, ICU, inpatient, imaging, laboratory, pharmacy, outpatient and administrative services. The dataset covers 500 selected monitored technology assets on one main campus and in its fictional cloud tenancy. It contains no patient records.</p>
<div class="stats">{cards}</div>
<p><b>The relationship being tested:</b> a hospital asset supports a named service; three or four registered risks describe its exposure; multiple observed alerts support an attack scenario; a review can propose risk-register and control-plan changes; later alerts use the new historically valid context and can receive higher response priority.</p>
<h2>What the hospital owns</h2>
{table(['Asset type','Count'],types.items())}
<h2>Which risks belong to which assets</h2>
{table(['Hospital asset role','Related registered risks'],risks_by_type.items())}
<p>Each of the 1,860 individual risks has an asset-specific statement and hospital consequence in <code>offline/risk_contexts.jsonl</code>. All risks have linked attack observations. Controls are drawn from the fixed catalogue, matched to technique and asset applicability, and retain explicit known or unknown implementation states.</p>
<h2>A complete EHR escalation example</h2>
<p><b>Asset:</b> cvh-ehr-app-001.hospital.test. <b>Service:</b> electronic health record access. <b>Risk:</b> {escape(risk['risk_statement'])}. The same measured web-attack pattern is replayed in separate runs on either side of the context changes.</p>
{table(['Context','Detector severity','Asset criticality','Registered risk score','Actual IRIS priority','Proposed hospital review priority'],phase_rows)}
<p><b>Read the last two columns separately.</b> IRIS actually raises the response from Medium to High after the asset enters live care. The current IRIS matrix does not use registered likelihood × impact to turn that Medium detector alert into Critical. The final Critical value is an explicitly proposed hospital review floor, supplied for review and not installed in IRIS. All actual working-record writes remain proposals requiring real SOC/GRC approval.</p>
<p>The simulated risk review follows the triggering alerts and takes effect only for later observations. Its likelihood increase and additional control planning are traceable in <code>offline/change_journal.jsonl</code>. Earlier observations retain their original snapshots.</p>
<h2>Actual primary control advice for the EHR example</h2>
{table(['Catalogue ID','Control','Registered state','Action'],control_rows) if control_rows else '<p>No experimental recommendation passed for this example; inspect the actual audit rather than inventing one.</p>'}
<p>These are actual primary catalogue actions for the uniquely matched risk. The separate experimental Model 2 results are retained in the detailed audit and may require review because of sparse support. All actions remain advisory and require actual approval.</p>
<h2>Executed acceptance results</h2>
{table(['Check','Observed result'],[
('Official contract qualifier','PASS: zero errors; one explained missing-technique warning'),
('Input accounting','15,000 events → 2,490 prepared sessions; every event accounted for exactly once'),
('Technique and class vocabulary','Unchanged supplied schemas pass; exact seven supported class names'),
('Registered controls','6,811 versioned existing/planned control memberships; applicability and technique checks pass'),
('Independent verification',f"PASS: {independent['check_evaluations']:,} checks; generated source files reproduce byte-for-byte"),
('Frozen Model 1','2,091 assessed; 399 explicit confidence abstentions'),
('Grounded Model 2','1,897 sessions assessed; 5,919 recommendation entries'),
('No observed technique','593 sessions: 500 benign and 93 subtle/noisy attacks; recommendations withheld'),
('Historical comparisons','72 of 72 show higher actual IRIS priority with detector severity held constant'),
('Training readiness','False: unreviewed labels and insufficient independent class support; no fitting performed')])}
<h2>All hospital role groups</h2>
{table(['Role','Count','Department','Supported service','Owner'],[(r['role'],r['count'],r['department'],r['service'],r['owner']) for r in roles])}
<h2>Scope and assumptions</h2><ul>{''.join('<li>'+escape(s)+'</li>' for s in dataset_notes)}</ul>
<h2>Interpretation limits and pending review</h2><ul>{''.join('<li>'+escape(s)+'</li>' for s in limitations)}</ul>
<p><small>Seed 20261114. Runtime inputs are exactly the three files in data/. Offline truth, target controls, expected priorities and proposed review rules never enter the runtime feature inputs. Full provenance and checksums are in manifest.json.</small></p></main></html>'''
    (root/'HOSPITAL_CONTEXT_AND_RESULTS.html').write_text(html,encoding='utf-8')
    m1=iris/'artifacts/model_versions/iris_scenarios_20261109/model1_scenario.joblib'
    contract=load(root/'reference/agreement/contract.json')
    actual_hash=hashlib.sha256(m1.read_bytes()).hexdigest()
    assert actual_hash==contract['model1_sha256']
    tools=['tools/validate_inputs.py','tools/prepare_expanded_training.py','tools/check_input_coverage.py','backend/input_contract.py','backend/training_handoff.py','backend/policy.py']
    dump(root/'validation/source_provenance.json',dict(
        base_commit='4289c59cbea80c41f635c8893fe738de40e24c7f',
        supplied_patch_sha256=hashlib.sha256((root/'reference/agreement/implementation/iris_refinement.patch').read_bytes()).hexdigest(),
        expected_branch_from_pack='iris-input-agreement-20261114',
        expected_branch_commit_from_pack='cdd036e53337fc813fd5a7a672a4e374a591055c',
        model_profile=coverage['selected_profile'],pinned_model1_sha256=actual_hash,model1_hash_matches_contract=True,
        tool_sha256={name:hashlib.sha256((iris/name).read_bytes()).hexdigest() for name in tools},
        python_version=platform.python_version(),runtime_sources_changed_by_audit=False,
        model_weights_changed=False,thresholds_changed=False,real_approvals_changed=False))
    manifest=dict(title='IRIS hospital synthetic data and temporal risk review',version=2,seed=20261114,
        organization=context['organization'],data_provenance='synthetic',runtime_directory='data',
        runtime_files=['data/asset_inventory.json','data/risk_register.json','data/siem_alerts.jsonl'],
        schema_contract='iris-expanded-input-v1',schema_contract_version='1.0.0',
        supplied_schemas_modified=False,supplied_catalogue_modified=False,
        counts=summary,qualification=dict(valid=qualification['valid'],error_count=len(qualification['errors']),warnings=qualification['warnings']),
        actual_workflow=workflow,model_coverage=coverage['model_coverage'],
        fitting_readiness=preparation['model1_ready_for_reviewed_synthetic_fitting'],
        scope_overrides=dataset_notes,limitations=limitations,
        user_requested_scope={'organization':'hospital','at_least_assets':500,'risks_per_asset':[3,4],'alerts':15000},
        original_example_scope=contract['generation_request'],
        generated_on='2026-11-14',files=[])
    for f in sorted(root.rglob('*')):
        if not f.is_file() or f.name=='manifest.json' or '__pycache__' in f.parts:continue
        manifest['files'].append(dict(path=f.relative_to(root).as_posix(),bytes=f.stat().st_size,sha256=hashlib.sha256(f.read_bytes()).hexdigest()))
    dump(root/'manifest.json',manifest)
    print(json.dumps({'manifest_files':len(manifest['files']),'organization':context['organization'],'contract_errors':len(qualification['errors']),'html_report':'HOSPITAL_CONTEXT_AND_RESULTS.html'},indent=2))


if __name__=='__main__':main()
