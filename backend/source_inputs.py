"""Read three operational inputs; adapt the supplied synthetic-v2 export only.

No training sidecar or generator script is opened. Scenario labels and risk/control
association targets are not predictor features. Canonical snapshots pass through unchanged. The synthetic-v2
mapping mirrors the offline feature mapping, retaining explicit candidate links
that the former training-only adapter discarded. Original files are immutable.
"""
from __future__ import annotations

import json
from pathlib import Path

VERSION = 'iris-runtime-source-adapter-v1'
INPUT_NAMES = {'asset_inventory': 'asset_inventory.json',
               'risk_register': 'risk_register.json', 'siem_alerts': 'siem_alerts.jsonl'}
MEASUREMENTS = {'bytes_sent', 'process_unsigned', 'privilege_change',
                'web_attack_signal', 'sensitive_data_access',
                'destination_untrusted', 'malicious_indicator'}


def read_alerts(path):
    """Accept an alerts export/array or JSON Lines without reading other files."""
    value = Path(path).read_text(encoding='utf-8-sig')
    try:
        payload = json.loads(value)
    except json.JSONDecodeError:
        # Preserve malformed lines for the existing integrator's quarantine.
        rows = []
        for line in value.splitlines():
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                rows.append(None)
        return rows
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        if isinstance(payload.get('alerts'), list):
            return payload['alerts']
        return [payload]
    raise ValueError('SIEM input must be an alerts object, array or JSON Lines')


def select_profile(paths):
    """Select a pinned feature contract from observed schema, not target labels.

    Expanded measurements select the 23-feature model even if incomplete: its
    existing completeness guard must report gaps rather than silently downgrade.
    SSH-only legacy telemetry uses the original SSH-trained model; synthetic-v2
    exports use the model fitted on their TCP/UDP mapping.
    """
    assets = json.loads(Path(paths['asset_inventory']).read_text(encoding='utf-8-sig'))
    if isinstance(assets, dict) and isinstance(assets.get('assets'), list):
        return 'iris_models_20261030'
    rows = read_alerts(paths['siem_alerts'])
    rows = [r.get('_source', r) for r in rows if isinstance(r, dict)]
    # bytes_sent alone is ordinary network telemetry, not the expanded contract.
    if any(isinstance(r, dict) and (MEASUREMENTS-{'bytes_sent'}).intersection(r) for r in rows):
        return 'iris_scenarios_20261109'
    protocols = {str(r.get('protocol', '')).upper() for r in rows if isinstance(r, dict)}
    return 'legacy' if 'SSH' in protocols else 'iris_models_20261030'


def _write(path, payload):
    path.write_text(json.dumps(payload, indent=2, allow_nan=False)+'\n', encoding='utf-8')


def normalize_inputs(paths, out):
    """Return canonical paths plus an explicit normalization/assumption report."""
    if set(paths) != set(INPUT_NAMES):
        raise ValueError('Exactly three operational inputs are required')
    assets = json.loads(Path(paths['asset_inventory']).read_text(encoding='utf-8-sig'))
    risks = json.loads(Path(paths['risk_register']).read_text(encoding='utf-8-sig'))
    if isinstance(assets, dict) and isinstance(assets.get('records'), list):
        if not isinstance(risks, dict) or not isinstance(risks.get('records'), list):
            raise ValueError('Do not mix canonical snapshots with synthetic-v2 exports')
        # A JSON alerts export is not JSON Lines merely because the API copied it
        # to a .jsonl filename. Re-encode containers, retaining each original row.
        try:
            export = json.loads(Path(paths['siem_alerts']).read_text(encoding='utf-8-sig'))
        except json.JSONDecodeError:
            export = None
        if isinstance(export, list) or isinstance(export, dict) and isinstance(export.get('alerts'), list):
            rows = export if isinstance(export, list) else export['alerts']
            if any(not isinstance(row, dict) for row in rows):
                raise ValueError('A canonical alerts export must contain event objects')
            out = Path(out)
            out.mkdir(parents=True, exist_ok=False)
            event_path = out/INPUT_NAMES['siem_alerts']
            with event_path.open('w', encoding='utf-8') as stream:
                for row in rows:
                    stream.write(json.dumps(row, allow_nan=False)+'\n')
            return {**paths, 'siem_alerts':event_path}, {
                'adapter':VERSION, 'format':'canonical_json_alert_export',
                'assumptions':[], 'training_labels_read':False}
        return paths, {'adapter': VERSION, 'format': 'canonical', 'assumptions': [],
                       'training_labels_read': False}
    if not (isinstance(assets, dict) and isinstance(assets.get('assets'), list)
            and isinstance(risks, dict) and isinstance(risks.get('risks'), list)):
        raise ValueError('Unsupported asset/risk schema: expected records or synthetic-v2 exports')
    if any(p.get('metadata', {}).get('synthetic') is not True for p in (assets, risks)):
        raise ValueError('Synthetic-v2 assumptions cannot be applied to real or undeclared data')
    # Never label an explicitly real/undeclared alerts export as synthetic merely
    # because a different inventory file was generated. Use the supplied JSON
    # export, or JSONL whose individual events declare synthetic provenance.
    try:
        alert_export = json.loads(Path(paths['siem_alerts']).read_text(encoding='utf-8-sig'))
    except json.JSONDecodeError:
        alert_export = None
    alert_rows = read_alerts(paths['siem_alerts'])
    declared = (isinstance(alert_export, dict)
                and alert_export.get('metadata', {}).get('synthetic') is True)
    if not declared and not all(isinstance(r,dict) and r.get('data_provenance')=='synthetic' for r in alert_rows):
        raise ValueError('Synthetic-v2 alerts must declare synthetic provenance; use the supplied siem_alerts.json export')
    if len(assets['assets']) > 5000 or len(alert_rows) > 50000:
        raise ValueError('Synthetic-v2 asset/alert limits exceeded')
    out = Path(out)
    out.mkdir(parents=True, exist_ok=False)
    converted = {key: out/name for key, name in INPUT_NAMES.items()}
    criticality = {'Low': 1, 'Medium': 3, 'High': 4, 'Critical': 5}
    asset_records, risk_records = [], []
    for a in assets['assets']:
        row = dict(asset_id=a['asset_id'], asset_version_id=a['asset_id']+'-V1',
                   hostname=a['hostname'], ip_addresses=[a['ip_address']],
                   asset_type=a['asset_type'], criticality=criticality[a['criticality']],
                   zone=a['network_zone'], owner=a['owner'], valid_from=a['valid_from'],
                   valid_to=a['valid_to'], recorded_at=a['valid_from'])
        if 'control_groups' in a:
            row['control_groups'] = a['control_groups']
        asset_records.append(row)
    for r in risks['risks']:
        history = sorted(r['history'], key=lambda h: h['valid_from'])
        if not history or len({h['valid_from'] for h in history}) != len(history):
            raise ValueError('Missing or ambiguous risk history: '+r['risk_id'])
        for i, h in enumerate(history):
            if len(risk_records) >= 5000:
                raise ValueError('Synthetic-v2 risk history exceeds 5000 snapshots')
            row = dict(risk_id=r['risk_id'], risk_version_id=r['risk_id']+'-V'+str(i+1),
                       asset_id=r['asset_id'], risk_category=r['category'],
                       likelihood=h['likelihood'], impact=h['impact'],
                       valid_from=h['valid_from'], recorded_at=h['valid_from'],
                       valid_to=history[i+1]['valid_from'] if i+1 < len(history) else None,
                       control_states={}, active_exception_control_ids=[])
            for key in ('existing_control_ids', 'planned_control_ids', 'mitre_attack_techniques'):
                if key in r:
                    row[key] = r[key]
            risk_records.append(row)
    _write(converted['asset_inventory'], {'schema_version': 'iris-asset-inventory-v1',
           'data_provenance': 'synthetic', 'records': asset_records})
    _write(converted['risk_register'], {'schema_version': 'iris-risk-register-v1',
           'data_provenance': 'synthetic', 'control_membership_basis': 'explicit_synthetic_static_membership',
           'records': risk_records})
    # The supplied v2 generator explicitly defines redeliveries with new IDs.
    # Preserve the offline cohort rule: full record equality except delivery ID.
    seen, events, duplicates = set(), [], 0
    for a in alert_rows:
        if not isinstance(a, dict):
            raise ValueError('Malformed synthetic-v2 alert; no observation was fabricated')
        identity = json.dumps({k:v for k,v in a.items() if k != 'alert_id'}, sort_keys=True)
        if identity in seen:
            duplicates += 1
            continue
        seen.add(identity)
        category = a['category']
        family = ('authentication' if category in {'authentication_failed', 'authentication_success', 'brute_force', 'kerberos'}
                  else 'network' if category in {'network_scan', 'web_scan', 'network_anomaly', 'enumeration'} else 'system')
        level = {1:10, 2:7, 3:4}[a['source_severity']] if a['source']=='suricata' else a['source_severity']
        row = dict(event_id=a['alert_id'], timestamp=a['timestamp'],
                   asset_id=a['associations'].get('asset_id'), destination_ip=a['dst_ip'],
                   source_ip=a['src_ip'], agent_name=a['hostname'], account=a.get('user'),
                   event_family=family, protocol=a['protocol'], rule_id=a['rule_id'], rule_level=level,
                   outcome='success' if category=='authentication_success' else 'failed'
                   if category in {'authentication_failed', 'brute_force'} else 'unknown',
                   run_id=a['session_id'], campaign_id='unassigned-runtime-group',
                   sensor_healthy=True, data_provenance='synthetic')
        if 'mitre_technique' in a:
            row['mitre_technique'] = a['mitre_technique']
        events.append(row)
    with converted['siem_alerts'].open('w', encoding='utf-8') as stream:
        for row in events:
            stream.write(json.dumps(row, allow_nan=False)+'\n')
    return converted, {'adapter': VERSION, 'format': 'supplied_synthetic_v2',
        'raw_alert_rows': len(alert_rows), 'redelivery_duplicates_removed': duplicates,
        'retained_alert_rows': len(events), 'asset_snapshots': len(asset_records),
        'risk_snapshots': len(risk_records), 'training_labels_read': False,
        'assumptions': ['Synthetic sensor health follows the existing offline adapter.',
            'Synthetic recorded_at equals validity start; knowledge timestamps were not supplied.',
            'Control membership is explicitly static for synthetic replay; control history was not supplied.',
            'Control implementation state remains unknown; no effectiveness was assumed.']}
