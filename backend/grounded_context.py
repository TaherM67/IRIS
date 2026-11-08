"""Allowlisted Model 2 context from the same immutable three runtime inputs.

The existing point-in-time integrator owns asset/risk selection and session
membership. This adapter only retains additional, explicitly supplied fields.
It never reads labels, scenario annotations, or associations.control_ids.
"""
from __future__ import annotations

import json

SCHEMA = 'iris-grounded-runtime-context-v1'


class GroundedContext:
    def __init__(self, paths):
        self.assets = {r['asset_version_id']: r for r in json.loads(
            paths['asset_inventory'].read_text(encoding='utf-8'))['records']}
        self.risks = {r['risk_version_id']: r for r in json.loads(
            paths['risk_register'].read_text(encoding='utf-8'))['records']}
        self.alerts, self.conflicts = {}, set()
        with paths['siem_alerts'].open(encoding='utf-8') as stream:
            for line in stream:
                try:
                    raw = json.loads(line)
                    row = raw.get('_source', raw)
                    eid = next((row[k] for k in ('event_id', 'id', '_id') if k in row), raw.get('_id'))
                    if eid is None:
                        continue
                    eid = str(eid).strip()
                    value = {'alert_id': eid, 'mitre_technique': row.get('mitre_technique')}
                    if eid in self.alerts and self.alerts[eid] != value:
                        self.conflicts.add(eid)
                    self.alerts[eid] = value
                except (ValueError, TypeError, AttributeError):
                    # The existing integrator already quarantines invalid rows.
                    continue

    def attach(self, session):
        missing = []
        snapshot = session.get('asset_snapshot') or {}
        raw_asset = self.assets.get(snapshot.get('asset_version_id'), {})
        asset = {'asset_id': snapshot.get('asset_id')}
        if 'control_groups' in raw_asset:
            asset['control_groups'] = raw_asset['control_groups']
        else:
            missing.append('asset.control_groups')
        alerts = []
        for eid in session['source_event_ids']:
            if eid not in self.alerts or eid in self.conflicts:
                missing.append('alerts[' + eid + '].unambiguous_observed_technique')
            else:
                alerts.append(self.alerts[eid])
        if not any(a.get('mitre_technique') for a in alerts):
            missing.append('alerts.mitre_technique')
        risks = []
        for snapshot in session.get('risk_snapshots', []):
            raw = self.risks.get(snapshot['risk_version_id'], {})
            risk = {key: snapshot[key] for key in ('asset_id', 'risk_id', 'risk_version_id', 'control_states')}
            for key in ('existing_control_ids', 'planned_control_ids', 'mitre_attack_techniques'):
                if key in raw:
                    risk[key] = raw[key]
                else:
                    missing.append('registered_risks.' + key)
            risks.append(risk)
        if not risks:
            missing.append('registered_risks')
        if not session.get('context'):
            missing.append('session.context')
        return {**session, 'model2_context': {
            'schema': SCHEMA, 'asset': asset, 'alerts': alerts, 'registered_risks': risks,
            'missing_fields': sorted(set(missing)),
            'membership_basis': 'versioned_runtime_risk_snapshots',
            'training_labels_read': False,
        }}
