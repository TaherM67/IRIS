"""Observed-only contract for the expanded synthetic scenario model.

The original 16-feature contract and pinned three-class artifacts remain intact.
Labels, risk scores, asset identity and campaign identifiers are not features.
"""
from __future__ import annotations

import json
import math

VERSION = 'iris-scenario-evidence-v2'
CLASSES = ('benign', 'credential_access', 'reconnaissance', 'malicious_execution',
           'privilege_escalation', 'web_exploitation', 'data_exfiltration')
NAMES = {
    'benign': 'Routine activity', 'credential_access': 'Credential attack',
    'reconnaissance': 'Network reconnaissance', 'malicious_execution': 'Malicious execution',
    'privilege_escalation': 'Privilege escalation', 'web_exploitation': 'Web exploitation',
    'data_exfiltration': 'Data exfiltration', 'needs_review': 'Needs analyst review',
}
RISK_CATEGORIES = {
    'credential_access': {'Unauthorized Access'}, 'reconnaissance': {'Reconnaissance'},
    'malicious_execution': {'Malware Execution'}, 'privilege_escalation': {'Privilege Escalation'},
    'web_exploitation': {'Web Application Compromise'}, 'data_exfiltration': {'Data Exfiltration'},
}
OBSERVED_FLAGS = {
    'process_unsigned': 'unsigned_process_count', 'privilege_change': 'privilege_change_count',
    'web_attack_signal': 'web_attack_count', 'sensitive_data_access': 'sensitive_access_count',
    'destination_untrusted': 'untrusted_destination_count', 'malicious_indicator': 'known_indicator_count',
}
EXTRA_FEATURES = ['bytes_sent_total', *OBSERVED_FLAGS.values()]


def evidence_from_alerts(alerts):
    """Aggregate explicit sensor measurements, never scenario/association fields."""
    result = dict.fromkeys(EXTRA_FEATURES, 0)
    for alert in alerts:
        value = alert.get('bytes_sent', 0)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= 1e12:
            raise ValueError('bytes_sent must be an explicit finite nonnegative measurement')
        result['bytes_sent_total'] += value
        for field, feature in OBSERVED_FLAGS.items():
            value = alert.get(field, False)
            if type(value) is not bool:
                raise ValueError(field + ' must be a boolean sensor observation')
            result[feature] += int(value)
    return result


def attach_evidence(sessions, paths):
    observed, conflicting = {}, set()
    fields = ('bytes_sent', *OBSERVED_FLAGS)
    with paths['siem_alerts'].open(encoding='utf-8') as stream:
        for line in stream:
            try:
                raw = json.loads(line)
                row = raw.get('_source', raw)
                eid = next((row[k] for k in ('event_id', 'id', '_id') if k in row), raw.get('_id'))
                if eid is None:
                    continue
                eid = str(eid).strip()
                selected = {k: row[k] for k in fields if k in row}
                if eid in observed and observed[eid] != selected:
                    conflicting.add(eid)
                observed[eid] = selected
            except (ValueError, TypeError, AttributeError):
                continue
    result = []
    for session in sessions:
        session = dict(session)
        try:
            ids = session['source_event_ids']
            if any(eid not in observed or eid in conflicting for eid in ids):
                raise ValueError('Ambiguous or absent observed session evidence')
            session['scenario_evidence'] = evidence_from_alerts([observed[eid] for eid in ids])
            session['scenario_evidence_schema'] = VERSION
            session['scenario_evidence_complete'] = all(all(k in observed[eid] for k in fields) for eid in ids)
        except ValueError as exc:
            session['scenario_evidence_error'] = str(exc)
        result.append(session)
    return result


def feature_row(session, base_features):
    from iris_models.contracts import validate_features
    base = validate_features(session['features'])
    if session.get('scenario_evidence_schema') != VERSION:
        raise ValueError('Expanded model requires the observed-evidence v2 contract')
    extra = session.get('scenario_evidence')
    if not isinstance(extra, dict) or set(extra) != set(EXTRA_FEATURES):
        raise ValueError('Expanded evidence feature allowlist mismatch')
    for key, value in extra.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            raise ValueError('Invalid expanded evidence measurement: ' + key)
        if key != 'bytes_sent_total' and (int(value) != value or value > base['event_count']):
            raise ValueError('Expanded event count exceeds session membership')
    return {**{k: base[k] for k in base_features}, **extra}


def rule_scenario(session):
    """Separate transparent evidence rules from the trained shadow classifier."""
    from iris_models.contracts import FEATURES, rule_label
    if session.get('sensor_healthy') is not True or session.get('scenario_evidence_error'):
        return None
    row = feature_row(session, FEATURES)
    level = row['max_rule_level']
    if row['event_family'] == 'process' and row['unsigned_process_count'] >= 2 and row['known_indicator_count'] >= 1 and level >= 8:
        return 'malicious_execution'
    if row['event_family'] == 'privilege' and row['privilege_change_count'] >= 1 and row['known_indicator_count'] >= 1 and level >= 8:
        return 'privilege_escalation'
    if row['event_family'] == 'web' and row['web_attack_count'] >= 2 and level >= 8:
        return 'web_exploitation'
    if row['event_family'] == 'network' and row['bytes_sent_total'] >= 5_000_000 and row['sensitive_access_count'] >= 1 and row['untrusted_destination_count'] >= 1 and level >= 8:
        return 'data_exfiltration'
    return rule_label(session['features'])
