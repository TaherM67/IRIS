"""Explain every runtime model outcome without treating coverage as accuracy."""
from collections import Counter


def session_outcome(session, prediction, metadata):
    """Return auditable reasons, including exact out-of-vocabulary field values."""
    candidate = prediction.get('shadow_candidate')
    m1 = {'status': candidate['status'] if candidate else 'NOT_RUN', 'reasons': []}
    if candidate:
        m1['predicted_class'] = candidate.get('scenario_class')
        if candidate['status'] == 'ABSTAINED':
            m1['reasons'].append('below_frozen_confidence_threshold')
    else:
        if session.get('sensor_healthy') is not True:
            m1['reasons'].append('sensor_health_unavailable_or_unhealthy')
        if session.get('data_provenance') != 'synthetic':
            m1['reasons'].append('unreleased_model_requires_synthetic_provenance')
        if session.get('aggregation_schema') != metadata['aggregation_schema']:
            m1['reasons'].append('session_contract_mismatch')
        vocab = metadata.get('model1', {}).get('categorical_vocab', {})
        unsupported = {k: session['features'].get(k) for k, values in vocab.items()
                       if session['features'].get(k) not in values}
        if unsupported:
            m1['reasons'].append('unseen_category')
            m1['unsupported_categories'] = unsupported
        if 'scenario_evidence_complete' in session and session['scenario_evidence_complete'] is not True:
            m1['reasons'].append('expanded_measurements_incomplete')
        if session.get('scenario_evidence_error'):
            m1['reasons'].append('invalid_expanded_measurements')
        if not m1['reasons']:
            m1['reasons'].append('no_candidate_returned')
    review = prediction.get('model2_review')
    if review is None:
        m2 = {'status': 'LEGACY_ADVISOR_OUTPUT', 'source': 'legacy_control_advisor'}
    else:
        missing = review.get('missing_fields', [])
        source = review.get('source')
        if source == 'experimental_grounded_candidate_model':
            status = 'ASSESSED'
        elif missing == ['alerts.mitre_technique']:
            status = 'NO_OBSERVED_TECHNIQUE'
        else:
            status = 'NOT_RUN'
        m2 = dict(status=status, source=source, missing_fields=missing,
                  recommendation_count=len(review.get('recommendations', [])))
        if review.get('reason'):
            m2['reason'] = review['reason']
    return {'session_id': session['session_id'], 'asset_id': session['asset_id'],
            'source_event_count': len(session['source_event_ids']), 'model1': m1, 'model2': m2}


def summarize(outcomes):
    """Count all sessions; no-technique cases remain visible, not called benign."""
    total = len(outcomes)
    m1 = Counter(r['model1']['status'] for r in outcomes)
    m2 = Counter(r['model2']['status'] for r in outcomes)
    return {'sessions_checked': total,
            'model1': {'status_counts': dict(m1),
                       'prediction_coverage': m1['ASSESSED']/total if total else 0,
                       'reasons': dict(Counter(reason for r in outcomes for reason in r['model1']['reasons']))},
            'model2': {'status_counts': dict(m2),
                       'prediction_coverage_all_sessions': (None if m2['LEGACY_ADVISOR_OUTPUT']
                                                            else m2['ASSESSED']/total if total else 0),
                       'missing_fields': dict(Counter(field for r in outcomes for field in r['model2'].get('missing_fields', [])))},
            'training_labels_read': False, 'accuracy_evaluated': False,
            'note': 'Coverage is not accuracy. No observed technique means no grounded recommendation, not proof of benign activity.'}
