"""Explain every runtime model outcome without treating coverage as accuracy."""
from collections import Counter
import math


def probability_diagnostics(candidate):
    """Report ambiguity without changing the frozen prediction or its threshold."""
    values = candidate.get('class_probabilities')
    if not isinstance(values, dict) or len(values) < 2:
        return None
    if any(type(p) not in (int, float) or not 0 <= p <= 1 or not math.isfinite(p)
           for p in values.values()) or not math.isclose(sum(values.values()), 1.0, abs_tol=1e-6):
        return {'valid': False, 'reason': 'invalid_probability_vector'}
    ranked = sorted(values.items(), key=lambda item: (-item[1], item[0]))
    entropy = -sum(p * math.log(p) for p in values.values() if p > 0) / math.log(len(values))
    return {'valid': True, 'class_probabilities': dict(values),
            'top_candidate': ranked[0][0], 'second_candidate': ranked[1][0],
            'top_two_probability_margin': ranked[0][1] - ranked[1][1],
            'normalized_entropy': entropy,
            'meaning': 'Predictive ambiguity only; not correctness, control effectiveness or risk reduction.'}


def session_outcome(session, prediction, metadata):
    """Return auditable reasons, including exact out-of-vocabulary field values."""
    candidate = prediction.get('shadow_candidate')
    m1 = {'status': candidate['status'] if candidate else 'NOT_RUN', 'reasons': []}
    if candidate:
        m1['predicted_class'] = candidate.get('scenario_class')
        m1['confidence'] = candidate.get('confidence')
        m1['threshold'] = candidate.get('threshold')
        m1['uncertainty'] = probability_diagnostics(candidate)
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
                  recommendation_count=len(review.get('recommendations', [])),
                  withheld_candidate_count=review.get('withheld_candidate_count', 0),
                  withheld_reason_counts=dict(Counter(reason for item in review.get('withheld_candidates', [])
                                                       for reason in item.get('reason_codes', []))))
        if review.get('reason'):
            m2['reason'] = review['reason']
    primary = prediction.get('soc_assessment', {})
    primary_label = primary.get('scenario_class') if primary.get('status') == 'ASSESSED' else None
    shadow_label = candidate.get('scenario_class') if candidate and candidate.get('status') == 'ASSESSED' else None
    return {'session_id': session['session_id'], 'asset_id': session['asset_id'],
            'source_event_count': len(session['source_event_ids']),
            'source_event_ids': list(session['source_event_ids']),
            'model1': m1, 'model2': m2,
            'primary_rule_assessment': {'scenario_class': primary_label,
                                        'status': primary.get('status'), 'method': primary.get('method')},
            'rule_model_disagreement': (primary_label != shadow_label
                                        if primary_label is not None and shadow_label is not None else None),
            'evidence_features': dict(session['features']),
            'warnings': list(prediction.get('warnings', []))}


def summarize(outcomes):
    """Count all sessions; no-technique cases remain visible, not called benign."""
    total = len(outcomes)
    m1 = Counter(r['model1']['status'] for r in outcomes)
    m2 = Counter(r['model2']['status'] for r in outcomes)
    return {'sessions_checked': total,
            'rule_model_disagreement_sessions': sum(r.get('rule_model_disagreement') is True for r in outcomes),
            'probability_diagnostics_available': sum(
                bool(r['model1'].get('uncertainty', {}).get('valid'))
                for r in outcomes if r['model1'].get('uncertainty') is not None),
            'model1': {'status_counts': dict(m1),
                       'prediction_coverage': m1['ASSESSED']/total if total else 0,
                       'reasons': dict(Counter(reason for r in outcomes for reason in r['model1']['reasons']))},
            'model2': {'status_counts': dict(m2),
                       'withheld_candidate_count': sum(r['model2'].get('withheld_candidate_count', 0) for r in outcomes),
                       'prediction_coverage_all_sessions': (None if m2['LEGACY_ADVISOR_OUTPUT']
                                                            else m2['ASSESSED']/total if total else 0),
                       'missing_fields': dict(Counter(field for r in outcomes for field in r['model2'].get('missing_fields', [])))},
            'training_labels_read': False, 'accuracy_evaluated': False,
            'note': 'Coverage is not accuracy. No observed technique means no grounded recommendation, not proof of benign activity.'}
