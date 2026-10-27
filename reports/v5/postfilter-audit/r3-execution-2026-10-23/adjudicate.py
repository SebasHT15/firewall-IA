"""D67 adjudication; frozen criteria and original responses are read-only."""
from collections import Counter
import hashlib
import json
import math
from pathlib import Path

HERE = Path(__file__).resolve().parent
AUDIT = HERE.parent
LABELS = frozenset(('VERIFIABLE', 'PROBABLY_CORRECT', 'UNCERTAIN', 'INCORRECT'))
FAILURES = frozenset(('prose','tool_output','placeholder','markdown_residue','setup_command',
                     'reference_url','wrong_category','truncated','encoding_garbage','other'))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def rows(raw):
    return [json.loads(line) for line in raw.decode('utf-8').split('\n') if line.strip()]


def unique(items):
    result = {r['sample_id']: r for r in items}
    if len(result) != len(items):
        raise ValueError('duplicate sample IDs')
    return result


def adjudicate(a1, a2, r3):
    if a1 not in LABELS or a2 not in LABELS:
        return None, 'UNRESOLVED_MISSING_INITIAL_VOTE'
    if a1 == a2:
        return a1, 'a1_a2_agreement'
    if {a1, a2} == {'VERIFIABLE', 'PROBABLY_CORRECT'}:
        return 'PROBABLY_CORRECT', 'vp_split_to_probably_correct/v1'
    if r3 not in LABELS:
        return None, 'UNRESOLVED_MISSING_R3'
    if r3 in (a1, a2):
        return r3, 'three_valid_votes_majority'
    return None, 'UNRESOLVED_THREE_WAY'


def wilson_upper(k, n, z):
    p = k / n
    return (p + z*z/(2*n) + z*math.sqrt(p*(1-p)/n + z*z/(4*n*n))) / (1 + z*z/n)


def validate_responses(inputs, outputs):
    if [r['sample_id'] for r in inputs] != [r.get('sample_id') for r in outputs]:
        raise ValueError('R3 response IDs/order/count mismatch')
    unique(outputs)
    for r in outputs:
        if r.get('status') == 'UNEVALUATED':
            if set(r) != {'sample_id','status','reason'} or not isinstance(r['reason'], str) or not r['reason'].strip():
                raise ValueError('invalid UNEVALUATED response')
            continue
        if set(r) != {'sample_id','label','failure_mode','better_category','rationale'} or r['label'] not in LABELS:
            raise ValueError('invalid R3 label response')
        if not isinstance(r['rationale'], str) or not r['rationale'].strip() or '\n' in r['rationale'] or '\r' in r['rationale']:
            raise ValueError('invalid rationale')
        if r['label'] == 'INCORRECT':
            if r['failure_mode'] not in FAILURES:
                raise ValueError('INCORRECT requires failure mode')
        elif r['failure_mode'] is not None or r['better_category'] is not None:
            raise ValueError('failure metadata on non-INCORRECT')
        if r['better_category'] is not None and (not isinstance(r['better_category'], str) or not r['better_category'].strip()):
            raise ValueError('invalid better_category')


def checksums(path):
    return {line.split()[1].removeprefix('./'):line.split()[0] for line in path.read_text().splitlines() if line.strip()}


def run():
    hashes = {}
    def read(path, expected=None):
        raw = path.read_bytes()
        h = sha(raw)
        if expected is not None and h != expected:
            raise ValueError(f'frozen integrity mismatch: {path.name}')
        hashes[str(path.relative_to(AUDIT))] = h
        return raw
    prereg_path = AUDIT/'preregistration/v5-postfilter-prereg-r4.json'
    pin = checksums(AUDIT/'preregistration/SHA256SUMS')
    prereg = json.loads(read(prereg_path, pin[prereg_path.name]))
    if prereg['status'] != 'FROZEN' or prereg['schema'] != 'v5-postfilter-preregistration/r4':
        raise ValueError('unexpected preregistration')
    review = AUDIT/'r3-review'
    pins = checksums(review/'SHA256SUMS')
    integrity = json.loads(read(review/'coordinator/integrity.json', pins['coordinator/integrity.json']))
    membership = unique(json.loads(read(review/'coordinator/membership.json', pins['coordinator/membership.json']))['records'])
    originals = {}
    for name in ('sample.jsonl', 'annotations_a1.jsonl', 'annotations_a2.jsonl'):
        originals[name] = unique(rows(read(AUDIT/'round-1'/name, integrity['source_hashes'][name])))
    frame = originals['sample.jsonl']
    a1, a2 = originals['annotations_a1.jsonl'], originals['annotations_a2.jsonl']
    if set(a1) != set(frame) or set(a2) != set(frame):
        raise ValueError('initial review coverage mismatch')
    r3 = {}
    response_pins = checksums(HERE/'raw/SHA256SUMS')
    execution = json.loads(read(HERE/'execution-record.json'))
    if execution['requested_model'] != 'gpt-6-sol' or execution['fork_turns'] != 'none':
        raise ValueError('execution does not match owner-approved substitution')
    for i in range(1,6):
        name = f'reviewer/batch_{i:02}.jsonl'
        inputs = rows(read(review/name, pins[name]))
        outputs = rows(read(HERE/f'raw/batch_{i:02}.jsonl', response_pins[f'batch_{i:02}.jsonl']))
        validate_responses(inputs, outputs)
        if set(r3) & set(unique(outputs)):
            raise ValueError('cross-batch duplicate')
        r3.update(unique(outputs))
        for item in inputs:
            if item['category'] != frame[item['sample_id']]['category']:
                raise ValueError('category mismatch')
    if set(r3) != set(membership) or len(r3) != prereg['review_populations']['unique_r3_review_records']:
        raise ValueError('R3 population mismatch')
    for sid, m in membership.items():
        if (m['a1_label'] != a1[sid]['label_class'] or m['a2_label'] != a2[sid]['label_class']
                or m['category'] != frame[sid]['category']):
            raise ValueError('coordinator reference mismatch')
    trace = []
    for sid, item in sorted(frame.items()):
        l1, l2, l3 = a1[sid]['label_class'], a2[sid]['label_class'], r3.get(sid, {}).get('label')
        label, basis = adjudicate(l1, l2, l3)
        trace.append({'sample_id': sid, 'category': item['category'], 'a1': l1, 'a2': l2, 'r3': l3,
                      'adjudicated_label': label, 'basis': basis, 'r3_required': sid in r3})
    criteria = prereg['acceptance_criteria']
    categories = {}
    for cat, n in prereg['denominators']['per_category_n_453_frame'].items():
        items = [r for r in trace if r['category'] == cat]
        if len(items) != n:
            raise ValueError('original frame denominator mismatch')
        counts = Counter(r['adjudicated_label'] or 'UNRESOLVED' for r in items)
        required = [r for r in items if r['r3_required']]
        reviewed = sum(r['r3'] in LABELS for r in required)
        complete = reviewed == len(required) and counts['UNRESOLVED'] == 0
        c1 = wilson_upper(counts['INCORRECT'], n, prereg['wilson']['z']) if complete else None
        c2 = wilson_upper(counts['UNCERTAIN']+counts['INCORRECT'], n, prereg['wilson']['z']) if complete else None
        status = ('INSUFFICIENT_EVIDENCE' if not complete else
                  'PASS_AI_AUDITED' if c1 <= criteria['C1']['limit'] and c2 <= criteria['C2']['limit'] else 'NOT_SUPPORTED')
        if cat == 'Server Side Request Forgery':
            status = 'NOT_SUPPORTED'
        categories[cat] = {'status': status, 'frame_n': n, 'adjudicated_counts': dict(counts),
            'r3_required': len(required), 'r3_reviewed': reviewed,
            'wilson_incorrect_upper': c1, 'wilson_uncertain_incorrect_upper': c2,
            'unresolved_ids': [r['sample_id'] for r in items if r['adjudicated_label'] is None]}
    reference_pairs = []
    for sid, response in r3.items():
        reference, _ = adjudicate(a1[sid]['label_class'], a2[sid]['label_class'], None)
        if reference is not None and response.get('label') in LABELS:
            reference_pairs.append((reference,response['label']))
    report = {'schema': 'v5-postfilter-r3-adjudication/v1', 'audit_type': 'ai_audited',
        'frame_rows': len(frame), 'r3_rows': len(r3), 'category_outcomes': categories,
        'unresolved_count': sum(r['adjudicated_label'] is None for r in trace),
        'training_authorized': False, 'human_validation': False,
        'r3_diagnostics_only': {'counts': dict(Counter(r.get('label','UNEVALUATED') for r in r3.values())),
            'agreement_with_a1a2_only_reference': {'numerator':sum(a==b for a,b in reference_pairs),'denominator':len(reference_pairs)}},
        'source_sha256': hashes,
        'limitations': ['AI audit only; no independent human truth.',
                       'Unresolved cases need evidence-based owner disposition.',
                       'No category result authorizes FINAL training or grants VERIFIED.',
                       'Selected service model gpt-6-sol; backend revision not exposed.']}
    return report, trace


if __name__ == '__main__':
    report, trace = run()
    (HERE/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    (HERE/'adjudication.jsonl').write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in trace))
    consumer = {'schema': 'v5-r3-category-outcomes-exchange/v1', 'audit_type': 'ai_audited',
                'source_report_sha256': sha((HERE/'report.json').read_bytes()),
                'category_outcomes': {k: ('FAIL' if v['status'] == 'NOT_SUPPORTED' else v['status'])
                                      for k,v in report['category_outcomes'].items()},
                'original_statuses': {k: v['status'] for k,v in report['category_outcomes'].items()},
                'mapping_note': 'NOT_SUPPORTED serializes as FAIL for #80; no eligibility is added.',
                'training_authorized': False}
    (HERE/'category-outcomes-for-consumers.json').write_text(json.dumps(consumer,indent=2)+'\n')
    print(json.dumps({'unresolved_count':report['unresolved_count'], 'categories':report['category_outcomes']},indent=2))
