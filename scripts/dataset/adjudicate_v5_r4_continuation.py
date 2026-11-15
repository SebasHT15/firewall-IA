#!/usr/bin/env python3
"""Apply the frozen D67 rules to the single corrected-pool continuation.

This consumes completed blind reviews; it never samples, reviews, repairs votes,
changes thresholds or authorizes training. Outputs are created only after every
input has been validated. No legacy human-review artifact is used.
"""
import argparse
from collections import Counter
import json
import math
from pathlib import Path

import collect_v5_postfilter_annotations as K
import v5_audit_evidence as AE
import v5_pools_common as C

LABELS = frozenset(('VERIFIABLE', 'PROBABLY_CORRECT', 'UNCERTAIN', 'INCORRECT'))
FAILURES = frozenset(K.PRE.FAILURE_MODES)


def rows(raw):
    return [json.loads(line) for line in raw.decode('utf-8').split('\n') if line.strip()]


def unique(items):
    out = {r['sample_id']: r for r in items}
    if len(out) != len(items):
        raise ValueError('duplicate sample IDs')
    return out


def adjudicate(a1, a2, r3):
    # Identical precedence to the original frozen r4 execution.
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


def validate_r3(inputs, outputs):
    if [r['sample_id'] for r in inputs] != [r.get('sample_id') for r in outputs]:
        raise ValueError('R3 response IDs/order/count mismatch')
    unique(outputs)
    for r in outputs:
        if r.get('status') == 'UNEVALUATED':
            if set(r) != {'sample_id', 'status', 'reason'} or not isinstance(r['reason'], str) or not r['reason'].strip():
                raise ValueError('invalid UNEVALUATED response')
            continue
        if set(r) != {'sample_id', 'label', 'failure_mode', 'better_category', 'rationale'} or r['label'] not in LABELS:
            raise ValueError('invalid R3 label response')
        if not isinstance(r['rationale'], str) or not r['rationale'].strip() or any(c in r['rationale'] for c in '\r\n'):
            raise ValueError('invalid R3 rationale')
        if r['label'] == 'INCORRECT':
            if r['failure_mode'] not in FAILURES:
                raise ValueError('INCORRECT requires failure mode')
        elif r['failure_mode'] is not None or r['better_category'] is not None:
            raise ValueError('failure metadata on non-INCORRECT')
        if r['better_category'] is not None and (not isinstance(r['better_category'], str) or not r['better_category'].strip()):
            raise ValueError('invalid better_category')


def summarize(trace, prereg):
    criteria = prereg['acceptance_criteria']
    z = prereg['wilson']['z']
    result = {}
    for cat in sorted({r['category'] for r in trace}):
        items = [r for r in trace if r['category'] == cat]
        n = len(items)
        counts = Counter(r['adjudicated_label'] or 'UNRESOLVED' for r in items)
        reviewed = sum(r['r3'] in LABELS for r in items)
        complete = reviewed == n and counts['UNRESOLVED'] == 0
        def bound(k):
            p = k / n
            return (p + z*z/(2*n) + z*math.sqrt(p*(1-p)/n + z*z/(4*n*n))) / (1+z*z/n)
        c1 = bound(counts['INCORRECT']) if complete else None
        c2 = bound(counts['UNCERTAIN']+counts['INCORRECT']) if complete else None
        status = ('INSUFFICIENT_EVIDENCE' if not complete else
                  'PASS_AI_AUDITED' if c1 <= criteria['C1']['limit'] and c2 <= criteria['C2']['limit'] else 'NOT_SUPPORTED')
        result[cat] = {'status': status, 'frame_n': n, 'adjudicated_counts': dict(counts),
                       'r3_required': n, 'r3_reviewed': reviewed,
                       'wilson_incorrect_upper': c1, 'wilson_uncertain_incorrect_upper': c2,
                       'unresolved_ids': [r['sample_id'] for r in items if r['adjudicated_label'] is None]}
    return result


class Capture:
    def __init__(self):
        self.hashes = {}
        self.raw = {}

    def read(self, path, expected=None):
        path = Path(path).resolve()
        C.assert_not_protected(str(path))
        if path not in self.raw:
            self.raw[path] = path.read_bytes()
        data = self.raw[path]
        digest = AE.sha256(data)
        if expected is not None and digest != expected:
            raise ValueError(f'frozen integrity mismatch: {path.name}')
        name = str(path.relative_to(C.REPO_ROOT)) if path.is_relative_to(C.REPO_ROOT) else str(path)
        self.hashes[name] = digest
        return data

    def doc(self, path, expected=None):
        return json.loads(self.read(path, expected))


def annotation(capture, directory, who, frame, model):
    base = directory/f'annotation_{who}'
    manifest = capture.doc(base/'batches.json')
    packet = rows(capture.read(base/'packet.jsonl', manifest['packet_sha256']))
    if set(unique(packet)) != set(frame):
        raise ValueError('annotation packet coverage mismatch')
    for item in packet:
        if item != {key: frame[item['sample_id']][key] for key in item}:
            raise ValueError('annotation packet differs from frozen sample')
    accepted, agents, batch_ids = [], set(), []
    for b in manifest['batches']:
        raw = capture.read(base/b['file'], b['sha256'])
        chunk = rows(raw)
        ids = [r['sample_id'] for r in chunk]
        if ids != b['sample_ids'] or len(ids) != b['rows']:
            raise ValueError('annotation batch membership mismatch')
        batch_ids.extend(ids)
        if chunk != packet[len(batch_ids)-len(ids):len(batch_ids)]:
            raise ValueError('annotation batches differ from packet')
        records = [capture.doc(p) for p in sorted((base/'raw').glob(f"batch_{b['batch']:02d}.attempt_*.provenance.json"))]
        records = [r for r in records if r.get('status') == 'ACCEPTED']
        if len(records) != 1:
            raise ValueError('need exactly one accepted attempt per annotation batch')
        rec = records[0]
        if (rec.get('models_served') != [model] or not rec.get('turns')
                or any(t.get('model') != model for t in rec['turns'])
                or rec.get('batch_sha256') != b['sha256']
                or rec.get('batch') != b['batch'] or rec.get('annotator') != who
                or not AE.valid_hash(rec.get('transcript_sha256'))):
            raise ValueError('annotation provenance/model mismatch')
        agent = rec.get('agent_id')
        if not isinstance(agent, str) or not agent.strip() or agent in agents:
            raise ValueError('annotation session identity missing or reused')
        agents.add(agent)
        allowed = {str((base/b['file']).resolve()), str((base/'README.md').resolve())}
        for call in rec.get('tool_calls', []):
            if call.get('tool') != K.HANDBACK and (call.get('tool') != 'Read' or str(Path(call.get('file_path') or '').resolve()) not in allowed):
                raise ValueError('forbidden annotation tool call in provenance')
        raw_path = base/'raw'/f"batch_{b['batch']:02d}.attempt_{rec['attempt']}.handback.txt"
        handback = capture.read(raw_path, rec['handback_sha256']).decode('utf-8')
        parsed = K.parse_handback(handback, ids)
        accepted.extend({**{field: r.get(field) for field in K.FIELDS}, 'batch': b['batch'], 'attempt': rec['attempt']} for r in parsed)
    if batch_ids != [r['sample_id'] for r in packet]:
        raise ValueError('annotation batch coverage mismatch')
    official = rows(capture.read(directory/f'annotations_{who}.jsonl'))
    if sorted(accepted, key=lambda r:r['sample_id']) != official:
        raise ValueError('official annotations differ from collected raw responses')
    return unique(official), agents


def run(directory, r3_directory):
    directory, r3_directory = Path(directory).resolve(), Path(r3_directory).resolve()
    capture = Capture()
    state = capture.doc(directory/'audit_state.json')
    if state.get('review_method') != 'D67_R4_AI_ONLY_CONTINUATION' or state.get('round') != 2:
        raise ValueError('not the single r4 correction continuation')
    AE.verify(state['prior_r4_evidence'])
    sample_raw = capture.read(directory/'sample.jsonl', state['sample']['sha256'])
    sample = rows(sample_raw);frame = unique(sample)
    selected = state['r3_preselected_sample']
    if (selected['sha256'] != state['sample']['sha256'] or selected['rows'] != len(frame)
            or set(state['categories_audited']) != {r['category'] for r in sample}):
        raise ValueError('preselected R3 frame mismatch')
    prereg_path = Path(C.REPO_ROOT)/state['r4_preregistration']['path']
    prereg = capture.doc(prereg_path, state['r4_preregistration']['sha256'])
    if prereg.get('schema') != 'v5-postfilter-preregistration/r4' or prereg.get('status') != 'FROZEN':
        raise ValueError('frozen r4 criteria missing')
    for cat in state['categories_audited']:
        n = sum(r['category'] == cat for r in sample)
        if n != state['per_category'][cat]['sample']:
            raise ValueError('category denominator differs from sampling state')
    meta = capture.doc(directory/'annotators.json')
    models = [(meta.get(who) or {}).get('model') for who in ('a1','a2')]
    if any(not isinstance(m,str) or not m.strip() for m in models) or models[0].strip().lower() == models[1].strip().lower():
        raise ValueError('two different actual annotator models required')
    a1, agents1 = annotation(capture,directory,'a1',frame,models[0])
    a2, agents2 = annotation(capture,directory,'a2',frame,models[1])
    if agents1 & agents2:
        raise ValueError('review session reused between annotators')
    # Check the sealed R3 inputs and verbatim responses, not only an aggregate.
    pins = {}
    for line in capture.read(r3_directory/'SHA256SUMS').decode().split('\n'):
        if not line.strip(): continue
        digest, name = line.split(maxsplit=1)
        path = (r3_directory/name).resolve()
        if not path.is_relative_to(r3_directory) or name in pins:
            raise ValueError('unsafe/duplicate R3 seal entry')
        capture.read(path,digest);pins[name]=digest
    execution = capture.doc(r3_directory/'execution-record.json',pins['execution-record.json'])
    if (execution['sample_sha256'] != state['sample']['sha256'] or execution['fork_turns'] != 'none'
            or execution['requested_model'] != 'gpt-6-sol'):
        raise ValueError('R3 execution differs from owner-approved substitution or sample')
    r3 = {}
    for b in execution['batches']:
        i = b['batch']
        inputs = rows(capture.read(r3_directory/f'reviewer/batch_{i:02d}.jsonl', b['packet_sha256']))
        outputs = rows(capture.read(r3_directory/f'raw/batch_{i:02d}.jsonl', b['response_sha256']))
        validate_r3(inputs, outputs)
        for item in inputs:
            if item != {key: frame[item['sample_id']][key] for key in item}:
                raise ValueError('R3 input differs from sample')
        if set(r3) & set(unique(outputs)): raise ValueError('duplicate R3 batch member')
        r3.update(unique(outputs))
    if set(r3) != set(frame): raise ValueError('incomplete R3 coverage')
    aggregate = rows(capture.read(r3_directory/'responses.jsonl',execution['aggregate_sha256']))
    if aggregate != [r3[r['sample_id']] for r in sample]:
        raise ValueError('R3 aggregate differs from verbatim responses')
    trace = []
    for item in sample:
        sid = item['sample_id']
        l1,l2,l3 = a1[sid]['label_class'],a2[sid]['label_class'],r3[sid].get('label')
        label,basis = adjudicate(l1,l2,l3)
        trace.append({'sample_id':sid,'category':item['category'],'a1':l1,'a2':l2,'r3':l3,
                      'adjudicated_label':label,'basis':basis,'r3_required':True})
    report = {'schema':AE.REPORT_SCHEMA,'audit_type':'ai_audited','round':2,
              'frame_rows':len(frame),'r3_rows':len(r3),'category_outcomes':summarize(trace,prereg),
              'unresolved_count':sum(r['adjudicated_label'] is None for r in trace),
              'human_validation':False,'training_authorized':False,
              'source_sha256':capture.hashes,
              'limitations':['AI adjudication is not independent human truth.',
                             'Wilson bounds describe this adjudicated sample, not ground-truth error.',
                             'No previous category outcomes are inherited by this corrected pool.',
                             'Collector provenance is checked against raw handbacks; transcript hashes are retained.',
                             'No outcome authorizes training or assigns VERIFIED.']}
    return report,trace


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--round-dir',required=True)
    parser.add_argument('--r3-dir',required=True)
    parser.add_argument('--out',required=True)
    args=parser.parse_args()
    out=Path(args.out)
    C.assert_not_protected(str(out))
    if out.exists(): raise ValueError('output already exists; adjudication evidence is never overwritten')
    report,trace=run(args.round_dir,args.r3_dir)
    out.mkdir(parents=True)
    raw=(json.dumps(report,ensure_ascii=False,indent=2)+'\n').encode()
    (out/'report.json').write_bytes(raw)
    (out/'adjudication.jsonl').write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in trace))
    exchange={'schema':AE.EXCHANGE_SCHEMA,'audit_type':'ai_audited',
              'source_report_sha256':AE.sha256(raw),
              'category_outcomes':{k:('FAIL' if v['status']=='NOT_SUPPORTED' else v['status']) for k,v in report['category_outcomes'].items()},
              'training_authorized':False}
    (out/'category-outcomes-for-consumers.json').write_text(json.dumps(exchange,indent=2)+'\n')
    print(json.dumps({'frame_rows':report['frame_rows'],'unresolved_count':report['unresolved_count'],
                      'outcomes':exchange['category_outcomes']},indent=2))


if __name__=='__main__':main()
