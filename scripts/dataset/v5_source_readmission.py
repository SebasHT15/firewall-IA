#!/usr/bin/env python3
"""Prepare pinned source-change evidence, without sampling, judging or admitting rows."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

import v5_audit_evidence as AE
import v5_pools_common as C
import v5_source_remediation as M

SCHEMA = 'v5-source-readmission-preparation/v1-PROPOSED'
ARTIFACTS = {'candidate_pool.jsonl','candidate_excluded.jsonl','source_locations.jsonl',
             'quarantined_source_blocks.jsonl'}
IMMUTABLE = ('payload_wire','dedup_scope','category_v4','source_file','payload_raw')


def capture(path, expected=None):
    C.assert_not_protected(str(path))
    raw=Path(path).read_bytes();sha=hashlib.sha256(raw).hexdigest()
    if expected is not None and sha != expected:raise ValueError(f'hash mismatch: {Path(path).name}')
    return raw,sha


def rows(raw):
    return [json.loads(line) for line in raw.split(b'\n') if line.strip()]


def index(items):
    result={r['record_id']:r for r in items}
    if len(result)!=len(items):raise ValueError('duplicate record IDs')
    return result


def prepare(candidate_dir, baseline_binding):
    """Continuity is evidence for a later decision, never automatic outcome transfer."""
    verified=AE.verify(baseline_binding)
    root=Path(candidate_dir).resolve()
    raw,manifest_sha=capture(root/'proposal_manifest.json');manifest=json.loads(raw)
    if (manifest.get('schema')!='v5-remediation-candidate-pool/proposal-v1'
            or manifest.get('training_eligible') is not False
            or manifest.get('audit_outcomes_inherited') is not False):
        raise ValueError('expected explicitly unadjudicated, non-trainable candidate')
    descriptors=manifest['artifacts']
    if len(descriptors)!=len(ARTIFACTS) or {a['path'] for a in descriptors}!=ARTIFACTS:
        raise ValueError('unexpected or duplicate candidate artifacts')
    candidate=None
    for art in descriptors:
        path=root/art['path']
        if not path.resolve().is_relative_to(root):raise ValueError('artifact escapes candidate directory')
        body,_=capture(path,art['sha256'])
        if len(body)!=art['bytes']:raise ValueError('artifact byte count mismatch')
        if sum(bool(line.strip()) for line in body.split(b'\n'))!=art['rows']:
            raise ValueError('artifact row count mismatch')
        if art['path']=='candidate_pool.jsonl':candidate=rows(body)
    for name,sha in manifest['implementation_sha256'].items():
        capture(Path(C.REPO_ROOT)/name,sha)
    if any(r.get('label_status')!=C.LABEL_PENDING or r.get('status')!=C.ACCEPTED for r in candidate):
        raise ValueError('candidate contains an admitted, rejected, or non-pending row')
    current=index(candidate)
    pool=baseline_binding['pool'];pool_path=Path(pool['path'])
    if not pool_path.is_absolute():pool_path=Path(C.REPO_ROOT)/pool_path
    before_raw,_=capture(pool_path,pool['sha256']);before=index(rows(before_raw))
    untouched_before={rid:r for rid,r in before.items() if r['category_v4'] not in M.FOCUS}
    untouched_after={rid:r for rid,r in current.items() if r['category_v4'] not in M.FOCUS}
    if untouched_before.keys()!=untouched_after.keys():raise ValueError('out-of-scope record set changed')
    for rid,old in untouched_before.items():
        if any(old.get(k)!=untouched_after[rid].get(k) for k in IMMUTABLE):
            raise ValueError('out-of-scope payload or source changed')
    categories={}
    for cat in sorted(M.FOCUS):
        old={rid:r for rid,r in before.items() if r['category_v4']==cat}
        new={rid:r for rid,r in current.items() if r['category_v4']==cat}
        previous=verified['category_outcomes'].get(cat)
        categories[cat]={'previous_outcome':previous,'old_rows':len(old),'candidate_rows':len(new),
            'record_ids_added':len(new.keys()-old.keys()),'record_ids_removed':len(old.keys()-new.keys()),
            'common_ids_with_changed_immutable_fields':sum(any(old[rid].get(k)!=new[rid].get(k) for k in IMMUTABLE) for rid in old.keys()&new.keys()),
            'candidate_training_eligible':False,'new_outcome':None,
            'continuation_requires_evidence':previous in ('FAIL','INSUFFICIENT_EVIDENCE')}
    return {'schema':SCHEMA,'status':'PREPARED_NOT_ADMITTED','training_authorized':False,
        'sample_drawn':False,'audit_results_transferred':False,'candidate_manifest_sha256':manifest_sha,
        'candidate_pool_sha256':next(a['sha256'] for a in descriptors if a['path']=='candidate_pool.jsonl'),
        'baseline_sha256':verified['sha256'],'candidate_rows':len(candidate),'categories':categories,
        'out_of_scope_continuity':{'records':len(untouched_before),'immutable_fields_equal':True,
            'full_records_equal':sum(old==untouched_after[rid] for rid,old in untouched_before.items()),
            'fields_checked':list(IMMUTABLE)},
        'remaining_actions':['Record acceptance of the documented source/filter change.',
            'Use the existing r4 one-reaudit limit and a fresh seed; do not reset history or redraw.',
            'Readmission requires new category evidence; continuity alone grants no PASS.'],
        'continuation_executor':'bound authoritative r4 evidence selects FAIL and INSUFFICIENT_EVIDENCE under existing history/seed/round limits; preparation draws no sample',
        'implementation_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}


def export_audit_input(candidate_dir,baseline_binding,out_dir):
    """Export pending source bytes in the stage-2 audit interface. No sample or PASS."""
    evidence=prepare(candidate_dir,baseline_binding)
    root=Path(candidate_dir).resolve();out=Path(out_dir)
    C.assert_not_protected(str(out))
    descriptor=baseline_binding['pool_manifest'];path=Path(descriptor['path'])
    if not path.is_absolute():path=Path(C.REPO_ROOT)/path
    raw,_=capture(path,descriptor['sha256']);baseline=json.loads(raw)
    if not isinstance(baseline.get('denylist'),dict):raise ValueError('baseline deny-list binding missing')
    raw,sha=capture(root/'candidate_pool.jsonl',evidence['candidate_pool_sha256'])
    manifest={'schema':'v5-attack-pool/v1','status':'UNADJUDICATED_AUDIT_INPUT',
              'purpose':'DOCUMENTED_FILTER_CORRECTION_CONTINUATION','training_authorized':False,
              'prior_category_results_inherited':False,'denylist':baseline['denylist'],
              'artifacts':[{'path':'attack_pool.jsonl','sha256':sha,'bytes':len(raw),'records':evidence['candidate_rows']}],
              'source_change_evidence':evidence}
    out.mkdir(exist_ok=False,parents=True)
    (out/'attack_pool.jsonl').write_bytes(raw)
    (out/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
    return manifest


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--candidate-dir',required=True,type=Path)
    ap.add_argument('--baseline-evidence',required=True,type=Path,help='verified evidence report containing binding')
    ap.add_argument('--out',required=True,type=Path)
    ap.add_argument('--audit-input-out',type=Path,default=None,help='optional new directory with unadjudicated audit source interface')
    args=ap.parse_args()
    raw,_=capture(args.baseline_evidence);baseline=json.loads(raw)['binding']
    result=prepare(args.candidate_dir,baseline)
    if args.audit_input_out:
        export_audit_input(args.candidate_dir,baseline,args.audit_input_out)
    C.assert_not_protected(str(args.out))
    with args.out.open('x',encoding='utf-8') as fh:json.dump(result,fh,ensure_ascii=False,indent=2)
    print(json.dumps({'status':result['status'],'candidate_rows':result['candidate_rows'],
                      'training_authorized':False}))


if __name__=='__main__':main()
