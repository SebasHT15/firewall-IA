"""Post-hoc attribution of observed native-DQ vs fast-noDQ output changes.

Only changed DEV cases, not a benchmark or independent quality population.
Native-noDQ and verified-noDQ share the same loaded model and weights.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from collect_evaluation import population, read_jsonl, checked_predictions
from train_successor import GPU_STATUS, gpu_available

REPO = Path(__file__).resolve().parents[2]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def signature(p):
    return tuple(p.get(k) for k in ('status','decision','reason','invalid_reason','ended_with_eos'))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', type=Path, required=True)
    ap.add_argument('--protocol', type=Path, required=True)
    ap.add_argument('--adapter', type=Path, required=True)
    ap.add_argument('--recipe', type=Path, required=True)
    args = ap.parse_args()
    out = args.root/'runtime-change-diagnosis'
    if out.exists():
        raise ValueError('diagnostic evidence already exists')
    _, cases = population(args.protocol, private=True)
    old_path = args.root/'native-recipe/quality-run/predictions.jsonl'
    fast_path = args.root/'verified-suffix/quality-run/predictions.jsonl'
    native = checked_predictions(cases, read_jsonl(old_path.read_bytes()))
    fast = checked_predictions(cases, read_jsonl(fast_path.read_bytes()))
    changed = [(c, a, b) for c, a, b in zip(cases, native, fast) if signature(a) != signature(b)]
    processes = subprocess.check_output(['nvidia-smi','--query-compute-apps=pid,process_name','--format=csv,noheader'],text=True).splitlines()
    gpu_available(json.loads(GPU_STATUS.read_bytes()), processes)
    out.mkdir()
    GPU_STATUS.write_text(json.dumps(dict(owner='Codex',state='IN_USE_BY_CODEX',pid=os.getpid(),UTC=time.time(),task='V51 changed-case quantization/decoder diagnosis'),indent=2)+'\n')
    def interrupted(signum, frame):
        raise KeyboardInterrupt('diagnostic interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    try:
        sys.path.insert(0,str(REPO/'control_plane'))
        import v5_inference_core as core
        from verified_suffix import candidates_for, classify_verified
        profile = args.root/'profiles/nf4-native.EXPERIMENTAL.json'
        model = core.load_v5(str(args.adapter), str(args.recipe), runtime_profile_path=str(profile),
                             runtime_profile_sha256=sha(profile),allow_experimental_runtime=True)
        candidates = candidates_for(model)
        records = []
        for case, previous, measured_fast in changed:
            calls = {}
            for method in ('native_noDQ','verified_noDQ'):
                p, measure = (core.classify_canonical(model,case['canonical_text']) if method=='native_noDQ' else
                              classify_verified(model,case['canonical_text'],candidates))
                raw = measure.pop('raw_text','')
                calls[method] = dict(status=p.status,decision=p.decision,reason=p.reason,invalid_reason=p.invalid_reason,
                                     ended_with_eos=measure['ended_with_eos'],output_sha256=hashlib.sha256(raw.encode()).hexdigest())
            records.append(dict(id=case['id'],label=case['label'],native_DQ_signature=list(signature(previous)),
                native_noDQ=calls['native_noDQ'],verified_noDQ=calls['verified_noDQ'],
                same_native_and_verified=calls['native_noDQ']==calls['verified_noDQ'],
                reproduced_API_fast=signature(calls['verified_noDQ'])==signature(measured_fast)))
        sources=[Path(__file__),Path(__file__).with_name('verified_suffix.py'),REPO/'control_plane/v5_inference_core.py']
        for p in sources:
            dest=out/'executed_sources'/p.relative_to(REPO);dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(p.read_bytes())
        result=dict(scope='POST_HOC_CHANGED_CASE_DIAGNOSIS_NOT_BENCHMARK',cases=len(records),records=records,
                    native_noDQ_vs_verified_mismatches=sum(not r['same_native_and_verified'] for r in records),
                    API_fast_not_reproduced=sum(not r['reproduced_API_fast'] for r in records),
                    adapter_sha256=model.adapter_sha256,recipe_sha256=model.contract.recipe_sha256,
                    native_profile_sha256=sha(profile),native_census_sha256=sha(old_path),fast_census_sha256=sha(fast_path),
                    source_sha256={str(p.relative_to(REPO)):sha(p) for p in sources})
        (out/'diagnosis.json').write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps({k:result[k] for k in ['cases','native_noDQ_vs_verified_mismatches','API_fast_not_reproduced']},indent=2))
    finally:
        state=json.loads(GPU_STATUS.read_bytes())
        if state.get('owner')=='Codex' and state.get('pid')==os.getpid():
            GPU_STATUS.write_text(json.dumps(dict(owner=None,state='AVAILABLE',UTC=time.time(),note='V51 changed-case diagnosis completed/stopped'),indent=2)+'\n')


if __name__=='__main__':
    main()
