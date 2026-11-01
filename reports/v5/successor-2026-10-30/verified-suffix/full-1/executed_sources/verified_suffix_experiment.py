"""Isolated DEV experiment: verified suffix versus unchanged native generation."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import time

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'control_plane'),str(Path(__file__).parent)]
from verified_suffix import candidates_for,classify_verified


def sha(raw):return hashlib.sha256(raw).hexdigest()


def percentile(values,q):
    import math
    values=sorted(values)
    return values[max(0,math.ceil(len(values)*q)-1)]


def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True)
    p.add_argument('--smoke',action='store_true');p.add_argument('--benchmark-only',action='store_true');args=p.parse_args()
    if args.out.exists():raise ValueError('Do not overwrite experiment evidence')
    original=REPO/'reports/v5/successor-2026-10-30/runtime'
    protocol=json.loads((original/'protocol.json').read_text())
    private=Path('/home/sebas/Documents/Codex/2026-10-26/ta/work/metrics-2026-10-30/inputs.private.jsonl')
    raw=private.read_bytes()
    if sha(raw)!=protocol['private_inputs_sha256']:raise ValueError('DEV input changed')
    byid={r['id']:r for r in map(json.loads,raw.splitlines()) if r.get('canonical_outcome')=='ACCEPT'}
    old={r['id']:r for r in map(json.loads,(original/'nf4_run4_quality_complete.jsonl').read_text().splitlines())}
    if set(old)!=set(byid):raise ValueError('Old comparison population differs')
    ids=protocol['benchmark_ids'][:8] if args.smoke else protocol['benchmark_ids']
    args.out.mkdir(parents=True);snap=args.out/'executed_sources';snap.mkdir()
    paths=[Path(__file__),Path(__file__).with_name('verified_suffix.py'),REPO/'control_plane/v5_inference_core.py',REPO/'control_plane/v5_runtime_profile.py']
    hashes={}
    for path in paths:
        data=path.read_bytes();(snap/path.name).write_bytes(data);hashes[str(path.relative_to(REPO))]=sha(data)
    import torch
    import v5_inference_core as core
    profile=original/'profiles/nf4.EXPERIMENTAL.json'
    model=core.load_v5(runtime_profile_path=str(profile),runtime_profile_sha256=sha(profile.read_bytes()),allow_experimental_runtime=True)
    if model.adapter_sha256!=protocol['adapter_sha256']:raise ValueError('Wrong weights')
    candidates=candidates_for(model)
    resultrows=[]
    path=args.out/'records.jsonl'
    with path.open('x') as handle:
        def infer(cid,method,phase):
            row=byid[cid]
            started=time.perf_counter()
            if method=='native':parsed,measure=core.classify_canonical(model,row['canonical_text'])
            else:parsed,measure=classify_verified(model,row['canonical_text'],candidates)
            elapsed=(time.perf_counter()-started)*1000
            output=measure.pop('raw_text','');measure.pop('content_rejected',None)
            record=dict(id=cid,method=method,phase=phase,status=parsed.status,
                        decision=parsed.decision,reason=parsed.reason,invalid_reason=parsed.invalid_reason,
                        output_sha256=sha(output.encode()),elapsed_ms=elapsed,measure=measure)
            handle.write(json.dumps(record)+'\n');handle.flush();resultrows.append(record)
            return record
        for method in ('native','verified'):
            infer(ids[0],method,'cold')
            for cid in ids[:4]:infer(cid,method,'warmup')
        for n,cid in enumerate(ids):
            for method in (('native','verified') if n%2==0 else ('verified','native')):
                infer(cid,method,'benchmark')
        if not args.smoke and not args.benchmark_only:
            for n,cid in enumerate(byid):
                if cid not in ids:infer(cid,'verified','quality')
                if n%100==0:print(f'quality {n}/{len(byid)}',flush=True)
    measured=[r for r in resultrows if r['phase'] in ('benchmark','quality')]
    signatures=lambda r:tuple(r.get(k) for k in ('status','decision','reason','invalid_reason','output_sha256'))
    mismatches=[];fresh_native_drift=[]
    native={r['id']:r for r in measured if r['method']=='native'}
    for r in measured:
        if signatures(r)!=signatures(old[r['id']]):
            (mismatches if r['method']=='verified' else fresh_native_drift).append(r['id'])
    latency={}
    for method in ('native','verified'):
        ms=[r['elapsed_ms'] for r in measured if r['method']==method and r['phase']=='benchmark']
        latency[method]=dict(n=len(ms),p50_ms=percentile(ms,.5),p95_ms=percentile(ms,.95),p99_ms=percentile(ms,.99))
    verified=[r for r in measured if r['method']=='verified']
    summary=dict(schema='v51-verified-suffix-experiment/v1',status='EXPERIMENTAL_NOT_SERVING_OR_APPROVED',
                 scope='DEV only; no training, source selection or protected data',smoke=args.smoke,benchmark_only=args.benchmark_only,
                 source_hashes=hashes,private_inputs_sha256=sha(raw),profile_sha256=sha(profile.read_bytes()),
                 adapter_sha256=model.adapter_sha256,runtime_settings=model.runtime_settings,
                 reference_sha256=sha((original/'nf4_run4_quality_complete.jsonl').read_bytes()),
                 benchmark_latency=latency,verified_cases=len(verified),
                 verified_suffix_successes=sum(r['measure'].get('suffix_verified',False) for r in verified),
                 native_fallbacks=sum(r['measure'].get('fallback',False) for r in verified),
                 output_mismatch_ids_vs_previous_native=mismatches,
                 fresh_native_drift_ids=fresh_native_drift,
                 paired_mismatch_ids=[r['id'] for r in verified if r['id'] in native and signatures(r)!=signatures(native[r['id']])],
                 remaining='Single process initial experiment; repeat in fresh processes and verify boundary behavior before any serving integration')
    (args.out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary,indent=2),flush=True)


if __name__=='__main__':main()
