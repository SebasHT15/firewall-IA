"""Paired native-NF4/suffix check on new weights, in three fresh processes.

Quality census stays separate. Fixed input selection never uses predictions.
No training, protected data, gateway or operational profile promotion.
"""
import argparse
from collections import defaultdict
import hashlib
import json
import os
from pathlib import Path
import random
import signal
import subprocess
import sys
import time

from collect_evaluation import population
from evaluation_metrics import distribution
from train_successor import GPU_STATUS, gpu_available

REPO = Path(__file__).resolve().parents[2]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def selected_ids(cases):
    """80 policy +20 authored, balanced labels, round-robin source strata."""
    rng = random.Random(20261101)
    chosen = []
    for cohort, count in [('policy_validation_selection', 40), ('authored_regression_known_DEV', 10)]:
        for label in ('ALLOW', 'BLOCK'):
            groups = defaultdict(list)
            for c in sorted(cases, key=lambda c: c['id']):
                if c['cohort'] == cohort and c['label'] == label:
                    key = (c.get('component_id') or c.get('category') or '', c.get('carrier') or '')
                    groups[key].append(c['id'])
            keys = sorted(groups)
            rng.shuffle(keys)
            for values in groups.values():
                rng.shuffle(values)
            selected = []
            while len(selected) < count:
                progress = False
                for key in keys:
                    if groups[key] and len(selected) < count:
                        selected.append(groups[key].pop())
                        progress = True
                if not progress:
                    raise ValueError('insufficient cases for declared benchmark strata')
            chosen += selected
    rng.shuffle(chosen)
    if len(chosen) != len(set(chosen)):
        raise ValueError('duplicate benchmark ID')
    return chosen


def worker(args):
    sys.path.insert(0, str(REPO/'control_plane'))
    import torch
    import psutil
    import transformers
    import v5_inference_core as core
    import verified_suffix
    protocol = json.loads((args.out/'protocol.json').read_bytes())
    _, cases = population(args.protocol, private=True)
    byid = {c['id']: c for c in cases}
    load_start = time.perf_counter()
    m = core.load_v5(str(args.adapter), str(args.recipe), runtime_profile_path=str(args.native_profile),
                     runtime_profile_sha256=sha(args.native_profile), allow_experimental_runtime=True)
    load_seconds = time.perf_counter()-load_start
    if m.adapter_sha256 != protocol['adapter_sha256']:
        raise ValueError('wrong benchmark weights')
    candidates = verified_suffix.candidates_for(m)
    torch.cuda.reset_peak_memory_stats()
    records = []
    with (args.out/f'repetition-{args.worker}.jsonl').open('x') as f:
        def infer(cid, method, phase):
            start = time.perf_counter()
            if method == 'native_nf4':
                parsed, measure = core.classify_canonical(m, byid[cid]['canonical_text'])
            else:
                parsed, measure = verified_suffix.classify_verified(m, byid[cid]['canonical_text'], candidates)
            elapsed = (time.perf_counter()-start)*1000
            raw = measure.pop('raw_text', '')
            measure.pop('content_rejected', None)
            record = dict(id=cid, method=method, phase=phase, status=parsed.status, decision=parsed.decision,
                          reason=parsed.reason, invalid_reason=parsed.invalid_reason,
                          output_sha256=hashlib.sha256(raw.encode()).hexdigest(),
                          elapsed_ms=elapsed, measure=measure)
            records.append(record)
            f.write(json.dumps(record, allow_nan=False)+'\n')
            f.flush()
        ids = protocol['benchmark_ids']
        methods = ['native_nf4', 'verified_suffix']
        if args.worker % 2 == 0:
            methods.reverse()
        for method in methods:
            infer(ids[0], method, 'cold')
            for cid in ids[:4]:
                infer(cid, method, 'warmup')
        for i, cid in enumerate(ids):
            for method in (methods if i % 2 == 0 else list(reversed(methods))):
                infer(cid, method, 'benchmark')
    metadata = dict(adapter_sha256=m.adapter_sha256, recipe_sha256=m.contract.recipe_sha256,
                    load_seconds=load_seconds, runtime_settings=m.runtime_settings,
                    peak_cuda_allocated_bytes=torch.cuda.max_memory_allocated(),
                    peak_cuda_reserved_bytes=torch.cuda.max_memory_reserved(),
                    rss_end_bytes=psutil.Process().memory_info().rss,
                    GPU=torch.cuda.get_device_name(), torch_version=torch.__version__,
                    transformers_version=transformers.__version__)
    (args.out/f'repetition-{args.worker}-metadata.json').write_text(json.dumps(metadata, indent=2)+'\n')
    return records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--protocol', type=Path, required=True)
    ap.add_argument('--adapter', type=Path, required=True)
    ap.add_argument('--recipe', type=Path, required=True)
    ap.add_argument('--native-profile', type=Path, required=True)
    ap.add_argument('--verified-profile', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--private-log-dir', type=Path, required=True)
    ap.add_argument('--worker', type=int)
    args = ap.parse_args()
    if args.worker:
        worker(args)
        return
    _, cases = population(args.protocol, private=True)
    if args.out.exists() or args.private_log_dir.exists():
        raise ValueError('new output and log directories required')
    sys.path.insert(0, str(REPO/'control_plane'))
    import v5_runtime_profile as RP
    bindings = dict(recipe_sha256=sha(args.recipe), adapter_sha256=sha(args.adapter/'adapter_model.safetensors'), allow_experimental=True)
    native_profile = RP.load_profile(args.native_profile, expected_sha256=sha(args.native_profile), **bindings)
    fast_profile = RP.load_profile(args.verified_profile, expected_sha256=sha(args.verified_profile), **bindings)
    if native_profile.precision != 'nf4' or native_profile.double_quant or native_profile.decoder != 'native':
        raise ValueError('paired reference must be native NF4 without double quantization')
    if fast_profile.decoder != 'verified_suffix/v1' or fast_profile.decoder_sha256 != sha(Path(__file__).with_name('verified_suffix.py')):
        raise ValueError('target decoder profile does not bind the measured decoder')
    processes = subprocess.check_output(['nvidia-smi', '--query-compute-apps=pid,process_name', '--format=csv,noheader'], text=True).splitlines()
    gpu_available(json.loads(GPU_STATUS.read_bytes()), processes)
    args.out.mkdir(parents=True)
    args.private_log_dir.mkdir(parents=True, mode=0o700)
    paths = [Path(__file__), Path(__file__).with_name('verified_suffix.py'),
             Path(__file__).with_name('collect_evaluation.py'), Path(__file__).with_name('evaluation_metrics.py'),
             Path(__file__).with_name('train_successor.py'), Path(__file__).with_name('successor_contract.py'),
             REPO/'control_plane/v5_inference_core.py', REPO/'control_plane/v5_runtime_profile.py']
    hashes = {str(p.relative_to(REPO)): sha(p) for p in paths}
    for p in paths:
        target = args.out/'executed_sources'/p.relative_to(REPO)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(p.read_bytes())
    protocol = dict(schema='v51-paired-decoder-benchmark/v1', status='EXPERIMENTAL_NOT_PROMOTED',
                    adapter_sha256=sha(args.adapter/'adapter_model.safetensors'), recipe_sha256=sha(args.recipe),
                    native_profile_sha256=sha(args.native_profile), profile_sha256=sha(args.verified_profile),
                    evaluation_protocol_sha256=sha(args.protocol), benchmark_ids=selected_ids(cases),
                    selection='80 policy URL,20 authored; balanced classes; fixed seed20261101, no predictions',
                    repetitions=3, cold_per_method=1, warmup_per_method=4, batch=1, concurrency=1,
                    source_sha256=hashes, protected_sets_used=False, reserve_opened=False)
    (args.out/'protocol.json').write_text(json.dumps(protocol, indent=2)+'\n')
    GPU_STATUS.write_text(json.dumps(dict(owner='Codex', state='IN_USE_BY_CODEX', pid=os.getpid(), UTC=time.time(),
        task='Paired native/suffix DEV benchmark on V51 new weights; CPU-only for Claude'), indent=2)+'\n')
    def interrupted(signum, frame):
        raise KeyboardInterrupt('benchmark interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    process = None
    try:
        env = dict(os.environ, HF_HUB_OFFLINE='1', TRANSFORMERS_OFFLINE='1', TOKENIZERS_PARALLELISM='false', PYTHONDONTWRITEBYTECODE='1')
        for rep in range(1, 4):
            command = [sys.executable, '-B', str(Path(__file__)), '--worker', str(rep),
                       '--protocol', str(args.protocol), '--adapter', str(args.adapter), '--recipe', str(args.recipe),
                       '--native-profile', str(args.native_profile), '--verified-profile', str(args.verified_profile),
                       '--out', str(args.out), '--private-log-dir', str(args.private_log_dir)]
            with (args.private_log_dir/f'repetition-{rep}.log').open('x') as log:
                process = subprocess.Popen(command, cwd=REPO, env=env, stdout=log, stderr=subprocess.STDOUT)
                if process.wait():
                    raise RuntimeError('benchmark worker failed; private log retained')
            print(f'paired decoder repetition {rep}/3 complete', flush=True)
        rows = [json.loads(line) for rep in range(1, 4) for line in (args.out/f'repetition-{rep}.jsonl').read_text().splitlines()]
        cells = defaultdict(dict)
        for row in rows:
            if row['phase'] == 'benchmark':
                # Each file has exactly one benchmark record per ID/method.
                cells[row['id']].setdefault(row['method'], []).append(row)
        def signature(r):
            return tuple(r.get(k) for k in ('status', 'decision', 'reason', 'invalid_reason', 'output_sha256')) + (r['measure']['ended_with_eos'],)
        mismatches = []
        for cid, methods in cells.items():
            if len(methods['native_nf4']) != 3 or len(methods['verified_suffix']) != 3:
                raise ValueError('incomplete paired benchmark')
            for i, (left, right) in enumerate(zip(methods['native_nf4'], methods['verified_suffix'])):
                if signature(left) != signature(right):
                    mismatches.append(dict(id=cid, repetition=i+1))
        if any(sha(REPO/name) != digest for name, digest in hashes.items()):
            raise ValueError('benchmark source changed during execution')
        result = dict(schema='v51-decoder-verification/v1', status='OBSERVED_PAIRED_PARITY' if not mismatches else 'DIFFERENCES_OBSERVED',
                      profile_sha256=protocol['profile_sha256'], native_profile_sha256=protocol['native_profile_sha256'],
                      adapter_sha256=protocol['adapter_sha256'], recipe_sha256=protocol['recipe_sha256'],
                      unique_cases=100, paired_observations=300, mismatches=mismatches,
                      pooled={method: distribution([r['elapsed_ms'] for r in rows if r['phase']=='benchmark' and r['method']==method]) for method in ('native_nf4','verified_suffix')},
                      by_repetition={str(rep): {method: distribution([json.loads(x)['elapsed_ms'] for x in (args.out/f'repetition-{rep}.jsonl').read_text().splitlines() if json.loads(x)['phase']=='benchmark' and json.loads(x)['method']==method]) for method in ('native_nf4','verified_suffix')} for rep in range(1, 4)},
                      source_sha256=hashes, provenance='Real weights; paired fixed DEV cases; three fresh processes, no gateway/load',
                      limitation='Observed equivalence, not a universal proof. Quality census/API parity is separate. No production approval.')
        (args.out/'verification.json').write_text(json.dumps(result, indent=2)+'\n')
    finally:
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        status = json.loads(GPU_STATUS.read_bytes())
        if status.get('owner') == 'Codex' and status.get('pid') == os.getpid():
            GPU_STATUS.write_text(json.dumps(dict(owner=None, state='AVAILABLE', UTC=time.time(), note='Codex paired decoder benchmark stopped.'), indent=2)+'\n')


if __name__ == '__main__':
    main()
