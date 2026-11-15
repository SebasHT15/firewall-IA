"""Controlled inference-only overrides; immutable V5 checkpoint and native core."""
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sys
import time

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO/'control_plane'), str(REPO)]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', choices=('nf4_dq', 'nf4', 'bf16'), required=True)
    parser.add_argument('--run', type=int, required=True)
    parser.add_argument('--private', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--quality', action='store_true')
    args = parser.parse_args()
    out = Path(args.out)
    protocol = json.loads((out/'protocol.json').read_text())
    data = Path(args.private).read_bytes()
    assert sha(data) == protocol['private_inputs_sha256']
    rows = [json.loads(line) for line in data.splitlines()]
    byid = {r['id']:r for r in rows if r.get('canonical_outcome') == 'ACCEPT'}
    import torch
    import psutil
    import transformers
    import v5_inference_core as core
    actual = {}
    original = transformers.AutoModelForCausalLM.from_pretrained

    def experimental_load(*positional, **kwargs):
        quant = kwargs.get('quantization_config')
        if args.config == 'bf16':
            kwargs.pop('quantization_config', None)
            kwargs['dtype'] = torch.bfloat16
        elif args.config == 'nf4':
            quant.bnb_4bit_use_double_quant = False
        actual.update(quantization=(quant.to_dict() if args.config != 'bf16' else None),
                      dtype_override=str(kwargs.get('dtype')), device_map=kwargs.get('device_map'))
        return original(*positional, **kwargs)

    start = time.perf_counter()
    transformers.AutoModelForCausalLM.from_pretrained = experimental_load
    try:
        model = core.load_v5(core.DEFAULT_ADAPTER_DIR)
    finally:
        transformers.AutoModelForCausalLM.from_pretrained = original
    load_s = time.perf_counter()-start
    assert model.adapter_sha256 == protocol['adapter_sha256']
    torch.cuda.reset_peak_memory_stats()
    process = psutil.Process()
    filename = f'{args.config}_run{args.run}' + ('_quality' if args.quality else '')
    quality = {}
    with (out/(filename+'.jsonl')).open('x') as f:
        def infer(cid, phase):
            r = byid[cid]
            parsed, measure = core.classify_canonical(model, r['canonical_text'])
            raw = measure.pop('raw_text', '')
            measure.pop('content_rejected', None)
            measure['pipeline_ms'] = sum(measure.get(k, 0) for k in
                ('encode_ms','tokenize_ms','transfer_ms','generate_ms','decode_ms','parse_ms'))
            record = dict(id=cid, config=args.config, run=args.run, phase=phase,
                cohort=r['cohort'], label=r['label'], category=r['category'],
                family=r.get('family'), placement=r.get('placement'),
                status=parsed.status, decision=parsed.decision, reason=parsed.reason,
                invalid_reason=parsed.invalid_reason, output_sha256=sha(raw.encode()),
                canonical_sha256=r['canonical_sha256'], measure=measure)
            f.write(json.dumps(record)+'\n')
            f.flush()
            return record
        ids = protocol['benchmark_ids']
        infer(ids[0], 'cold')
        for cid in ids[:4]:
            infer(cid, 'warmup')
        for cid in ids:
            quality[cid] = infer(cid, 'benchmark')
        if args.quality:
            for cid in byid:
                if cid not in quality:
                    quality[cid] = infer(cid, 'quality')
                    if len(quality)%100 == 0:
                        print(f'{args.config} quality {len(quality)}/{len(byid)}', flush=True)
            (out/(filename+'_complete.jsonl')).write_text(''.join(json.dumps(quality[cid])+'\n' for cid in byid))
    base = model.model.get_base_model()
    actual.update(attention_implementation=getattr(base.config,'_attn_implementation',None),
        model_dtype=str(base.dtype), config_use_cache=base.config.use_cache,
        generation_use_cache=base.generation_config.use_cache,
        max_new_tokens=model.contract.max_new_tokens,
        parameter_dtypes=sorted({str(p.dtype) for p in model.model.parameters()}))
    meta = dict(status='EXPERIMENTAL_RUNTIME_OVERRIDE_NOT_RECIPE_APPROVAL', config=args.config,
        run=args.run, recipe_contract=core.contract_summary(model.contract), actual_runtime=actual,
        adapter_sha256=model.adapter_sha256, load_s=load_s, total_s=time.perf_counter()-start,
        peak_cuda_allocated_bytes=torch.cuda.max_memory_allocated(),
        peak_cuda_reserved_bytes=torch.cuda.max_memory_reserved(), rss_end_bytes=process.memory_info().rss,
        torch_version=torch.__version__, transformers_version=transformers.__version__,
        UTC=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()))
    (out/(filename+'_metadata.json')).write_text(json.dumps(meta,indent=2)+'\n')
    print(json.dumps(dict(done=args.config,run=args.run,seconds=meta['total_s'])), flush=True)

if __name__ == '__main__':
    main()
