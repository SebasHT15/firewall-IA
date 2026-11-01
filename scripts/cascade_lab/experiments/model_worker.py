"""One fresh GPU process; native unmodified inference cores, no training."""
import argparse,json,sys,time,hashlib,os,platform,subprocess,threading
from pathlib import Path
REPO=Path(__file__).resolve().parents[3]; sys.path[:0]=[str(REPO/'control_plane'),str(REPO)]
import torch,psutil

def sha(b):return hashlib.sha256(b).hexdigest()
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--model',choices=['v4','v5'],required=True);ap.add_argument('--run',type=int,required=True);ap.add_argument('--private',required=True);ap.add_argument('--out',required=True);args=ap.parse_args()
    out=Path(args.out); protocol=json.loads((out/'protocol.json').read_text()); inputs=Path(args.private).read_bytes(); assert sha(inputs)==protocol['private_inputs_sha256']
    rows=[json.loads(l) for l in inputs.splitlines()]; eligible=[r for r in rows if r.get('canonical_outcome')=='ACCEPT']; byid={r['id']:r for r in eligible}
    dest=out/f'{args.model}_run{args.run}.jsonl'; process=psutil.Process(); load0=time.perf_counter()
    if args.model=='v5':
        import v5_inference_core as core
        model=core.load_v5(core.DEFAULT_ADAPTER_DIR); identity=core.contract_summary(model.contract); identity['adapter_sha256']=model.adapter_sha256
        def classify(r):
            parsed,m=core.classify_canonical(model,r['canonical_text']); raw=m.pop('raw_text',''); m.pop('content_rejected',None)
            return dict(status=parsed.status,decision=parsed.decision,reason=parsed.reason,invalid_reason=parsed.invalid_reason,output_sha256=sha(raw.encode()),measure=m)
    else:
        import inference_core as core
        tok,mdl=core.load_model(); device=core.resolve_device(); identity={'adapter_dir':core.DEFAULT_ADAPTER_DIR,'base_model':core.BASE_MODEL,'base_commit':getattr(mdl.config,'_commit_hash',None),'max_new_tokens':core.MAX_NEW_TOKENS,'v4_prompt_sha256':sha(core.build_prompt('').encode())}
        identity['adapter_files']={p.name:sha(p.read_bytes()) for p in Path(core.DEFAULT_ADAPTER_DIR).iterdir() if p.is_file() and p.suffix in ('.json','.safetensors')}
        def classify(r):
            raw,m=core.classify_timed(tok,mdl,r['v4_text'],device); t=time.perf_counter();dec,reason,status=core.parse_prediction(raw,ended_with_eos=m['ended_with_eos']);m['parse_ms']=(time.perf_counter()-t)*1000
            return dict(status=status,decision=dec,reason_sha256=sha((reason or '').encode()),reason_exact_expected=(core.normalize_reason(reason)==core.normalize_reason(r['category'])) if r['cohort']=='legacy_dev' and dec=='BLOCK' and r['label']=='BLOCK' else None,invalid_reason=None if status=='ok' else ('no_eos' if not m['ended_with_eos'] else 'parse_error'),output_sha256=sha(raw.encode()),measure=m)
    load_s=time.perf_counter()-load0; torch.cuda.reset_peak_memory_stats()
    benchmark=protocol['benchmark_ids']; all_quality={}; n=0
    with dest.open('w') as f:
        def infer(case_id,phase,repeat=None):
            nonlocal n
            r=byid[case_id]; t=time.perf_counter(); rec=classify(r);wall=(time.perf_counter()-t)*1000
            m=rec['measure']; stages=['encode_ms','prompt_build_ms','tokenize_ms','transfer_ms','generate_ms','decode_ms','parse_ms'];m['pipeline_ms']=sum(m.get(k,0) for k in stages);m['wall_ms']=wall
            rec.update(id=case_id,model=args.model,run=args.run,phase=phase,repeat=repeat,label=r['label'],category=r['category'],family=r.get('family'),placement=r.get('placement'),pair_id=r.get('pair_id'),cohort=r['cohort'],wire_sha256=r['wire_sha256'],canonical_sha256=r['canonical_sha256'],v4_text_sha256=r['v4_text_sha256'],rss_bytes=process.memory_info().rss,cuda_allocated_bytes=torch.cuda.memory_allocated(),cuda_reserved_bytes=torch.cuda.memory_reserved(),elapsed_s=time.perf_counter()-load0)
            f.write(json.dumps(rec)+'\n');f.flush();n+=1
            if n%50==0:print(f'{args.model} run{args.run} {phase}: {n} ({time.perf_counter()-load0:.1f}s)',flush=True)
            return rec
        infer(benchmark[0],'cold')
        for cid in benchmark[:4]:infer(cid,'warmup')
        for cid in benchmark:
            rec=infer(cid,'benchmark')
            if args.run==1:all_quality[cid]=rec
        if args.run==1:
            for r in eligible:
                if r['id'] not in all_quality:all_quality[r['id']]=infer(r['id'],'quality')
            for rep in (2,3):
                for cid in protocol['determinism_ids']:infer(cid,'determinism',rep)
    quality=out/f'{args.model}_quality.jsonl'
    if args.run==1:quality.write_text(''.join(json.dumps(all_quality[r['id']])+'\n' for r in eligible))
    meta={'model':args.model,'run':args.run,'load_s':load_s,'identity':identity,'rows_written':n,'total_s':time.perf_counter()-load0,'cuda_peak_allocated_bytes':torch.cuda.max_memory_allocated(),'cuda_peak_reserved_bytes':torch.cuda.max_memory_reserved(),'rss_end_bytes':process.memory_info().rss,'python':sys.version,'torch':torch.__version__,'cuda':torch.version.cuda,'gpu':torch.cuda.get_device_name(0),'input_sha256':protocol['private_inputs_sha256'],'finished_at_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
    (out/f'{args.model}_run{args.run}_metadata.json').write_text(json.dumps(meta,indent=2)+'\n');print(json.dumps({'done':args.model,'run':args.run,'seconds':meta['total_s']}),flush=True)
if __name__=='__main__':main()
