"""Independent checks of the kept observations and source/model identities."""
import json,sys,hashlib,math,collections,subprocess,time,csv
from pathlib import Path
REPO=Path(__file__).resolve().parents[3];OUT=REPO/'reports/v5/hybrid/experiments-2026-10-30'
def read(name):return [json.loads(l) for l in (OUT/name).read_text().splitlines() if l]
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def counts(rows,pred):
    result=dict(TP=0,TN=0,FP=0,FN=0,N=len(rows))
    for r in rows:
        d=pred(r)
        key=('TP' if d=='BLOCK' else 'FN') if r['label']=='BLOCK' else ('TN' if d=='ALLOW' else 'FP')
        result[key]+=1
    return result

def main():
    failures=[];checks=[]
    def check(name,ok,detail=None):
        checks.append(dict(check=name,passed=bool(ok),detail=detail))
        if not ok:failures.append(name)
    s=json.loads((OUT/'summary.json').read_text(),parse_constant=lambda x:(_ for _ in ()).throw(ValueError(x)));p=json.loads((OUT/'protocol.json').read_text());check('protocol binding',s['protocol_sha256']==digest(OUT/'protocol.json'))
    for model in ('v4','v5'):
        q=read(model+'_quality.jsonl');check(model+' quality ID uniqueness',len(q)==len({r['id'] for r in q})==1012)
        for cohort in ('legacy_dev','authored_paired_dev'):
            rs=[r for r in q if r['cohort']==cohort];independent=counts(rs,lambda r:r['decision']);got=s['quality'][model][cohort]['principal'];check(model+' E5 '+cohort,all(got[k]==v for k,v in independent.items()),independent)
        for run in range(1,4):
            rs=read(f'{model}_run{run}.jsonl');bs=[r for r in rs if r['phase']=='benchmark'];meta=json.loads((OUT/f'{model}_run{run}_metadata.json').read_text());check(f'{model} run{run} benchmark order',[r['id'] for r in bs]==p['benchmark_ids']);check(f'{model} run{run} input binding',meta['input_sha256']==p['private_inputs_sha256']);check(f'{model} run{run} warming',sum(r['phase']=='cold' for r in rs)==1 and sum(r['phase']=='warmup' for r in rs)==4)
            vals=sorted(r['measure']['pipeline_ms'] for r in bs if r['measure']['generated_tokens']>0);actual=vals[math.ceil(.95*len(vals))-1];check(f'{model} run{run} nearest-rank P95',actual==s['benchmarks'][model]['runs'][run-1]['pipeline_ms']['p95'])
        check(model+' three-output DEV repeats',len(s['determinism'][model]['byte_hash_divergences'])==0)
    for name in p['live_modes']:
        rows=read('gateway_'+name+'.jsonl');check(name+' real wire IDs',len(rows)==len({r['id'] for r in rows})==600)
        semantic=[r for r in rows if r['wire_ok'] and r['canonical_outcome']=='ACCEPT'];got=s['gateway'][name]
        check(name+' actual call count',sum(r['v5_calls'] for r in rows)==got['actual_V5_calls'])
        check(name+' no L2 mismatches',got['L2_enforcement_mismatch_N']==0)
        check(name+' wire preservation',all(x['wire_sha256']==r['wire_sha256'] for r in rows for x in r['independent_upstream']))
        # L3 is independently reconstructed from sink evidence, not router intent.
        independent=counts(semantic,lambda r:'ALLOW' if r['independent_upstream'] else 'BLOCK');check(name+' independent L3',all(got['L3_delivery_eligible']['principal'][k]==v for k,v in independent.items()))
        for c,load in s['gateway_load'][name].items():check(name+' load receipts '+c,load['aggregate_receipt_hash_counts_match_forwarded'])
    for name in ('baseline34','path-ablation32'):
        rows=read('gateway_'+name+'.jsonl');v5={r['id']:r for r in read('v5_quality.jsonl')};m2={r['id']:r for r in read('model2_quality.jsonl')};mismatches=[]
        for r in rows:
            if not r['wire_ok']:continue
            cid=r['id'];expected='BLOCK' if m2[cid][name]['decision']=='BLOCK' and m2[cid][name]['status']=='OK' else v5[cid]['decision'];trace=r['trace'];actual='BLOCK' if trace['deciding_stage']=='model2' else (trace.get('v5') or {}).get('decision')
            if expected!=actual:mismatches.append(cid)
        check(name+' counterfactual agrees with real route decisions',not mismatches,mismatches)
        check(name+' fast-path guard probes',all(r['pass_guard'] for r in s['fast_path_synthetic'][name]))
    root=REPO/'model-output-model2/final/v4-d82-20261027T052308Z';expected={'baseline34':'da6f6eb85c5a687bd038c6298baf59abdbe0489a80c8993b74a34dae7c60aa38','path-ablation32':'6fda4fa0d0bacd7573234e3b2ebdda23706af1a6312c3fe33e185c0237664d15'}
    for name,h in expected.items():check(name+' unchanged FINAL bytes',digest(root/(name+'.json'))==h)
    adapter=REPO/'model-output-v5/final/v5-final-v4-20261027T022649Z/adapter/adapter_model.safetensors';check('V5 unchanged FINAL weights',digest(adapter)=='c27e363fe76190f5cb4be77f02e110419ab5d95ef5ee1f959a238ba99bc72393')
    sources=json.loads((OUT/'measurement_source_hashes.json').read_text())['files']
    for path,record in sources.items():
        if '/experiments/analyze.py' in path or '/experiments/figures.py' in path or '/experiments/report.py' in path:continue
        check('measurement source '+path,digest(REPO/path)==record['sha256'])
    head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip();env=json.loads((OUT/'environment.json').read_text());check('no commit made',head==env['git_head']);check('nothing staged',subprocess.run(['git','diff','--cached','--quiet'],cwd=REPO).returncode==0)
    check('unit tests',json.loads((OUT/'test_results.json').read_text())['total']==72)
    route=(OUT/'real_routes.log').read_text();check('18 real route checks',route.count('[PASS]')==18 and '[FAIL]' not in route)
    check('four failure controls',all(x['passed'] for x in s['failure_controls']))
    check('recovered after load',s['post_load_recovery']['status']=='ok')
    result={'verified_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'checks':checks,'passed':len(checks)-len(failures),'failures':failures}
    (OUT/'verification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'passed':result['passed'],'failures':failures}));sys.exit(bool(failures))
if __name__=='__main__':main()
