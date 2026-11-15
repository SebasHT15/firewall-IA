"""Real HTTP check of the explicit decoder profile; services stopped by own PID."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.request

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'control_plane'),str(REPO/'data_plane'),str(Path(__file__).parent)]
from verified_suffix_experiment import percentile
from cascade_manifest import load_manifest,v5_contract_problems


def sha(raw):return hashlib.sha256(raw).hexdigest()


def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--private-out',type=Path,required=True);a=p.parse_args()
    if a.out.exists() or a.private_out.exists():raise ValueError('No evidence overwrite')
    root=REPO/'reports/v5/successor-2026-10-30';runtime=root/'runtime'
    protocol=json.loads((runtime/'protocol.json').read_text())
    raw=Path('/home/sebas/Documents/Codex/2026-10-26/ta/work/metrics-2026-10-30/inputs.private.jsonl').read_bytes()
    if sha(raw)!=protocol['private_inputs_sha256']:raise ValueError('Input hash mismatch')
    byid={r['id']:r for r in map(json.loads,raw.splitlines()) if r.get('canonical_outcome')=='ACCEPT'}
    old={r['id']:r for r in map(json.loads,(runtime/'nf4_run4_quality_complete.jsonl').read_text().splitlines())}
    a.out.mkdir(parents=True);a.private_out.mkdir(parents=True)
    profile=json.loads((runtime/'profiles/nf4.EXPERIMENTAL.json').read_text())
    decoder_path=Path(__file__).with_name('verified_suffix.py')
    profile.update(schema='v5-inference-profile/v2',profile_id='v5-nf4-verified-suffix-dev-20261031',
                   decoder='verified_suffix/v1',decoder_sha256=sha(decoder_path.read_bytes()),
                   note='Experimental exact greedy suffix verification with native fallback; no production approval.')
    profile_path=a.out/'verified-suffix.EXPERIMENTAL.json'
    profile_path.write_text(json.dumps(profile,indent=2)+'\n')
    base_manifest=REPO/'reports/v5/hybrid/gateway-integration-v1/manifests/dev_fixture_baseline34_nf4_profile.json'
    manifest=json.loads(base_manifest.read_text());manifest['manifest_id']='dev-v5-verified-suffix-baseline34'
    manifest['v5']['runtime_profile_sha256']=sha(profile_path.read_bytes())
    manifest_path=a.out/'cascade-manifest.EXPERIMENTAL.json';manifest_path.write_text(json.dumps(manifest,indent=2)+'\n')
    results=[]
    for name,selected in [('native',runtime/'profiles/nf4.EXPERIMENTAL.json'),('verified',profile_path)]:
        with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        env=dict(os.environ,HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1',PYTHONDONTWRITEBYTECODE='1',TOKENIZERS_PARALLELISM='false',
                 FIREWALL_V5_RUNTIME_PROFILE=str(selected),FIREWALL_V5_RUNTIME_PROFILE_SHA256=sha(selected.read_bytes()),FIREWALL_V5_ALLOW_EXPERIMENTAL_RUNTIME='1')
        log=(a.private_out/(name+'.log')).open('x')
        proc=subprocess.Popen(['/usr/bin/python3.12','-B','-m','uvicorn','--app-dir','control_plane','v5_classifier_api:app','--host','127.0.0.1','--port',str(port)],cwd=REPO,env=env,stdout=log,stderr=subprocess.STDOUT)
        try:
            url=f'http://127.0.0.1:{port}'
            def get(path):
                with urllib.request.urlopen(url+path,timeout=3) as reply:return json.load(reply)
            deadline=time.monotonic()+90
            while True:
                if proc.poll() is not None:raise RuntimeError('Service exited; private log retained')
                try:
                    health=get('/health')
                    if health['model_loaded']:break
                except OSError:pass
                if time.monotonic()>deadline:raise TimeoutError('Service readiness')
                time.sleep(.2)
            contract=get('/contract')
            assert health['runtime_profile']==contract['runtime_profile']
            expected=load_manifest(str(manifest_path if name=='verified' else base_manifest))
            assert not v5_contract_problems(expected,health,contract)
            if name=='verified':
                assert 'v5_runtime_profile_mismatch' in v5_contract_problems(load_manifest(str(base_manifest)),health,contract)
            def classify(cid):
                query=urllib.request.Request(url+'/classify',data=json.dumps({'canonical_request':byid[cid]['canonical_text']}).encode(),headers={'Content-Type':'application/json'})
                start=time.perf_counter()
                with urllib.request.urlopen(query,timeout=20) as reply:payload=json.load(reply)
                return payload,(time.perf_counter()-start)*1000
            ids=protocol['benchmark_ids'];classify(ids[0])
            for cid in ids[:4]:classify(cid)
            records=[];mismatches=[]
            for n,cid in enumerate(list(ids)+([k for k in byid if k not in ids] if name=='verified' else [])):
                response,client_ms=classify(cid)
                fields=('status','decision','reason','invalid_reason')
                if any(response.get(k)!=old[cid].get(k) for k in fields):mismatches.append(cid)
                records.append(dict(id=cid,benchmark=cid in ids,client_ms=client_ms,**response))
                if n%200==0:print(name,n,flush=True)
            (a.out/(name+'.jsonl')).write_text(''.join(json.dumps(r)+'\n' for r in records))
            bench=[r for r in records if r['benchmark']]
            results.append(dict(config=name,cases=len(records),benchmark_n=len(bench),health=health,contract=contract,
                                mismatch_ids=mismatches,pipeline_p95_ms=percentile([r['pipeline_ms'] for r in bench],.95),
                                client_p95_ms=percentile([r['client_ms'] for r in bench],.95)))
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:proc.wait(timeout=15)
                except subprocess.TimeoutExpired:proc.kill();proc.wait()
            log.close()
    sources=[Path(__file__),decoder_path,REPO/'control_plane/v5_inference_core.py',REPO/'control_plane/v5_runtime_profile.py',REPO/'control_plane/v5_classifier_api.py']
    snapshot=a.out/'executed_sources';snapshot.mkdir()
    for path in sources:(snapshot/path.name).write_bytes(path.read_bytes())
    summary=dict(status='EXPERIMENTAL_HTTP_CHECK',private_inputs_sha256=sha(raw),results=results,
                 services_stopped=True,source_sha256={str(p.relative_to(REPO)):sha(p.read_bytes()) for p in sources},
                 manifest_sha256=sha(manifest_path.read_bytes()),profile_sha256=sha(profile_path.read_bytes()),
                 note='API/profile verification only; gateway/load must be checked separately with this manifest.')
    (a.out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({r['config']:{k:r[k] for k in ('cases','mismatch_ids','pipeline_p95_ms','client_p95_ms')} for r in results},indent=2))


if __name__=='__main__':main()
