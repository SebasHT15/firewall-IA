"""Verify default and explicit runtime profiles over HTTP with real weights."""
import argparse,hashlib,json,os,socket,subprocess,time,urllib.request
from pathlib import Path
REPO=Path(__file__).resolve().parents[2]
OUT=REPO/'reports/v5/successor-2026-10-30/runtime'
STATUS=Path('/home/sebas/Documents/Codex/2026-10-26/ta/outputs/Coordinacion_modelos_arquitectura/GPU_STATUS.json')
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--evidence-dir',type=Path,default=OUT);args=parser.parse_args();evidence=args.evidence_dir;evidence.mkdir(parents=True,exist_ok=True)
    STATUS.write_text(json.dumps(dict(owner='Codex',state='BUSY',task='Real HTTP runtime profile verification',pid=os.getpid(),UTC=time.time()),indent=2)+'\n')
    results=[]
    try:
        for config in ['default','nf4','bf16']:
            with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
            env=dict(os.environ,HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1',PYTHONDONTWRITEBYTECODE='1',TOKENIZERS_PARALLELISM='false')
            for name in ['FIREWALL_V5_RUNTIME_PROFILE','FIREWALL_V5_RUNTIME_PROFILE_SHA256','FIREWALL_V5_ALLOW_EXPERIMENTAL_RUNTIME']:env.pop(name,None)
            if config!='default':
                profile=OUT/'profiles'/f'{config}.EXPERIMENTAL.json';env.update(FIREWALL_V5_RUNTIME_PROFILE=str(profile),FIREWALL_V5_RUNTIME_PROFILE_SHA256=hashlib.sha256(profile.read_bytes()).hexdigest(),FIREWALL_V5_ALLOW_EXPERIMENTAL_RUNTIME='1')
            log=(evidence/f'service_{config}.log').open('x');proc=subprocess.Popen(['/usr/bin/python3.12','-B','-m','uvicorn','--app-dir','control_plane','v5_classifier_api:app','--host','127.0.0.1','--port',str(port)],cwd=REPO,env=env,stdout=log,stderr=subprocess.STDOUT)
            try:
                url=f'http://127.0.0.1:{port}';deadline=time.monotonic()+90
                while True:
                    if proc.poll() is not None:raise RuntimeError('Service exited')
                    try:
                        with urllib.request.urlopen(url+'/health',timeout=2) as r:health=json.load(r)
                        if health['model_loaded']:break
                    except OSError:pass
                    if time.monotonic()>deadline:raise RuntimeError('Readiness timeout')
                    time.sleep(.3)
                settings=health['runtime_settings'];assert settings['loaded_in_4bit']==(config!='bf16')
                if config!='bf16':assert settings['double_quant']==(config=='default')
                if config=='default':assert health['runtime_profile'] is None
                else:assert health['runtime_profile']['status']=='EXPERIMENTAL' and health['runtime_profile']['precision']==config
                with urllib.request.urlopen(url+'/contract',timeout=2) as r:contract=json.load(r)
                assert contract['runtime_profile']==health['runtime_profile'];assert contract['token_budget_B']==415
                outcomes=[]
                for text in ['GET /catalog/widgets HTTP/1.1\n',"GET /products?id=1%27%20OR%20%271%27%3D%271%20UNION%20SELECT%20password%20FROM%20users HTTP/1.1\n"]:
                    q=urllib.request.Request(url+'/classify',data=json.dumps(dict(canonical_request=text)).encode(),headers={'Content-Type':'application/json'})
                    with urllib.request.urlopen(q,timeout=20) as r:payload=json.load(r)
                    assert payload['status']=='ok';outcomes.append(payload)
                assert [r['decision'] for r in outcomes]==['ALLOW','BLOCK']
                results.append(dict(config=config,health=health,contract=contract,classifications=outcomes))
                print(config+' real HTTP profile PASS',flush=True)
            finally:
                if proc.poll() is None:
                    proc.terminate()
                    try:proc.wait(timeout=15)
                    except subprocess.TimeoutExpired:proc.kill();proc.wait()
                log.close()
        sources={str(p.relative_to(REPO)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [REPO/'control_plane/v5_inference_core.py',REPO/'control_plane/v5_classifier_api.py',REPO/'control_plane/v5_runtime_profile.py',Path(__file__)]}
        (evidence/'service_profile_verification.json').write_text(json.dumps({'passed':len(results),'profiles':results,'source_sha256':sources},indent=2)+'\n')
    finally:STATUS.write_text(json.dumps(dict(owner='Codex',state='SERVICE_PROFILE_STAGE_FINISHED',UTC=time.time()),indent=2)+'\n')
if __name__=='__main__':main()
