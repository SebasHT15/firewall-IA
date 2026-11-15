"""Run GPU stages serially. Own and clean up only the service we start."""
import sys,os,subprocess,time,json,socket,urllib.request,threading,hashlib,platform
from pathlib import Path
REPO=Path(__file__).resolve().parents[3]; HERE=Path(__file__).resolve().parent
OUT=REPO/'reports/v5/hybrid/experiments-2026-10-30'
PRIVATE='/home/sebas/Documents/Codex/2026-10-26/ta/work/metrics-2026-10-30/inputs.private.jsonl'
ENV=dict(os.environ,HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1',PYTHONDONTWRITEBYTECODE='1',TOKENIZERS_PARALLELISM='false')
def main():
    initial=subprocess.check_output(['git','status','--porcelain=v1'],cwd=REPO,text=True)
    (OUT/'initial_git_status.txt').write_text(initial)
    env={'platform':platform.platform(),'python':sys.version,'git_head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip(),'cpu':subprocess.check_output(['lscpu'],text=True),'started_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'packages':subprocess.check_output(['/usr/bin/python3.12','-m','pip','freeze'],text=True),'analyzer_packages':subprocess.check_output([str(REPO/'.venv-analyzer/bin/python'),'-m','pip','freeze'],text=True)}
    (OUT/'environment.json').write_text(json.dumps(env,indent=2)+'\n')
    stop=threading.Event()
    def monitor():
        with (OUT/'gpu_telemetry.jsonl').open('w') as f:
            while not stop.is_set():
                p=subprocess.run(['nvidia-smi','--query-gpu=timestamp,name,temperature.gpu,utilization.gpu,memory.used,power.draw,clocks.sm','--format=csv,noheader,nounits'],capture_output=True,text=True)
                f.write(json.dumps({'utc':time.time(),'csv':p.stdout.strip(),'error':p.stderr.strip()})+'\n');f.flush();stop.wait(1)
    monitor_thread=threading.Thread(target=monitor,daemon=True);monitor_thread.start()
    def run(name,command):
        print('START '+name,flush=True)
        with (OUT/(name+'.log')).open('w') as log:
            p=subprocess.Popen(command,cwd=REPO,env=ENV,stdout=log,stderr=subprocess.STDOUT)
            code=p.wait()
        if code:raise RuntimeError(f'{name} failed ({code}); see log')
        print('DONE '+name,flush=True)
    service=None; service_log=None
    try:
        for index,(model,rep) in enumerate([('v4',1),('v5',1),('v5',2),('v4',2),('v4',3),('v5',3)]):
            run(f'{model}_run{rep}',['/usr/bin/python3.12','-B',str(HERE/'model_worker.py'),'--model',model,'--run',str(rep),'--private',PRIVATE,'--out',str(OUT)])
        with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        service_log=(OUT/'v5_service.log').open('w')
        service=subprocess.Popen(['/usr/bin/python3.12','-B','-m','uvicorn','--app-dir','control_plane','v5_classifier_api:app','--host','127.0.0.1','--port',str(port)],cwd=REPO,env=ENV,stdout=service_log,stderr=subprocess.STDOUT)
        url=f'http://127.0.0.1:{port}'; deadline=time.monotonic()+90
        while True:
            if service.poll() is not None:raise RuntimeError('V5 service exited')
            try:
                with urllib.request.urlopen(url+'/health',timeout=2) as r:h=json.load(r)
                if h['model_loaded']:
                    assert h['adapter_sha256']=='c27e363fe76190f5cb4be77f02e110419ab5d95ef5ee1f959a238ba99bc72393'
                    (OUT/'service_health.json').write_text(json.dumps(h,indent=2)+'\n');break
            except (OSError,ValueError):pass
            if time.monotonic()>deadline:raise RuntimeError('V5 readiness timeout')
            time.sleep(.5)
        run('live_experiments',[str(REPO/'.venv-analyzer/bin/python'),'-B',str(HERE/'live.py'),'--private',PRIVATE,'--out',str(OUT),'--url',url])
        run('real_routes',[str(REPO/'.venv-analyzer/bin/python'),'-B',str(REPO/'scripts/cascade_lab/integration_check.py')]) if False else None
        # integration check uses an explicit URL environment, never an existing service.
        route_env=dict(ENV,FIREWALL_V5_URL=url)
        with (OUT/'real_routes.log').open('w') as f:
            subprocess.run([str(REPO/'.venv-analyzer/bin/python'),'-B','scripts/cascade_lab/integration_check.py'],cwd=REPO,env=route_env,stdout=f,stderr=subprocess.STDOUT,check=True)
        (OUT/'execution_complete.json').write_text(json.dumps({'status':'all_stages_complete','utc':time.time(),'trained':False,'protected_sets_read':False})+'\n')
    except BaseException as e:
        (OUT/'execution_error.json').write_text(json.dumps({'type':type(e).__name__,'message':str(e),'utc':time.time()})+'\n');raise
    finally:
        if service and service.poll() is None:
            service.terminate()
            try:service.wait(timeout=15)
            except subprocess.TimeoutExpired:service.kill();service.wait()
        if service_log:service_log.close()
        stop.set();monitor_thread.join(timeout=3)
        (OUT/'final_git_status.txt').write_text(subprocess.check_output(['git','status','--porcelain=v1'],cwd=REPO,text=True))
if __name__=='__main__':main()
