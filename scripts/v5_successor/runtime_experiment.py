"""Balanced order, three fresh processes/configuration, one GPU, no fitting."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import threading
import time

REPO = Path(__file__).resolve().parents[2]
OUT = REPO/'reports/v5/successor-2026-10-30/runtime'
PREVIOUS = REPO/'reports/v5/hybrid/experiments-2026-10-30'
PRIVATE = '/home/sebas/Documents/Codex/2026-10-26/ta/work/metrics-2026-10-30/inputs.private.jsonl'
STATUS = Path('/home/sebas/Documents/Codex/2026-10-26/ta/outputs/Coordinacion_modelos_arquitectura/GPU_STATUS.json')


def main():
    if (OUT/'protocol.json').exists():
        raise RuntimeError('Output exists; do not overwrite evidence')
    OUT.mkdir(parents=True, exist_ok=True)
    old = json.loads((PREVIOUS/'protocol.json').read_text())
    rows = [json.loads(l) for l in (PREVIOUS/'v5_run1.jsonl').read_text().splitlines()]
    ids = [r['id'] for r in rows if r['phase']=='benchmark' and r['measure']['generated_tokens']>0]
    protocol = dict(scope='DEVELOPMENT inference runtime comparison; no training, protected data or operational approval',
        private_inputs_sha256=old['private_inputs_sha256'], adapter_sha256='c27e363fe76190f5cb4be77f02e110419ab5d95ef5ee1f959a238ba99bc72393',
        benchmark_ids=ids, eligibility='Original benchmark IDs excluding content-boundary rejection; same 95 IDs/order for every configuration',
        configs=['nf4_dq','nf4','bf16'], cold=1, warmup=4, batch_size=1, concurrency=1,
        runs=[['nf4_dq',1],['nf4',1],['bf16',1],['bf16',2],['nf4_dq',2],['nf4',2],['nf4',3],['bf16',3],['nf4_dq',3]],
        percentile='nearest rank; no trimming', utc=time.time())
    protocol['source_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__),Path(__file__).with_name('runtime_worker.py'),REPO/'control_plane/v5_inference_core.py']}
    (OUT/'protocol.json').write_text(json.dumps(protocol,indent=2)+'\n')
    STATUS.write_text(json.dumps(dict(owner='Codex',state='BUSY',task='V5 controlled runtime profiling',pid=os.getpid(),UTC=time.time(),rule='Claude: CPU/doubles only; do not start GPU jobs until explicit handoff'),indent=2)+'\n')
    stop=threading.Event()
    def monitor():
        with (OUT/'gpu_telemetry.jsonl').open('x') as f:
            while not stop.is_set():
                p=subprocess.run(['nvidia-smi','--query-gpu=timestamp,temperature.gpu,clocks.sm,utilization.gpu,memory.used,power.draw','--format=csv,noheader,nounits'],capture_output=True,text=True)
                f.write(json.dumps(dict(UTC=time.time(),csv=p.stdout.strip(),error=p.stderr.strip()))+'\n');f.flush();stop.wait(1)
    thread=threading.Thread(target=monitor,daemon=True);thread.start()
    env=dict(os.environ,HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1',PYTHONDONTWRITEBYTECODE='1',TOKENIZERS_PARALLELISM='false')
    try:
        for config,run in protocol['runs']:
            name=f'{config}_run{run}'
            print('START '+name,flush=True)
            with (OUT/(name+'.log')).open('x') as log:
                subprocess.run(['/usr/bin/python3.12','-B',str(Path(__file__).with_name('runtime_worker.py')),'--config',config,'--run',str(run),'--private',PRIVATE,'--out',str(OUT)],cwd=REPO,env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
            print('DONE '+name,flush=True)
        (OUT/'execution_complete.json').write_text(json.dumps(dict(status='complete',UTC=time.time()))+'\n')
    except BaseException as exc:
        (OUT/'execution_error.json').write_text(json.dumps(dict(type=type(exc).__name__,error=str(exc),UTC=time.time()))+'\n')
        raise
    finally:
        stop.set();thread.join(timeout=3)
        STATUS.write_text(json.dumps(dict(owner='Codex',state='PROFILING_STAGE_FINISHED_RESERVED_FOR_FOLLOWUP',UTC=time.time(),rule='Further model experiments/training pending; CPU/doubles until explicit handoff'),indent=2)+'\n')

if __name__=='__main__':
    main()
