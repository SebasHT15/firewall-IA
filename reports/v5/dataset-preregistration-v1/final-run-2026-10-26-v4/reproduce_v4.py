#!/usr/bin/env python3
"""A2 for the new v4 (not a repeat of v3's accredited A2). No training."""
from pathlib import Path
import concurrent.futures,hashlib,json,os,subprocess
R=Path(__file__).resolve().parents[4];D=Path(__file__).resolve().parent;SRC=R/'datasets/v5_sources/final_source_2026-10-26-v4'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def git(*a):return subprocess.check_output(['git',*a],cwd=R,text=True).strip()
head=git('rev-parse','HEAD');dirty=git('status','--porcelain','--untracked-files=no')
if dirty:raise SystemExit('A2 requires clean tracked tree')
m=json.loads((SRC/'manifest.json').read_text());arts=m['artifacts'];before=sha(SRC/'manifest.json')
def run(seed):
 out=R/f'datasets/v5_sources/regeneration-v4-seed{seed}'
 if out.exists():raise ValueError('Never overwrite a regeneration')
 cmd=['/usr/bin/python3','-B',str(R/'scripts/dataset/v5_pilot_inputs.py'),'prepare',
 '--pilot-pools','/home/sebas/Documents/Codex/2026-10-22/firewall-c1-model2-continuidad/work/pilot-integration-007/pools',
 '--benign-pools',str(R/'datasets/v5_sources/hygiene_inputs_2026-10-26-v4/benign'),
 '--attack-pool',str(R/'datasets/v5_sources/hygiene_inputs_2026-10-26-v4/attack_pool.jsonl'),
 '--build-authorization',str(D/'build-authorization.json'),'--dataset-prereg',str(D/'preregistration.json'),
 '--split-config',str(D/'split-config.json'),'--generator-config',str(D/'generator-config.json'),'--out',str(out)]
 cwd=R if seed==17 else Path('/tmp');env=dict(os.environ,PYTHONHASHSEED=str(seed))
 with (D/f'a2-seed{seed}.log').open('w')as f:p=subprocess.run(cmd,cwd=cwd,env=env,stdout=f,stderr=subprocess.STDOUT)
 diffs=[x['path']for x in arts if not(out/x['path']).is_file()or sha(out/x['path'])!=x['sha256']]
 return {'seed':seed,'cwd':str(cwd),'command':cmd,'exit_code':p.returncode,'fresh_process':True,'directory':str(out),
         'manifest_sha256':sha(out/'manifest.json') if(out/'manifest.json').is_file()else None,
         'manifest_byte_equal':(out/'manifest.json').is_file()and sha(out/'manifest.json')==before,'artifacts_compared':len(arts),'artifact_differences':diffs}
with concurrent.futures.ThreadPoolExecutor(max_workers=2)as ex:runs=list(ex.map(run,[17,83]))
after=git('rev-parse','HEAD');dirty_after=git('status','--porcelain','--untracked-files=no')
report={'schema':'v5-A2-regeneration/v4','base_manifest_sha256':before,'python':subprocess.check_output(['/usr/bin/python3','--version'],text=True).strip(),
 'head_before':head,'head_after':after,'tracked_dirty_before':bool(dirty),'tracked_dirty_after':bool(dirty_after),'regenerations':runs,
 'A2_pass':all(x['exit_code']==0 and x['manifest_byte_equal']and not x['artifact_differences']for x in runs)and head==after and not dirty_after}
(D/'A2-regeneration.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');print(json.dumps({'A2_pass':report['A2_pass'],'manifest':before}))
raise SystemExit(0 if report['A2_pass']else 1)
