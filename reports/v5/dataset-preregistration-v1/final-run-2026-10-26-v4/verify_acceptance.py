#!/usr/bin/env python3
"""Execute factual v4 acceptance controls, no target-model training or protected evaluation."""
from pathlib import Path
import json,subprocess,sys,hashlib
R=Path(__file__).resolve().parents[4];D=Path(__file__).resolve().parent
DS=R/'datasets/v5_sources/final_source_2026-10-26-v4';ATT=R/'datasets/v5_sources/hygiene_inputs_2026-10-26-v4/attack_pool.jsonl';PY=R/'.venv-analyzer/bin/python'
commands=[
 ['scripts/dataset/v5_protected_collision_check.py',str(DS),'--out',str(D/'protected-collision-counts.json')],
 ['scripts/dataset/v5_cs7_check.py',str(DS),'--preregistration',str(D/'preregistration.json'),'--out',str(D/'cs7-counts.json')],
 ['scripts/dataset/v5_shortcut_checks.py',str(DS),'--out',str(D/'shortcut-partial.json')],
 ['scripts/dataset/v5_token_purity.py',str(DS),'--out',str(D/'token-purity.json')],
 ['scripts/dataset/v5_structure_probe.py',str(DS),'--out',str(D/'structure-probe.json')],
 ['scripts/dataset/v5_novelty_ancestry.py',str(DS),'--attack-pool',str(ATT),'--out',str(D/'novelty-ancestry.json')],
 ['reports/v5/freeze-prep-claude-2026-10-26/h1_identity_secrets_scan.py',str(DS),str(D/'h1-identity-secrets.json')],
 ['scripts/dataset/v5_freeze_precheck.py','--dataset',str(DS),'--attack-pool',str(ATT),'--collisions',str(D/'protected-collision-counts.json'),'--cs7',str(D/'cs7-counts.json'),'--out',str(D/'freeze-precheck.json')],
]
execution=[]
for command in commands:
 p=subprocess.run([str(PY),'-B',*command],cwd=R,text=True,capture_output=True)
 execution.append({'command':[str(PY),'-B',*command],'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
 print(Path(command[0]).name,p.returncode,p.stdout[-300:].strip(),flush=True)
 if p.returncode:raise SystemExit(p.stderr[-1500:])
(D/'acceptance-execution.json').write_text(json.dumps(execution,indent=2,sort_keys=True)+'\n')
load=lambda n:json.loads((D/n).read_text())
checks={
 'L7':load('protected-collision-counts.json')['blocking_pass'],
 'C-S7':load('cs7-counts.json')['blocking_pass'],
 'C-S1_S2_S6':load('shortcut-partial.json')['blocking_pass_for_checks_run'],
 'C-S3':load('token-purity.json')['blocking_pass'],
 'C-S4':load('structure-probe.json')['status']=='PASS',
 'H1':load('h1-identity-secrets.json')['H1_pass_on_v3'],
 'precheck':load('freeze-precheck.json')['checks_run_pass']}
result={'schema':'v5-v4-acceptance/v1','blocking_controls':checks,'blocking_pass':all(checks.values()),
 'manifest_sha256':hashlib.sha256((DS/'manifest.json').read_bytes()).hexdigest(),
 'freeze_authorized_by_this_report':False,'trained':False,'warnings':{'L10':load('novelty-ancestry.json')['splits'],'L11_hit_records':len(load('novelty-ancestry.json')['L11_unique_hit_record_ids'])}}
(D/'acceptance.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
print(json.dumps({'blocking_controls':checks,'blocking_pass':all(checks.values())}))
raise SystemExit(0 if result['blocking_pass'] else 1)
