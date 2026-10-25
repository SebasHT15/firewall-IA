#!/usr/bin/env python3
"""Assemble only rows admitted by their owning, independently verified component."""
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

ROOT=Path('/home/sebas/Desktop/firewall-IA')
sys.path.insert(0,str(ROOT/'scripts/dataset'))
import v5_audit_evidence as AE
import v5_component_binding as CB

sha=lambda raw:hashlib.sha256(raw).hexdigest()
components_path=ROOT/'reports/v5/postfilter-audit/final-component-bindings.json'
components=json.loads(components_path.read_bytes())['components']
selected={}
for component in components:
    outcomes=AE.verify(component['audit_evidence'],expected_outcomes=component['category_outcomes'])['category_outcomes']
    declared=set(component['categories'])
    assert all(outcomes[cat]=='PASS_AI_AUDITED' for cat in declared)
    path=ROOT/component['audit_evidence']['pool']['path']
    for line in path.read_text().splitlines():
        record=json.loads(line)
        category=next((record.get(k) for k in ('category_v4','d47_category','dedup_scope')
                       if record.get(k) in declared),None)
        if category is None:continue
        rid=record['record_id']
        if rid in selected:raise ValueError(f'overlapping authoritative record: {rid}')
        selected[rid]=(record,component['component_id'],category)
assert len(selected)==1816
rows=[selected[k][0] for k in sorted(selected)]
check_rows=[{'meta':{'label':'BLOCK','attack_category':selected[r['record_id']][2],
                     'payload_record_id':r['record_id'],'payload_wire':r['payload_wire']}} for r in rows]
resolved=CB.resolve_components(check_rows,components)
if resolved['diags']:raise ValueError(f'component binding failed: {resolved["diags"][:3]}')
out=ROOT/'datasets/v5_sources/final_candidate'
out.mkdir(parents=True,exist_ok=True)
raw=''.join(json.dumps(r,ensure_ascii=False,sort_keys=True)+'\n' for r in rows).encode()
(out/'attack_pool.jsonl').write_bytes(raw)
manifest={'schema':'v5-attack-pool-component-assembly/v1','status':'ADMITTED_CANDIDATE_NOT_FROZEN',
          'records':len(rows),'by_audit_category':dict(Counter(selected[r['record_id']][2] for r in rows)),
          'pool_sha256':sha(raw),'components_sha256':sha(components_path.read_bytes()),
          'component_outcomes':resolved['merged_outcomes'],
          'combined_pool_pass':False,'training_authorized':False}
(out/'manifest.json').write_text(json.dumps(manifest,sort_keys=True,ensure_ascii=False,indent=2)+'\n')
print(json.dumps({'records':len(rows),'by_audit_category':manifest['by_audit_category'],
                  'pool_sha256':sha(raw)}))
