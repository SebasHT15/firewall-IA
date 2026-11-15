#!/usr/bin/env python3
"""Deterministically project the audited source census to the stage-2 pool interface.

The source population and all payload bytes remain immutable. The projection
introduces only the fields required by the V5 dataset builder. It does not
transfer the original pool's outcome or label individual payloads VERIFIED.
"""
import hashlib
import json
import sys
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROOT=Path('/home/sebas/Desktop/firewall-IA')
sys.path.insert(0,str(ROOT/'scripts/dataset'))
from parse_dataset_v4 import canonical_key
sha=lambda raw:hashlib.sha256(raw).hexdigest()
source_raw=(HERE/'population.jsonl').read_bytes()
prereg=json.loads((HERE/'preregistration.json').read_bytes())
assert sha(source_raw)==prereg['population']['sha256']
result=json.loads((HERE/'result.json').read_bytes())
assert result['population_sha256']==sha(source_raw)
rows=[]
for line in source_raw.splitlines():
    if not line:continue
    src=json.loads(line)
    s=src['source'];wire=src['payload_wire'];cat=src['category']
    assert result['category_outcomes'][cat]['status'] in ('PASS_AI_AUDITED','NOT_SUPPORTED')
    row={'record_id':src['sample_id'],'category_v4':cat,'dedup_scope':cat,
         'd47_category':{'Command Injection':'command_injection','SQL Injection':'sql_injection',
                         'Server Side Template Injection':'ssti','XSS Injection':'xss'}[cat],
         'payload_wire':wire,'payload_logical':wire,'payload_raw':wire,
         'payload_wire_form':'plain','canonical_key':canonical_key(wire),
         'source_file':s['source_file'],'source_sha256':s['source_sha256'],
         'source_utf8_byte_start':s['utf8_byte_start'],
         'source_utf8_byte_end':s['utf8_byte_end'],
         'proposed_context':src['proposed_context'],
         'status':'ACCEPTED','label_status':'PENDING_ADJUDICATION',
         'exclusion_reason':None,'native_forms':[],
         'reason_string':{'Command Injection':'Command injection payload detected.',
                          'SQL Injection':'SQL injection payload detected.',
                          'Server Side Template Injection':'Server-side template injection payload detected.',
                          'XSS Injection':'Cross-site scripting payload detected.'}[cat],
         'audit_source_sample_id':src['sample_id']}
    assert row['canonical_key']
    rows.append(row)
assert len(rows)==166 and len({r['record_id'] for r in rows})==166
raw=''.join(json.dumps(r,ensure_ascii=False,sort_keys=True)+'\n' for r in rows).encode()
(HERE/'stage2-pool.jsonl').write_bytes(raw)
manifest={'schema':'v5-contextual-source-stage2-pool/v1','status':'CATEGORY_AUDITED_NOT_FROZEN',
          'source_population_sha256':sha(source_raw),'owner_result_sha256':sha((HERE/'result.json').read_bytes()),
          'pool_sha256':sha(raw),'records':len(rows),'training_authorized':False,
          'projection_implementation_sha256':sha(Path(__file__).read_bytes())}
(HERE/'stage2-manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
(HERE/'SHA256SUMS').write_text(''.join(f'{sha((HERE/name).read_bytes())}  {name}\n' for name in ('PROPOSAL.md','owner-decision.json','result.json','base-result.json','preregistration.json','population.jsonl','stage2-pool.jsonl','stage2-manifest.json','prepare_stage2_pool.py','consume_owner_decision.py')))
print(json.dumps({'records':len(rows),'pool_sha256':sha(raw)}))
