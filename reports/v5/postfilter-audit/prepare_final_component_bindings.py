#!/usr/bin/env python3
"""Pin three independent audited components for the six-category V5 pool."""
import hashlib
import json
import sys
from pathlib import Path

ROOT=Path('/home/sebas/Desktop/firewall-IA')
sys.path.insert(0,str(ROOT/'scripts/dataset'))
import v5_audit_evidence as AE
import v5_component_binding as CB

def desc(rel):
    raw=(ROOT/rel).read_bytes()
    return {'path':rel,'sha256':hashlib.sha256(raw).hexdigest()}

c='reports/v5/postfilter-audit/source-census-owner-review-2026-10-25/'
s='reports/v5/postfilter-audit/sqli-v3-source-first/'
old=json.loads((ROOT/'reports/v5/training-readiness/INTEGRACION_AUDIT_EVIDENCE_2026-10-23.json').read_bytes())['binding']
components=[
 {'component_id':'original-path-file-access','categories':['path_file_access'],
  'category_outcomes':AE.verify(old)['category_outcomes'],'audit_evidence':old},
 {'component_id':'contextual-source-census-166','categories':['Command Injection','Server Side Template Injection','XSS Injection'],
  'category_outcomes':{'Command Injection':'PASS_AI_AUDITED','SQL Injection':'FAIL',
      'Server Side Template Injection':'PASS_AI_AUDITED','XSS Injection':'PASS_AI_AUDITED'},
  'audit_evidence':{'schema':'v5-native-source-audit-evidence/v1','kind':'census-owner-resolved',
    'pool':desc(c+'stage2-pool.jsonl'),'pool_manifest':desc(c+'stage2-manifest.json'),
    'result':desc(c+'result.json'),'preregistration':desc(c+'preregistration.json'),
    'source_population':desc(c+'population.jsonl'),'base_result':desc(c+'base-result.json'),
    'owner_decision':desc(c+'owner-decision.json')}},
 {'component_id':'sqli-v3-source-first','categories':['SQL Injection'],
  'category_outcomes':{'SQL Injection':'PASS_AI_AUDITED'},
  'audit_evidence':{'schema':'v5-native-source-audit-evidence/v1','kind':'sqli-v3',
    'pool':desc(s+'pool.jsonl'),'pool_manifest':desc(s+'manifest.json'),
    'result':desc(s+'validation-codex-v3/result.json'),
    'preregistration':desc(s+'preregistration.json'),'sample':desc(s+'sample_n50.jsonl'),
    'authorization':desc(s+'execution-authorization.CITED.json'),
    'handbacks':{role:desc(s+f'validation-codex-v3/{role}.handback.jsonl') for role in ('a1','a2','r3')},
    'session_evidence':{role:desc(s+f'validation-codex-v3/{role}.session-evidence.json') for role in ('a1','a2','r3')}}}
]
for comp in components:
    got=AE.verify(comp['audit_evidence'],expected_outcomes=comp['category_outcomes'])
    assert got['audit_type']=='ai_audited'
rows=[]
for comp in components:
    declared=set(comp['categories'])
    for line in (ROOT/comp['audit_evidence']['pool']['path']).read_text().splitlines():
        r=json.loads(line)
        category=next((r.get(k) for k in ('category_v4','d47_category','dedup_scope')
                       if r.get(k) in declared),None)
        if category is not None:
            rows.append({'meta':{'label':'BLOCK','attack_category':category,
                                 'payload_record_id':r['record_id'],'payload_wire':r['payload_wire']}})
resolved=CB.resolve_components(rows,components)
if resolved['diags'] or set(resolved['merged_outcomes'].values())!={'PASS_AI_AUDITED'}:
    raise ValueError(f'actual component row binding failed: {resolved["diags"][:3]}')
out={'schema':'v5-component-evidence-assembly/v1','status':'VERIFIED_NOT_FROZEN',
     'components':components,'verified_row_count':len(rows),
     'training_authorized':False,'combined_pool_pass':False}
path=ROOT/'reports/v5/postfilter-audit/final-component-bindings.json'
path.write_text(json.dumps(out,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
print(json.dumps({'components':[c['component_id'] for c in components],
                  'verified_rows':len(rows),
                  'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}))
