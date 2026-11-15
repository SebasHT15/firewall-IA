"""Verify native source-census and SQLi-v3 evidence for V5 component binding.

This keeps each prospective campaign's own schema and result. It does not
serialize a source census as the older PF2/R3 campaign or combine outcomes.
"""
import hashlib
import json
from pathlib import Path

import adjudicate_v5_r4_continuation as R
import v5_pools_common as C
from parse_dataset_v4 import canonical_key

SCHEMA='v5-native-source-audit-evidence/v1'
STATUS={'PASS_AI_AUDITED','NOT_SUPPORTED','INSUFFICIENT_EVIDENCE'}

def _sha(raw):return hashlib.sha256(raw).hexdigest()

def _read(desc,committed_checker=None):
    if type(desc) is not dict or type(desc.get('path')) is not str or type(desc.get('sha256')) is not str:
        raise ValueError('native audit descriptor missing')
    path=Path(desc['path'])
    if not path.is_absolute():path=Path(C.REPO_ROOT)/path
    C.assert_not_protected(str(path))
    if committed_checker is not None and not committed_checker(str(path)):
        raise ValueError(f'native audit evidence must be committed and unchanged: {path}')
    raw=path.read_bytes()
    if _sha(raw)!=desc['sha256']:raise ValueError(f'native audit hash mismatch: {path}')
    return raw

def _doc(desc,check=None):return json.loads(_read(desc,check))
def _rows(raw):return [json.loads(x) for x in raw.splitlines() if x.strip()]
def _map(rows,key):
    out={r[key]:r for r in rows}
    if len(out)!=len(rows):raise ValueError(f'duplicate {key} in native audit')
    return out

def _outcomes(traces,prereg):
    result=R.summarize(traces,prereg)
    if any(v['status'] not in STATUS for v in result.values()):raise ValueError('invalid native outcome')
    return result

def _check_original_trace(trace):
    label,rule=R.adjudicate(trace['a1'],trace['a2'],trace['r3'])
    if label!=trace['adjudicated_label'] or rule!=trace['rule']:
        raise ValueError('native trace differs from frozen adjudication')

def _census(binding,result,pool_rows,check):
    prereg=_doc(binding['preregistration'],check)
    source_raw=_read(binding['source_population'],check)
    base_raw=_read(binding['base_result'],check)
    decision_raw=_read(binding['owner_decision'],check)
    base=json.loads(base_raw);decision=json.loads(decision_raw)
    source=_rows(source_raw)
    if (_sha(source_raw)!=prereg['population']['sha256'] or
        len(source)!=prereg['population']['rows'] or
        result['population_sha256']!=_sha(source_raw) or
        base['population_sha256']!=_sha(source_raw) or
        result['preregistration_sha256']!=_sha(_read(binding['preregistration'],check))):
        raise ValueError('native census population/preregistration mismatch')
    if (result['schema']!='v5-contextual-source-census-owner-resolved/v1' or
        base['schema']!='v5-contextual-source-census-result/v2' or
        result['base_result_sha256']!=_sha(base_raw) or
        result['owner_decision_sha256']!=_sha(decision_raw) or
        decision['base_result_sha256']!=_sha(base_raw)):
        raise ValueError('native census decision chain mismatch')
    if (decision.get('decision_status')!='APPROVED_IN_CHAT_NOT_CRYPTOGRAPHICALLY_SIGNED' or
        decision.get('owner_chat_quote')!='Sí, aprobar las cuatro como UNCERTAIN' or
        decision.get('disposition_type')!='RESOLVE_WITH_EVIDENCE' or
        decision.get('resolved_label')!='UNCERTAIN' or
        decision.get('training_authorized') is not False):
        raise ValueError('native census owner disposition invalid')
    source_ids=_map(source,'sample_id')
    if set(source_ids)!=set(pool_rows) or len(base['traces'])!=len(source):
        raise ValueError('native census stage-2 pool membership mismatch')
    for rid,s in source_ids.items():
        p=pool_rows[rid];ss=s['source']
        if (p['payload_wire']!=s['payload_wire'] or p['payload_logical']!=s['payload_wire'] or
            p['payload_raw']!=s['payload_wire'] or p['category_v4']!=s['category'] or
            p['dedup_scope']!=s['category'] or p['canonical_key']!=canonical_key(s['payload_wire']) or
            p['source_file']!=ss['source_file'] or p['source_sha256']!=ss['source_sha256'] or
            p['source_utf8_byte_start']!=ss['utf8_byte_start'] or
            p['source_utf8_byte_end']!=ss['utf8_byte_end'] or p['proposed_context']!=s['proposed_context']):
            raise ValueError(f'native census pool projection mismatch: {rid}')
    old=_map(base['traces'],'sample_id');new=_map(result['traces'],'sample_id')
    if set(old)!=set(source_ids) or set(new)!=set(source_ids):
        raise ValueError('native census trace coverage mismatch')
    ids=set(decision['sample_ids'])
    if len(ids)!=4 or ids!={rid for rid,t in old.items() if t['adjudicated_label'] is None}:
        raise ValueError('owner disposition does not match exactly four unresolved cases')
    for rid,t in old.items():
        _check_original_trace(t)
        u=new[rid]
        if rid in ids:
            expected={**t,'adjudicated_label':'UNCERTAIN',
                      'owner_disposition':{'type':'RESOLVE_WITH_EVIDENCE','decision_sha256':_sha(decision_raw)}}
        else:expected=t
        if u!=expected:raise ValueError(f'native census vote or label modified: {rid}')
    if base['category_outcomes']!=_outcomes(base['traces'],prereg):
        raise ValueError('native census base result does not recompute')
    if result['category_outcomes']!=_outcomes(result['traces'],prereg):
        raise ValueError('native census owner result does not recompute')
    return result['category_outcomes']

def _sqli(binding,result,pool_rows,check):
    prereg_raw=_read(binding['preregistration'],check)
    prereg=json.loads(prereg_raw)
    auth_raw=_read(binding['authorization'],check)
    auth=json.loads(auth_raw)
    sample_raw=_read(binding['sample'],check)
    sample=_rows(sample_raw)
    if (result['schema']!='sqli-v3-prospective-result/v1' or
        result['preregistration_sha256']!=_sha(prereg_raw) or
        result['population_sha256']!=binding['pool']['sha256'] or
        result['sample_sha256']!=_sha(sample_raw) or
        result['authorization_sha256']!=_sha(auth_raw) or
        auth.get('owner_approved') is not True or
        auth.get('training_authorized') is not False or
        auth.get('preregistration_sha256')!=_sha(prereg_raw) or
        auth.get('population_sha256')!=binding['pool']['sha256'] or
        auth.get('sample_sha256')!=_sha(sample_raw) or
        prereg['population']['sha256']!=binding['pool']['sha256'] or
        prereg['sample']['sha256']!=_sha(sample_raw) or
        len(sample)!=prereg['sample']['rows']):
        raise ValueError('SQLi-v3 sealed preregistration/sample mismatch')
    sample_ids=[r['record_id'] for r in sample]
    if len(set(sample_ids))!=len(sample_ids) or not set(sample_ids)<=set(pool_rows):
        raise ValueError('SQLi-v3 sample membership mismatch')
    if any({k:pool_rows[r['record_id']].get(k) for k in r}!=r for r in sample):
        raise ValueError('SQLi-v3 sample differs from pinned pool')
    roles={'a1':'gpt-6.1-sol','a2':'gpt-6-astra','r3':'gpt-6-sol'}
    answers={}
    for role,model in roles.items():
        raw=_read(binding['handbacks'][role],check)
        evidence_raw=_read(binding['session_evidence'][role],check)
        evidence=json.loads(evidence_raw)
        prov=next((p for p in result['provenance'] if p['role']==role),None)
        if (prov is None or prov['model_requested']!=model or
            prov['handback_sha256']!=_sha(raw) or
            prov['session_evidence_sha256']!=_sha(evidence_raw) or
            evidence['model_in_turn_context']!=[model] or
            evidence['selected_final_answer_sha256_terminal_lf']!=_sha(raw) or
            evidence['preregistration_sha256']!=_sha(prereg_raw) or
            evidence['sample_sha256']!=_sha(sample_raw)):
            raise ValueError(f'SQLi-v3 reviewer provenance mismatch: {role}')
        answers[role]=_rows(raw)
        if [r['sample_id'] for r in answers[role]]!=sample_ids:
            raise ValueError(f'SQLi-v3 handback coverage mismatch: {role}')
    traces=[]
    for rid in sample_ids:
        i=sample_ids.index(rid)
        votes={role:answers[role][i]['label_class'] for role in roles}
        label,rule=R.adjudicate(votes['a1'],votes['a2'],votes['r3'])
        traces.append({'sample_id':rid,'category':'SQL Injection',**votes,
                       'adjudicated_label':label,'rule':rule})
    if traces!=result['traces']:
        raise ValueError('SQLi-v3 result differs from frozen votes')
    criteria=prereg['criteria_r4']
    common={'acceptance_criteria':{'C1':{'limit':criteria['C1']['limit']},
                                   'C2':{'limit':criteria['C2']['limit']}},
            'wilson':{'z':criteria['wilson_z']}}
    if result['category_outcomes']!=_outcomes(traces,common):
        raise ValueError('SQLi-v3 result does not recompute')
    return result['category_outcomes']

def verify(binding,*,expected_pool_sha256=None,expected_outcomes=None,records=None,
           record_ids=None,committed_checker=None):
    if type(binding) is not dict or binding.get('schema')!=SCHEMA:
        raise ValueError('native source audit binding schema invalid')
    kind=binding.get('kind')
    if kind not in ('census-owner-resolved','sqli-v3'):
        raise ValueError('native source audit kind invalid')
    pool_raw=_read(binding['pool'],committed_checker)
    pool_rows=_map(_rows(pool_raw),'record_id')
    manifest=_doc(binding['pool_manifest'],committed_checker)
    manifest_sha=manifest.get('pool_sha256',manifest.get('population_sha256'))
    manifest_rows=manifest.get('records',manifest.get('population_rows'))
    if manifest_sha!=_sha(pool_raw) or manifest_rows!=len(pool_rows):
        raise ValueError('native pool manifest mismatch')
    if expected_pool_sha256 is not None and expected_pool_sha256!=_sha(pool_raw):
        raise ValueError('native dataset and audited pool differ')
    result=_doc(binding['result'],committed_checker)
    if kind=='census-owner-resolved':outcomes=_census(binding,result,pool_rows,committed_checker)
    else:outcomes=_sqli(binding,result,pool_rows,committed_checker)
    mapped={cat:('FAIL' if value['status']=='NOT_SUPPORTED' else value['status'])
            for cat,value in outcomes.items()}
    if expected_outcomes is not None and mapped!=expected_outcomes:
        raise ValueError('native declared outcomes differ from verified result')
    for rid in record_ids or ():
        if rid not in pool_rows:raise ValueError(f'native dataset record absent from audited pool: {rid}')
    for row in records or ():
        source=pool_rows.get(row.get('record_id'))
        if source is None:raise ValueError('native world record absent from audited pool')
        for field in ('payload_wire','dedup_scope','category_v4','source_file','payload_raw'):
            if field in source and row.get(field)!=source[field]:
                raise ValueError(f'native world record differs from audited pool: {field}')
    return {'category_outcomes':mapped,'audit_type':'ai_audited',
            'pool_sha256':_sha(pool_raw),
            'sha256':{k:v['sha256'] for k,v in binding.items() if isinstance(v,dict) and 'sha256' in v}}
