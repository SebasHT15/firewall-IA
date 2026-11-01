"""Audit reference provenance and coverage; never relabel from a detector."""
import ast
from collections import Counter, defaultdict
import csv
import hashlib
import json
from pathlib import Path

REPO=Path(__file__).resolve().parents[2]
OUT=REPO/'reports/v5/successor-2026-10-30/coverage'
BASE=REPO/'reports/v5/hybrid/experiments-2026-10-30'
PRIVATE=Path('/home/sebas/Documents/Codex/2026-10-26/ta/work/metrics-2026-10-30/inputs.private.jsonl')
PRIMARY={'sql_injection','xss','command_injection','path_file_access','ssti'}
LEGACY_PRIMARY={'SQL injection payload detected.','Cross-site scripting payload detected.','Command injection payload detected.','Path traversal attack detected.','File inclusion attack detected.','Server-side template injection payload detected.'}

def main():
    OUT.mkdir(exist_ok=True,parents=True)
    data=[json.loads(l) for l in PRIVATE.read_text().splitlines()]
    inputs={r['id']:r for r in data}
    current={r['id']:r for r in map(json.loads,(BASE/'v5_quality.jsonl').read_text().splitlines())}
    old=[json.loads(l) for l in (REPO/'eval.jsonl').read_text().splitlines() if l.strip()]
    source=(REPO/'scripts/dataset/parse_dataset.py').read_text()
    tree=ast.parse(source)
    function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='categorize_csic_anomalous')
    namespace={}
    exec(compile(ast.Module(body=[function],type_ignores=[]),'<original-csic-classification-function>','exec'),namespace)
    replay=namespace[function.name]
    outcomes=[]
    for r in current.values():
        if r['label']!='BLOCK' or r['decision']=='BLOCK':continue
        i=inputs[r['id']]
        record={k:r.get(k) for k in ('id','cohort','family','category','status','decision','invalid_reason')}
        record.update(canonical_sha256=i['canonical_sha256'],text_sha256=i.get('v4_text_sha256'))
        record['coverage']='inside_trained_categories' if (r['family'] in PRIMARY if r['cohort']=='authored_paired_dev' else r['category'] in LEGACY_PRIMARY) else 'outside_trained_categories'
        record['reference_status']='PROJECT_AUTHORED_ATTEMPT_REFERENCE' if r['cohort']=='authored_paired_dev' else 'HISTORICAL_REFERENCE_UNVERIFIED_NOT_GROUND_TRUTH'
        if r['cohort']=='legacy_dev':
            idx=int(i['source'].rsplit('idx',1)[1]);original=old[idx]
            reproduced=replay(original['input']).replace(' ###END###','').strip()
            record['current_historical_classifier_replay_reason']=reproduced
            # This records a lexical rule's provenance, not a security oracle.
            if r['id'] in {'dev-00028','dev-00051','dev-00114','dev-00147','dev-00595'}:
                record['review_disposition']='UNSUPPORTED_SQLI_REASON_IN_REQUEST; binary anomaly/intent cannot be adjudicated without original scenario'
                record['review_basis']='Payment-form parameters such as modo=insertar trigger the historical INSERT substring rule; no identified SQL injection construction in the visible request. No automatic relabel to ALLOW.'
            else:record['review_disposition']='PENDING_CONTEXTUAL_REFERENCE_REVIEW'
        elif r['family'] in {'jwt','csrf'}:
            record['reference_status']='STATEFUL_CONTEXT_REQUIRED_FOR_SECURITY_CONCLUSION'
        outcomes.append(record)
    (OUT/'false_negative_reference_audit.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in outcomes))
    meta=[json.loads(l) for l in (REPO/'datasets/v5_sources/final_source_2026-10-26-v4/rows.TRAIN.meta.jsonl').read_text().splitlines()]
    diversity=[]
    for cat in sorted({r['attack_category'] for r in meta if r.get('attack_category')}):
        rows=[r for r in meta if r['attack_category']==cat]
        diversity.append({'category':cat,'TRAIN_attack_rows':len(rows),'payload_records':len({r['payload_record_id'] for r in rows}),'payload_families':len({r['payload_family_id'] for r in rows}),'source_files':len({r['payload_source_file'] for r in rows}),'templates':len({r['template_id'] for r in rows}),'carriers':dict(Counter(r['carrier'] for r in rows)),'encoders':dict(Counter(r['encoder_profile'] for r in rows))})
    (OUT/'TRAIN_diversity.json').write_text(json.dumps(diversity,indent=2)+'\n')
    totals={}
    for cohort in ('legacy_dev','authored_paired_dev'):
        rows=[r for r in outcomes if r['cohort']==cohort]
        totals[cohort]={'E5_non_blocks':len(rows),'actually_ALLOWED':sum(r['decision']=='ALLOW' for r in rows),'invalid_runtime_denies':sum(r['decision'] is None for r in rows),'inside_trained_categories':sum(r['coverage']=='inside_trained_categories' for r in rows),'outside_trained_categories':sum(r['coverage']=='outside_trained_categories' for r in rows),'families_or_reasons':dict(Counter((r['family'] or r['category']) for r in rows))}
    summary={'status':'REFERENCE_AUDIT_NOT_RELABELLED_DATASET','inputs_sha256':hashlib.sha256(PRIVATE.read_bytes()).hexdigest(),'historical_dataset_sha256':hashlib.sha256((REPO/'eval.jsonl').read_bytes()).hexdigest(),'historical_classifier_source_sha256':hashlib.sha256(source.encode()).hexdigest(),'totals':totals,'manual_review_sql_reason_unsupported_ids':['dev-00028','dev-00051','dev-00114','dev-00147','dev-00595'],'warning':'Historical root eval.jsonl is the rejected pre-V4 corpus, not datasets/v4_clean/eval.jsonl. It contains weak reason assignment. Original DEV counts are unchanged, not security ground truth. Labels remain as recorded; uncertain references are not silently changed to improve scores.','TRAIN_diversity':diversity}
    (OUT/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    text='''# Revisión de cobertura y referencias

La medición histórica usa el antiguo eval.jsonl raíz, ya rechazado en E0; no es el eval de V4-clean. Sus números describen concordancia con etiquetas históricas, no una tasa de ataques reales que atraviesan un firewall.

Se identificaron cinco casos etiquetados SQLi cuya explicación no está sustentada por una construcción de inyección visible. El clasificador histórico busca, entre otras subcadenas, `insert`; un valor legítimo de un formulario como `modo=insertar` puede dispararlo. La anomalía binaria o intención original requiere el escenario de origen; no se relabeló automáticamente ALLOW.

La frase anterior «V5 pierde tantos ataques SQLi» fue demasiado fuerte para esta fuente. Se preservan los conteos E5 originales y se añade esta auditoría separada. No se debe entrenar para imitar esas etiquetas ni elegir configuraciones por esa concordancia exclusivamente.

En el conjunto authored DEV hay referencias de intentos construidos, pero JWT/CSRF requieren contexto de estado para concluir un bypass real. Los fallos de salida inválida son errores E5, aunque el gateway los bloquee preventivamente; no son peticiones realmente permitidas.

La ampliación del dataset debe cubrir familias ausentes y variantes reales sin recrear los falsos positivos del corpus antiguo. Se requiere trazabilidad por fuente, payload y grupo; el número de filas no mide por sí solo diversidad.
'''
    (OUT/'REFERENCE_AUDIT.md').write_text(text)
    print(json.dumps(summary,indent=2))

if __name__=='__main__':main()
