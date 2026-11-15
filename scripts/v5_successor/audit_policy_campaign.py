"""Audit only TRAIN/VALIDATION candidates; reserved cases remain unopened."""
import argparse,hashlib,json,sys
from pathlib import Path
from collections import defaultdict,Counter
REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'scripts/dataset'),str(REPO/'control_plane'),str(REPO/'scripts/training')]
import v5_identities as I
import v5_inference_core as core
from transformers import AutoTokenizer
OUT=REPO/'reports/v5/successor-2026-10-30/policy-campaign'

def main():
    global OUT
    parser=argparse.ArgumentParser();parser.add_argument('--campaign-dir',type=Path,default=OUT);args=parser.parse_args();OUT=args.campaign_dir
    manifest=json.loads((OUT/'manifest.json').read_text());by={a['split']:a for a in manifest['artifacts']};rows=[]
    for split in ['TRAIN_CANDIDATE','VALIDATION_CANDIDATE']:
        desc=by[split];raw=Path(desc['path']).read_bytes();assert hashlib.sha256(raw).hexdigest()==desc['sha256'];rows.extend(json.loads(l) for l in raw.splitlines())
    contract=core.load_contract(str(REPO/'reports/v5/successor-2026-10-30/v51-expanded-vocabulary.recipe.DRAFT.json'))
    tok=AutoTokenizer.from_pretrained(REPO/'model-output-v5/final/v5-final-v4-20261027T022649Z/adapter',local_files_only=True)
    token_failures=[];families=defaultdict(list);values=defaultdict(list)
    for r in rows:
        try:core.encode_canonical(contract,tok,r['text'])
        except core.V5ContentRejected:token_failures.append(r['id'])
        values[I.value_equivalence_key(r['logical_value'])].append(r)
        if r['label']=='BLOCK':families[I.family_key(r['logical_value'])].append(r)
    conflicts=[]
    for kind,groups in [('payload_family',families),('value_equivalence',values)]:
        for key,group in groups.items():
            if len({r['split'] for r in group})>1:conflicts.append(dict(kind=kind,key_sha256=hashlib.sha256(key.encode()).hexdigest(),splits=sorted({r['split'] for r in group}),mechanism_groups=sorted({r['mechanism_group'] for r in group}),rows=len(group)))
    result=dict(status='BLOCKED_IDENTITY_LEAKAGE' if conflicts or token_failures else 'PARTIAL_AUDIT_PASS',opened_splits=['TRAIN_CANDIDATE','VALIDATION_CANDIDATE'],reserve_opened=False,rows=len(rows),token_failures=token_failures,identity_conflicts=conflicts,training_authorized=False,warning='Mechanism labels do not replace frozen payload-family/value identities; do not weaken identity gates or train this v1 campaign.')
    (OUT/'admission_audit.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()
