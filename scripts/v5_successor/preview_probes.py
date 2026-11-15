"""C-S3/C-S4 diagnostics on original TRAIN plus new open preview splits."""
from collections import Counter,defaultdict
import argparse,json
from pathlib import Path
import sys

from audit_stage4_preview import ROOT,REPO,read_preview_splits,sha
sys.path.insert(0,str(REPO/'scripts/dataset'))
import v5_token_purity as P
import v5_structure_probe as S


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--preview',type=Path,default=ROOT/'stage4-preview-expanded-v2');args=parser.parse_args()
    root=args.preview;out=root/'token_and_structure_probes.json'
    if out.exists():raise ValueError('Do not overwrite evidence')
    report=json.loads((root/'preview.json').read_text());parts=read_preview_splits(report['artifacts'])
    oldroot=REPO/'datasets/v5_sources/final_source_2026-10-26-v4'
    texts=[json.loads(l) for l in (oldroot/'rows.TRAIN.jsonl').read_text().splitlines()]
    meta=[json.loads(l) for l in (oldroot/'rows.TRAIN.meta.jsonl').read_text().splitlines()]
    if len(texts)!=len(meta):raise ValueError('Original row count mismatch')
    old=[dict(text=t['text'],meta=m) for t,m in zip(texts,meta)]
    parts['TRAIN_CANDIDATE']=old+parts['TRAIN_CANDIDATE']
    purity={}
    for split,rows in parts.items():
        counts=defaultdict(Counter)
        for row in rows:
            masked=P._masked(row['text'],row['meta']['leaf_spans'])
            for token in set(P.TOKEN.findall(masked.lower())):counts[token][row['meta']['label']]+=1
        eligible=[c for c in counts.values() if sum(c.values())/len(rows)>=.01]
        maximum=max(max(c.values())/sum(c.values()) for c in eligible)
        purity[split]=dict(rows=len(rows),eligible_tokens=len(eligible),max_purity=maximum,
                           block_tokens=sum(max(c.values())/sum(c.values())>=.95 for c in eligible),
                           warn_tokens=sum(.80<=max(c.values())/sum(c.values())<.95 for c in eligible))
    # Use the original implementation exactly; it reads TRAIN/VALIDATION only.
    # Files remain private and are not an authorized dataset (no manifest/auth).
    private=Path('/home/sebas/Documents/Codex/2026-10-26/ta/work')/('v51-structure-probe-'+root.name)
    private.mkdir()
    for split,name in [('TRAIN_CANDIDATE','TRAIN'),('VALIDATION_CANDIDATE','VALIDATION')]:
        path=private/f'rows.{name}.meta.jsonl'
        path.write_text(''.join(json.dumps(r['meta'])+'\n' for r in parts[split]));path.chmod(0o600)
    probe=S.check(private)
    obj=dict(schema='v51-preview-probes/v1',status='DIAGNOSTIC_NOT_FREEZE_ACCREDITATION',
             preview_sha256=sha((root/'preview.json').read_bytes()),checker_sha256=sha(Path(__file__).read_bytes()),
             source_sha256={p.name:sha(p.read_bytes()) for p in [REPO/'scripts/dataset/v5_token_purity.py',REPO/'scripts/dataset/v5_structure_probe.py']},
             C_S3=purity,C_S4=probe,reserve_opened=False,target_models_trained=False,
             note='The fitted logistic model is only the prescribed structure probe; neither V5 nor Model 2 was trained. No invented C-S5 acceptance control is applied; additional ENC-4 associations remain diagnostic.')
    out.write_text(json.dumps(obj,indent=2)+'\n');print(json.dumps(obj,indent=2))


if __name__=='__main__':main()
