"""Apply existing shortcut arithmetic to new open splits, not protected files."""
from collections import Counter,defaultdict
import argparse,json
from pathlib import Path
import sys
from audit_stage4_preview import ROOT,REPO,read_preview_splits,sha
sys.path.insert(0,str(REPO/'scripts/dataset'))
import v5_shortcut_checks as C


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--preview',type=Path,default=ROOT/'stage4-preview-expanded-v2');args=parser.parse_args()
    root=args.preview;out=root/'shortcut_diagnostics.json'
    if out.exists():raise ValueError('Do not overwrite evidence')
    report=json.loads((root/'preview.json').read_text());parts=read_preview_splits(report['artifacts'])
    oldpath=REPO/'datasets/v5_sources/final_source_2026-10-26-v4/rows.TRAIN.meta.jsonl'
    old=[json.loads(l) for l in oldpath.read_text().splitlines()]
    result={}
    for split,records in parts.items():
        rows=[r['meta'] for r in records]+(old if split=='TRAIN_CANDIDATE' else [])
        s1={key:C._score(rows,key) for key in C.FEATURES}
        pure=[]
        for key in C.FEATURES:
            for counts in C._cells(rows,key).values():
                if sum(counts.values())/len(rows)>=.01 and max(counts.values())/sum(counts.values())>=.99:
                    pure.append(key)
        family_for={r['pair_id']:r['payload_family_id'] for r in rows if r.get('payload_family_id')}
        families=defaultdict(list)
        for row in rows:families[family_for[row['pair_id']]].append(row)
        s6=0;family_shortcuts=0
        for group in families.values():
            for key in C.FEATURES:
                score=C._score(group,key)
                family_shortcuts+=score['accuracy']>=.8 or score['margin']>=.1
                for counts in C._cells(group,key).values():
                    n=sum(counts.values())
                    if n/len(group)>=.01 and min(counts['ALLOW'],counts['BLOCK'])/max(counts.values())<.5:s6+=1
        dominance={}
        for label in ('ALLOW','BLOCK'):
            subset=[r for r in rows if r['label']==label]
            counts=Counter(tuple(value) for r in subset for value in {tuple(v) for v in r['value_entries']})
            maxshare=max(counts.values(),default=0)/len(subset)
            dominance[label]=dict(rows=len(subset),max_element_share=maxshare,
                                  over_003=sum(n/len(subset)>.03 for n in counts.values()),
                                  raw_status='BLOCK' if maxshare>.03 else 'WARN' if maxshare>.01 else 'PASS')
        result[split]=dict(rows=len(rows),C_S1=s1,C_S1_block_features=[k for k,v in s1.items() if v['accuracy']>=.8 or v['margin']>=.1],
                           C_S1_within_family_block_cells=family_shortcuts,C_S2_pure_feature_levels=len(pure),
                           C_S6_block_levels=s6,C_S7=dominance)
    obj=dict(schema='v51-preview-shortcuts/v1',status='DIAGNOSTIC_NOT_FREEZE_ACCREDITATION',
             preview_sha256=sha((root/'preview.json').read_bytes()),checker_sha256=sha(Path(__file__).read_bytes()),
             original_shortcut_math_sha256=sha((REPO/'scripts/dataset/v5_shortcut_checks.py').read_bytes()),
             opened_splits=list(parts),reserve_opened=False,splits=result,
             not_covered=['C-S3 token-purity tests','C-S4 fitted structure probe','Additional ENC-4 feature-association diagnostics'],
             owner_exception_applied=False,training_authorized=False)
    out.write_text(json.dumps(obj,indent=2)+'\n')
    print(json.dumps({s:{k:v for k,v in x.items() if k!='C_S1'} for s,x in result.items()},indent=2))


if __name__=='__main__':main()
