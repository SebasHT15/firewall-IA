"""CPU diagnostic after the sealed Docker experiment, not candidate selection.

Cross-check baseline scores against actual gateway rows and describe the other
already-trained candidate. The ablation cascade is a counterfactual only.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
REPO=HERE.parents[2]
sys.path[:0]=[str(REPO),str(HERE),str(HERE.parent)]
import population as P
import evaluation_metrics as M
from scripts.model2 import training as T
from scripts.v5_successor.collect_evaluation import counterfactual


def read(path):
    return [json.loads(x) for x in Path(path).read_text().splitlines() if x.strip()]


def run(root, private_cases):
    root=Path(root)
    cases=read(private_cases)
    public=read(root/'cases.jsonl')
    if [P.public_case(c) for c in cases]!=public:
        raise ValueError('Private/public sealed population mismatch')
    out=root/'model2-posthoc'
    out.mkdir(exist_ok=False)
    cases=[dict(**c,canonical_text=P.canonical(c),canonical_sha256=P.public_case(c)['canonical_sha256']) for c in cases]
    measured={r['id']:r for r in read(root/'verified-CASCADE_ACTIVE.jsonl')}
    v5_rows={r['id']:r for r in read(root/'verified-V5_ONLY.jsonl')}
    v5=[dict(id=c['id'],canonical_sha256=c['canonical_sha256'],
        **{k:v5_rows[c['id']]['v5'].get(k) for k in ('status','decision','invalid_reason')}) for c in cases]
    artifacts={
        'baseline34':('baseline34.json','da6f6eb85c5a687bd038c6298baf59abdbe0489a80c8993b74a34dae7c60aa38'),
        'path-ablation32':('path-ablation32.json','6fda4fa0d0bacd7573234e3b2ebdda23706af1a6312c3fe33e185c0237664d15')}
    reports={}
    for name,(filename,expected) in artifacts.items():
        path=REPO/'model-output-model2/final/v4-d82-20261027T052308Z'/filename
        artifact=T.load_artifact(str(path),expected_sha256=expected)
        predictions=[dict(id=c['id'],canonical_sha256=c['canonical_sha256'],status='OK',
                          p_block=T.score(artifact,c['canonical_text'])) for c in cases]
        with (out/f'{name}.scores.jsonl').open('x') as fh:
            fh.write(''.join(json.dumps(p,sort_keys=True)+'\n' for p in predictions))
        diffs=[abs(p['p_block']-measured[p['id']]['model2']['p_block']) for p in predictions] if name=='baseline34' else None
        if diffs and max(diffs)!=0:
            raise ValueError('Baseline CPU scores differ from actual gateway')
        cf=counterfactual(cases,v5,predictions,.9)
        selected=[(c,p,q) for c,p,q in zip(cases,predictions,cf) if c['cohort']!='known_regression']
        root_ids=[c['id'] for c in cases if c['method']=='GET' and c['target']=='/']
        reports[name]=dict(artifact_sha256=expected,feature_view=artifact['feature_view'],
            probability_diagnostics=M.probability_metrics([c for c,_,_ in selected],[p for _,p,_ in selected],[.9]),
            cascade_counterfactual=M.quality([c for c,_,_ in selected],[q for _,_,q in selected]),
            baseline_score_vs_observed_max_abs_diff=max(diffs) if diffs else None,
            root_scores=sorted({p['p_block'] for p in predictions if p['id'] in root_ids}),
            scope='Baseline was measured through gateway. Ablation score/cascade here is CPU reconstruction ONLY; '
                  'no ablation gateway, timing, effect or capacity measurement and no candidate/threshold selection.')
    doc=dict(schema='docker-development-model2-posthoc/v1',reports=reports,
             source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
             selected_candidate=None,selected_threshold=None,
             note='Diagnostic planned after observing baseline false blocks; this population is now known DEV.')
    (out/'COMPARISON.json').write_text(json.dumps(doc,indent=2,sort_keys=True)+'\n')
    print(json.dumps(reports,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',required=True);p.add_argument('--private-cases',required=True)
    a=p.parse_args();run(a.root,a.private_cases)
