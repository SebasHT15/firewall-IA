"""Source-only provisional split proposal; original TRAIN stays anchored.

No model predictions or protected sets are used. This is not a stage-4 build.
"""
from collections import Counter,defaultdict
import argparse,hashlib,json,random,sys
from pathlib import Path
REPO=Path(__file__).resolve().parents[2];sys.path.insert(0,str(REPO/'scripts/dataset'))
import v5_identities as I
import v5_catalog as K
OUT=REPO/'reports/v5/successor-2026-10-30/partition'
PRIVATE=Path('/home/sebas/Documents/Codex/2026-10-26/ta/work/v51-source-partitions')

def sha(raw):return hashlib.sha256(raw).hexdigest()
def expand_template_proposal():
    path=OUT/'partition-expanded.DRAFT.json'
    if path.exists():raise RuntimeError('Do not overwrite partition evidence')
    previous=OUT/'partition.DRAFT.json';result=json.loads(previous.read_text())
    catalog_path=REPO/'reports/v5/successor-2026-10-30/catalog/catalog-v51-expanded.DRAFT.json'
    catalog=K.load_catalog(str(catalog_path))
    audit=K.audit(catalog)
    if not audit['ok']:raise RuntimeError('Expanded structures failed the unchanged audit')
    assignments=dict(result['new_template_assignments']);counts=Counter()
    splits=['TRAIN_CANDIDATE','VALIDATION_CANDIDATE','RESERVE_CANDIDATE']
    for t in catalog.templates:
        if not t.name.startswith('v51-') or t.template_id in assignments:continue
        offset={'query':0,'form':1,'json':2}[t.carrier]
        split=splits[(counts[t.carrier]+offset)%3];counts[t.carrier]+=1
        assignments[t.template_id]=dict(name=t.name,cluster=t.struct_cluster_id,carrier=t.carrier,split=split)
    totals=Counter(d['split'] for d in assignments.values())
    assert set(totals.values())=={13},totals
    result.update(parent_partition_sha256=sha(previous.read_bytes()),catalog_path=str(catalog_path),
                  catalog_sha256=sha(catalog_path.read_bytes()),new_template_assignments=assignments,
                  expanded_template_counts=dict(totals),source_assignments_changed=False,
                  reserve_source_file_reopened=False)
    path.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(path=str(path),template_counts=dict(totals),source_assignments_changed=False),indent=2))
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--expand-templates',action='store_true');args=parser.parse_args()
    if args.expand_templates:return expand_template_proposal()
    if PRIVATE.exists():raise RuntimeError('Do not overwrite partition evidence')
    desc=json.loads((REPO/'reports/v5/successor-2026-10-30/sources/patt_url_derived_v3.json').read_text());data=Path(desc['output_path']).read_bytes();assert sha(data)==desc['output_sha256']
    rows=[r for r in map(json.loads,data.splitlines()) if r['attack_category'] in ('Server Side Request Forgery','Open Redirect')]
    oldmeta=REPO/'datasets/v5_sources/final_source_2026-10-26-v4/rows.TRAIN.meta.jsonl';oldrows=[json.loads(l) for l in oldmeta.read_text().splitlines()]
    oldkeys={r['payload_family_id'] for r in oldrows if r.get('payload_family_id')};newkeys={r['payload_family_id'] for r in rows};keys=oldkeys|newkeys
    tokens={k:I.payload_shingles(k) for k in keys};assert all(tokens.values())
    pairs=I.near_duplicate_pairs(tokens);parent={k:k for k in keys}
    def find(x):
        while parent[x]!=x:parent[x]=parent[parent[x]];x=parent[x]
        return x
    for a,b,_,_ in pairs:parent[find(a)]=find(b)
    members=defaultdict(list)
    for key in keys:members[find(key)].append(key)
    group_for={key:sha(min(members[find(key)]).encode()) for key in keys}
    anchored={group_for[key] for key in oldkeys};groups=defaultdict(list)
    for row in rows:groups[group_for[row['payload_family_id']]].append(row)
    assignment={g:'TRAIN_CANDIDATE' for g in groups if g in anchored}
    rng=random.Random(20261030);order=sorted(g for g in groups if g not in assignment);rng.shuffle(order)
    cats=['Open Redirect','Server Side Request Forgery']
    # Predeclare small, group-disjoint diagnostic holdouts. No rare-risk or
    # >=30-independent-family acceptance claim is made for these source sets.
    for split in ['VALIDATION_CANDIDATE','RESERVE_CANDIDATE']:
        for cat in cats:
            count=lambda:sum(assignment.get(g)==split and any(r['attack_category']==cat for r in items) for g,items in groups.items())
            for g in order:
                if count()>=2:break
                if g not in assignment and any(r['attack_category']==cat for r in groups[g]):assignment[g]=split
            if count()<2:raise RuntimeError('Insufficient independent source components for diagnostic holdout')
    target=round(len(rows)*.15)
    for split in ['VALIDATION_CANDIDATE','RESERVE_CANDIDATE']:
        current=sum(len(groups[g]) for g in groups if assignment.get(g)==split)
        available=[g for g in order if g not in assignment]
        for g in available:
            if current>=target:break
            if len(groups[g])<=target-current+2:assignment[g]=split;current+=len(groups[g])
    for g in groups:assignment.setdefault(g,'TRAIN_CANDIDATE')
    key_partition={k:'TRAIN_CANDIDATE' for k in oldkeys}
    for key in newkeys:key_partition[key]=assignment[group_for[key]]
    cross=I.near_duplicate_pairs(tokens,partition=key_partition);assert not cross
    PRIVATE.mkdir(parents=True);OUT.mkdir(parents=True,exist_ok=True)
    artifacts=[]
    for split in ['TRAIN_CANDIDATE','VALIDATION_CANDIDATE','RESERVE_CANDIDATE']:
        selected=[dict(r,split=split,source_component_sha256=group_for[r['payload_family_id']]) for r in rows if assignment[group_for[r['payload_family_id']]]==split]
        raw=''.join(json.dumps(r)+'\n' for r in selected).encode();path=PRIVATE/(split+'.source.jsonl')
        with path.open('xb') as f:f.write(raw)
        path.chmod(0o600);artifacts.append(dict(split=split,path=str(path),sha256=sha(raw),source_rows=len(selected),components=len({r['source_component_sha256'] for r in selected}),categories=dict(Counter(r['attack_category'] for r in selected))))
    catalog=K.load_catalog(str(REPO/'reports/v5/successor-2026-10-30/catalog/catalog-v51.DRAFT.json'));new=[t for t in catalog.templates if t.name.startswith('v51-')];template_assign={};counts=Counter()
    splits=['TRAIN_CANDIDATE','VALIDATION_CANDIDATE','RESERVE_CANDIDATE']
    for t in new:
        split=splits[counts[t.carrier]%3];counts[t.carrier]+=1;template_assign[t.template_id]=dict(name=t.name,cluster=t.struct_cluster_id,carrier=t.carrier,split=split)
    old_tpls={r['template_id'] for r in oldrows};assert not old_tpls&set(template_assign)
    result=dict(schema='v51-source-partition-proposal/v1',status='DRAFT_NOT_STAGE4_OR_TRAINING_AUTHORIZATION',seed=20261030,source_registry_sha256=desc['output_sha256'],original_TRAIN_meta_sha256=sha(oldmeta.read_bytes()),original_TRAIN_rows=len(oldrows),original_TRAIN_family_keys=len(oldkeys),selected_new_values=len(rows),new_component_groups=len(groups),new_groups_anchored_to_old_TRAIN=len(set(groups)&anchored),artifacts=artifacts,new_template_assignments=template_assign,checks=dict(original_TRAIN_preserved=True,old_VALIDATION_not_reused_for_training=True,source_family_disjoint=True,original_4gram_near_duplicate_pairs_across_splits=0,template_IDs_new_vs_old_TRAIN_disjoint=True),limitations=['Anchoring currently uses original TRAIN row family IDs; pre-merge/value-entry full checks still required in final stage-4 binding','Diagnostic holdouts have few components; no D18/D77 or rare-FPR accreditation','Original old protected sets are unopened; new RESERVE_CANDIDATE now sealed before training/inference','No final rows generated, no trained successor and no approved source/recipe/auth record'],remaining=['Stage-4 row/meta generation with actual shared encoding','Full SPL/template/value/pair/shortcut/H1 checks','Contract-bound source/owner admission and commit before training'])
    (OUT/'partition.DRAFT.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:result[k] for k in ['status','selected_new_values','new_component_groups','new_groups_anchored_to_old_TRAIN','artifacts','checks']},indent=2))
if __name__=='__main__':main()
