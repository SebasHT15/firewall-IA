"""Policy campaign v2: split actual normalized/near-duplicate families first.

No historical reserved artifact is opened or reused. v1 stays rejected.
This remains a review corpus: integration into stage-4 and admission are pending.
"""
from collections import Counter,defaultdict
import hashlib,json,random,sys
from pathlib import Path

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'scripts/dataset'),str(REPO/'data_plane'),str(Path(__file__).parent)]
import v5_identities as I
import v5_labels as L
import canonical_request as CR
import http1_wire as W
from build_policy_campaign import MECHANISMS,OUTPUTS,ALLOW,wire_for,extracted,digest,write_new

OUT=REPO/'reports/v5/successor-2026-10-30/policy-campaign-v2'
PRIVATE=Path('/home/sebas/Documents/Codex/2026-10-26/ta/work/v51-policy-campaign-v2')
# Fixed on source mechanisms before any inference. Connected components must
# agree with this assignment; this never substitutes for the original n-gram rule.
SPLITS={
 'metadata-ipv4':'TRAIN_CANDIDATE','metadata-ipv6':'TRAIN_CANDIDATE','metadata-listed-address':'TRAIN_CANDIDATE',
 'obfuscated-dword':'TRAIN_CANDIDATE','obfuscated-hex':'TRAIN_CANDIDATE','obfuscated-octal':'TRAIN_CANDIDATE',
 'ftp-scheme':'TRAIN_CANDIDATE','scheme-relative':'TRAIN_CANDIDATE',
 'userinfo-confusion':'VALIDATION_CANDIDATE','gopher-scheme':'VALIDATION_CANDIDATE','backslash-relative':'VALIDATION_CANDIDATE',
 'file-scheme':'RESERVE_CANDIDATE','dict-scheme':'RESERVE_CANDIDATE','scheme-no-slashes':'RESERVE_CANDIDATE',
}

def family_assignment():
    keys={name:I.family_key(value) for name,value,_ in MECHANISMS}
    tokens={name:I.payload_shingles(key) for name,key in keys.items()}
    assert all(tokens.values())
    pairs=I.near_duplicate_pairs(tokens)
    parent={name:name for name in keys}
    def find(x):
        while parent[x]!=x:parent[x]=parent[parent[x]];x=parent[x]
        return x
    for a,b,_,_ in pairs:parent[find(a)]=find(b)
    groups=defaultdict(list)
    for name in keys:groups[find(name)].append(name)
    for group in groups.values():
        assert len({SPLITS[name] for name in group})==1,group
    assert not I.near_duplicate_pairs(tokens,partition=SPLITS)
    return keys,list(groups.values())

def main():
    if PRIVATE.exists():raise RuntimeError('No overwrite')
    keys,groups=family_assignment();table=L.load_policy_table()
    PRIVATE.mkdir(parents=True);OUT.mkdir(parents=True,exist_ok=True)
    rng=random.Random(20261031);records=[]
    for gi,(name,attack,expected) in enumerate(MECHANISMS):
        policy=L.classify_url(attack,L.DATA,table);assert policy.policy_id==expected
        category=L.FROZEN_CATEGORY[expected]
        for variant in range(12):
            prefix=('http' if variant%2 else 'https')+'://docs.example/'
            if len(prefix)>len(attack):prefix='/'
            benign=prefix+''.join(rng.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(len(attack)-len(prefix)))
            bp=L.classify_url(benign,L.DATA,table);assert bp.kind=='RELATIVE' or bp.policy_id=='POL-URL-PUBLIC'
            assert len(benign)==len(attack)
            for carrier in ('query','form','json'):
                pair=f'{name}-{variant:03d}-{carrier}'
                # Frame variation is label symmetric; never appended to the attack
                # payload merely to fake distinct families or inflate source diversity.
                field=['resource','target','link'][variant%3]+f'_{gi}_{variant}'
                for role,value,output in [('attack',attack,OUTPUTS[category]),('benign',benign,ALLOW)]:
                    wire=wire_for(carrier,field,value,gi);parts=W.parse_request(wire).parts
                    assert extracted(parts,carrier)==value
                    canon=CR.canonicalize(parts,CR.Limits(max_decoded_body=48*415,token_budget=415,max_bytes_per_token=48));assert canon.outcome=='ACCEPT'
                    assert extracted(CR.parse_canonical(canon.text),carrier)==value
                    label=L.classify_url(value,L.DATA,table)
                    records.append(dict(id=pair+'-'+role,pair_id=pair,mechanism_group=name,split=SPLITS[name],carrier=carrier,role=role,label='BLOCK' if role=='attack' else 'ALLOW',output=output,label_status='POLICY_DEFINED',label_status_basis='policy_defined',policy_id=label.policy_id,attack_category=category if role=='attack' else None,text=canon.text,text_sha256=digest(canon.text.encode()),wire_sha256=digest(wire),logical_value=value,payload_family_id=keys[name] if role=='attack' else None,source='project-authored-policy-mechanisms/v2',assumed_context='Existing D62/D75 typed-URL application policy; no network execution of these URLs.'))
    assert len({r['text_sha256'] for r in records})==len(records)
    values=defaultdict(set)
    for r in records:values[I.value_equivalence_key(r['logical_value'])].add(r['split'])
    assert all(len(s)==1 for s in values.values())
    artifacts=[]
    for split in ['TRAIN_CANDIDATE','VALIDATION_CANDIDATE','RESERVE_CANDIDATE']:
        subset=[r for r in records if r['split']==split];raw=''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in subset).encode();path=PRIVATE/(split+'.jsonl');write_new(path,raw);artifacts.append(dict(split=split,rows=len(subset),path=str(path),sha256=digest(raw)))
    manifest=dict(schema='v51-policy-review-campaign/v2',status='PROVISIONAL_REVIEW_CORPUS_NOT_AUTHORIZED_FOR_TRAINING',artifacts=artifacts,rows=len(records),unique_attack_values=len(MECHANISMS),payload_family_keys=len(set(keys.values())),near_duplicate_components=len(groups),component_mechanisms=groups,policy_sha256=digest((REPO/'scripts/dataset/v5_policy/policy_table_v1.json').read_bytes()),builder_sha256=digest(Path(__file__).read_bytes()),helper_builder_sha256=digest(Path(__file__).with_name('build_policy_campaign.py').read_bytes()),class_counts=dict(Counter(r['label'] for r in records)),checks=dict(exact_value_roundtrip=True,canonical_text_unique=True,equal_byte_length_pairs=True,normalized_payload_families_disjoint=True,value_equivalence_disjoint=True,original_4gram_jaccard_060_components_disjoint=True),unexecuted_gates=['H1 full identity/secret scan','tokenizer budget audit on TRAIN/VALIDATION','full original template/cluster/value-entry SPL gates','stage-4 row-contract and category evidence admission','committed manifest-bound training authorization'],reserve='New reserve sealed now, before training/inference. v1 reserve was never read; v1 retired for source-identity failure, not performance.',limitations=['1008 frames contain only 14 unique attack values; do not advertise 504 independent attacks','9 near-duplicate components, not production-independent families','Synthetic policy campaign supplements eligible original categories; never use it alone as replacement dataset','Still not a stage-4 authorized real build; no training may consume this review corpus'])
    (OUT/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))
if __name__=='__main__':main()
