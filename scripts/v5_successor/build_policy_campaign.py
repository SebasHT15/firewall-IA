"""Policy-grounded review corpus. Does not claim stage-4/training admission."""
import hashlib,json,random,sys
from collections import Counter,defaultdict
from pathlib import Path
from urllib.parse import urlencode,parse_qsl,urlsplit

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'scripts/dataset'),str(REPO/'data_plane')]
import v5_labels as L
import canonical_request as CR
import http1_wire as W

OUT=REPO/'reports/v5/successor-2026-10-30/policy-campaign'
PRIVATE=Path('/home/sebas/Documents/Codex/2026-10-26/ta/work/v51-policy-campaign')
# Reviewed expected classes are fixed before model inference. They are research
# application-policy cases, not claims that all such values are universally attacks.
MECHANISMS=[
 ('metadata-ipv4','http://169.254.169.254/latest/meta-data/','POL-URL-META'),
 ('metadata-ipv6','http://[fd00:ec2::254]/latest/meta-data/','POL-URL-META'),
 ('metadata-listed-address','http://100.100.100.200/latest/meta-data/','POL-URL-META'),
 ('obfuscated-dword','http://2130706433/path','POL-URL-OBFUSCATED'),
 ('obfuscated-hex','http://0x7f000001/path','POL-URL-OBFUSCATED'),
 ('obfuscated-octal','http://0177.0.0.1/path','POL-URL-OBFUSCATED'),
 ('userinfo-confusion','https://user@docs.example/path','POL-URL-OBFUSCATED'),
 ('scheme-relative','//docs.example/path','POL-REDIRECT-DIFF'),
 ('backslash-relative','/\\docs.example/path','POL-REDIRECT-DIFF'),
 ('scheme-no-slashes','https:docs.example/path','POL-REDIRECT-DIFF'),
 ('file-scheme','file:///etc/passwd','POL-URL-SCHEME'),
 ('gopher-scheme','gopher://docs.example/path','POL-URL-SCHEME'),
 ('ftp-scheme','ftp://docs.example/path','POL-URL-SCHEME'),
 ('dict-scheme','dict://docs.example/path','POL-URL-SCHEME'),
]
OUTPUTS={'Server Side Request Forgery':'BLOCK | Server-side request forgery attack detected.',
         'Open Redirect':'BLOCK | Open redirect payload detected.'}
ALLOW='ALLOW | Normal HTTP request with no attack patterns detected.'

def digest(data):return hashlib.sha256(data).hexdigest()
def write_new(path,data):
    with path.open('xb') as f:f.write(data)
    path.chmod(0o600)

def wire_for(carrier,field,value,group):
    # Both labels have the same structure, field and HTTP method within each pair.
    path='/api/preview-'+str(group)
    if carrier=='query':
        return ('GET '+path+'?'+urlencode({field:value})+' HTTP/1.1\r\nHost: lab.example\r\n\r\n').encode()
    if carrier=='form':body=urlencode({field:value}).encode();ctype='application/x-www-form-urlencoded'
    else:body=json.dumps({field:value},ensure_ascii=False,separators=(',',':')).encode();ctype='application/json'
    return (f'POST {path} HTTP/1.1\r\nHost: lab.example\r\nContent-Type: {ctype}\r\nContent-Length: {len(body)}\r\n\r\n').encode()+body

def extracted(parts,carrier):
    if carrier=='query':return parse_qsl(urlsplit(parts.target.decode()).query,keep_blank_values=True)[0][1]
    if carrier=='form':return parse_qsl(parts.body.decode(),keep_blank_values=True)[0][1]
    return next(iter(json.loads(parts.body).values()))

def build_records():
    table=L.load_policy_table();records=[];rng=random.Random(20261030)
    for gi,(name,base,expected) in enumerate(MECHANISMS):
        # Mechanism holdout only, not a claim of SPL-3...9 source-family independence.
        split=['TRAIN_CANDIDATE','VALIDATION_CANDIDATE','RESERVE_CANDIDATE'][gi%3]
        for variant in range(12):
            suffix=f'?sample={variant:03d}'
            attack=base+suffix
            parsed=L.classify_url(attack,L.DATA,table)
            if parsed.policy_id!=expected:raise ValueError((name,parsed,expected))
            category=L.FROZEN_CATEGORY[expected];label=OUTPUTS[category]
            # Equal byte length, seeded benign content, no class-specific field names.
            prefix=('http' if variant%2 else 'https')+'://docs.example/'
            if len(prefix)>len(attack):prefix='/'
            benign=prefix+''.join(rng.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(len(attack)-len(prefix)))
            assert len(benign)==len(attack)
            bp=L.classify_url(benign,L.DATA,table)
            assert bp.kind=='RELATIVE' or bp.policy_id=='POL-URL-PUBLIC'
            for carrier in ('query','form','json'):
                pair_id=f'{name}-{variant:03d}-{carrier}'
                field=['resource','target','link'][variant%3]+'_'+str(gi)
                for role,value,output in [('attack',attack,label),('benign',benign,ALLOW)]:
                    wire=wire_for(carrier,field,value,gi);w=W.parse_request(wire)
                    assert extracted(w.parts,carrier)==value
                    canon=CR.canonicalize(w.parts,CR.Limits(max_decoded_body=48*415,token_budget=415,max_bytes_per_token=48))
                    assert canon.outcome=='ACCEPT'
                    # Serving projection must retain the exact logical URL value.
                    serving=CR.parse_canonical(canon.text)
                    assert extracted(serving,carrier)==value
                    policy=L.classify_url(value,L.DATA,table)
                    records.append(dict(id=f'{pair_id}-{role}',pair_id=pair_id,mechanism_group=name,
                        split=split,carrier=carrier,role=role,label='BLOCK' if role=='attack' else 'ALLOW',
                        output=output,label_status='POLICY_DEFINED',label_status_basis='policy_defined',
                        assumed_context='Typed URL input of an application that follows the existing D62/D75 policy table; no request is sent to these destinations.',
                        policy_id=policy.policy_id,attack_category=category if role=='attack' else None,
                        text=canon.text,text_sha256=digest(canon.text.encode()),wire_sha256=digest(wire),
                        logical_value=value,source='project-authored-policy-mechanisms/v1',
                        source_validation='expected policy class + exact logical-value round trip; not human validation'))
    return records

def main():
    if PRIVATE.exists():raise RuntimeError('Private corpus directory already exists; no overwrite')
    PRIVATE.mkdir(parents=True);OUT.mkdir(parents=True,exist_ok=True)
    records=build_records();sha_splits=defaultdict(set);group_splits=defaultdict(set)
    for r in records:sha_splits[r['text_sha256']].add(r['split']);group_splits[r['mechanism_group']].add(r['split'])
    assert all(len(x)==1 for x in sha_splits.values());assert all(len(x)==1 for x in group_splits.values())
    artifacts=[]
    for split in ('TRAIN_CANDIDATE','VALIDATION_CANDIDATE','RESERVE_CANDIDATE'):
        data=''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in records if r['split']==split).encode()
        path=PRIVATE/(split+'.jsonl');write_new(path,data);artifacts.append(dict(split=split,rows=sum(r['split']==split for r in records),path=str(path),sha256=digest(data)))
    manifest=dict(schema='v51-policy-review-campaign/v1',status='PROVISIONAL_REVIEW_CORPUS_NOT_AUTHORIZED_FOR_TRAINING',
        source='Project-authored cases derived from existing policy, not copied historical eval rows',
        policy_sha256=digest((REPO/'scripts/dataset/v5_policy/policy_table_v1.json').read_bytes()),
        builder_sha256=digest(Path(__file__).read_bytes()),artifacts=artifacts,rows=len(records),
        class_counts=dict(Counter(r['label'] for r in records)),mechanism_groups=len(group_splits),
        carrier_counts=dict(Counter(r['carrier'] for r in records)),category_counts=dict(Counter(r['attack_category'] for r in records if r['label']=='BLOCK')),
        checks=dict(exact_value_roundtrip=True,canonical_text_disjoint_splits=True,mechanism_groups_disjoint_splits=True,equal_byte_length_pairs=True),
        unexecuted_gates=['H1 and full identity/shortcut audits','tokenizer B/EOS/special-id audit','original SPL-3...9 family/template/value-entry checks','category evidence/row-contract integration and source admission','owner-bound committed experimental or FINAL authorization'],
        reservation='RESERVE_CANDIDATE is now sealed before training. Do not inspect or score reserve cases for development.',
        limitations=['Artificial mechanism corpus, not representative production traffic','Mechanism groups are not claimed independent attack families','Must mix with eligible original category data to avoid narrowing coverage','Policy labels are context-dependent and are not human-validated security ground truth'])
    (OUT/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))
if __name__=='__main__':main()
