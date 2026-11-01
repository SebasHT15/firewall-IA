"""Derived URL policy candidates with explicit transformations and pending admission.

This never upgrades historical annotations to VERIFIED and never changes old pools.
"""
from collections import Counter,defaultdict
import hashlib,importlib.util,json,re,sys
from pathlib import Path
REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'scripts/dataset'))
import v5_labels as L
import v5_identities as I
PRIVATE=Path('/home/sebas/Documents/Codex/2026-10-26/ta/work/v51-sources')
OUT=REPO/'reports/v5/successor-2026-10-30/sources'
SPEC=importlib.util.spec_from_file_location('h1_source_primitives',REPO/'reports/v5/freeze-prep-claude-2026-10-26/h1_identity_secrets_scan.py')
H=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(H)
DNS=re.compile(r'(?<![A-Za-z0-9_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![A-Za-z0-9_-])')
USERINFO=re.compile(r'(?P<prefix>(?:https?://|//))(?P<userinfo>[^/?#\s]*@)',re.I)

def sha(raw):return hashlib.sha256(raw).hexdigest()
def main():
    origin=PRIVATE/'patt-url-policy-candidates.private.jsonl';candidates=[json.loads(l) for l in origin.read_text().splitlines()];policy=L.load_policy_table();kept=[];excluded=[]
    for item in candidates:
        source=item['source_record'];raw=source['payload_logical'];rid=source['record_id']
        if H.SECRET.search(raw):excluded.append(dict(source_record_id=rid,reason='SECRET_PATTERN_IN_RAW_SOURCE'));continue
        # Minimize identity-bearing tokens; retain exact source and transform hashes
        # locally, never pretending the derived text is the unmodified source.
        value=DNS.sub('localhost',raw)
        value=USERINFO.sub(lambda m:m.group('prefix')+'u@',value)
        p=L.classify_url(value,L.NAVIGATION if source['category_v4']=='Open Redirect' else L.DATA,policy)
        if p.kind!='POLICY' or p.policy_id!=item['policy_id']:
            excluded.append(dict(source_record_id=rid,reason='POLICY_CHANGED_DURING_IDENTITY_MINIMIZATION'));continue
        family=I.family_key(value)
        if I.is_unobservable(family):excluded.append(dict(source_record_id=rid,reason='UNOBSERVABLE_FAMILY_IDENTITY'));continue
        # Unknown domain-like residues remain a rejection, never a broad whitelist.
        if DNS.search(value):excluded.append(dict(source_record_id=rid,reason='UNRESOLVED_DOMAIN_AFTER_TRANSFORM'));continue
        category=policy.policies[p.policy_id].get('attack_category_by_scheme',{}).get(p.scheme,policy.policies[p.policy_id]['attack_category'])
        kept.append(dict(record_id=sha((rid+'\0'+value).encode()),source_record_id=rid,
            source_file=source['source_file'],source_kind=source['source_kind'],source_license=source['license'],
            source_commit='e961fef231d8327bae83b563fab50aec2e6b77c0',source_payload_sha256=sha(raw.encode()),
            payload_logical=value,payload_sha256=sha(value.encode()),payload_family_id=family,
            source_category=source['category_v4'],attack_category=category,policy_id=p.policy_id,
            label='BLOCK',label_status='POLICY_DEFINED',label_status_basis='policy_defined',
            transform='v51-dns-to-localhost-and-userinfo-u/v1',transform_changed=value!=raw,
            status='PENDING_H1_SOURCE_CONTEXT_AND_STAGE4_ADMISSION'))
    # Remove exact duplicate derived values. Do not invent more independent examples.
    unique={}
    for row in sorted(kept,key=lambda r:r['record_id']):
        if row['payload_sha256'] in unique:excluded.append(dict(source_record_id=row['source_record_id'],reason='DERIVED_PAYLOAD_DUPLICATE'));continue
        unique[row['payload_sha256']]=row
    kept=list(unique.values());keys={r['payload_family_id'] for r in kept};tokens={k:I.payload_shingles(k) for k in keys};pairs=I.near_duplicate_pairs(tokens);parent={k:k for k in keys}
    def find(x):
        while parent[x]!=x:parent[x]=parent[parent[x]];x=parent[x]
        return x
    for a,b,_,_ in pairs:parent[find(a)]=find(b)
    components=defaultdict(list)
    for k in keys:components[find(k)].append(k)
    for row in kept:row['near_duplicate_component_sha256']=sha(min(components[find(row['payload_family_id'])]).encode())
    target=PRIVATE/'patt-url-derived-policy-candidates.private.jsonl';data=''.join(json.dumps(r)+'\n' for r in kept).encode();target.write_bytes(data);target.chmod(0o600)
    summary=dict(status='DERIVED_SOURCE_CANDIDATES_NOT_TRAINING_AUTHORIZATION',input_rows=len(candidates),unique_derived_payloads=len(kept),normalized_family_keys=len(keys),near_duplicate_components=len(components),category_counts=dict(Counter(r['attack_category'] for r in kept)),policy_counts=dict(Counter(r['policy_id'] for r in kept)),excluded_counts=dict(Counter(r['reason'] for r in excluded)),transformed_rows=sum(r['transform_changed'] for r in kept),input_sha256=sha(origin.read_bytes()),derived_candidates_sha256=sha(data),derived_candidates_path=str(target),builder_sha256=sha(Path(__file__).read_bytes()),policy_sha256=sha((REPO/'scripts/dataset/v5_policy/policy_table_v1.json').read_bytes()),remaining=['H1 scoped numeric-address/userinfo proof review','per-file source licence confirmation against existing denylist provenance','source family and template split assignment before build','stage-4 evidence/row-contract admission and owner-bound training records'],warning='Identity minimization preserves the existing policy class, not a claim that exploitation semantics are unchanged in every possible application. No source attack label is promoted to independent human validation.')
    (OUT/'patt_url_derived_candidates.json').write_text(json.dumps(summary,indent=2)+'\n');(OUT/'patt_url_derived_exclusions.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in excluded));print(json.dumps(summary,indent=2))
if __name__=='__main__':main()
