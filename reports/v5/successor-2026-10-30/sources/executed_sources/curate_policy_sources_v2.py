"""Second derived-source hygiene pass; no blanket source/identity exemption."""
from collections import Counter,defaultdict
import hashlib,importlib.util,ipaddress,json,re,sys
from pathlib import Path
from urllib.parse import urlsplit,parse_qsl,unquote
REPO=Path(__file__).resolve().parents[2];sys.path.insert(0,str(REPO/'scripts/dataset'))
import v5_labels as L
import v5_identities as I
PRIVATE=Path('/home/sebas/Documents/Codex/2026-10-26/ta/work/v51-sources')
OUT=REPO/'reports/v5/successor-2026-10-30/sources'
spec=importlib.util.spec_from_file_location('h1_curator_v2',REPO/'reports/v5/freeze-prep-claude-2026-10-26/h1_identity_secrets_scan.py');H=importlib.util.module_from_spec(spec);spec.loader.exec_module(H)
def sha(b):return hashlib.sha256(b).hexdigest()
def inspect_identity(value):
    special=[]
    for text in H.variants(value):
        if H.SECRET.search(text):return 'SECRET_PATTERN',[]
        if H.EMAIL.search(text):return 'EMAIL_SHAPED_TEXT',[]
        if H.VENDOR.search(text):return 'UNRESOLVED_VENDOR_WORD',[]
        for key,_ in parse_qsl(urlsplit(text).query,keep_blank_values=True):
            if H.CRED_KEY.fullmatch(key):return 'CREDENTIAL_KEY',[]
        # Original URL extraction preserves authority boundaries. Special-use
        # numeric addresses are reported for scoped admission, never waived here.
        for match in H.URL.finditer(text):
            if '%' in match.group(1):continue
            try:host=H.clean_authority(match.group(1))
            except ValueError:return 'UNPARSED_HTTP_AUTHORITY',[]
            if H.reserved(host):continue
            try:address=ipaddress.ip_address(host)
            except ValueError:
                ip,_,mapped=L._host_info(host);address=ip or mapped
            if address is None:return 'UNRESERVED_EXTERNAL_HOST',[]
            if address.is_global:return 'GLOBAL_LITERAL_ADDRESS',[]
            special.append(str(address))
    return None,sorted(set(special))
def main():
    source=PRIVATE/'patt-url-derived-policy-candidates.private.jsonl';rows=[json.loads(l) for l in source.read_text().splitlines()];table=L.load_policy_table();kept=[];excluded=[];seen=set()
    for row in rows:
        old=row['payload_logical'];value=H.VENDOR.sub('service',old)
        try:
            p=L.classify_url(value,L.NAVIGATION if row['source_category']=='Open Redirect' else L.DATA,table)
            reject,special=inspect_identity(value)
        except (ValueError,TypeError):reject='UNPARSED_URL';special=[];p=None
        if p is None or p.policy_id!=row['policy_id']:reject='POLICY_CHANGED_DURING_SECOND_TRANSFORM'
        if reject:excluded.append(dict(source_record_id=row['source_record_id'],reason=reject));continue
        value_hash=sha(value.encode())
        if value_hash in seen:excluded.append(dict(source_record_id=row['source_record_id'],reason='DUPLICATE_AFTER_SECOND_TRANSFORM'));continue
        seen.add(value_hash)
        new=dict(row,parent_derived_record_id=row['record_id'],parent_derived_payload_sha256=row['payload_sha256'],
            record_id=sha(('v2\0'+row['source_record_id']+'\0'+value).encode()),payload_logical=value,payload_sha256=value_hash,
            payload_family_id=I.family_key(value),transform='v51-dns-userinfo-v1-plus-vendor-word-to-service/v2',
            second_transform_changed=value!=old,special_use_numeric_addresses=special,
            identity_admission='SCOPED_NUMERIC_ADDRESS_RULE_REQUIRED' if special else 'NO_PRIMITIVE_IDENTITY_FINDING_NOT_FINAL_H1',
            status='PENDING_CONTEXT_SOURCE_AND_STAGE4_ADMISSION')
        kept.append(new)
    keys={r['payload_family_id'] for r in kept};tokens={k:I.payload_shingles(k) for k in keys};assert all(tokens.values());pairs=I.near_duplicate_pairs(tokens);parent={k:k for k in keys}
    def find(x):
        while parent[x]!=x:parent[x]=parent[parent[x]];x=parent[x]
        return x
    for a,b,_,_ in pairs:parent[find(a)]=find(b)
    groups=defaultdict(list)
    for key in keys:groups[find(key)].append(key)
    for row in kept:row['near_duplicate_component_sha256']=sha(min(groups[find(row['payload_family_id'])]).encode())
    path=PRIVATE/'patt-url-derived-policy-v2.private.jsonl';raw=''.join(json.dumps(r)+'\n' for r in kept).encode();path.write_bytes(raw);path.chmod(0o600)
    result=dict(status='POLICY_CANDIDATES_NOT_TRAINING_ADMISSION',input_rows=len(rows),unique_derived_payloads=len(kept),normalized_families=len(keys),near_duplicate_components=len(groups),policy_counts=dict(Counter(r['policy_id'] for r in kept)),category_counts=dict(Counter(r['attack_category'] for r in kept)),identity_admission_counts=dict(Counter(r['identity_admission'] for r in kept)),excluded_counts=dict(Counter(r['reason'] for r in excluded)),input_sha256=sha(source.read_bytes()),output_path=str(path),output_sha256=sha(raw),builder_sha256=sha(Path(__file__).read_bytes()),no_original_pool_modified=True,no_source_label_upgraded_to_verified=True,remaining=['Explicit special-use address admission bound to source ID, policy and URL context','Per-file provenance/third-party review','Actual stage-4 template and source-family split binding','Training authorization records and owner commit'])
    (OUT/'patt_url_derived_v2.json').write_text(json.dumps(result,indent=2)+'\n');(OUT/'patt_url_derived_v2_exclusions.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in excluded));print(json.dumps(result,indent=2))
if __name__=='__main__':main()
