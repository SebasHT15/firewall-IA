"""DRAFT scoped hygiene rule for numeric destinations in registered policy URLs.

Not wired into the historical H1 checker or a trainer. Passing this proposal is
not owner approval. Source identity, policy context and existing address lists
are mandatory; there is no domain-wide or address-wide exception.
"""
import hashlib,ipaddress,json,sys
from pathlib import Path
REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'scripts/dataset'))
import v5_labels as L

class AdmissionError(ValueError):pass


def known_special_address(value,table):
    address=ipaddress.ip_address(value)
    if isinstance(address,ipaddress.IPv6Address) and address.ipv4_mapped:
        address=address.ipv4_mapped
    if address.is_global:return False
    for key in ('meta_networks','loopback_networks','private_networks'):
        if any(address.version==net.version and address in net for net in table.networks(key)):return True
    return str(address) in table.lists['meta_hosts']


def validate_registered_url(record_id,value,*,registry,slot_type,label,category,role,table):
    row=registry.get(record_id)
    if row is None:raise AdmissionError('unregistered source record')
    if slot_type!='url' or label!='BLOCK':raise AdmissionError('wrong slot or label context')
    digest=hashlib.sha256(value.encode()).hexdigest()
    if row['payload_sha256']!=digest:raise AdmissionError('source value changed')
    if row.get('label_status')!='POLICY_DEFINED' or row.get('label_status_basis')!='policy_defined':
        raise AdmissionError('wrong evidence class')
    # The renderer derives a URL role from the actual slot. Source-folder names
    # do not establish that role. Both defined roles must replay the exact same
    # registered BLOCK policy; undefined or context-excluded roles never pass.
    if role not in (L.DATA,L.NAVIGATION):raise AdmissionError('wrong URL role')
    policy=L.classify_url(value,role,table)
    if policy.kind!='POLICY' or policy.policy_id!=row['policy_id'] or policy.policy_id not in table.block_policies:
        raise AdmissionError('policy replay mismatch')
    expected_category=table.policies[policy.policy_id].get('attack_category_by_scheme',{}).get(policy.scheme,table.policies[policy.policy_id]['attack_category'])
    if category!=expected_category or category!=row['attack_category']:
        raise AdmissionError('wrong attack category')
    addresses=row.get('special_use_numeric_addresses',[])
    if not all(known_special_address(a,table) for a in addresses):
        raise AdmissionError('address not in the existing bounded special-use lists')
    return dict(status='PASS_UNDER_DRAFT_SCOPED_RULE',record_id=record_id,policy_id=policy.policy_id,
                scoped_addresses=addresses,owner_approved=False,training_authorized=False)


def main():
    root=REPO/'reports/v5/successor-2026-10-30/sources';desc=json.loads((root/'patt_url_derived_v3.json').read_text());raw=Path(desc['output_path']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=desc['output_sha256']:raise AdmissionError('source registry hash mismatch')
    rows=[json.loads(l) for l in raw.splitlines()];registry={r['record_id']:r for r in rows};assert len(registry)==len(rows)
    table=L.load_policy_table();results=[];errors=[]
    for row in rows:
        try:results.append(validate_registered_url(row['record_id'],row['payload_logical'],registry=registry,slot_type='url',label='BLOCK',category=row['attack_category'],role=L.NAVIGATION if row['source_category']=='Open Redirect' else L.DATA,table=table))
        except AdmissionError as e:errors.append(dict(record_id=row['record_id'],reason=str(e)))
    proposal=dict(schema='v51-policy-source-admission-proposal/v1',status='DRAFT_PENDING_OWNER_REVIEW',
        source_registry_sha256=desc['output_sha256'],policy_sha256=hashlib.sha256((REPO/'scripts/dataset/v5_policy/policy_table_v1.json').read_bytes()).hexdigest(),validator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        rules=['Only an exact hash-bound derived source record, no arbitrary source membership','Only typed URL BLOCK/POLICY_DEFINED rows in a defined data/navigation role and the registered category','Actual rendered slot role must replay to the same existing D62/D75 BLOCK class','Only addresses in existing meta/loopback/private lists; global addresses forbidden','No new email, credential, vendor or arbitrary domain exemption','Historical H1 marker ruling and checker remain unchanged','Canonical row must round-trip to the registered logical value during stage-4 integration'],
        records_passed_under_proposal=len(results),errors=errors,numeric_exception_records=sum(bool(r['scoped_addresses']) for r in results),owner_approved=False,training_authorized=False,
        next='Owner review/commit plus stage-4 evidence/row binding; do not bypass the current H1 or training gates.')
    (root/'policy_source_admission.DRAFT.json').write_text(json.dumps(proposal,indent=2)+'\n');print(json.dumps(proposal,indent=2))
if __name__=='__main__':main()
