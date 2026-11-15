"""Pre-admission H1 primitive audit on new TRAIN/VALIDATION only, never reserve."""
from collections import Counter
import hashlib,importlib.util,ipaddress,json,sys
from pathlib import Path
REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'scripts/dataset'))
import v5_labels as L
checker=REPO/'reports/v5/freeze-prep-claude-2026-10-26/h1_identity_secrets_scan.py'
spec=importlib.util.spec_from_file_location('original_h1_primitives',checker);H=importlib.util.module_from_spec(spec);spec.loader.exec_module(H)
OUT=REPO/'reports/v5/successor-2026-10-30/policy-campaign-v2'

def main():
    manifest=json.loads((OUT/'manifest.json').read_text());records=[]
    for desc in manifest['artifacts']:
        if desc['split'] not in ('TRAIN_CANDIDATE','VALIDATION_CANDIDATE'):continue
        raw=Path(desc['path']).read_bytes();assert hashlib.sha256(raw).hexdigest()==desc['sha256'];records.extend(json.loads(l) for l in raw.splitlines())
    findings=[];seen=set()
    for r in records:
        for text in H.variants(r['text']):
            for rx in (H.URL,H.RELATIVE_URL):
                for match in rx.finditer(text):
                    authority=match.group(1)
                    if '%' in authority:continue
                    try:host=H.clean_authority(authority)
                    except ValueError:kind='UNPARSED_AUTHORITY';host=authority
                    else:
                        if H.reserved(host):continue
                        try:address=ipaddress.ip_address(host)
                        except ValueError:
                            try:ip,_,mapped=L._host_info(host)
                            except (ValueError,TypeError):ip=mapped=None
                            address=ip or mapped
                        kind='SPECIAL_USE_POLICY_ADDRESS_NEEDS_SCOPED_H1_ADMISSION' if address is not None and not address.is_global else 'UNRESERVED_HOST_REJECT'
                    key=(r['id'],kind,host)
                    if key not in seen:seen.add(key);findings.append(dict(id=r['id'],kind=kind,value_sha256=hashlib.sha256(host.encode()).hexdigest(),policy_id=r['policy_id']))
            for regex,kind in [(H.EMAIL,'EMAIL_SHAPED_USERINFO_NEEDS_SOURCE_SCOPE'),(H.VENDOR,'VENDOR_WORD_NEEDS_CONTEXT_REVIEW'),(H.SECRET,'SECRET_PATTERN_REJECT')]:
                for match in regex.finditer(text):
                    key=(r['id'],kind,match.group())
                    if key not in seen:seen.add(key);findings.append(dict(id=r['id'],kind=kind,value_sha256=hashlib.sha256(match.group().encode()).hexdigest(),policy_id=r['policy_id']))
    result=dict(status='H1_ADMISSION_NOT_CLOSED',opened_splits=['TRAIN_CANDIDATE','VALIDATION_CANDIDATE'],reserve_opened=False,rows=len(records),counts=dict(Counter(r['kind'] for r in findings)),findings=findings,checker_sha256=hashlib.sha256(checker.read_bytes()).hexdigest(),original_checker_modified=False,warning='Reused original extraction primitives only. Full old scan opens INTERNAL_TEST and was NOT called. Special-use URLs and synthetic userinfo need explicit source/context-bound admission, never broad domain/secret exemptions. No final H1 pass or training authorization.')
    (OUT/'identity_review.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':result['status'],'rows':len(records),'counts':result['counts']},indent=2))
if __name__=='__main__':main()
