"""Synthetic pinned AI audit bundle. Never an authorization or actual audit."""
import hashlib
import json
from pathlib import Path


def make_bundle(directory, *, records=(), outcomes=None):
    root=Path(directory);root.mkdir(parents=True,exist_ok=True)
    outcomes={'SQL Injection':'PASS_AI_AUDITED'} if outcomes is None else outcomes
    files={}
    def put(name, obj=None, raw=None):
        data=raw if raw is not None else (json.dumps(obj,sort_keys=True)+'\n').encode()
        path=root/(name+'.json');path.write_bytes(data)
        files[name]={'path':str(path),'sha256':hashlib.sha256(data).hexdigest()}
        return files[name]['sha256']
    pool_sha=put('pool',raw=b''.join((json.dumps(r,sort_keys=True)+'\n').encode() for r in records))
    man_sha=put('pool_manifest',{'synthetic':True})
    sample_sha=hashlib.sha256(b'synthetic sample, no actual review').hexdigest()
    put('state',{'sample':{'sha256':sample_sha},'pool':{'sha256':pool_sha},'pool_manifest_sha256':man_sha})
    report_sha=put('report',{'schema':'v5-postfilter-r3-adjudication/v1','audit_type':'ai_audited',
        'source_sha256':{'round-1/sample.jsonl':sample_sha},
        'category_outcomes':{k:{'status':v} for k,v in outcomes.items()}})
    put('exchange',{'schema':'v5-r3-category-outcomes-exchange/v1','audit_type':'ai_audited',
                    'source_report_sha256':report_sha,'category_outcomes':outcomes})
    return {'schema':'v5-ai-audit-evidence/v1-PROPOSED',**files}
