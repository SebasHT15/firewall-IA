"""Which structured CRS request tests survive the current V5 representation?"""
from collections import Counter,defaultdict
import hashlib,json,sys
from pathlib import Path
from urllib.parse import urlsplit
REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'data_plane'))
import canonical_request as CR
import http1_wire as W
PRIVATE=Path('/home/sebas/Documents/Codex/2026-10-26/ta/work/v51-sources')
OUT=REPO/'reports/v5/successor-2026-10-30/sources'

def render(inp):
    if not isinstance(inp.get('headers',{}),dict):raise ValueError('non_mapping_headers')
    if any(k in inp for k in ('raw_request','encoded_request','multipart_files')):raise ValueError('requires_fixture_specific_wire_adapter')
    method=inp.get('method','GET');uri=inp.get('uri','/');version=inp.get('version','HTTP/1.1');body=inp.get('data','')
    if body is None:body=''
    if not all(isinstance(v,str) for v in (method,uri,version,body)):raise ValueError('non_string_http_field')
    headers=list(inp.get('headers',{}).items());body=body.encode('utf8')
    if body and not any(str(k).lower() in ('content-length','transfer-encoding') for k,_ in headers):headers.append(('Content-Length',str(len(body))))
    head=[f'{method} {uri} {version}']+[f'{name}: {value}' for name,value in headers]
    return '\r\n'.join(head).encode('utf8')+b'\r\n\r\n'+body

def main():
    source=PRIVATE/'owasp-crs-candidate-stages.private.jsonl';rows=[json.loads(l) for l in source.read_text().splitlines()];stats=defaultdict(Counter);records=[];groups=defaultdict(list)
    for row in rows:
        if not row['group'].startswith('REQUEST-') or row['nominal_family'] is None:continue
        family=row['nominal_family'];stats[family]['source_stages']+=1
        rec={k:row[k] for k in ('record_id','source_file','test_id','nominal_family','rule_id')}
        try:wire=render(row['input']);parsed=W.parse_request(wire)
        except (ValueError,UnicodeError,TypeError,W.WireError) as exc:
            reason=getattr(exc,'reason',str(exc));rec.update(outcome='SOURCE_ADAPTER_OR_PROTOCOL_REJECT',reason=reason);stats[family][rec['outcome']]+=1;records.append(rec);continue
        result=CR.canonicalize(parsed.parts,CR.Limits(max_decoded_body=48*415,token_budget=415,max_bytes_per_token=48));rec['outcome']=result.outcome;stats[family][result.outcome]+=1
        if result.outcome=='ACCEPT':
            digest=hashlib.sha256(result.text.encode()).hexdigest();rec['canonical_sha256']=digest
            inp=row['input'];headers=inp.get('headers',{});uri=inp.get('uri','/');data=inp.get('data')
            default={'host','accept','content-length','connection','content-type'}
            extras=[str(h).lower() for h in headers if str(h).lower() not in default and not (str(h).lower()=='user-agent' and headers[h]=='OWASP CRS test agent')]
            rec['discarded_nondefault_header_names']=extras
            rec['header_only_candidate']=bool(extras and not data and not urlsplit(uri).query)
            if rec['header_only_candidate']:stats[family]['header_only_candidates']+=1
            log=row['output_assertions'].get('log') or {};expected={str(x) for x in log.get('expect_ids',[])};not_expected={str(x) for x in log.get('no_expect_ids',[])};rid=str(row['rule_id'])
            rec['expected_rule_outcome']='EXPECT_RULE' if rid in expected else 'EXPECT_NO_RULE' if rid in not_expected else 'OTHER_OR_UNSPECIFIED'
            groups[(row['rule_id'],digest)].append(rec)
        records.append(rec)
    contradictions=[]
    for (rule,digest),group in groups.items():
        kinds={r['expected_rule_outcome'] for r in group}
        if {'EXPECT_RULE','EXPECT_NO_RULE'}<=kinds:contradictions.append(dict(rule_id=rule,canonical_sha256=digest,stages=len(group),record_ids=[r['record_id'] for r in group]))
    summary=dict(scope='Source projection audit, not measured attack recall; no automatic labels or training admission',source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),groups={k:dict(v) for k,v in stats.items()},same_input_conflicting_rule_outcomes=contradictions,warning='Some CRS rules inspect headers/XML/response/state absent from current canonical request. Do not copy their expected rule outcome as a classifier label or move the payload into another carrier without a separate derived-case audit.')
    (OUT/'owasp_crs_projection.json').write_text(json.dumps(summary,indent=2)+'\n');(OUT/'owasp_crs_projection_records.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in records))
    print(json.dumps(dict(groups=summary['groups'],conflicting_rule_groups=len(contradictions)),indent=2))
if __name__=='__main__':main()
