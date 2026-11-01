"""Inventory public CRS regressions without promoting rule outcomes to labels."""
from collections import Counter,defaultdict
import hashlib,json
from pathlib import Path
import yaml
REPO=Path(__file__).resolve().parents[2]
PRIVATE=Path('/home/sebas/Documents/Codex/2026-10-26/ta/work/v51-sources')
OUT=REPO/'reports/v5/successor-2026-10-30/sources'
MAP={'REQUEST-930-APPLICATION-ATTACK-LFI':'path_file_access','REQUEST-931-APPLICATION-ATTACK-RFI':'remote_file_inclusion','REQUEST-932-APPLICATION-ATTACK-RCE':'command_injection','REQUEST-933-APPLICATION-ATTACK-PHP':'php_injection','REQUEST-934-APPLICATION-ATTACK-GENERIC':'generic_injection','REQUEST-941-APPLICATION-ATTACK-XSS':'xss','REQUEST-942-APPLICATION-ATTACK-SQLI':'sql_injection','REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION':'session_fixation','REQUEST-944-APPLICATION-ATTACK-JAVA':'java_injection'}
def main():
    OUT.mkdir(parents=True,exist_ok=True)
    origin=json.loads((PRIVATE/'owasp-crs-source.json').read_text());root=Path(origin['local_root']);stats=defaultdict(Counter);items=[];errors=[]
    for f in sorted((root/'tests/regression').rglob('*.yaml')):
        data=f.read_bytes()
        try:q=yaml.safe_load(data) or {}
        except Exception as e:errors.append({'path':str(f.relative_to(root)),'error':type(e).__name__});continue
        if not isinstance(q,dict):continue
        tests=q.get('tests',[]) or []
        for case in tests:
            if not isinstance(case,dict):continue
            group=f.parent.name;stats[group]['tests']+=1
            for number,stage in enumerate(case.get('stages',[]) or []):
                if not isinstance(stage,dict):continue
                inp=stage.get('input') or {};output=stage.get('output') or {};log=output.get('log') or {};stats[group]['stages']+=1
                for key,cond in [('raw_request','raw_request' in inp),('expect_rule',bool(log.get('expect_ids'))),('no_expect_rule',bool(log.get('no_expect_ids'))),('status_assert',bool(output.get('status')))]:
                    if cond:stats[group][key]+=1
                rid=hashlib.sha256(json.dumps([origin['commit'],str(f.relative_to(root)),case.get('test_id'),number],sort_keys=True).encode()).hexdigest()
                items.append(dict(record_id=rid,source='OWASP CRS',source_commit=origin['commit'],source_file=str(f.relative_to(root)),source_file_sha256=hashlib.sha256(data).hexdigest(),rule_id=q.get('rule_id'),test_id=case.get('test_id'),stage=number,nominal_family=MAP.get(group),group=group,input=inp,output_assertions=output,description=case.get('desc'),label=None,label_status='PENDING_CONTEXTUAL_REVIEW',redistribution_status='LOCAL_CANDIDATE_ONLY',license_basis='Apache-2.0 root; per-file review pending',multi_stage=len(case.get('stages',[]))>1))
    raw=PRIVATE/'owasp-crs-candidate-stages.private.jsonl';raw.write_text(''.join(json.dumps(x)+'\n' for x in items));raw.chmod(0o600)
    summary=dict(source=origin,root_license_sha256=hashlib.sha256((root/'LICENSE').read_bytes()).hexdigest(),parsed_stages=len(items),groups={k:dict(v) for k,v in sorted(stats.items())},yaml_errors=errors,private_candidates_sha256=hashlib.sha256(raw.read_bytes()).hexdigest(),private_candidates_path=str(raw),accepted_training_rows=0,warning='Expected WAF rule/log/status is not independent security ground truth. No automatic BLOCK or ALLOW labels. Candidate corpus is not admitted to training.')
    (OUT/'owasp_crs_inventory.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({'parsed_stages':len(items),'yaml_errors':len(errors),'groups':summary['groups']},indent=2))
if __name__=='__main__':main()
