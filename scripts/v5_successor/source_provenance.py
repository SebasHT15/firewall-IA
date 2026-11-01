"""Verify candidate origins at the pinned PATT commit; no licence upgrades."""
from collections import Counter
import hashlib,json,re,subprocess
from pathlib import Path
REPO=Path(__file__).resolve().parents[2]
PATT=Path('/home/sebas/PayloadsAllTheThings')
PRIVATE=Path('/home/sebas/Documents/Codex/2026-10-26/ta/work/v51-sources')
OUT=REPO/'reports/v5/successor-2026-10-30/sources'
COMMIT='e961fef231d8327bae83b563fab50aec2e6b77c0'
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
    desc=json.loads((OUT/'patt_url_derived_v3.json').read_text());data=Path(desc['output_path']).read_bytes();assert sha(data)==desc['output_sha256'];rows=[json.loads(l) for l in data.splitlines()]
    original={r['record_id']:r for r in map(json.loads,(REPO/'datasets/v5_sources/attack/attack_pool.jsonl').read_text().splitlines())}
    deny_path=REPO/'scripts/dataset/v5_lexicon/patt_third_party_denylist_v2.json';deny=json.loads(deny_path.read_text());denied={r['path'] for r in deny['denied']}
    assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=PATT,text=True).strip()==COMMIT
    files={};problems=[];records=[]
    for name in sorted({r['source_file'] for r in rows}):
        local=(PATT/name).resolve();assert local.is_relative_to(PATT)
        content=local.read_bytes();committed=subprocess.check_output(['git','show',COMMIT+':'+name],cwd=PATT)
        text=content.decode();flags=[i+1 for i,l in enumerate(text.splitlines()) if re.search(r'copyright|spdx-license|copied from|taken from|originally from|source:|credits|adapted from',l,re.I)]
        issues=[]
        if content!=committed:issues.append('WORKTREE_DIFFERS_FROM_PIN')
        if name in denied:issues.append('DENYLISTED_FILE')
        if flags:issues.append('EXPLICIT_ORIGIN_OR_LICENSE_LINE_REVIEW_REQUIRED')
        files[name]=dict(sha256=sha(content),bytes=len(content),candidate_rows=sum(r['source_file']==name for r in rows),pinned_blob_matches=content==committed,denylisted=name in denied,explicit_origin_or_licence_lines=flags,licence_basis='Existing D58 default MIT assumption for unattributed PATT content; no new licence assertion',issues=issues)
        problems.extend(dict(source_file=name,reason=x) for x in issues)
    for row in rows:
        source=original[row['source_record_id']];content=(PATT/source['source_file']).read_text()
        ok=source['payload_raw'] in content
        if not ok:problems.append(dict(source_record_id=source['record_id'],reason='RAW_SOURCE_BYTES_NOT_FOUND'))
        records.append(dict(record_id=row['record_id'],source_record_id=source['record_id'],source_file=source['source_file'],raw_source_substring_found=ok,source_file_sha256=files[source['source_file']]['sha256']))
    report=dict(status='PINNED_SOURCE_IDENTITY_PASS_CONDITIONAL_ROOT_LICENCE' if not problems else 'SOURCE_REVIEW_BLOCKED',source_commit=COMMIT,root_licence_sha256=sha((PATT/'LICENSE').read_bytes()),denylist_sha256=sha(deny_path.read_bytes()),candidate_sha256=sha(data),files=files,records=records,problems=problems,warning='This verifies provenance and the existing approved default, not a legal opinion, human label audit or training authorization.')
    (OUT/'patt_source_provenance.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'files':len(files),'records':len(records),'problems':problems}))
if __name__=='__main__':main()
