from pathlib import Path
import json,hashlib,shutil,re,sys
R=Path(__file__).resolve().parents[4];old=R/'reports/v5/dataset-preregistration-v1/final-run-2026-10-25-v3';D=R/'reports/v5/dataset-preregistration-v1/final-run-2026-10-26-v4';S=R/'datasets/v5_sources/hygiene_inputs_2026-10-26-v4'
sys.path.insert(0,str(R/'reports/v5/freeze-prep-claude-2026-10-26'));import h1_identity_secrets_scan as H

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,x):p.write_text(json.dumps(x,indent=2,sort_keys=True,ensure_ascii=False)+'\n');return sha(p)
S.mkdir(exist_ok=False);shutil.copytree(R/'datasets/v5_sources/benign',S/'benign')
source=R/'datasets/v5_sources/final_candidate/attack_pool.jsonl';kept=[];excluded=[]
for line in source.read_bytes().splitlines(keepends=True):
 r=json.loads(line);reasons=set()
 for text in {r.get('payload_wire',''),r.get('payload_logical','')}:
  for t in H.variants(text):
   markers=list(H.MARKER_RE.finditer(t)) if r['record_id']==H.MARKER_PAYLOAD_RECORD_ID else []
   for rx in (H.URL,H.RELATIVE_URL,H.HEADER):
    for m in rx.finditer(t):
     if '%'in m.group(1):continue
     try:host=H.clean_authority(m.group(1))
     except ValueError:reasons.add('unparsed_authority');continue
     if host==H.MARKER_HOST and any(a.start()<=m.start()and m.end()<=a.end()for a in markers):continue
     if not H.reserved(host):reasons.add('non_reserved_host:'+host)
   for m in H.VENDOR.finditer(t):
    if re.match(r'"\s*:',t[m.end():]):continue
    reasons.add('vendor_pattern:'+m.group().lower())
   if H.EMAIL.search(t):reasons.add('email_pattern_in_attack_source')
   if H.SECRET.search(t):reasons.add('secret_pattern')
 if reasons:excluded.append({'record_id':r['record_id'],'category':r['dedup_scope'],'reasons':sorted(reasons),'original_record_sha256':hashlib.sha256(line).hexdigest()})
 else:kept.append(line)
(S/'attack_pool.jsonl').write_bytes(b''.join(kept))
p=S/'benign/symbols.jsonl';lines=p.read_bytes().splitlines(keepends=True);symbol_excluded=[];out=[]
for line in lines:
 r=json.loads(line)
 if r.get('status')=='ACCEPTED' and H.VENDOR.search(r.get('value','')):
  symbol_excluded.append({'value_entry_id':r['value_entry_id'],'value_sha256':hashlib.sha256(r['value'].encode()).hexdigest(),'reason':'vendor_pattern','source_record_sha256':hashlib.sha256(line).hexdigest()})
 else:out.append(line)
p.write_bytes(b''.join(out));m=json.loads((S/'benign/manifest.json').read_text())
for a in m['artifacts']:
 if Path(a['path']).name=='symbols.jsonl':a.update(sha256=sha(p),bytes=p.stat().st_size,records=len(out))
stat=m['pools']['symbols'];stat['accepted']-=len(symbol_excluded);stat['extracted']-=len(symbol_excluded);stat['rows_read']-=len(symbol_excluded)
# Keep parent counts as provenance, rather than claim an extraction was repeated.
m['hygiene_subset']={'owner_decision':'D78','source_manifest_sha256':sha(R/'datasets/v5_sources/benign/manifest.json'),'excluded_values':symbol_excluded,'method':'subset of original records, surviving bytes unchanged'}
for k in ['flags_accepted','flags_extracted']:stat.pop(k,None)
save(S/'benign/manifest.json',m)
ledger={'schema':'v5-hygiene-source-subset/v1','owner_decision':'D78','parent_attack_sha256':sha(source),'attack_pool_sha256':sha(S/'attack_pool.jsonl'),'kept_attack_records':len(kept),'excluded_attacks':excluded,'excluded_symbols':symbol_excluded,'benign_manifest_sha256':sha(S/'benign/manifest.json'),'policy':'prospective source-only hygiene filtering before v4; no model outputs; no threshold changes; component membership required for every retained attack','unchanged_retained_attack_bytes':True,'old_dataset_untouched':True}
save(D/'source-hygiene-ledger.json',ledger)
for name in ['generator-config.json','split-config.json']:(D/name).write_bytes((old/name).read_bytes())
sys.path.insert(0,str(R/'scripts/dataset'))
import v5_identities as I,v5_split as SP
cfg=json.loads((D/'split-config.json').read_text())
known={I._family_key(json.loads(line)['payload_wire']) for line in kept}
changed=[];projected=[]
for group in cfg['family_merges']:
 remaining=[x for x in group if x in known]
 if len(remaining)>1:projected.append(remaining)
 if remaining!=group:changed.append({'removed_absent_ids':[x for x in group if x not in known],'survivors':remaining})
cfg['family_merges']=projected;save(D/'split-config.json',cfg)
ledger['merge_projection']={'method':'project old equivalence classes onto surviving source family IDs; preserve all remaining group relations','changed_groups':changed}
save(D/'source-hygiene-ledger.json',ledger)
pr=json.loads((old/'preregistration.json').read_text());pr.update(version='v5-dataset-v4',training_authorized=False)
pr['owner_decisions'].append('D78');pr['correction']={'owner_ruling':'D78','reason':'Prospective H1 source hygiene subset; prior dataset preserved; no model output viewed','parent_manifest_sha256':'7c1ebb9a98fa437c1a1be6839cfe1b2e9b31cac247b8a6ec4d08dc12d5ae8d16','source_hygiene_ledger_sha256':sha(D/'source-hygiene-ledger.json')}
pr['ratified']['split_config_file_sha256']=sha(D/'split-config.json');pr['ratified']['split_config_sha256']=SP.config_sha256(cfg)
pr['ratified']['attack_pool_sha256']=sha(S/'attack_pool.jsonl');pr['ratified']['benign_manifest_sha256']=sha(S/'benign/manifest.json')
prsha=save(D/'preregistration.json',pr)
a=json.loads((old/'build-authorization.json').read_text());a.update(split_config_sha256=SP.config_sha256(cfg),assembled_pool_sha256=sha(S/'attack_pool.jsonl'),preregistration_sha256=prsha,owner_decision='D78; owner instruction to resolve all readiness points; source hygiene subset',date='2026-10-26')
save(D/'build-authorization.json',a)
print(json.dumps({'attack_kept':len(kept),'attack_excluded':len(excluded),'symbols_excluded':len(symbol_excluded),'preregistration':prsha,'source_inputs':str(S)}))
