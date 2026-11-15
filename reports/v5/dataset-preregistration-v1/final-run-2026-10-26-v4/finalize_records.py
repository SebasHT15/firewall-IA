#!/usr/bin/env python3
"""Complete separate A/B/C records after acceptance; never launches either trainer."""
from pathlib import Path
import hashlib,json,sys,re,shutil
R=Path(__file__).resolve().parents[4];D=Path(__file__).resolve().parent;DS=R/'datasets/v5_sources/final_source_2026-10-26-v4'
sys.path.insert(0,str(R));sys.path.insert(0,str(R/'scripts/dataset'))
from scripts.model2 import final_training as F,training as T
from scripts.training import v5_train_data as VD
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def load(p):return json.loads(p.read_text())
def save(p,o):p.write_text(json.dumps(o,indent=2,sort_keys=True,ensure_ascii=False)+'\n');return sha(p)
def ev(p):return {'path':str(p.relative_to(R)),'sha256':sha(p)}
accept=load(D/'acceptance.json');a2=load(D/'A2-regeneration.json')
assert accept['blocking_pass'] and a2['A2_pass']
manifest=load(DS/'manifest.json');msha=sha(DS/'manifest.json');assert msha==accept['manifest_sha256']==a2['base_manifest_sha256']
assert manifest['status']=='REAL' and manifest['gates']['ok']
assert sha(R/'datasets/v5_sources/final_source_2026-10-25-v3/manifest.json')=='7c1ebb9a98fa437c1a1be6839cfe1b2e9b31cac247b8a6ec4d08dc12d5ae8d16'
pre=load(D/'preregistration.json');test=R/'tests/test_canonical_request_review.py';assert sha(test)==pre['ratified']['i7']['test_source_sha256']
original=Path('/tmp/claude-1000/-home-sebas-Desktop-firewall-IA/0aa1a8e9-73ac-411c-8177-983eeefebc21/scratchpad/i7.log')
if original.exists():shutil.copyfile(original,D/'i7-accredited-original.log')
assert (D/'i7-accredited-original.log').is_file()
save(D/'i7-continuity.json',{'schema':'v5-i7-continuity/v1','test_source':ev(test),'preregistered':pre['ratified']['i7'],
 'original_execution_log':ev(D/'i7-accredited-original.log'),'original_command':'/usr/bin/python3.12 -m unittest tests.test_canonical_request_review',
 'result':'115 methods; OK, skipped=8; the two TestTotalityFuzz methods were not skipped',
 'canonical_implementation':ev(R/'data_plane/canonical_request.py'),'rerun_v3_i7':False,'new_rows':'Generated through the unchanged canonicalize/round-trip gates; no truncation allowed.'})
counts={'rows':0,'transfer_encoding_header_lines':0,'raw_chunk_size_lines':0}
for split in ['TRAIN','VALIDATION','INTERNAL_TEST']:
 for line in (DS/f'rows.{split}.jsonl').read_text().splitlines():
  t=json.loads(line)['text'];counts['rows']+=1;counts['transfer_encoding_header_lines']+=len(re.findall(r'(?im)^Transfer-Encoding\s*:',t));counts['raw_chunk_size_lines']+=len(re.findall(r'(?:^|\r\n)[0-9a-fA-F]+\r\n',t))
assert counts['transfer_encoding_header_lines']==counts['raw_chunk_size_lines']==0
save(D/'h2-h3-evidence.json',{'schema':'v5-h2-h3-review/v1','manifest_sha256':msha,'H2':'PASS, unchanged value-semantics labelling and M8 signature/renaming evidence','H3':counts,'sources':[ev(R/p)for p in ['scripts/dataset/v5_render.py','scripts/dataset/v5_labels.py','data_plane/canonical_request.py']]})
nov=load(D/'novelty-ancestry.json');a5=R/'reports/v5/freeze-prep-claude-2026-10-26';cs7=load(D/'cs7-counts.json')
report=f'''# V5 v4 dataset freeze report — 2026-10-26 (Costa Rica)

Dataset manifest REAL: `{msha}`. Formal freeze is a separate v5-dataset-freeze-record/v1; its issuance does not modify this manifest.
Owner direction: D78 exact chat instruction; A, B and C implemented as separate D79/D80/D81 records. No target model has trained.

## Identity and composition

3080 TRAIN, 40 VALIDATION, 40 INTERNAL_TEST; {manifest['counts']['pairs']['complete']} complete pairs; quota shortfalls {len(manifest['counts']['quota_shortfalls'])}.
Generator/split configs are ratified with the existing D74/D75/D76 values. Twelve H1-disallowed attack records and one symbols value were removed prospectively before generation.
All retained attack source lines are byte-identical to parent records and pass their own original path/census/SQLi component membership checks.
No normalization, fabricated label, new payload, category PASS transfer or combined-pool PASS. The projected merge declarations preserve equivalence relations among surviving IDs.
The full composition, assignment hashes, class/provider/category counts, source pins, seeds and environment are in the manifest and source-hygiene-ledger.json.
The validation/internal-test row and metadata artifacts are byte-identical to v3, verified in sealed-set-continuity.json. Earlier versions remain preserved.

## Acceptance

| Control | Measurement / acceptance |
|---|---|
| A1 | 14 declared artifact hashes/sizes valid in freeze-precheck.json |
| A2 | Two fresh CPython 3.14.4 processes, PYTHONHASHSEED 17/83, repo and /tmp cwd, manifest plus 14 artifacts byte-identical; clean tracked tree before/after |
| A3 / SPL | Manifest SPL-3…9 PASS; targeted Invariants tests include order/seed and violations; split principles unchanged |
| A4 | Retained source provenance/licence review; A4_SOURCE_REVIEW.md, parent A4, source hygiene ledger and local archives |
| A5 | 34 H1 tests and 27 targeted checker tests OK, zero skips in these targeted runs. Existing generator/dataset/shortcuts tests retained; no unsupported '83/83 generator' claim |
| A6 | Eleven factual checks pass on v4; aggregator freeze_ready remains false by design. Its unchanged fail-closed implementation and earlier mutation evidence remain accredited |
| I7 | Exact preregistered source pin and existing execution preserved in i7-continuity.json; deterministic corpus 2500/seed20261013 + 256-byte sweeps, neither fuzz method skipped |
| L1/L2/L4/L5/L9 | Manifest SPL-3/SPL-6: no cross-split identity/text/payload/value overlap; detailed counters in manifest |
| L7/L7a | Counts-only, 13 registered entries; all blocking sets checked and passing. CSIC extractor's unchecked warning is covered separately by L11 |
| L8 | Probe pool remaining overlap zero; new sources are subsets of prior verified pools |
| M-1…M-8 / C-M2 / C-M3 | Manifest label invariants/pair integrity PASS; complete twins; class share .5 per split. Targeted negative tests for M-1…8 and C-M3 |
| C-S1/S2/S6 | All thresholds pass in shortcut-partial.json; minimum symmetry ratio 1.0 |
| C-S3 | Token-purity report blocking PASS |
| C-S4 | Structure-only checker accuracy .5, PASS; a protocol quality probe, not either FINAL target model |
| C-S7 | TRAIN passes; small protected split concentrations retained as WARN under D76 |
| H1 | All 3160 rows pass corrected context/provenance-based checker; 0 confirmed or unresolved findings |
| H2/H3 | Source review PASS; {counts['rows']} texts, zero Transfer-Encoding header lines and zero raw chunk framing |
| STAB | Original sealed STAB-HELD retained; source-subset disjointness proof, seal unchanged, D77 G1–G5 linked; no sealed cases opened/evaluated |

## §11.3 evidence

post_filter_audit: original path_file_access, census CmdI/SSTI/XSS and SQLi v3 remain separate, each PASS_AI_AUDITED only for its declared categories.
blocking_checks: above reports plus acceptance.json and A2-regeneration.json. dataset_preregistration: committed before full build.
stab_held_sealed: original SEAL and D77 continuity. dataset_freeze_report: this report. Each is hash-bound by freeze-record.json.

## Warnings, disclosures and limits accepted in the readiness instruction

CmdI/SQLi/SSTI/XSS remain TRAIN-only/NOT_EVALUABLE per D60/D74; only path_file_access evaluable, with the two named single-structure exceptions.
L10 WARN high remains: VALIDATION 15/20 and INTERNAL_TEST 19/20; L11 has {len(nov['L11_unique_hit_record_ids'])} hit record IDs.
STAB is project-authored/concept-built, not an independent traffic sample or human-adjudicated set. PATT legacy provenance lacks per-row hashes for 1666 parent rows; do not imply this was repaired.
AI_AUDITED is not human validation. No production security/performance, threshold, operational winner or runtime activation is authorized.
Local source archives are recovery-verified; no off-device backup is claimed. CPython3.14.4 is needed for manifest byte identity, while trainers use their pinned Python3.12 environments.

## Rejection/continuation log and next guards

v1 failed L8; v2 failed C-S7; v3 preserved with H1 failure; v4 corrects source hygiene prospectively before any model output.
The freeze is not a model result. PR to develop remains required under D73. Actual model fitting is not started here.
FINAL launch must recheck committed records, source/library bindings, eligibility and clean tree. INTERNAL_TEST/STAB are never used for checkpoint selection.
'''
(D/'DATASET_FREEZE_REPORT.md').write_text(report)
# Record separate owner decisions without pretending the human signed JSON bytes.
dp=R/'DECISIONS.md';dec=dp.read_text()
assert '## D79 'not in dec
for num,title,body in [
 (79,'dataset v4 research freeze (A)',f'Implements the owner instruction quoted in D78 after measured acceptance. Dataset manifest {msha}; acceptance.json and A2-regeneration.json pass. The five r4 §11.3 items are hash-bound in final-run-2026-10-26-v4/freeze-record.json. The manifest remains REAL and the separate record is FROZEN. All D60/D67/D74/D76, provenance, L10, concentration and STAB limitations in DATASET_FREEZE_REPORT.md persist. This records a research dataset freeze, not production validation or a model result.'),
 (80,'V5 ai-audited FINAL readiness authorization (B)','Separately implements the owner-directed readiness step B enumerated before the instruction quoted in D78. Allows the hash-bound V5 FINAL run on frozen v4 with the D73-ratified recipe/preregistration. The disclosed AI_AUDITED basis is acknowledged as not human validation; four injection categories remain NOT_EVALUABLE. The separate ai-audit authorization is committed and bound to the freeze record. No Model2 authorization, operating threshold or runtime activation follows from B. The agent stops at gate-only; actual training is left to the owner launch command.'),
 (81,'Model2 FINAL_OFFLINE readiness authorization (C)','Separately implements owner-directed step C under the same D78 instruction. Authorizes the baseline34 and target-path-neutralized32 candidates independently, with exact recipe/C1/selection/dataset/source/library pins. Fit on TRAIN, compare on VALIDATION, preserve identity groups; C1 extensions metadata-only, C2 absent, no operating threshold or deployed winner. The shared reader requires the separately bound ai-audit authorization. The agent stops at gate-only; no fitting occurs in this task. D73 PR-to-develop remains a precondition before actual training.')]:
 dec+=f'\n\n## D{num} — {title}\n\nOwner authorization evidence: the exact current-chat instruction recorded in D78, 2026-10-26 (Costa Rica). These are separate implementation records of that direction, not invented additional quotes, signatures or decisions by another person.\n\n{body}\n'
dp.write_text(dec)
components=load(D/'build-authorization.json')['components']
files=['acceptance.json','acceptance-execution.json','A2-regeneration.json','freeze-precheck.json','cs7-counts.json','protected-collision-counts.json','shortcut-partial.json','token-purity.json','structure-probe.json','novelty-ancestry.json','h1-identity-secrets.json','h2-h3-evidence.json','i7-continuity.json','i7-accredited-original.log','source-hygiene-ledger.json','input-retention.json','sealed-set-continuity.json','A4_SOURCE_REVIEW.md','h1-unit-tests.log']
freeze={'schema':'v5-dataset-freeze-record/v1','status':'FROZEN','spec':'V5-DATA-SPEC-r4','dataset_manifest_sha256':msha,'owner_decision':'D79, separately implementing owner readiness instruction D78',
 'items':{'post_filter_audit':{'status':'DONE','audit_type':'ai_audited','components':components,'combined_pool_pass':False,'evidence':[ev(R/'reports/v5/postfilter-audit/final-component-bindings.json')]},
 'blocking_checks':{'status':'DONE','evidence':[ev(D/n)for n in files]+[ev(a5/'a5-closeout-tests.log'),ev(a5/'h1_identity_secrets_scan.py'),ev(a5/'test_h1_identity_secrets.py'),ev(R/'tests/test_v5_freeze_precheck.py')]},
 'dataset_preregistration':{'status':'DONE','evidence':[ev(D/'preregistration.json')]},
 'stab_held_sealed':{'status':'DONE','evidence':[ev(R/'datasets/v5_sources/stab_held_2026-10-25-v1/SEAL.json'),ev(D/'sealed-set-continuity.json')]},
 'dataset_freeze_report':{'status':'DONE','evidence':[ev(D/'DATASET_FREEZE_REPORT.md')]}},
 'known_limitations':['AI_AUDITED is not human validation.','Four injection categories TRAIN-only/NOT_EVALUABLE.','Path protected splits have single-structure exceptions.','L10 WARN high.','STAB concept-built; no independent external validation.','PATT legacy per-row provenance limitations persist.','Local retained inputs do not establish independent off-device backup.']}
fsha=save(D/'freeze-record.json',freeze)
recipe_path=R/'scripts/training/v5_training_recipe_v1.json';recipe,rsha=VD.load_recipe(str(recipe_path))
ai={'schema':'v5-ai-audit-training-authorization/v1-PROPOSED','scope':'FINAL','audit_type':'ai_audited',
 'dataset_manifest_sha256':msha,'freeze_record_sha256':fsha,'owner_decision':'D80','authorized_by':'SebasHT15 (owner current-chat instruction, D78/D80)','date':'2026-10-26',
 'authorizes_ai_audited_final_training':True,'acknowledges_not_human_validation':True}
aisha=save(D/'v5-ai-audit-training-authorization.json',ai)
save(D/'v5-training-preregistration.json',{'schema':'v5-training-preregistration/v1','status':'RATIFIED','owner_decision':'D80','dataset_manifest_sha256':msha,'recipe_sha256':rsha,'template_fingerprint':VD.template_fingerprint(recipe),
 'sealed_stability_gates':{'owner_decision':'D77','evidence':ev(R/'reports/v5/dataset-preregistration-v1/final-run-2026-10-25-v3/STAB_GATES_TO_RATIFY.md')},'protected_sets_not_for_selection':['INTERNAL_TEST','STAB-HELD','E6_RESERVE','External_v1']})
M=R/'reports/v5/hybrid/model2-readiness';c1=M/'c1-training-input-candidate-v1.json';selection=R/'reports/v5/training-readiness/MODEL2_RECETAS_PROPUESTA_2026-10-24.md'
for tag,name in [('baseline34','model2-recipe-candidate-v1.json'),('path-ablation32','model2-recipe-path-ablation-candidate-v1.json')]:
 rp=M/name;rec=load(rp);T.validate_recipe(rec,'FINAL');F.validate_c1(load(c1),rec)
 auth={'schema':'model2-final-training-authorization/v1-PROPOSED','scope':'FINAL_OFFLINE_MODEL2','status':'AUTHORIZED','owner_decision':'D81','authorized_by':'SebasHT15 (owner current-chat instruction, D78/D81)','date':'2026-10-26',
 'dataset_manifest_sha256':msha,'recipe_sha256':T.digest(T.encode(rec)),'recipe_file_sha256':sha(rp),'c1_contract_sha256':sha(c1),'selection_protocol_sha256':sha(selection),
 'dataset_preregistration_sha256':sha(D/'preregistration.json'),'freeze_record_sha256':fsha,'vocabulary_recipe_sha256':rsha,'ai_audit_authorization_sha256':aisha,
 'source_sha256':T.source_hashes(),'reader_source_sha256':F.reader_hashes(),'library_versions':F.library_versions()}
 save(D/f'model2-authorization.{tag}.json',auth)
print(json.dumps({'manifest':msha,'freeze_record':fsha,'A':'D79','B':'D80','C':'D81','trained':False}))
