"""Materialize a reviewable experimental composition; never approve or train it."""
import argparse
from collections import Counter
import copy
import json
from pathlib import Path
import sys

from successor_contract import (REPO,D,RC,SCHEMA,AUTH_SCHEMA,PROTOCOL_SCHEMA,
                                bound,capture,sha,mapped_meta,prepare)

ROOT=REPO/'reports/v5/successor-2026-10-30'
PREVIEW=ROOT/'stage4-preview-expanded-v3'
PARENT=REPO/'datasets/v5_sources/final_source_2026-10-26-v4'
PARENT_RECORDS=REPO/'reports/v5/dataset-preregistration-v1/final-run-2026-10-26-v4'
COORD=Path('/home/sebas/Documents/Codex/2026-10-26/ta/outputs/Coordinacion_modelos_arquitectura')


def write_json(path,obj):
    with path.open('x') as handle:json.dump(obj,handle,indent=2);handle.write('\n')


def main():
    p=argparse.ArgumentParser();p.add_argument('--dataset',type=Path,required=True);p.add_argument('--out',type=Path,required=True);args=p.parse_args()
    dataset=args.dataset.resolve();out=args.out.resolve()
    if dataset.exists() or out.exists():raise ValueError('Do not overwrite a prepared package')
    D.C.assert_not_protected(str(dataset))
    preview=json.loads((PREVIEW/'preview.json').read_text())
    partition=json.loads((ROOT/'partition/partition-expanded.DRAFT.json').read_text())
    opened=('TRAIN_CANDIDATE','VALIDATION_CANDIDATE')
    desc={r['split']:r for r in preview['artifacts']}
    source_desc={r['split']:r for r in partition['artifacts']}
    augmentation={s:D._jsonl_records(capture(desc[s]).decode()) for s in opened}
    oldmanifest,msha=D.load_manifest(str(PARENT))
    parent_art={a['path']:a for a in oldmanifest['artifacts']}
    parent_raw={}
    for name in ('rows.TRAIN.jsonl','rows.TRAIN.meta.jsonl'):
        parent_raw[name]=capture(dict(path=str(PARENT/name),sha256=parent_art[name]['sha256'],bytes=parent_art[name]['bytes']))
        if not parent_raw[name].endswith(b'\n'):raise ValueError('Parent TRAIN lacks terminal LF')
    old_rows,diags=D.parse_split(parent_raw['rows.TRAIN.jsonl'].decode(),parent_raw['rows.TRAIN.meta.jsonl'].decode(),'TRAIN')
    if diags:raise ValueError('Parent row alignment failed')
    if len(old_rows)!=3080:raise ValueError('Unexpected parent TRAIN size')
    # The old draft inherited RATIFIED at root. New records make proposal status
    # explicit; no historical recipe or evidence is amended.
    recipe=copy.deepcopy(json.loads((ROOT/'v51-expanded-vocabulary.recipe.DRAFT.json').read_text()))
    recipe.update(recipe_id='v51-policy-composition-experimental-20261031',status='PROPOSED',
                  note='Experimental successor proposal. Same pinned base, fresh LoRA; original TRAIN preserved. Requires committed owner admission for this exact composition. No FINAL or production authorization.')
    for key,value in recipe.items():
        if isinstance(value,dict) and key!='smoke' and 'status' in value:
            value.update(status='PROPOSED',source='Inherited parameters from the original recipe; this composition requires explicit experimental owner admission.')
    recipe['initialization']=dict(mode='PINNED_BASE_WITH_NEW_LORA',continue_from_adapter=False,
                                 original_TRAIN_preserved=True,status='PROPOSED')
    protocol=dict(schema=PROTOCOL_SCHEMA,status='PROPOSED',scope='EXPERIMENTAL_V5_ONLY',
        parent_usage='UNCHANGED_TRAIN_ONLY',parent_manifest_sha256=msha,
        new_label_basis='Existing D62/D75 typed-URL policy, POLICY_DEFINED; no fabricated AI audit outcome or VERIFIED upgrade',
        source_admission='Owner explicitly accepts exact source/context/hash-bound H1 proposal; no domain-wide exception',
        sampling=dict(source_seed=20261030,base_pairs_per_cluster_category=40,
                      added_coverage_pairs=3,coverage_attempt_start=100000,coverage_attempts_per_source=5000,
                      coverage_selection='Only source inventory coverage, never model predictions; complete ALLOW/BLOCK siblings retained'),
        reserve=dict(source_artifact=source_desc['RESERVE_CANDIDATE'],
                     rendered_cases='NOT_MATERIALIZED_OR_EVALUATED',
                     template_ids=sorted(k for k,v in partition['new_template_assignments'].items() if v['split']=='RESERVE_CANDIDATE'),
                     rule='Source assignment and generation code frozen before training. Never use reserve for tuning; no FINAL claims from this experiment.'),
        validation=dict(purpose='URL-policy development validation, not an independent security benchmark',
                        source_records=18,source_components=15,template_clusters=13,
                        early_stopping_or_checkpoint='Existing recipe lowest VALIDATION loss; acceptance also requires nonregression checks'),
        selection=dict(max_initial_training_runs=1,
                       checks=['Report binary and reason accuracy plus invalids separately',
                               'Report per policy, family/component, carrier and benign URL type; rows are not independent trials',
                               'Check old primary-family and benign DEV nonregression; do not train on its errors',
                               'No protected sets for development/selection',
                               'Revalidate NF4 and verified-suffix decoding on the NEW weights/vocabulary before integration']),
        exclusions=['No claim to solve JWT/CSRF state/context absence',
                    'No CMD/json_leaf compatibility change in this experiment',
                    'ALT_A includes NoSQL/XPath/CRLF outputs without training examples; no coverage claim',
                    'No Model2 retraining, threshold selection or production deployment'])
    evidence_paths=dict(preview=PREVIEW/'preview.json',preview_audit=PREVIEW/'audit.json',
        shortcuts=PREVIEW/'shortcut_diagnostics.json',probes=PREVIEW/'token_and_structure_probes.json',
        catalog_audit=ROOT/'catalog/structural_audit-expanded.json',
        policy_admission=ROOT/'sources/policy_source_admission.DRAFT.json',
        provenance=ROOT/'sources/patt_source_provenance.json',partition=ROOT/'partition/partition-expanded.DRAFT.json')
    source_files=['scripts/v5_successor/'+name for name in
        ('successor_contract.py','prepare_successor_training.py','train_successor.py','policy_admission_proposal.py',
         'audit_stage4_preview.py','stage4_preview.py','curate_policy_sources_v2.py')]
    # Include all original dependencies whose hashes Model2 already binds. No
    # files are added to those dynamic-glob directories or modified there.
    pinned=json.loads((COORD/'CONTRATO_DE_TRABAJO.json').read_text())['immutable_model2_bound_sources']
    for path,digest in pinned.items():
        if sha((REPO/path).read_bytes())!=digest:raise ValueError('Immutable source changed: '+path)
    source_files+=list(pinned)+['control_plane/v5_output_contract.py','control_plane/v5_inference_core.py',
        'reports/v5/freeze-prep-claude-2026-10-26/h1_identity_secrets_scan.py',
        'scripts/dataset/v5_templates/field_names_v1.json','scripts/dataset/v5_policy/policy_table_v1.json',
        'reports/v5/successor-2026-10-30/catalog/catalog-v51-expanded.DRAFT.json']
    hashes={path:sha((REPO/path).read_bytes()) for path in sorted(set(source_files))}
    # All validation/input checks happen before either output directory exists.
    dataset.mkdir(parents=True);out.mkdir(parents=True)
    recipe_path=out/'recipe.EXPERIMENTAL.json';protocol_path=out/'protocol.PROPOSED.json'
    write_json(recipe_path,recipe);write_json(protocol_path,protocol)
    artifacts=[]
    for split,source_split in zip(('TRAIN','VALIDATION'),opened):
        additions=augmentation[source_split]
        rows=''.join(D.canonical_json(dict(text=r['text'],output=r['meta']['output']))+'\n' for r in additions).encode()
        meta=''.join(D.canonical_json(mapped_meta(r['meta'],split))+'\n' for r in additions).encode()
        for suffix,raw in [('',rows),('.meta',meta)]:
            name=f'rows.{split}{suffix}.jsonl'
            if split=='TRAIN':raw=parent_raw[name]+raw
            path=dataset/name
            with path.open('xb') as handle:handle.write(raw)
            path.chmod(0o600);artifacts.append(dict(name=name,**bound(path)))
    manifest_path=out/'dataset-manifest.EXPERIMENTAL.json'
    manifest=dict(schema=SCHEMA,status='EXPERIMENTAL_CANDIDATE',manifest_path=str(manifest_path),
        dataset_dir=str(dataset),row_contract=RC.SCHEMA,
        parent=dict(dataset_dir=str(PARENT),manifest=bound(PARENT/'manifest.json'),TRAIN_rows=len(old_rows),
                    records={key:bound(PARENT_RECORDS/name) for key,name in
                             [('preregistration','preregistration.json'),('freeze','freeze-record.json'),('ai_authorization','v5-ai-audit-training-authorization.json')]}),
        artifacts=artifacts,recipe=bound(recipe_path),protocol=bound(protocol_path),
        source_sha256=hashes,evidence={key:bound(path) for key,path in evidence_paths.items()},
        augmentation=dict(source_artifacts={s:bound(source_desc[s+'_CANDIDATE']['path']) for s in ('TRAIN','VALIDATION')},
                          preview_artifacts={s:bound(desc[s+'_CANDIDATE']['path']) for s in ('TRAIN','VALIDATION')}),
        training_permission='SEPARATE_COMMITTED_OWNER_ADMISSION_REQUIRED',mode='EXPERIMENTAL_ONLY_NOT_FINAL')
    write_json(manifest_path,manifest)
    admission=dict(schema=AUTH_SCHEMA,status='DRAFT_PENDING_OWNER',scope='EXPERIMENTAL_V5_ONLY',
        training_allowed=False,accept_scoped_policy_sources=False,owner_decision='',authorized_by='',date='',
        dataset_manifest_sha256=sha(manifest_path.read_bytes()),recipe_sha256=manifest['recipe']['sha256'],
        protocol_sha256=manifest['protocol']['sha256'],policy_source_admission_sha256=manifest['evidence']['policy_admission']['sha256'])
    write_json(out/'owner-admission.DRAFT.json',admission)
    m,_,rows,_,_=prepare(manifest_path,training=False)
    summary=dict(status='MATERIALIZED_TECHNICAL_REVIEW_PASSED_PENDING_OWNER_AND_COMMIT',
                 manifest=bound(manifest_path),rows={s:len(r) for s,r in rows.items()},
                 labels={s:dict(Counter(r['meta']['label'] for r in rr)) for s,rr in rows.items()},
                 parent_TRAIN_byte_prefix_preserved=True,training_authorized=False,reserve_opened=False)
    write_json(out/'composition-check.json',summary)
    print(json.dumps(summary,indent=2))


if __name__=='__main__':main()
