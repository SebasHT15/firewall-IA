"""Versioned EXPERIMENTAL composition: frozen parent TRAIN + policy URL rows.

This does not declare the old FINAL reader applicable to new source components.
The owner must approve and commit this protocol and its exact artifacts before
the training launcher can run. Review/tokenization mode confers no permission.
"""
import hashlib
import json
from pathlib import Path
import sys
from urllib.parse import unquote_plus

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'scripts/training'),str(REPO/'scripts/dataset')]
import v5_train_data as D
import v5_component_binding as CB
import v5_row_contract as RC
import v5_identities as I
import v5_labels as L
import v5_generator as G
from policy_admission_proposal import validate_registered_url

SCHEMA='v51-experimental-composition/v1'
AUTH_SCHEMA='v51-experimental-training-admission/v1'
PROTOCOL_SCHEMA='v51-experimental-composition-protocol/v1'
ROW_SCHEMA='v51-policy-augmentation-row/v1'
SPLITS=('TRAIN','VALIDATION')
ARTIFACTS={f'rows.{s}{suffix}.jsonl' for s in SPLITS for suffix in ('','.meta')}


class Refused(ValueError):pass


def sha(raw):return hashlib.sha256(raw).hexdigest()


def capture(desc):
    path=Path(desc['path'])
    try:D.C.assert_not_protected(str(path))
    except SystemExit as exc:raise Refused(str(exc)) from None
    raw=path.read_bytes()
    if sha(raw)!=desc['sha256'] or ('bytes' in desc and len(raw)!=desc['bytes']):
        raise Refused('bound artifact changed: '+str(path))
    return raw


def bound(path):
    path=Path(path);raw=path.read_bytes()
    return dict(path=str(path.resolve()),sha256=sha(raw),bytes=len(raw))


def load_package(path):
    path=Path(path)
    try:D.C.assert_not_protected(str(path))
    except SystemExit as exc:raise Refused(str(exc)) from None
    raw=path.read_bytes();m=json.loads(raw)
    if m.get('schema')!=SCHEMA or m.get('status')!='EXPERIMENTAL_CANDIDATE':
        raise Refused('not an experimental successor composition')
    if m.get('manifest_path')!=str(path.resolve()):raise Refused('manifest path mismatch')
    names=[a.get('name') for a in m.get('artifacts',[])]
    if len(names)!=len(ARTIFACTS) or set(names)!=ARTIFACTS:
        raise Refused('only exact TRAIN/VALIDATION artifacts may be opened')
    if m.get('row_contract')!=RC.SCHEMA:raise Refused('training-reference contract missing')
    for desc in m['artifacts']:
        if Path(desc['path']).resolve()!=Path(m['dataset_dir']).resolve()/desc['name']:
            raise Refused('row artifact outside declared dataset directory')
    return m,sha(raw)


def verify_lineage(m,evidence,protocol):
    """A passing report for another rendering/source partition is not evidence."""
    preview=evidence['preview'];partition=evidence['partition']
    for key in ('preview_audit','shortcuts','probes'):
        if evidence[key].get('preview_sha256')!=m['evidence']['preview']['sha256']:
            raise Refused('evidence belongs to another rendering: '+key)
    if preview.get('source_partition_sha256')!=m['evidence']['partition']['sha256']:
        raise Refused('preview partition mismatch')
    if protocol.get('parent_manifest_sha256')!=m['parent']['manifest']['sha256']:
        raise Refused('protocol parent mismatch')
    registry=partition.get('source_registry_sha256')
    if not registry or registry!=evidence['provenance'].get('candidate_sha256') or registry!=evidence['policy_admission'].get('source_registry_sha256'):
        raise Refused('policy source registry lineage mismatch')
    for field,evidence_key in [('policy_sha256','scripts/dataset/v5_policy/policy_table_v1.json'),
                                ('validator_sha256','scripts/v5_successor/policy_admission_proposal.py')]:
        if evidence['policy_admission'].get(field)!=m['source_sha256'][evidence_key]:
            raise Refused('scoped source rule changed')
    if evidence['catalog_audit'].get('catalog_sha256')!=preview.get('catalog_sha256') or preview.get('catalog_sha256')!=partition.get('catalog_sha256'):
        raise Refused('catalog evidence lineage mismatch')
    for target,key,collection in [('preview_artifacts','preview','artifacts'),('source_artifacts','partition','artifacts')]:
        descriptors={d['split']:d for d in evidence[key][collection]}
        for split in SPLITS:
            expected=descriptors.get(split+'_CANDIDATE');actual=m['augmentation'][target][split]
            if expected is None or actual['sha256']!=expected['sha256'] or Path(actual['path']).resolve()!=Path(expected['path']).resolve():
                raise Refused('augmentation input is not the reviewed '+target)


def verify_metadata(m):
    """Check code/protocol/evidence pins; never open rows or reserve here."""
    for path,digest in m['source_sha256'].items():
        if sha((REPO/path).read_bytes())!=digest:raise Refused('source code changed: '+path)
    protocol=json.loads(capture(m['protocol']))
    if protocol.get('schema')!=PROTOCOL_SCHEMA or protocol.get('scope')!='EXPERIMENTAL_V5_ONLY':
        raise Refused('wrong composition protocol')
    if protocol.get('parent_usage')!='UNCHANGED_TRAIN_ONLY':raise Refused('parent scope changed')
    evidence={key:json.loads(capture(item)) for key,item in m['evidence'].items()}
    verify_lineage(m,evidence,protocol)
    audit=evidence['preview_audit']
    if (audit.get('status')!='ENGINEERING_CHECKS_PASS_ADMISSION_PENDING'
            or audit.get('identity',{}).get('status')!='PASS_UNDER_DRAFT_RULE'):
        raise Refused('preview technical audit is blocked')
    if not evidence['catalog_audit'].get('ok'):raise Refused('catalog audit is blocked')
    if evidence['policy_admission'].get('errors'):raise Refused('policy source admission has errors')
    for cell in evidence['shortcuts']['splits'].values():
        if any(cell[key] for key in ('C_S1_block_features','C_S1_within_family_block_cells','C_S2_pure_feature_levels','C_S6_block_levels')):
            raise Refused('structural shortcut evidence is blocked')
        if any(x['raw_status']=='BLOCK' for x in cell['C_S7'].values()):raise Refused('value dominance evidence is blocked')
    probes=evidence['probes']
    if probes['C_S4']['status']=='BLOCK' or any(cell['block_tokens'] for cell in probes['C_S3'].values()):
        raise Refused('token/structure probes are blocked')
    for row in evidence['provenance']['files'].values():
        if row['issues'] or row['denylisted'] or not row['pinned_blob_matches']:
            raise Refused('source provenance is blocked')
    parent=m['parent'];manifest=json.loads(capture(parent['manifest']))
    paths=parent['records']
    for desc in paths.values():capture(desc)
    diags=D.gate_dataset_final(manifest,parent['manifest']['sha256'],
        dataset_prereg=paths['preregistration']['path'],freeze_record=paths['freeze']['path'],
        ai_audit_authorization=paths['ai_authorization']['path'])
    if diags:raise Refused('parent dataset no longer eligible: '+','.join(d.code for d in diags))
    return protocol,manifest


def require_admission(m,msha,authorization,*,committed=D.git_committed_unmodified):
    """Access/training gate before row reads. No status is inferred from a commit."""
    if authorization is None:raise Refused('owner admission missing; review confers no training permission')
    path=Path(authorization)
    if not committed(str(path)):raise Refused('owner admission must be committed and unchanged')
    obj=json.loads(path.read_bytes())
    if obj.get('schema')!=AUTH_SCHEMA or obj.get('status')!='APPROVED_EXPERIMENTAL':
        raise Refused('owner admission is not APPROVED_EXPERIMENTAL')
    if obj.get('scope')!='EXPERIMENTAL_V5_ONLY' or obj.get('training_allowed') is not True:
        raise Refused('owner admission scope does not authorize this training')
    for key in ('owner_decision','authorized_by','date'):
        if not isinstance(obj.get(key),str) or not obj[key].strip():raise Refused('owner admission incomplete: '+key)
    expected=dict(dataset_manifest_sha256=msha,recipe_sha256=m['recipe']['sha256'],
                  protocol_sha256=m['protocol']['sha256'],
                  policy_source_admission_sha256=m['evidence']['policy_admission']['sha256'])
    if any(obj.get(k)!=v for k,v in expected.items()):raise Refused('owner admission hash mismatch')
    if obj.get('accept_scoped_policy_sources') is not True:
        raise Refused('scoped policy source admission not accepted')
    # Commit the reviewed manifest/recipe/protocol/evidence and all executing
    # sources. Global dirty files belonging to parallel work are not concealed
    # or stashed; EXPERIMENTAL does not claim the FINAL clean-tree condition.
    required=[m['manifest_path'],m['recipe']['path'],m['protocol']['path']]
    required += [d['path'] for d in m['evidence'].values()]
    required += [str(REPO/p) for p in m['source_sha256']]
    if any(not committed(p) for p in required):raise Refused('bound sources/records must be committed and unchanged')
    return obj


def mapped_meta(meta,split):
    out=dict(meta)
    out.update(schema=ROW_SCHEMA,split=split,source_split=meta['split'],source_component='policy-url-v3')
    return out


def require_policy_label(meta,source):
    category=meta.get('attack_category')
    if category not in L.K.POLICY_CATEGORIES:raise Refused('new component category outside typed-URL policy scope')
    if meta.get('label_status')!=L.POLICY_DEFINED or meta.get('label_status_basis')!='policy_defined':
        raise Refused('new URL rows cannot inherit an AI audit or VERIFIED status')
    policy_id=source['policy_id'];reason=L.CATEGORY_REASON[category]
    if (meta.get('policy_id')!=policy_id or meta.get('label_rule')!=policy_id
            or meta.get('reason_string')!=reason or meta.get('output')!='BLOCK | '+reason):
        raise Refused('new policy row reason/rule does not match its source')


def read_rows(m,parent_manifest):
    # Recompute the review on its exact bound rendering, including full-pool
    # equivalence, near-duplicate families, I9 and scoped identity checks. The
    # lineage comparison below then binds every composed row to that rendering.
    from audit_stage4_preview import audit
    current=audit(Path(m['evidence']['preview']['path']).parent)
    if current['status']!='ENGINEERING_CHECKS_PASS_ADMISSION_PENDING':
        raise Refused('recomputed rendering audit is blocked')
    artifacts={a['name']:a for a in m['artifacts']}
    raw={name:capture(desc) for name,desc in artifacts.items()}
    result={}
    for split in SPLITS:
        rows,diags=D.parse_split(raw[f'rows.{split}.jsonl'].decode(),raw[f'rows.{split}.meta.jsonl'].decode(),split)
        if diags:raise Refused('row alignment: '+','.join(d.code for d in diags))
        result[split]=rows
    parent=m['parent'];parent_artifacts={a['path']:a for a in parent_manifest['artifacts']}
    oldraw={}
    for name in ('rows.TRAIN.jsonl','rows.TRAIN.meta.jsonl'):
        desc=dict(path=str(Path(parent['dataset_dir'])/name),sha256=parent_artifacts[name]['sha256'],bytes=parent_artifacts[name]['bytes'])
        oldraw[name]=capture(desc)
        if not raw[name].startswith(oldraw[name]):raise Refused('original TRAIN prefix altered')
    old,diags=D.parse_split(oldraw['rows.TRAIN.jsonl'].decode(),oldraw['rows.TRAIN.meta.jsonl'].decode(),'TRAIN')
    if diags:raise Refused('parent rows malformed')
    count=len(old)
    if count!=m['parent']['TRAIN_rows']:raise Refused('parent count changed')
    freeze=json.loads(capture(parent['records']['freeze']))
    diags=CB.verify_components(old,D.audit_item_of(freeze),committed_checker=D.git_committed_unmodified)
    if diags:raise Refused('parent row audit binding: '+','.join(d[0] for d in diags))
    registry_by_split={}
    for split in SPLITS:
        source=m['augmentation']['source_artifacts'][split]
        if Path(source['path']).resolve().name!=split+'_CANDIDATE.source.jsonl':
            raise Refused('unexpected source role; reserve must not be opened')
        source_rows=D._jsonl_records(capture(source).decode())
        if any(r.get('split')!=split+'_CANDIDATE' for r in source_rows):raise Refused('source split mismatch')
        registry={r['record_id']:r for r in source_rows}
        if len(registry)!=len(source_rows):raise Refused('duplicate source record')
        registry_by_split[split]=registry
        preview_desc=m['augmentation']['preview_artifacts'][split]
        if Path(preview_desc['path']).resolve().name!=split+'_CANDIDATE.preview.jsonl':
            raise Refused('unexpected preview role; reserve must not be opened')
        preview=D._jsonl_records(capture(preview_desc).decode())
        augmented=result[split][count:] if split=='TRAIN' else result[split]
        if len(preview)!=len(augmented):raise Refused('augmentation count changed')
        integrity_rows=[]
        for source_row,row in zip(preview,augmented):
            expected_meta=mapped_meta(source_row['meta'],split)
            if (row['meta']!=expected_meta or row['text']!=source_row['text']
                    or row['output']!=source_row['meta']['output']):
                raise Refused('augmentation differs from reviewed rendering')
            integrity_rows.append(dict(row,payload=source_row.get('payload')))
            meta=row['meta']
            if meta.get('label')=='BLOCK':
                rid=meta['payload_record_id']
                if rid not in registry:raise Refused('source is not assigned to this split')
                require_policy_label(meta,registry[rid])
                a,b=meta['leaf_spans'][meta['attacked_slot']];text=row['text'][a:b]
                logical=json.loads(text) if meta['carrier']=='json' else unquote_plus(text,errors='strict')
                validate_registered_url(rid,logical,registry=registry,slot_type=meta['attacked_slot_type'],
                    label=meta['label'],category=meta['attack_category'],role=meta['attacked_slot_role'],table=L.load_policy_table())
        # Re-run only the NEW component's original pair/encoding/M arithmetic,
        # on actual materialized bytes. Parent accredited checks are inherited
        # by exact prefix and evidence, not re-executed.
        live=[G.gate_pairs(integrity_rows),G.gate_enc(integrity_rows),
              L.check_m_invariants([r['meta'] for r in augmented],L.load_policy_table(),True,row_contract=RC.SCHEMA)]
        if any(check.get('ok') is not True for check in live):raise Refused('new component pair/encoding/label integrity failed')
    recipe,rsha=D.load_recipe(m['recipe']['path'])
    if rsha!=m['recipe']['sha256']:raise Refused('recipe changed')
    diags=D.check_disjoint(result['TRAIN'],result['VALIDATION'])
    for rows in result.values():
        diags+=D.check_rows(rows,D.recipe_vocabulary(recipe),row_contract=RC.SCHEMA)
        diags+=D.check_audit_rows(rows,D.AUDIT_AI)
    if diags:raise Refused('row contract: '+','.join(d.code for d in diags))
    keys={r['meta']['payload_family_id'] for rows in result.values() for r in rows if r['meta'].get('payload_family_id')}
    tokens={k:I.payload_shingles(k) for k in keys}
    if any(not v for v in tokens.values()):raise Refused('unobservable source family')
    assignment={r['meta']['payload_family_id']:s for s,rows in result.items() for r in rows if r['meta'].get('payload_family_id')}
    if I.near_duplicate_pairs(tokens,partition=assignment):raise Refused('near-duplicate family leakage')
    return result,recipe


def prepare(manifest_path,*,authorization=None,training=False):
    m,msha=load_package(manifest_path)
    if training:require_admission(m,msha,authorization)
    protocol,parent=verify_metadata(m)
    rows,recipe=read_rows(m,parent)
    return m,msha,rows,recipe,protocol
