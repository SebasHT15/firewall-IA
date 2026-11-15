"""Independent CPU audit of proposed rows; no reserve or model inference."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import sys

from stage4_preview import (REPO, ROOT, OPEN_SPLITS, read_bound, logical_from_span,
                           benign_pools, sha, I, L, K)
from urllib.parse import unquote_plus
from curate_policy_sources_v2 import inspect_identity
from policy_admission_proposal import validate_registered_url


def group_conflicts(rows, field):
    groups = defaultdict(set)
    for row in rows:
        if row.get(field):
            groups[row[field]].add(row['split'])
    return sum(len(splits) > 1 for splits in groups.values())


def identity_audit(rows, registry, table, catalog):
    failures, scoped = [], 0
    for row in rows:
        m = row['meta']
        # Source hygiene parses a logical URL, not a complete HTTP query. Decode
        # each actual typed leaf first, preserving '&' and authority boundaries.
        # Names such as "token" or the JSON container "meta" are schema names,
        # not evidence that generated values are real credentials/vendor hosts.
        addresses, errors = set(), []
        template = catalog.by_id[m['template_id']]
        for slot in template.slots:
            a,b=m['leaf_spans'][slot.slot_id]
            raw=row['text'][a:b]
            value=json.loads(raw) if slot.location=='json' else unquote_plus(raw,errors='strict')
            if slot.value_type=='token' and not re.fullmatch(r'[0-9a-f]{16}',str(value)):
                errors.append('SYNTHETIC_TOKEN_PROVENANCE_MISMATCH')
            if isinstance(value,str):
                error, found = inspect_identity(value)
                if error:errors.append(error)
                addresses.update(found)
        error=errors[0] if errors else None
        if error:
            failures.append(dict(pair_id=m['pair_id'], role=m['pair_role'], reason=error))
            continue
        if addresses:
            rid = m.get('payload_record_id')
            source = registry.get(rid)
            if m['pair_role'] != 'twin' or source is None:
                failures.append(dict(pair_id=m['pair_id'], role=m['pair_role'], reason='NUMERIC_HOST_OUTSIDE_BOUND_ATTACK'))
                continue
            try:
                logical = logical_from_span(row)
                if logical != source['payload_logical']:
                    raise ValueError('logical source mismatch')
                validate_registered_url(rid, logical, registry=registry, table=table,
                                        slot_type=m['attacked_slot_type'], label=m['label'],
                                        category=m['attack_category'], role=m['attacked_slot_role'])
                if not addresses <= set(source['special_use_numeric_addresses']):
                    raise ValueError('unregistered numeric address in rendered row')
            except ValueError as exc:
                failures.append(dict(pair_id=m['pair_id'], role=m['pair_role'], reason=str(exc)))
            else:
                scoped += 1
    return dict(status='PASS_UNDER_DRAFT_RULE' if not failures else 'BLOCKED',
                failures=failures, scoped_numeric_rows=scoped, owner_approved=False,
                original_H1_checker_modified=False,
                scope='Logical values of every typed leaf; generated token scalars require exact hex16 format. No real-source credential exemption.')


def read_preview_splits(descriptors):
    splits=[d['split'] for d in descriptors]
    if len(splits)!=len(set(splits)) or set(splits)!=set(OPEN_SPLITS):
        raise ValueError('Unexpected split: reserve cannot be read by this audit')
    return {d['split']:read_bound(d) for d in descriptors}


def audit(preview):
    report = json.loads((preview / 'preview.json').read_text())
    by_split = read_preview_splits(report['artifacts'])
    rows = [r for group in by_split.values() for r in group]
    partition = json.loads((ROOT / 'partition/partition-expanded.DRAFT.json').read_text())
    if sha((ROOT / 'partition/partition-expanded.DRAFT.json').read_bytes()) != report['source_partition_sha256']:
        raise ValueError('Wrong partition')
    registry = {r['record_id']: r for d in partition['artifacts'] if d['split'] in OPEN_SPLITS
                for r in read_bound(d)}
    oldpath = REPO / 'datasets/v5_sources/final_source_2026-10-26-v4/rows.TRAIN.meta.jsonl'
    oldraw = oldpath.read_bytes()
    old = [dict(json.loads(line), split='TRAIN_CANDIDATE') for line in oldraw.splitlines()]
    meta = [r['meta'] for r in rows]
    combined = old + meta
    catalog=K.load_catalog(partition['catalog_path'])
    if catalog.sha256!=report['catalog_sha256']:raise ValueError('Wrong catalog')
    identity = identity_audit(rows, registry, L.load_policy_table(), catalog)
    keys_by_split = defaultdict(set)
    for m in combined:
        if m.get('payload_family_id'):
            keys_by_split[m['split']].add(m['payload_family_id'])
    key_splits = defaultdict(set)
    for split, keys in keys_by_split.items():
        for key in keys:
            key_splits[key].add(split)
    tokens = {key: I.payload_shingles(key) for key in key_splits}
    near = I.near_duplicate_pairs(tokens, partition={k: sorted(v)[0] for k, v in key_splits.items()})
    # Include the entire freshly generated value pools, not only sampled entries.
    values = defaultdict(set)
    entries = defaultdict(set)
    for m in old:
        for value in m['values']:
            values[I.value_equivalence_key(value)].add('TRAIN_CANDIDATE')
        for pool, vid in m['value_entries']:
            entries[(pool, vid)].add('TRAIN_CANDIDATE')
    for split in OPEN_SPLITS:
        for pool, items in benign_pools(split).items():
            for vid, value in items.items():
                values[I.value_equivalence_key(value)].add(split)
                entries[(pool, vid)].add(split)
    duplicates = Counter(r['meta']['text_sha256'] for r in rows)
    shares, distribution = {}, {}
    for split in OPEN_SPLITS:
        subset = [m for m in combined if m['split'] == split]
        counts = Counter(m['struct_cluster_id'] for m in subset)
        shares[split] = dict(rows=len(subset), clusters=len(counts),
                             largest_share=max(counts.values()) / len(subset),
                             clusters_at_or_above_warn_008=sum(100 * n >= 8 * len(subset) for n in counts.values()),
                             clusters_above_block_012=sum(100 * n > 12 * len(subset) for n in counts.values()))
        distribution[split] = dict(labels=dict(Counter(m['label'] for m in subset)),
                                    BLOCK_categories=dict(Counter(m['attack_category'] for m in subset if m['label'] == 'BLOCK')),
                                    augmented_carriers=dict(Counter(m['carrier'] for m in meta if m['split'] == split)))
    checks = dict(typed_preview_schema_only=all(m['schema']=='v51-stage4-preview-row/v1' for m in meta),
                  template_conflicts=group_conflicts(combined, 'template_id'),
                  cluster_conflicts=group_conflicts(combined, 'struct_cluster_id'),
                  family_conflicts=sum(len(v) > 1 for v in key_splits.values()),
                  unobservable_family_keys=sum(not v for v in tokens.values()),
                  original_4gram_near_pairs_across_splits=len(near),
                  full_pool_value_equivalence_conflicts=sum(len(v)>1 for v in values.values()),
                  full_pool_value_entry_conflicts=sum(len(v)>1 for v in entries.values()),
                  canonical_duplicate_groups=sum(n>1 for n in duplicates.values()),
                  source_guard_cross_pairs=report['public_path_source_guard']['near_pairs_across_sources'])
    okay = (checks['typed_preview_schema_only'] and all(v == 0 for k,v in checks.items() if k != 'typed_preview_schema_only')
            and identity['status'] == 'PASS_UNDER_DRAFT_RULE'
            and all(d['clusters_at_or_above_warn_008']==0 for d in shares.values()))
    return dict(schema='v51-stage4-preview-audit/v1',
                status='ENGINEERING_CHECKS_PASS_ADMISSION_PENDING' if okay else 'BLOCKED',
                preview_sha256=sha((preview/'preview.json').read_bytes()),
                auditor_sha256=sha(Path(__file__).read_bytes()),
                original_TRAIN_meta_sha256=sha(oldraw), opened_splits=list(OPEN_SPLITS), reserve_opened=False,
                checks=checks, identity=identity, combined_cluster_shares=shares, distribution=distribution,
                training_authorized=False,
                pending=['Source-specific H1 proposal requires owner admission',
                         'Mixed-data shortcut checks and complete original stage-4 evidence binding',
                         'Small number of independent validation sources; rows are not independent trials',
                         'Additional original-category source/slot coverage, recipe/training authorization and owner commit'])


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--preview',type=Path,required=True);args=parser.parse_args()
    path=args.preview/'audit.json'
    if path.exists():raise ValueError('Refusing to overwrite evidence')
    result=audit(args.preview)
    path.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
