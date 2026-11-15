"""Exercise unchanged stage-4 rendering on proposed URL sources, never train.

Only proposed TRAIN/VALIDATION source files are opened. Reserve stays sealed.
The emitted schema is intentionally NOT a trainable stage-4 dataset schema.
Source admission, I9 and complete successor authorization remain separate gates.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import random
import re
import sys
from urllib.parse import unquote_plus

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO / p) for p in
                ('scripts/dataset', 'scripts/training', 'control_plane', 'data_plane')]
import canonical_request as CR
import v5_catalog as K
import v5_generator as G
import v5_identities as I
import v5_labels as L
import v5_oracle as O
import v5_pools_common as C
import v5_render as R
import v5_split as S
import v5_train_data as D
import v5_inference_core as CORE
from parse_dataset_v4 import canonical_key
from policy_admission_proposal import validate_registered_url

ROOT = REPO / 'reports/v5/successor-2026-10-30'
OPEN_SPLITS = ('TRAIN_CANDIDATE', 'VALIDATION_CANDIDATE')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_bound(desc):
    raw = Path(desc['path']).read_bytes()
    if sha(raw) != desc['sha256']:
        raise ValueError('bound input changed')
    return [json.loads(line) for line in raw.splitlines()]


class PreviewPolicyBasis:
    """No human/AI audit impersonation: accepts policy-only synthesis for review."""
    mode = 'DRAFT_POLICY_PREVIEW_NOT_TRAINING_ADMISSION'
    audit_type = None

    def __init__(self, registry, table):
        self.registry, self.table = registry, table

    def check(self, record, category):
        if category not in K.POLICY_CATEGORIES:
            raise L.LabelBlocked('Preview cannot admit injection-category references')
        validate_registered_url(record['record_id'], record['payload_logical'],
                                registry=self.registry, slot_type='url', label='BLOCK',
                                category=category, role=L.DATA, table=self.table)


def benign_pools(split):
    rng = random.Random('v51-benign-url-pools-20261031-' + split)
    pools = {p: {} for p in ('urls_relative', 'urls_public')}
    # Both absolute and relative benign URLs, spanning the source length bins.
    # Every value remains stable if an earlier generation attempt is abandoned.
    for pool, prefix in [('urls_relative', '/'), ('urls_public', 'https://docs.example/')]:
        for length in (8, 16, 32, 64, 128, 192):
            for _ in range(24):
                n = max(8, length - len(prefix))
                value = prefix + ''.join(rng.choice('abcdefghijklmnopqrstuvwxyz0123456789')
                                         for _ in range(n))
                pools[pool][C.value_entry_id(pool, value)] = value
    return pools


def logical_from_span(row):
    m = row['meta']
    start, end = m['leaf_spans'][m['attacked_slot']]
    value = row['text'][start:end]
    if m['carrier'] == 'json':
        # JSON spans include the enclosing JSON string quotes.
        return json.loads(value)
    return unquote_plus(value, errors='strict')


def public_source_guard(rows):
    """Exclude ancestry in ALL public path sources without opening old held-out rows."""
    path = REPO / 'datasets/v5_sources/attack/attack_pool.jsonl'
    raw = path.read_bytes()
    old = [r for r in map(json.loads, raw.splitlines())
           if r['dedup_scope'] in ('File Inclusion', 'Path Traversal', K.PATH_FILE)]
    oldkeys = {I.family_key(r['payload_wire']) for r in old}
    newkeys = {r['payload_family_id'] for r in rows}
    tokens = {k: I.payload_shingles(k) for k in oldkeys | newkeys}
    partition = {k: 'PUBLIC_PATH_SOURCE' for k in oldkeys}
    partition.update({k: 'NEW_URL_SOURCE' for k in newkeys - oldkeys})
    cross = I.near_duplicate_pairs(tokens, partition=partition)
    return dict(method='conservative exclusion against entire public source category; no protected rows opened',
                source_pool_sha256=sha(raw), public_path_records=len(old),
                public_path_family_keys=len(oldkeys), new_family_keys=len(newkeys),
                exact_overlap=len(oldkeys & newkeys), near_pairs_across_sources=len(cross),
                unobservable_old_keys=sum(not tokens[k] for k in oldkeys),
                unobservable_new_keys=sum(not tokens[k] for k in newkeys),
                protected_rows_opened=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--private-out', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--pairs-per-cell', type=int, default=40)
    args = parser.parse_args()
    if args.private_out.exists() or args.out.exists():
        raise ValueError('Refusing to overwrite evidence')
    if args.pairs_per_cell < 1:
        raise ValueError('Positive engineering quota required')
    proposal = json.loads((ROOT / 'partition/partition.DRAFT.json').read_text())
    descs = {r['split']: r for r in proposal['artifacts']}
    sources = {split: read_bound(descs[split]) for split in OPEN_SPLITS}
    registry = {r['record_id']: r for rows in sources.values() for r in rows}
    records = {}
    for rid, row in registry.items():
        value = row['payload_logical']
        if re.search(r'%[0-9A-Fa-f]{2}', value):
            raise ValueError('Encoded-source carrier semantics need a separate reviewed protocol')
        records[rid] = dict(row, status='ACCEPTED', synthetic=False,
                            dedup_scope=row['attack_category'], payload_wire=value,
                            payload_wire_form=R.PLAIN, canonical_key=canonical_key(value),
                            native_forms=R.native_forms(value))
    families = I.build_families(list(records.values()), merges=())
    catalog = K.load_catalog(str(ROOT / 'catalog/catalog-v51.DRAFT.json'))
    table = L.load_policy_table()
    recipe_path = ROOT / 'v51-expanded-vocabulary.recipe.DRAFT.json'
    recipe, _ = D.load_recipe(str(recipe_path))
    from transformers import AutoTokenizer
    tok = AutoTokenizer.from_pretrained(CORE.DEFAULT_ADAPTER_DIR, local_files_only=True)
    template = D.recipe_template(recipe)
    contract = CORE.load_contract(str(recipe_path))
    count_tokens = G.tokenizer_counter(tok, template)
    pools = {split: benign_pools(split) for split in OPEN_SPLITS}
    pool_values = {p: {vid: v for split in OPEN_SPLITS for vid, v in pools[split][p].items()}
                   for p in ('urls_relative', 'urls_public')}
    cfg = dict(placement_shares=dict(replace=1, prefix=0, suffix=0, embedded=0),
               length_bins=dict(edges=[8, 16, 32, 64, 128]),
               trained_categories=dict(categories=list(K.POLICY_CATEGORIES)))
    world = G.World(catalog=catalog, policy=table, assignment=None, split_cfg={},
                    gen_cfg=cfg, pool_values=pool_values, records=records, families=families,
                    oracle=O.BenignOracle(list(records.values()), O.OracleConfig(12, 'PENDING')),
                    basis=PreviewPolicyBasis(registry, table),
                    limits=CR.Limits(max_decoded_body=48 * contract.token_budget_B,
                                     token_budget=contract.token_budget_B, max_bytes_per_token=48),
                    count_tokens=count_tokens, row_contract=G.RC.SCHEMA)
    rows, attempts, shortfalls = [], Counter(), []
    source_coverage, artifacts = {}, []
    for split in OPEN_SPLITS:
        allowed = {r['record_id'] for r in sources[split]}
        by_cat = {cat: tuple(k for k, fam in families.items()
                            if cat in fam.categories and set(fam.members) <= allowed)
                  for cat in K.POLICY_CATEGORIES}
        tpls = [catalog.by_id[tid] for tid, d in proposal['new_template_assignments'].items()
                if d['split'] == split]
        part = S.Partition(split, tuple(t.struct_cluster_id for t in tpls),
                           tuple(t.template_id for t in tpls), by_cat,
                           {p: tuple(sorted(pools[split][p])) for p in pools[split]})
        index = G.AttackIndex(world, part)
        for t in tpls:
            for cat in K.POLICY_CATEGORIES:
                done = 0
                for i in range(args.pairs_per_cell * 30):
                    result = G.build_pair(world, split, part, index, t.struct_cluster_id, [t], cat, i)
                    attempts[result.get('reason', result['status'])] += 1
                    if result['status'] != 'complete':
                        continue
                    pair_rows = [dict(meta=m, text=text, payload=payload)
                                 for m, text, payload in result['rows'].values()]
                    # Exact shared token contract, not a byte-length approximation.
                    for row in pair_rows:
                        CORE.encode_canonical(contract, tok, row['text'])
                        m = row['meta']
                        if m['pair_role'] == 'twin':
                            logical = logical_from_span(row)
                            rid = m['payload_record_id']
                            if logical != registry[rid]['payload_logical']:
                                raise ValueError('canonical leaf no longer matches registered source')
                            validate_registered_url(rid, logical, registry=registry,
                                slot_type=m['attacked_slot_type'], label=m['label'],
                                category=m['attack_category'], role=m['attacked_slot_role'], table=table)
                    rows.extend(pair_rows)
                    done += 1
                    if done == args.pairs_per_cell:
                        break
                if done != args.pairs_per_cell:
                    shortfalls.append(dict(split=split, template=t.name, category=cat, pairs=done))
        used = {r['meta']['payload_record_id'] for r in rows
                if r['meta']['split'] == split and r['meta']['pair_role'] == 'twin'}
        source_coverage[split] = dict(available=len(allowed), used=len(used),
                                     unused_record_ids=sorted(allowed - used))
    checks = [G.gate_pairs(rows), G.gate_enc(rows), G.enc7_self_test(rows),
              L.check_m_invariants([r['meta'] for r in rows], table, True, row_contract=G.RC.SCHEMA)]
    args.private_out.mkdir(parents=True)
    args.out.mkdir(parents=True)
    for split in OPEN_SPLITS:
        selected = [r for r in rows if r['meta']['split'] == split]
        # Deliberately not an accepted trainer schema: these are review artifacts.
        for r in selected:
            r['meta']['schema'] = 'v51-stage4-preview-row/v1'
        raw = ''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in selected).encode()
        path = args.private_out / (split + '.preview.jsonl')
        with path.open('xb') as handle:
            handle.write(raw)
        path.chmod(0o600)
        clusters = Counter(r['meta']['struct_cluster_id'] for r in selected)
        artifacts.append(dict(split=split, path=str(path), sha256=sha(raw), rows=len(selected),
                              cluster_count=len(clusters), largest_cluster_share=max(clusters.values()) / len(selected)))
    guard = public_source_guard([r for group in sources.values() for r in group])
    report = dict(schema='v51-stage4-engineering-preview/v1', status='PREVIEW_NOT_ADMITTED_FOR_TRAINING',
                  source_partition_sha256=sha((ROOT / 'partition/partition.DRAFT.json').read_bytes()),
                  builder_sha256=sha(Path(__file__).read_bytes()), recipe_sha256=contract.recipe_sha256,
                  catalog_sha256=catalog.sha256, artifacts=artifacts, source_coverage=source_coverage,
                  checks=checks, shortfalls=shortfalls, attempts=dict(attempts),
                  public_path_source_guard=guard, reserve_opened=False, training_authorized=False,
                  original_TRAIN_rows_preserved=3080,
                  limitations=['Nine-template preview exceeds I9 cluster shares: expansion/rebalance still needed',
                               'Full SPL/value/shortcut/H1 and owner source admission pending',
                               'Not a replacement for original category TRAIN; no model trained or selected'])
    (args.out / 'preview.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
