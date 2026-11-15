"""Freeze allowed DEV cohorts for post-training comparison. CPU only.

Uses only the reviewed successor composition and already-used authored DEV.
Does not open old protected sets, legacy eval, or the sealed source reserve.
"""
import argparse
from collections import Counter, defaultdict
import json
import os
from pathlib import Path

from successor_contract import REPO, bound, capture, load_package, verify_metadata

LEGACY_PREPARATION = REPO/'reports/v5/hybrid/experiments-2026-10-30/protocol.json'
AUTHORED_INPUT = Path('/home/sebas/Documents/Codex/2026-10-26/ta/work/metrics-2026-10-30/inputs.private.jsonl')


def jsonl(raw):
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def dump(path, obj):
    with Path(path).open('x', encoding='utf-8') as f:
        json.dump(obj, f, indent=2, ensure_ascii=False, allow_nan=False)
        f.write('\n')


def prepare(manifest, out, private):
    from successor_contract import sha
    m, msha = load_package(manifest)
    verify_metadata(m)
    if out.exists() or private.exists():
        raise ValueError('use new public and private output directories')
    # Read only the exact permitted TRAIN metadata (overlap audit), VALIDATION
    # rows/meta and source registry. No RESERVE path is dereferenced.
    artifacts = {a['name']: a for a in m['artifacts']}
    rows = jsonl(capture(artifacts['rows.VALIDATION.jsonl']))
    meta = jsonl(capture(artifacts['rows.VALIDATION.meta.jsonl']))
    train_meta = jsonl(capture(artifacts['rows.TRAIN.meta.jsonl']))
    train_hashes = {r['text_sha256'] for r in train_meta}
    sources = jsonl(capture(m['augmentation']['source_artifacts']['VALIDATION']))
    registry = {r['record_id']: r for r in sources}
    if len(registry) != len(sources) or len(rows) != len(meta):
        raise ValueError('source or row alignment failure')
    pairs = defaultdict(list)
    for item in meta:
        pairs[item['pair_id']].append(item)
    source_for_pair = {}
    for pid, group in pairs.items():
        if len(group) != 2 or {r['label'] for r in group} != {'ALLOW', 'BLOCK'}:
            raise ValueError('policy minimal pair is incomplete')
        block = next(r for r in group if r['label'] == 'BLOCK')
        source_for_pair[pid] = registry[block['payload_record_id']]
    cases = []
    for index, (row, item) in enumerate(zip(rows, meta)):
        if row['output'] != item['output'] or sha(row['text'].encode()) != item['text_sha256']:
            raise ValueError('validation text/reference mismatch')
        source = source_for_pair[item['pair_id']]
        cases.append(dict(id=f'policy-val-{index:05d}', canonical_text=row['text'],
            canonical_sha256=item['text_sha256'], label=item['label'], expected_reason=row['output'].split(' | ', 1)[1],
            category=item.get('attack_category') or item['twin_category'], carrier=item['carrier'],
            family=sha(source['payload_family_id'].encode()), component_id='source:'+source['source_component_sha256'],
            pair_id='policy:'+item['pair_id'], cohort='policy_validation_selection',
            label_basis='POLICY_DEFINED' if item['label'] == 'BLOCK' else 'BENIGN_ORACLE',
            reference_scope='Project typed-URL policy; not universal exploitability',
            length_bin=item['length_bin'], overlap_TRAIN=item['text_sha256'] in train_hashes,
            source_id=source['record_id'], template_id=item['template_id']))
    if any(c['overlap_TRAIN'] for c in cases):
        raise ValueError('policy validation text overlaps TRAIN')
    # Existing public protocol pins the private bundle containing authored DEV.
    # Its legacy rows are NOT admitted to these cohorts or training references.
    previous = json.loads(LEGACY_PREPARATION.read_bytes())
    authored_raw = AUTHORED_INPUT.read_bytes()
    if sha(authored_raw) != previous['private_inputs_sha256']:
        raise ValueError('historical authored input binding mismatch')
    import sys
    sys.path.insert(0, str(REPO/'control_plane'))
    import v5_output_contract as OC
    authored = [r for r in jsonl(authored_raw) if r['cohort'] == 'authored_paired_dev']
    excluded = Counter()
    for row in authored:
        if row.get('canonical_outcome') != 'ACCEPT':
            excluded[str(row.get('canonical_outcome'))] += 1
            continue
        text = row['canonical_text']
        if sha(text.encode()) != row['canonical_sha256']:
            raise ValueError('authored text binding mismatch')
        expected = OC._BLOCK.get(row.get('family')) if row['label'] == 'BLOCK' else OC.ALLOW_OUTPUT
        cases.append(dict(id=row['id'], canonical_text=text, canonical_sha256=row['canonical_sha256'],
            label=row['label'], expected_reason=expected.split(' | ', 1)[1] if expected else None,
            category=row.get('family') or 'unknown', family=row.get('family'), carrier=row.get('placement'),
            component_id=None, pair_id=row.get('pair_id'), cohort='authored_regression_known_DEV',
            label_basis='CONSTRUCTED_EXPECTATION', reference_scope='Known DEV construction; no exploitation oracle',
            length_bin=None, overlap_TRAIN=row['canonical_sha256'] in train_hashes,
            context_gap=row.get('family') in ('jwt', 'csrf')))
    ids = [c['id'] for c in cases]
    if len(set(ids)) != len(ids):
        raise ValueError('duplicate case IDs')
    public = [{k: v for k, v in c.items() if k != 'canonical_text'} for c in cases]
    collisions = defaultdict(set)
    for c in cases:
        collisions[c['canonical_sha256']].add(c['label'])
    contradictions = {k for k, labels in collisions.items() if len(labels) > 1}
    out.mkdir(parents=True)
    private.mkdir(parents=True, mode=0o700)
    os.chmod(private, 0o700)
    raw_path = private/'cases.private.jsonl'
    with raw_path.open('x', encoding='utf-8') as f:
        os.chmod(raw_path, 0o600)
        f.writelines(json.dumps(c, ensure_ascii=False)+'\n' for c in cases)
    with (out/'cases.public.jsonl').open('x', encoding='utf-8') as f:
        f.writelines(json.dumps(c, ensure_ascii=False)+'\n' for c in public)
    protocol = dict(schema='v51-post-training-dev-evaluation/v1', status='PREPARED_NOT_EXECUTED',
        scope='DEVELOPMENT_ONLY_NOT_FINAL_EVALUATION', training_manifest=bound(manifest),
        training_manifest_sha256=msha, cases_private=bound(raw_path), cases_public=bound(out/'cases.public.jsonl'),
        input_bindings=[artifacts[k] for k in ('rows.VALIDATION.jsonl', 'rows.VALIDATION.meta.jsonl', 'rows.TRAIN.meta.jsonl')]
                       +[m['augmentation']['source_artifacts']['VALIDATION'], bound(LEGACY_PREPARATION), bound(AUTHORED_INPUT)],
        cohorts=dict(Counter(c['cohort'] for c in cases)),
        policy_validation_components=len({c['component_id'] for c in cases if c['component_id']}),
        excluded_authored_canonical_outcomes=dict(excluded), overlap_TRAIN=dict(Counter(c['cohort'] for c in cases if c['overlap_TRAIN'])),
        opposite_reference_same_text=dict(hash_groups=len(contradictions), cases=sum(c['canonical_sha256'] in contradictions for c in cases)),
        thresholds_descriptive_only=[.5, .7, .8, .9, .95, .975, .99], selected_threshold=None,
        random_seed=20261101, bootstrap_replicates=1000,
        protected_sets_used=False, reserve_opened=False, legacy_eval_admitted=False,
        benchmark=dict(status='SEPARATE_OPERATIONAL_PROTOCOL_REQUIRED',
            rule='Quality-pass latency is not capacity. Keep cold/warmup/steady phases separate; pool raw rows, never average percentiles.'),
        interpretation=['Policy validation was used for checkpoint selection; not independent final evaluation.',
                        'Known authored DEV is regression-only, not new generalization evidence.',
                        'Invalid => error in E5; derived fail-closed action is separate from detection.',
                        'No row-IID substitute for missing source groups in authored DEV.',
                        'Do not count sink delivery as exploit success. No protected/RESERVE selection.',
                        'Counterfactual Model2+V5 combination excludes Fast Path and is not observed gateway performance.'],
        source_sha256={str(p.relative_to(REPO)): bound(p)['sha256'] for p in
            [Path(__file__), Path(__file__).with_name('evaluation_metrics.py'), Path(__file__).with_name('collect_evaluation.py')]})
    dump(out/'protocol.json', protocol)
    return protocol


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--manifest', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--private', type=Path, required=True)
    args = ap.parse_args()
    result = prepare(args.manifest, args.out, args.private)
    print(json.dumps({k: result[k] for k in ('status', 'cohorts', 'policy_validation_components', 'overlap_TRAIN', 'opposite_reference_same_text')}, indent=2))


if __name__ == '__main__':
    main()
