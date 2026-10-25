#!/usr/bin/env python3
"""Recompute factual pre-freeze checks for a source-backed V5 build.

The report is explicitly PARTIAL: it never marks §11.3 DONE or substitutes for
shortcut checks, protected stability, byte-identical regeneration, or a freeze record.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def count_lines(path: Path) -> int:
    with path.open('rb') as fh:
        return sum(1 for _ in fh)


def check(dataset: Path, attack_pool: Path, collisions: Path, cs7: Path | None = None) -> dict:
    manifest_path = dataset / 'manifest.json'
    m = json.loads(manifest_path.read_text())
    checks = {}
    artifacts = []
    for item in m.get('artifacts', []):
        p = dataset / item['path']
        artifacts.append({'path': item['path'], 'ok': p.is_file() and sha(p) == item['sha256']
                          and p.stat().st_size == item['bytes']})
    checks['A1_artifact_hashes'] = {'ok': bool(artifacts) and all(x['ok'] for x in artifacts),
                                   'checked': len(artifacts),
                                   'failures': [x['path'] for x in artifacts if not x['ok']]}

    rows = {}
    for split in ('TRAIN', 'VALIDATION', 'INTERNAL_TEST'):
        data = dataset / f'rows.{split}.jsonl'
        meta = dataset / f'rows.{split}.meta.jsonl'
        rows[split] = count_lines(data)
        if rows[split] != count_lines(meta):
            checks.setdefault('row_meta_alignment', {'ok': False, 'splits': []})['splits'].append(split)
    checks.setdefault('row_meta_alignment', {'ok': True, 'splits': []})
    expected = m['counts']['by_split_disposition']
    checks['split_row_counts'] = {'ok': all(rows[s] == expected.get(s+'|split') for s in rows),
                                  'rows': rows}
    checks['generator_gates'] = {'ok': m.get('gates', {}).get('ok') is True,
                                 'quota_shortfalls': len(m['counts']['quota_shortfalls'])}
    checks['i9'] = {'ok': m['i9_rebalance'].get('converged') is True and
                   {(x['split'], x['cluster']) for x in m['i9_rebalance'].get('owner_rulings_applied', [])}
                   == {('VALIDATION', 'path-media'), ('INTERNAL_TEST', 'path-export')},
                   'owner_rulings': len(m['i9_rebalance'].get('owner_rulings_applied', []))}
    checks['L8'] = {'ok': m['pilot_inputs']['value_dedup']['probe_overlap']['remaining_overlap'] == 0,
                    'excluded': m['pilot_inputs']['value_dedup']['probe_overlap']['excluded_total']}
    c = json.loads(collisions.read_text())
    checks['L7'] = {'ok': c.get('blocking_pass') is True and c.get('dataset_manifest_sha256') == sha(manifest_path),
                    'sets': len(c.get('entries', [])),
                    'unchecked_nonblocking': [x['id'] for x in c['entries'] if x['status'] != 'CHECKED'
                                              and not any(str(v).startswith('BLOCK_ANY')
                                                          for v in x['policies'].values())]}

    by_cat = defaultdict(Counter)
    for line in attack_pool.open(encoding='utf-8'):
        row = json.loads(line)
        by_cat[row['dedup_scope']][row['source_file']] += 1
    shares = {cat: {'rows': sum(files.values()), 'max_file_rows': max(files.values()),
                    'max_file_share': max(files.values()) / sum(files.values())}
              for cat, files in sorted(by_cat.items())}
    checks['source_file_cap'] = {'ok': all(x['max_file_share'] <= .75 for x in shares.values()),
                                 'cap': .75, 'categories': shares}
    over = m['diagnostics']['over_limit_by_category_role']
    checks['over_limit'] = {'ok': all(x['over_limit'] / x['rows'] <= .01 for x in over if x['rows']),
                            'max_share': max((x['over_limit'] / x['rows'] for x in over if x['rows']), default=0),
                            'threshold': .01}
    balance = m['diagnostics']['class_balance_C-M3']
    checks['C-M3'] = {'ok': all(.48 <= float(x['block_share']) <= .52 for x in balance.values()),
                      'by_split': {k: v['block_share'] for k, v in sorted(balance.items())}}
    if cs7 is not None:
        s7 = json.loads(cs7.read_text())
        checks['C-S7'] = {'ok': s7.get('blocking_pass') is True,
                          'blocked_cells': sorted(k for k, v in s7.get('cells', {}).items()
                                                  if v.get('status') == 'BLOCK'),
                          'evidence_sha256': sha(cs7)}
    return {'schema': 'v5-freeze-precheck/v1', 'status': 'PARTIAL_PRE_FREEZE',
            'manifest_sha256': sha(manifest_path), 'checks': checks,
            'checks_run_pass': all(x['ok'] for x in checks.values()),
            'freeze_ready': False,
            'still_required': ['A2 byte-identical regeneration in two fresh processes',
                               'A4 complete source provenance and licensing review',
                               'A5 mutation self-tests for every blocking checker',
                               'C-S1 through C-S7 full shortcut probes under D75 thresholds',
                               'L10/L11 warning counts and rulings',
                               'STAB-HELD independent generator, disjointness and seal',
                               'V5 tokenizer remeasurement and library pins',
                               '§11.3 freeze report and committed freeze record']}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--dataset', type=Path, required=True)
    p.add_argument('--attack-pool', type=Path, required=True)
    p.add_argument('--collisions', type=Path, required=True)
    p.add_argument('--cs7', type=Path)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    r = check(a.dataset, a.attack_pool, a.collisions, a.cs7)
    a.out.write_text(json.dumps(r, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'checks_run_pass': r['checks_run_pass'], 'freeze_ready': r['freeze_ready'],
                      'manifest_sha256': r['manifest_sha256'], 'checks': len(r['checks'])}, sort_keys=True))


if __name__ == '__main__':
    main()
