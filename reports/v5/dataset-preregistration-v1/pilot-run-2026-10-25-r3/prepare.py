#!/usr/bin/env python3
"""Versioned pilot after L8 probe-pool overlap was found in full-build v1."""
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
HERE = Path(__file__).resolve().parent
PRIOR = HERE.parent / 'pilot-run-2026-10-25-r2'
sys.path.insert(0, str(ROOT / 'scripts/dataset'))
import v5_generator as G  # noqa: E402
import v5_pilot_inputs as P  # noqa: E402
import v5_split as S  # noqa: E402


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def put(name, obj):
    path = HERE / name
    path.write_text(json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return sha(path)


def main():
    attack = ROOT / 'datasets/v5_sources/final_candidate/attack_pool.jsonl'
    components = ROOT / 'reports/v5/postfilter-audit/final-component-bindings.json'
    prior_measurement = ROOT / 'datasets/v5_sources/pilot_source_2026-10-25-r2/pilot_measurements.json'
    pilot_pools = Path('/home/sebas/Documents/Codex/2026-10-22/firewall-c1-model2-continuidad/work/pilot-integration-007/pools')
    benign = ROOT / 'datasets/v5_sources/benign'
    values, _ = P.load_pool_values(str(pilot_pools), str(benign))
    split = json.loads((PRIOR / 'split-config.json').read_text())
    _, dedup = P.dedup_loaded_pools(values, split)
    overlap = dedup['probe_overlap']
    assert overlap['excluded_total'] == 56 and overlap['remaining_overlap'] == 0
    config = json.loads((PRIOR / 'generator-config.json').read_text())
    S.validate_config(split)
    G.validate_gen_config(config)
    split_sha = put('split-config.json', split)
    config_sha = put('generator-config.json', config)
    prereg = {
        'schema': 'v5-source-backed-pilot-preregistration/v1',
        'status': 'CORRECTED_AFTER_RECORDED_L8_FAILURE',
        'scope': 'CALIBRATION_ONLY',
        'correction_reason': 'L8: remove 56 V5 value-pool elements overlapping published probe pools before D-3 dedup and split',
        'rejected_full_build_manifest_sha256': sha(ROOT / 'datasets/v5_sources/final_source_2026-10-25-v1/manifest.json'),
        'prior_pilot_preregistration_sha256': sha(PRIOR / 'preregistration.json'),
        'prior_pilot_measurement_sha256': sha(prior_measurement),
        'attack_pool_sha256': sha(attack),
        'components_sha256': sha(components),
        'pilot_pools_manifest_sha256': sha(pilot_pools / 'manifest.json'),
        'benign_pools_manifest_sha256': sha(benign / 'manifest.json'),
        'generator_config_file_sha256': config_sha,
        'split_config_file_sha256': split_sha,
        'generator_config_sha256': G.config_sha256(config),
        'split_config_sha256': S.config_sha256(split),
        'probe_overlap_exclusion': overlap,
        'value_equivalence_groups': dedup['groups'],
        'value_equivalent_entries_excluded': len(dedup['excluded']),
        'full_pairs_per_cluster_category': 20,
        'pilot_pairs_per_cluster_category': 2,
        'training_authorized': False,
    }
    prereg_sha = put('preregistration.json', prereg)
    auth = json.loads((PRIOR / 'authorization.json').read_text())
    auth.update(status='AUTHORIZED', date='2026-10-25',
                owner_decision='Original pilot approval plus instruction to correct failed gates; versioned L8 correction',
                preregistration_sha256=prereg_sha,
                generator_config_sha256=G.config_sha256(config),
                split_config_sha256=S.config_sha256(split),
                assembled_pool_sha256=sha(attack), allows_training=False, final_dataset=False)
    auth_sha = put('authorization.json', auth)
    print(json.dumps({'status': 'PREPARED_NOT_BUILT', 'preregistration_sha256': prereg_sha,
                      'authorization_sha256': auth_sha, 'probe_excluded': overlap['excluded_total']}, sort_keys=True))


if __name__ == '__main__':
    main()
