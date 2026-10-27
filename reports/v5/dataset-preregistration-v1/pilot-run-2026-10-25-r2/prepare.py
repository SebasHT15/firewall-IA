#!/usr/bin/env python3
"""Prepare one reproducible source-backed V5 pilot configuration for owner review."""
import hashlib
import json
import sys
from pathlib import Path

ROOT=Path('/home/sebas/Desktop/firewall-IA')
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts/dataset'))
import v5_generator as G
import v5_pilot_inputs as P
import v5_split as S
import v5_identities as I

sha=lambda b:hashlib.sha256(b).hexdigest()
def put(name,obj):
    path=HERE/name
    path.write_text(json.dumps(obj,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
    return sha(path.read_bytes())

pilot_pools=Path('/home/sebas/Documents/Codex/2026-10-22/firewall-c1-model2-continuidad/work/pilot-integration-007/pools')
benign=ROOT/'datasets/v5_sources/benign'
attack=ROOT/'datasets/v5_sources/final_candidate/attack_pool.jsonl'
components=ROOT/'reports/v5/postfilter-audit/final-component-bindings.json'
pools,provenance=P.load_pool_values(str(pilot_pools),str(benign))
split=P.pilot_split_config(pools,P.PILOT_CATEGORIES)
split['master_seed']='v5-pilot-source-2026-10-25'
records=P.load_attack_records(str(attack))
families=I.build_families(records)
split['family_merges']=I.propose_merges(I.family_near_duplicate_pairs(families))
assert not I.unobservable_keys(I.build_families(records,split['family_merges']))
assert not I.family_near_duplicate_pairs(I.build_families(records,split['family_merges']))
S.validate_config(split)
config=P.pilot_gen_config(P.PILOT_CATEGORIES)
config['mode']='real'
config['attack_label_basis']='post_filter_audit'
config['quota']['status']='PROPOSED'
config['oracle']['status']='PENDING'
G.validate_gen_config(config)
split_file_sha=put('split-config.json',split)
config_file_sha=put('generator-config.json',config)
value_dedup=P.dedup_loaded_pools(pools,split)[1]
prior=ROOT/'reports/v5/dataset-preregistration-v1/pilot-run-2026-10-25/preregistration.json'
prereg={'schema':'v5-source-backed-pilot-preregistration/v1','status':'CORRECTED_AFTER_RECORDED_SPLIT_GATE_FAILURE',
        'scope':'CALIBRATION_ONLY','attack_pool_sha256':sha(attack.read_bytes()),
        'prior_attempt_preregistration_sha256':sha(prior.read_bytes()),
        'correction_reason':'SPL-6 equivalent values across splits and SPL-9 near-duplicate families/unobservable key',
        'held_unobservable_source_record_id':'f9ab7b1e37124234f4815e66757bce5aadde3c5eebf0a726e7f2bddbe6df9a16',
        'family_merge_groups':len(split['family_merges']),
        'value_equivalence_groups':value_dedup['groups'],
        'value_equivalent_entries_excluded':len(value_dedup['excluded']),
        'components_sha256':sha(components.read_bytes()),
        'pilot_pools_manifest_sha256':sha((pilot_pools/'manifest.json').read_bytes()),
        'benign_pools_manifest_sha256':sha((benign/'manifest.json').read_bytes()),
        'generator_config_file_sha256':config_file_sha,
        'split_config_file_sha256':split_file_sha,
        'generator_config_sha256':G.config_sha256(config),
        'split_config_sha256':S.config_sha256(split),
        'full_pairs_per_cluster_category':20,'pilot_pairs_per_cluster_category':2,
        'training_authorized':False,
        'measurement_purpose':['oracle L','placement shares','length bins','pool contributions','split/gates']}
prereg_sha=put('preregistration.json',prereg)
auth={'schema':'v5-pilot-build-authorization/v1-PROPOSED','scope':'PILOT_BUILD',
      'purpose':'CALIBRATION_ONLY','status':'AWAITING_SPECIFIC_OWNER_APPROVAL',
      'generator_config_sha256':G.config_sha256(config),
      'split_config_sha256':S.config_sha256(split),
      'preregistration_sha256':prereg_sha,
      'authorized_by':'','date':'','owner_decision':'',
      'dataset_spec':'V5-DATA-SPEC-r4','row_contract':'v5-training-reference-contract/v1-PROPOSED',
      'allows_training':False,'final_dataset':False,
      'pilot_fraction':{'numerator':1,'denominator':10},
      'full_pairs_per_cluster_category':20,
      'assembled_pool_sha256':sha(attack.read_bytes()),
      'components':json.loads(components.read_bytes())['components']}
put('authorization.proposed.json',auth)
print(json.dumps({'preregistration_sha256':prereg_sha,'attack_pool_sha256':prereg['attack_pool_sha256'],
                  'full_quota':20,'pilot_quota':2,'source':'real_component_pool',
                  'benign_pools':'built','merge_groups':len(split['family_merges']),
                  'value_equivalence_groups':value_dedup['groups'],
                  'status':'CORRECTED_UNDER_OWNER_FIX_INSTRUCTION'}))
