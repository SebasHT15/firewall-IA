#!/usr/bin/env python3
"""V5 stage 4 — synthetic, harmless fixture for the constructive generator (issue #74).

This module exists ONLY to exercise the STRUCTURE of the pipeline (templates, pairs, identities,
rendering, labels, exclusions, SPL / M / ENC invariants, determinism). It invents:

  * abstract attack *markers* — strings such as ``synthmark sqli 0007`` that carry NO functional
    exploit content; they stand in for a payload family so the identity, pairing and rendering code
    can be tested. The only real strings reused are the V4/D47 reason labels (spec §4.5 M-7), which
    are category names, not payloads;
  * synthetic benign value pools (abstract words, never a real person, address, host or secret).

Nothing here asserts that any real attack is detected or blocked, and no real payload, pool, split or
dataset is produced. The attack-label basis is ``fixture_synthetic``: `v5_labels.AttackBasis` labels a
record only when it declares ``synthetic: true`` (`v5_generator` and `v5_labels` refuse otherwise), so
these markers can never be mistaken for adjudicated attack data.

Mirrors the shape of the stage-3 fixture (`v5_split_checks.fixture_records`): records carry the stage-2
fields the identity and generator code reads (`record_id`, `status`, `payload_wire`, `payload_logical`,
`payload_wire_form`, `canonical_key`, `dedup_scope`, `native_forms`, `reason_string`).

CLI (for the determinism check; writes only inside a caller-provided throwaway directory):
  python3 scripts/dataset/v5_fixture.py generate --out DIR [--quiet]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
for _p in (HERE, os.path.join(REPO_ROOT, "data_plane")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import canonical_request as cr  # noqa: E402
import v5_catalog as K  # noqa: E402
import v5_generator as G  # noqa: E402
import v5_identities as I  # noqa: E402
import v5_labels as L  # noqa: E402
import v5_oracle as O  # noqa: E402
import v5_pools_common as C  # noqa: E402
import v5_render as R  # noqa: E402
import v5_split as S  # noqa: E402
from parse_dataset_v4 import canonical_key  # noqa: E402

# Injection categories (stage-2 `dedup_scope` names) with their V4/D47 reason labels (M-7). The two
# "rich" categories have enough families to be EVALUABLE (all three splits); the others stay
# NOT_EVALUABLE (families in TRAIN only), so both split outcomes are exercised.
FIXTURE_CATEGORIES = {
    "SQL Injection": ("sqli", "SQL injection payload detected.", 170),
    "XSS Injection": ("xss", "Cross-site scripting payload detected.", 170),
    "Command Injection": ("cmdi", "Command injection payload detected.", 40),
    "path_file_access": ("pfa", "Path traversal attack detected.", 60),
}
FIXTURE_TRAINED = tuple(FIXTURE_CATEGORIES)
# Synthetic benign pools (abstract words only). Each >= ~250 entries so every split clears the
# >= 20-per-split minimum (spec §4.6 step 3).
FIXTURE_POOLS = (("names_given", 250), ("streets", 250), ("symbols", 250),
                 ("urls_relative", 250), ("rel_paths", 250))
FIXTURE_PROFILE_B = 12            # oracle L (fixture value; > V4 MIN_LEN=4)


def _word(tag: str, i: int, length: int = 10) -> str:
    """Deterministic letters-only token from a sha256 digest (no two tags share a 4-gram by luck)."""
    h = hashlib.sha256(f"{tag}\0{i}".encode()).hexdigest()
    return "".join(chr(ord("a") + int(c, 16) % 26) for c in h[:length])


def fixture_attack_records():
    """Synthetic ACCEPTED attack records. Abstract markers only; one family per record."""
    recs = []
    for cat, (slug, reason, count) in FIXTURE_CATEGORIES.items():
        for i in range(count):
            wire = f"synthmark {slug} {i:04d} {_word(cat, i)}"
            recs.append({
                "record_id": f"synth-{slug}-{i:04d}",
                "status": C.ACCEPTED,
                "synthetic": True,                       # the fixture_synthetic label basis requires this
                "payload_wire": wire,
                "payload_logical": wire,
                "payload_wire_form": R.PLAIN,
                "canonical_key": canonical_key(wire),
                "dedup_scope": cat,
                "native_forms": [],
                "reason_string": reason,
                "source_file": f"SYNTHETIC/{slug}.txt",
                "label_status": C.LABEL_PENDING,
            })
    return recs


def fixture_pool_values():
    """pool_id -> [benign value strings]. Abstract words; none is a real name, host, path or secret."""
    pools = {}
    for pool, n in FIXTURE_POOLS:
        vals = []
        for i in range(n):
            w = _word(pool, i, 12).capitalize()
            if pool == "names_given":
                vals.append(w)
            elif pool == "streets":
                vals.append(f"{w} {100 + i}")
            elif pool == "symbols":
                vals.append(f"O'{w}")                    # benign apostrophe value (survives the oracle)
            elif pool == "urls_relative":
                vals.append(f"/synthetic/{w.lower()}/{i:04d}")
            elif pool == "rel_paths":
                vals.append(f"synthetic/{w.lower()}/{i:04d}.txt")
        pools[pool] = vals
    return pools


def fixture_split_config(**over):
    cats = sorted(FIXTURE_CATEGORIES)
    cfg = {
        "schema": S.SCHEMA_CONFIG, "salt": "v5-split-v1", "master_seed": "FIXTURE-stage4-not-a-real-seed",
        "shares_percent": {"INTERNAL_TEST": 20, "VALIDATION": 10, "TRAIN": 70},
        "carrier_strata": list(K.CARRIERS), "pools": [p for p, _ in FIXTURE_POOLS],
        "category_vocabulary": {"source": "stage2_dedup_scope", "order": "python_str_code_point", "categories": cats},
        "evaluability": {"min_families": 100, "min_internal_test_families": 30},
        "e6": {"reserve_percent": 8, "min_reserve_families": 30, "forced_overflow_policy": None},
        "value_min_per_split": 20, "near_duplicate_jaccard": "0.60",
        "pfid_rules_version": I.PFID_RULES_VERSION, "family_merges": [], "cluster_merges": [],
        "cluster_share": {"warn": "0.02", "block": "0.05", "status": "PROPOSED"},
        "value_equivalence": I.VALUE_EQUIVALENCE, "value_pool_precedence": [p for p, _ in FIXTURE_POOLS],
        "value_equivalence_semantic_notes": {},
    }
    cfg.update(over)
    return cfg


def fixture_gen_config(**over):
    cfg = {
        "schema": G.GEN_CONFIG_SCHEMA, "mode": "fixture",
        "quota": {"pairs_per_cluster_category": 2, "max_attempts_factor": 20, "status": "FIXTURE"},
        "placement_shares": {"replace": 3, "prefix": 1, "suffix": 1, "embedded": 1, "status": "PROPOSED"},
        "length_bins": {"edges": [8, 16, 32, 64, 128], "status": "PROPOSED"},
        "encoder_profiles": {"weights": "uniform", "status": "PROPOSED"},
        "oracle": {"L": FIXTURE_PROFILE_B, "status": "FIXTURE"},
        "token_budget": {"B": 415, "counter": "utf8_bytes_upper_bound", "status": "PROPOSED"},
        "trained_categories": {"categories": list(FIXTURE_TRAINED), "status": "PROPOSED"},
        "attack_label_basis": "fixture_synthetic", "twins_per_pair": 1,
        # I-9 cluster-share rebalancing (spec §4.6 step 5). Disabled by default: the clean fixture
        # has single-cluster carriers in VALIDATION / INTERNAL_TEST, where the rule is mathematically
        # infeasible and must stop (or need an owner ruling). The tests enable it explicitly.
        # cap="warn": the literal D62 §4.6 step 5 reading (WARN and BLOCK both trigger reduction;
        # BLOCK is the higher-severity band). Values 2%/5% stay PROPOSED (§11.2), ratified at the
        # preregistration; the fixture is never forced to satisfy them (I-9 is disabled here).
        "i9": {"enabled": False, "warn_share": "0.02", "block_share": "0.05", "cap": "warn",
               "max_iterations": 100, "max_rounds": 4, "owner_rulings": {}, "status": "PROPOSED"},
    }
    cfg.update(over)
    return cfg


def build_world(split_cfg=None, gen_cfg=None, records=None, pool_values=None, catalog=None, policy=None):
    """Assemble a `v5_generator.World` from synthetic inputs (no real pools, no real split)."""
    split_cfg = split_cfg or fixture_split_config()
    gen_cfg = G.validate_gen_config(gen_cfg or fixture_gen_config())
    catalog = catalog or K.load_catalog()
    policy = policy or L.load_policy_table()
    records = records if records is not None else fixture_attack_records()
    pool_values = pool_values if pool_values is not None else fixture_pool_values()

    families = I.build_families(records, split_cfg["family_merges"])
    table = K.cluster_table(catalog, split_cfg["cluster_merges"])
    value_ids = {p: [C.value_entry_id(p, v) for v in vs] for p, vs in pool_values.items()}
    assignment = S.build(split_cfg, table, families.values(), value_ids)

    oracle = O.BenignOracle(records, O.OracleConfig(gen_cfg["oracle"]["L"], gen_cfg["oracle"]["status"]))
    basis = L.AttackBasis(gen_cfg["attack_label_basis"])
    budget = gen_cfg["token_budget"]["B"]
    limits = cr.Limits(max_decoded_body=48 * budget, token_budget=budget,
                       count_tokens=lambda t: len(t.encode("utf-8")))
    pv = {p: {C.value_entry_id(p, v): v for v in vs} for p, vs in pool_values.items()}
    world = G.World(catalog=catalog, policy=policy, assignment=assignment, split_cfg=split_cfg,
                    gen_cfg=gen_cfg, pool_values=pv, records={r["record_id"]: r for r in records},
                    families=families, oracle=oracle, basis=basis, limits=limits,
                    count_tokens=G.utf8_bytes_upper_bound)
    return world


def fixture_pool_value_lists(pool_values=None):
    """{pool: [value strings]} for the SPL-6 pool-value gate."""
    return dict(pool_values or fixture_pool_values())


def generate(world=None):
    world = world or build_world()
    gen = G.generate_balanced(world)                 # single pass when I-9 is disabled (fixture default)
    gates = G.run_gates(world, gen, fixture_pool_value_lists())
    return world, gen, gates


def cmd_generate(args) -> int:
    world = build_world()
    gen = G.generate_balanced(world)
    gates = G.run_gates(world, gen, fixture_pool_value_lists())
    res = G.write_outputs(world, gen, gates, args.out, extra={"fixture": True})
    if not args.quiet:
        print(json.dumps({"ok": gates["ok"], "rows": len(gen["rows"]),
                          "manifest_sha256": res["manifest_sha256"]}, sort_keys=True))
    return 0 if gates["ok"] else 2


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate")
    g.add_argument("--out", required=True)
    g.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)
    return cmd_generate(args)


if __name__ == "__main__":
    sys.exit(main())
