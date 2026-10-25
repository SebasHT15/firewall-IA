#!/usr/bin/env python3
"""V5 pilot inputs preparer — load + verify pools/config, assemble a World, leave the pilot invocable.

Integrates the shared generator, audit evidence, split, identity, oracle and label APIs. It:

  1. loads + verifies the CONSTRUCTED pilot pools (`build_v5_pilot_pools.py` output) by manifest sha256;
  2. assembles the benign value pools the chosen config needs (the five constructed ones + the five
     existing benign pools, or clearly-marked synthetic stand-ins when a built benign dir is not given);
  3. sends supplied stage-2 attack candidates through the shared authorized-build entry;
     else runs on a clearly-marked `fixture_synthetic` attack set so the wiring (World → generate →
     gates → measurements) is exercised FOR REAL on synthetic attacks — never a mocked validator;
  4. builds a `v5_generator.World` and writes the prepared inputs + a manifest (counts, hashes, the
     exact MISSING input when the real emitter/pool is absent).

Chosen config = the SIX ratified-vocabulary attack families (D71): SQLi, XSS, path_traversal,
file_inclusion, Command Injection, SSTI. As GENERATOR categories that is FIVE
(`path_file_access` unites traversal + file inclusion, D49). Pool usage of the chosen config:
  * free_string / json_leaf slots → names_given, names_family, streets, prose_en, symbols, passwords, addr_data
  * path_file slots (path_file_access) → rel_paths
  * url slots → urls_public / urls_relative are drawn ONLY as benign fillers for templates that carry a
    url slot, and would be the attacked pool only for url-type categories (Open Redirect / SSRF), which are
    NOT in the ratified vocabulary. They are built for completeness and future scope.

Nothing here is a real build / freeze / training, and nothing is ratified. A real pilot build is still
gated by `v5_generator.real_build_preconditions` / `authorized_build` (owner authorization + sealed audit).

CLI:
  python3 scripts/dataset/v5_pilot_inputs.py prepare --pilot-pools DIR --out DIR \
      [--attack-pool POOL.jsonl] [--benign-pools DIR] [--per-category N]
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
import v5_split_checks as SC  # noqa: E402
from parse_dataset_v4 import canonical_key  # noqa: E402

PILOT_POOL_IDS = ("passwords", "urls_public", "urls_relative", "rel_paths", "addr_data")
BENIGN_POOL_IDS = ("names_given", "names_family", "streets", "prose_en", "symbols")
# The SIX ratified-vocabulary families as GENERATOR categories (path_file_access unites two).
PILOT_CATEGORIES = ("SQL Injection", "XSS Injection", "path_file_access", "Command Injection",
                    "Server Side Template Injection")
CATEGORY_REASON = {"SQL Injection": "SQL injection payload detected.",
                   "XSS Injection": "Cross-site scripting payload detected.",
                   "path_file_access": "Path traversal attack detected.",
                   "Command Injection": "Command injection payload detected.",
                   "Server Side Template Injection": "Server-side template injection payload detected."}
PILOT_PROFILE_L = 12                 # oracle L (pilot stand-in; > V4 MIN_LEN=4; PENDING ratification §4.4)


class PilotInputError(ValueError):
    """The pilot inputs cannot be assembled safely. Never partially prepared."""


# ───────────────────────────── pools ─────────────────────────────
def implementation_hashes():
    result = {}
    for name in ('v5_pilot_inputs.py','build_v5_pilot_pools.py'):
        with open(os.path.join(HERE,name),'rb') as fh:
            result[name] = hashlib.sha256(fh.read()).hexdigest()
    return result


def _capture(path):
    """Guard, capture, and hash the exact bytes that the caller parses."""
    C.assert_not_protected(path)
    with open(path, 'rb') as fh:
        raw = fh.read()
    return raw, hashlib.sha256(raw).hexdigest()


def _verify_pool_manifest(pool_dir: str, pool_ids, *, with_evidence=False):
    C.assert_not_protected(pool_dir)
    raw, manifest_sha = _capture(os.path.join(pool_dir, 'manifest.json'))
    manifest = json.loads(raw)
    artifacts = manifest.get('artifacts', [])
    by_path = {os.path.basename(a['path']):a for a in artifacts}
    if len(by_path) != len(artifacts):
        raise PilotInputError('duplicate manifest artifact paths')
    values = {}
    for pid in pool_ids:
        name = f'{pid}.jsonl'
        raw, sha = _capture(os.path.join(pool_dir, name))
        if name not in by_path or sha != by_path[name]['sha256']:
            raise PilotInputError(f'{name}: missing manifest artifact or hash mismatch')
        records = [json.loads(line) for line in raw.split(b'\n') if line.strip()]
        vals = []
        for row in records:
            if row.get('status') == C.ACCEPTED and row.get('exclusion_reason') is None:
                value = row['value']
                if row.get('pool_id') != pid or row.get('value_entry_id') != C.value_entry_id(pid,value):
                    raise PilotInputError(f'{name}: pool identity mismatch')
                vals.append(value)
        if not vals or len(set(vals)) != len(vals):
            raise PilotInputError(f'{name}: empty or duplicate accepted values')
        values[pid] = vals
    return (values,manifest_sha) if with_evidence else values


def _synthetic_benign_stand_ins(per_pool: int = 300) -> dict:
    """Clearly-marked synthetic benign values for the five existing benign pools when a built dir is not
    supplied. Abstract tokens only (never a real name/street/secret); used so the preparer runs now."""
    def tok(pool, i, n=12):
        h = hashlib.sha256(f"stand-in\0{pool}\0{i}".encode()).hexdigest()
        return "".join(chr(ord("a") + int(c, 16) % 26) for c in h[:n])
    pools = {}
    for pool in BENIGN_POOL_IDS:
        out = []
        for i in range(per_pool):
            w = tok(pool, i).capitalize()
            out.append({"names_given": w, "names_family": w,
                        "streets": f"{w} {100 + i}", "symbols": f"O'{w}",
                        "prose_en": f"the {w.lower()} is on the table"}[pool])
        pools[pool] = out
    return pools


def load_pool_values(pilot_dir: str, benign_dir=None) -> tuple:
    """Return ({pool: [values]} for all ten pools, provenance dict). Pilot pools are verified by hash;
    benign pools come from `benign_dir` (verified) or synthetic stand-ins (marked)."""
    values, pilot_manifest_sha = _verify_pool_manifest(pilot_dir, PILOT_POOL_IDS,with_evidence=True)
    provenance = {p: {"source": "constructed_pilot_pool", "dir": os.path.relpath(pilot_dir, REPO_ROOT),
                  "manifest_sha256":pilot_manifest_sha}
                  for p in PILOT_POOL_IDS}
    if benign_dir:
        benign, benign_manifest_sha = _verify_pool_manifest(benign_dir, BENIGN_POOL_IDS,with_evidence=True)
        for p in BENIGN_POOL_IDS:
            provenance[p] = {"source": "built_benign_pool", "dir": os.path.relpath(benign_dir, REPO_ROOT),
                             "manifest_sha256":benign_manifest_sha}
    else:
        benign = _synthetic_benign_stand_ins()
        for p in BENIGN_POOL_IDS:
            provenance[p] = {"source": "synthetic_stand_in", "note": "no --benign-pools dir; abstract tokens"}
    values.update(benign)
    return values, provenance


# ───────────────────────────── attack records ─────────────────────────────
def synthetic_attack_records(per_category: int = 60) -> list:
    """Clearly-marked `fixture_synthetic` attack markers (NO exploit content) for the pilot categories, so
    the preparer can exercise the real World/generate/gates when the admitted pool is not yet available."""
    recs = []
    for cat in PILOT_CATEGORIES:
        slug = cat.lower().replace(" ", "-")
        for i in range(per_category):
            h = hashlib.sha256(f"{slug}\0{i}".encode()).hexdigest()
            wire = f"synthmark {slug} {i:04d} {''.join(chr(ord('a') + int(c, 16) % 26) for c in h[:10])}"
            recs.append({"record_id": f"synth-{slug}-{i:04d}", "status": C.ACCEPTED, "synthetic": True,
                         "payload_wire": wire, "payload_logical": wire, "payload_wire_form": R.PLAIN,
                         "canonical_key": canonical_key(wire), "dedup_scope": cat, "native_forms": [],
                         "reason_string": CATEGORY_REASON[cat], "source_file": f"SYNTHETIC/{slug}.txt",
                         "label_status": C.LABEL_PENDING})
    return recs


def load_attack_records(path: str, *, with_sha=False):
    """Capture stage-2 candidates; ACCEPTED is extraction status, never audit admission."""
    raw, sha = _capture(path)
    records = [json.loads(line) for line in raw.split(b'\n') if line.strip()]
    recs = [r for r in records if r.get('status') == C.ACCEPTED
            and r.get('dedup_scope') in PILOT_CATEGORIES]
    if not recs:
        raise PilotInputError('no accepted stage-2 records in the pilot categories')
    ids = [r.get('record_id') for r in recs]
    if any(not isinstance(rid,str) or not rid for rid in ids) or len(set(ids)) != len(ids):
        raise PilotInputError('missing or duplicate attack record IDs')
    return (recs,sha) if with_sha else recs


# ───────────────────────────── config + World ─────────────────────────────
def pilot_split_config(pools, categories, **over) -> dict:
    cats = sorted(categories)
    cfg = {"schema": S.SCHEMA_CONFIG, "salt": "v5-split-v1", "master_seed": "PILOT-not-a-real-seed",
           "shares_percent": {"INTERNAL_TEST": 20, "VALIDATION": 10, "TRAIN": 70},
           "carrier_strata": list(K.CARRIERS), "pools": list(pools),
           "category_vocabulary": {"source": "stage2_dedup_scope", "order": "python_str_code_point", "categories": cats},
           "evaluability": {"min_families": 100, "min_internal_test_families": 30},
           "e6": {"reserve_percent": 8, "min_reserve_families": 30, "forced_overflow_policy": None},
           "value_min_per_split": 20, "near_duplicate_jaccard": "0.60",
           "pfid_rules_version": I.PFID_RULES_VERSION, "family_merges": [], "cluster_merges": [],
           "cluster_share": {"warn": "0.02", "block": "0.05", "status": "PROPOSED"},
           "value_equivalence": I.VALUE_EQUIVALENCE, "value_pool_precedence": list(pools),
           "value_equivalence_semantic_notes": {}}
    cfg.update(over)
    return cfg


def pilot_gen_config(categories, **over) -> dict:
    cfg = {"schema": G.GEN_CONFIG_SCHEMA, "mode": "fixture",
           "quota": {"pairs_per_cluster_category": 2, "max_attempts_factor": 20, "status": "FIXTURE"},
           "placement_shares": {"replace": 3, "prefix": 1, "suffix": 1, "embedded": 1, "status": "PROPOSED"},
           "length_bins": {"edges": [8, 16, 32, 64, 128], "status": "PROPOSED"},
           "encoder_profiles": {"weights": "uniform", "status": "PROPOSED"},
           "oracle": {"L": PILOT_PROFILE_L, "status": "FIXTURE"},
           "token_budget": {"B": 415, "counter": "utf8_bytes_upper_bound", "status": "PROPOSED"},
           "trained_categories": {"categories": list(categories), "status": "PROPOSED"},
           "attack_label_basis": "fixture_synthetic", "twins_per_pair": 1,
           "i9": {"enabled": False, "warn_share": "0.02", "block_share": "0.05", "cap": "warn",
                  "max_iterations": 100, "max_rounds": 4, "owner_rulings": {}, "status": "PROPOSED"}}
    cfg.update(over)
    return cfg


def build_pilot_world(pool_values: dict, records: list, categories, split_cfg=None, gen_cfg=None, *, count_tokens=None) -> "G.World":
    """Assemble a `v5_generator.World` from pilot pools + attack records, via the existing APIs (same
    assembly as the fixture builder, but with the pilot config/pools). No API is edited."""
    pools = [p for p in pool_values]
    split_cfg = split_cfg or pilot_split_config(pools, categories)
    gen_cfg = G.validate_gen_config(gen_cfg or pilot_gen_config(categories))
    catalog = K.load_catalog()
    policy = L.load_policy_table()
    families = I.build_families(records, split_cfg["family_merges"])
    table = K.cluster_table(catalog, split_cfg["cluster_merges"])
    value_ids = {p: [C.value_entry_id(p, v) for v in vs] for p, vs in pool_values.items()}
    assignment = S.build(split_cfg, table, families.values(), value_ids)
    oracle = O.BenignOracle(records, O.OracleConfig(gen_cfg["oracle"]["L"], gen_cfg["oracle"]["status"]))
    basis = L.AttackBasis(gen_cfg["attack_label_basis"])
    budget = gen_cfg["token_budget"]["B"]
    counter = gen_cfg['token_budget']['counter']
    if counter == 'tokenizer' and count_tokens is None:
        raise PilotInputError('tokenizer counter required by generator config')
    if counter == 'utf8_bytes_upper_bound':
        count_tokens = G.utf8_bytes_upper_bound
    limits = cr.Limits(max_decoded_body=48 * budget, token_budget=budget, count_tokens=count_tokens)
    pv = {p: {C.value_entry_id(p, v): v for v in vs} for p, vs in pool_values.items()}
    return G.World(catalog=catalog, policy=policy, assignment=assignment, split_cfg=split_cfg,
                   gen_cfg=gen_cfg, pool_values=pv, records={r["record_id"]: r for r in records},
                   families=families, oracle=oracle, basis=basis, limits=limits,
                   count_tokens=count_tokens)


# ───────────────────────────── prepare ─────────────────────────────
def prepare(pilot_dir: str, out_dir: str, *, attack_pool=None, benign_dir=None, per_category=60,
            authorization_path=None, audit_exchange_path=None, dataset_prereg=None,
            split_config=None, generator_config=None, count_tokens=None, build_purpose="REAL_BUILD") -> dict:
    """Load+verify pools, assemble the World, run generate+gates FOR REAL, write outputs + a prepared
    manifest. Returns the prepared-inputs summary. `missing_inputs` names the exact pending real input."""
    SC.guard_output(out_dir)
    if os.path.exists(out_dir):
        raise PilotInputError('output already exists; use a new directory')
    if attack_pool:
        return prepare_authorized(pilot_dir, out_dir, attack_pool=attack_pool, benign_dir=benign_dir,
            authorization_path=authorization_path,audit_exchange_path=audit_exchange_path,
            dataset_prereg=dataset_prereg,split_config=split_config,generator_config=generator_config,
            count_tokens=count_tokens,build_purpose=build_purpose)
    if per_category < 1:
        raise PilotInputError('per_category must be positive')
    pool_values, provenance = load_pool_values(pilot_dir, benign_dir)
    missing = []
    records = synthetic_attack_records(per_category)
    attack_source = {'source':'fixture_synthetic','records':len(records),
                     'note':'synthetic markers; not an admitted attack pool'}
    missing.append({'input':'--attack-pool','what':'stage-2 source pool plus pinned audit evidence and build authorization'})
    missing.append({'input':'--build-authorization','what':'owner-authorized REAL_BUILD record and configurations'})
    if benign_dir is None:
        missing.append({'input':'--benign-pools','what':'existing source-based benign pools; current values are synthetic stand-ins'})

    world = build_pilot_world(pool_values, records, PILOT_CATEGORIES)
    gen = G.generate_balanced(world)
    gates = G.run_gates(world, gen, {p: vs for p, vs in pool_values.items()})
    extra = {"pilot_inputs": {"implementation_sha256":implementation_hashes(),"attack_source": attack_source, "pool_provenance": provenance,
                              "categories_generator": list(PILOT_CATEGORIES),
                              "constructed_pools": list(PILOT_POOL_IDS),
                              "missing_inputs": missing}}
    if not gates['ok']:
        return {'status':'REFUSED','gates_ok':False,'unmet':[{'code':'BUILD_GATES_FAILED'}], 'gates':gates}
    wr = G.write_outputs(world, gen, gates, out_dir, extra=extra)
    summary = {"status": "PREPARED" if gates["ok"] else "PREPARED_GATES_FAILED",
               "gates_ok": gates["ok"], "rows": len(gen["rows"]),
               "manifest_sha256": wr["manifest_sha256"], "out_dir": os.path.relpath(out_dir, REPO_ROOT),
               "attack_source": attack_source, "missing_inputs": missing,
               "pool_counts": {p: len(vs) for p, vs in sorted(pool_values.items())}}
    with open(os.path.join(out_dir, "pilot_inputs_summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, sort_keys=True)
    return summary


def prepare_authorized(pilot_dir, out_dir, *, attack_pool, benign_dir, authorization_path,
                       audit_exchange_path, dataset_prereg, split_config, generator_config,
                       count_tokens=None,build_purpose="REAL_BUILD"):
    """Source inputs go only through the effective shared REAL_BUILD gate; no fixture promotion."""
    required = {'--benign-pools':benign_dir,'--build-authorization':authorization_path,
                '--dataset-prereg':dataset_prereg,
                '--split-config':split_config,'--generator-config':generator_config}
    missing = [name for name,value in required.items() if not value]
    if missing:
        raise PilotInputError('source-backed preparation requires '+', '.join(missing))
    SC.guard_output(out_dir)
    if os.path.exists(out_dir):
        raise PilotInputError('output already exists; use a new directory')
    cfg_raw, cfg_sha = _capture(generator_config)
    split_raw, split_sha = _capture(split_config)
    _, prereg_sha = _capture(dataset_prereg)
    cfg = json.loads(cfg_raw)
    auth_raw, _ = _capture(authorization_path)
    auth = json.loads(auth_raw)
    if auth.get('components') is None and not audit_exchange_path:
        raise PilotInputError('single-component build requires --audit-exchange')
    split = S.validate_config(json.loads(split_raw))
    if cfg.get('mode') != 'real' or cfg.get('attack_label_basis') != 'post_filter_audit':
        raise PilotInputError('source inputs require mode=real and post_filter_audit')
    categories = cfg['trained_categories']['categories']
    if set(categories) != set(PILOT_CATEGORIES):
        raise PilotInputError('generator config must retain the five-category planned pilot scope')
    pools, provenance = load_pool_values(pilot_dir,benign_dir)
    records, pool_sha = load_attack_records(attack_pool,with_sha=True)
    if auth.get('components') is not None:
        if pool_sha != auth.get('assembled_pool_sha256'):
            raise PilotInputError('attack input differs from authorization-pinned component assembly')
    elif pool_sha != ((auth.get('audit_evidence') or {}).get('pool') or {}).get('sha256'):
        raise PilotInputError('attack input differs from authorization-pinned source pool')
    world = build_pilot_world(pools,records,categories,split_cfg=split,gen_cfg=cfg,count_tokens=count_tokens)
    source = {'source':'stage2_candidates_pending_authorized_build','sha256':pool_sha,
              'path':os.path.relpath(attack_pool,REPO_ROOT),'records':len(records)}
    result = G.authorized_build(world,authorization_path=authorization_path,
        audit_exchange_path=audit_exchange_path,out_dir=out_dir,preregistration_sha256=prereg_sha,
        category_selection=list(categories),pool_values_list=pools,build_purpose=build_purpose,
        extra={'pilot_inputs':{'implementation_sha256':implementation_hashes(),'attack_source':source,'pool_provenance':provenance,
              'generator_config_file_sha256':cfg_sha,'split_config_file_sha256':split_sha,
              'missing_inputs':[]}})
    # BUILT means the shared gate admitted this production-route build. Source
    # records never acquire fixture_synthetic/VERIFIED through this preparer.
    if result['status'] == 'BUILT':
        with open(os.path.join(out_dir,'pilot_inputs_summary.json'),'w',encoding='utf-8') as fh:
            json.dump(result,fh,indent=2,sort_keys=True)
    return result


# ───────────────────────────── pilot measurements ─────────────────────────────
# §11.2 values that stay PENDING until the pilot resolves them (names only; no value is invented here).
PILOT_PENDING_11_2 = ("cluster_share_warn", "cluster_share_block", "over_limit_stop_value",
                      "fuzz_corpus_size_i7", "acceptance_thresholds_section7", "benign_oracle_L",
                      "benign_oracle_signatures", "placement_mode_shares", "per_source_file_cap",
                      "category_distribution")


def measure(prepared_dir: str, out_file=None) -> dict:
    """Assemble the pilot measurements from a PREPARED inputs directory (the ones the pilot foresees):
    distribution, split separation, cluster-share, exclusions / OVER_LIMIT, per-source contribution, and the
    §11.2 values still pending. Captures the manifest and verified TRAIN/VALIDATION metadata; computes nothing new that
    the gates did not already produce (measurements, not decisions)."""
    C.assert_not_protected(prepared_dir)
    raw, manifest_sha = _capture(os.path.join(prepared_dir, 'manifest.json'))
    m = json.loads(raw)
    if out_file:
        SC.guard_output(out_file)
        if os.path.realpath(out_file) == os.path.realpath(os.path.join(prepared_dir,'manifest.json')):
            raise PilotInputError('measurement output cannot replace manifest or artifacts')
        protected_outputs = {os.path.realpath(os.path.join(prepared_dir,a['path'])) for a in m.get('artifacts',[])}
        if os.path.realpath(out_file) in protected_outputs:
            raise PilotInputError('measurement output cannot replace manifest or artifacts')
    diag, counts, gates = m.get("diagnostics", {}), m.get("counts", {}), m.get("gates", {})
    per_source = {}
    artifacts = {a["path"]:a for a in m.get("artifacts",[])}
    for split in ("TRAIN", "VALIDATION"):
        meta_path = os.path.join(prepared_dir, f"rows.{split}.meta.jsonl")
        meta_raw, meta_sha = _capture(meta_path)
        name = os.path.basename(meta_path)
        if name not in artifacts or meta_sha != artifacts[name]['sha256']:
            raise PilotInputError(f'{name}: measurement input hash mismatch')
        for row in (json.loads(line) for line in meta_raw.split(b'\n') if line.strip()):
            for entry in row.get("value_entries") or []:
                pool = entry[0] if isinstance(entry, (list, tuple)) and entry else None
                if pool:
                    per_source[pool] = per_source.get(pool, 0) + 1
    spl = gates.get("SPL", {})
    measurements = {
        "source_manifest_sha256": manifest_sha,
        "per_source_contribution_scope": ["TRAIN", "VALIDATION"],
        "protected_role_files_opened": [],
        "distribution": {"by_split_disposition": counts.get("by_split_disposition"),
                         "class_balance_C-M3": diag.get("class_balance_C-M3"),
                         "length_bins_by_class": diag.get("length_bins_by_class"),
                         "placement_modes": diag.get("placement_modes"),
                         "carrier_symmetry_C-S6": diag.get("carrier_symmetry_C-S6"),
                         "categories_not_trained": m.get("categories_not_trained")},
        "split_separation": {"SPL_ok": all(g.get("ok") for g in spl.values()) if spl else None,
                             "SPL": {k: g.get("ok") for k, g in spl.items()}},
        "cluster_share": diag.get("cluster_share_step5"),
        "exclusions_over_limit": {"over_limit_by_category_role": diag.get("over_limit_by_category_role"),
                                  "pairs_abandoned": counts.get("pairs_abandoned"),
                                  "quota_shortfalls": counts.get("quota_shortfalls")},
        "per_source_contribution": dict(sorted(per_source.items())),
        "pending_11_2": list(PILOT_PENDING_11_2),
        "note": "Measurements from the PREPARED inputs. Thresholds (cluster-share WARN/BLOCK, OVER_LIMIT, L, "
                "§7) stay PROPOSED/PENDING (§11.2); these numbers inform them, they do not ratify them. If the "
                "attack source was fixture_synthetic, the numbers exercise the pipeline, not a real pilot.",
        "attack_source": (m.get("pilot_inputs") or {}).get("attack_source"),
    }
    if out_file:
        with open(out_file, "w", encoding="utf-8") as fh:
            json.dump(measurements, fh, indent=2, sort_keys=True)
    return measurements


def cmd_measure(args) -> int:
    out = args.out or os.path.join(args.prepared, "pilot_measurements.json")
    meas = measure(args.prepared, out)
    print(json.dumps({"out": os.path.relpath(out, REPO_ROOT), "split_separation": meas["split_separation"],
                      "per_source_contribution": meas["per_source_contribution"]}, sort_keys=True))
    return 0


def cmd_prepare(args) -> int:
    summary = prepare(args.pilot_pools, args.out, attack_pool=args.attack_pool,
                      benign_dir=args.benign_pools, per_category=args.per_category,
                      authorization_path=args.build_authorization,audit_exchange_path=args.audit_exchange,
                      dataset_prereg=args.dataset_prereg,split_config=args.split_config,
                      generator_config=args.generator_config,count_tokens=_cli_counter(args.tokenizer_recipe),
                      build_purpose=args.build_purpose)
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary.get("gates_ok") is True else 2


def _cli_counter(recipe_path):
    if not recipe_path:
        return None
    C.assert_not_protected(recipe_path)
    sys.path.insert(0,os.path.join(REPO_ROOT,'scripts','training'))
    import v5_train_data as D
    from transformers import AutoTokenizer
    recipe, _ = D.load_recipe(recipe_path)
    base = recipe['base_model']
    tok = AutoTokenizer.from_pretrained(base['name'],revision=base['revision'],local_files_only=True)
    return G.tokenizer_counter(tok,D.recipe_template(recipe))


def build_parser():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("prepare", help="load+verify pools, assemble the World, write prepared pilot inputs")
    p.add_argument("--pilot-pools", required=True, help="build_v5_pilot_pools.py output dir")
    p.add_argument("--out", required=True, help="output dir for the prepared pilot inputs")
    p.add_argument("--attack-pool", default=None, help="stage-2 source pool; requires authorization, audit evidence and explicit configs; synthetic if absent")
    p.add_argument("--benign-pools", default=None, help="built benign pools dir; synthetic stand-ins if absent")
    p.add_argument("--per-category", type=int, default=60, help="synthetic attack records per category when no --attack-pool")
    for option in ('build-authorization','audit-exchange','dataset-prereg','split-config','generator-config','tokenizer-recipe'):
        p.add_argument('--'+option,default=None)
    p.add_argument("--build-purpose",choices=("REAL_BUILD","PILOT_BUILD"),default="REAL_BUILD")
    p.set_defaults(func=cmd_prepare)
    mm = sub.add_parser("measure", help="assemble the pilot measurements from a prepared inputs dir")
    mm.add_argument("--prepared", required=True, help="a 'prepare' output directory")
    mm.add_argument("--out", default=None, help="measurements json (default: <prepared>/pilot_measurements.json)")
    mm.set_defaults(func=cmd_measure)
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
