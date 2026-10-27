#!/usr/bin/env python3
"""Emit version 2 after the L8 probe-pool exclusion; preserve rejected v1.

This only prepares and hashes decisions. It does not generate rows or mark a freeze complete.
"""
from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
HERE = Path(__file__).resolve().parent
PILOT = HERE.parent / "pilot-run-2026-10-25-r3"
sys.path.insert(0, str(ROOT / "scripts/dataset"))
import v5_generator as G  # noqa: E402
import v5_split as S  # noqa: E402


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def emit(name: str, value: dict) -> str:
    path = HERE / name
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return sha(path)


def main() -> None:
    attack = ROOT / "datasets/v5_sources/final_candidate/attack_pool.jsonl"
    measurement = ROOT / "datasets/v5_sources/pilot_source_2026-10-25-r3/pilot_measurements.json"
    component_path = ROOT / "reports/v5/postfilter-audit/final-component-bindings.json"
    policy = ROOT / "scripts/dataset/v5_policy/policy_table_v1.json"
    signatures = ROOT / "scripts/dataset/v5_policy/oracle_signatures_v1.json"
    catalog = ROOT / "scripts/dataset/v5_templates/catalog_v1.json"
    denylist = ROOT / "scripts/dataset/v5_lexicon/patt_third_party_denylist_v2.json"
    expected = {
        attack: "4d43e0bf190e6b08b9fb0828ae20aa4c17f9eef849b149389a00abc035ae0c39",
        measurement: "db7e64c40ba1d7bd8e1838534b64d27c6ac62bc650bd86d09eae06e9d3013cda",
        policy: "a881df75cc31ad8e93688c073127027cb824dff45f659caa042b454074306a22",
        signatures: "162670025d6fbb812716e2ca3818ea93e24e49277d4c3138223d61431a6ff40b",
        catalog: "26cd2c1342e42044aa21aa65ac452cf59597fd8cb06d1f3a6bfd81a87c73d7de",
        denylist: "3e5570580a10319fc03ca622c034786a384a3ea6dddaf95bfeb413cf3fc7dd7e",
    }
    for path, digest in expected.items():
        if sha(path) != digest:
            raise ValueError(f"source drift: {path}")

    cfg = read(PILOT / "generator-config.json")
    cfg["quota"]["pairs_per_cluster_category"] = 20
    cfg["i9"].update(enabled=True, warn_share="0.08", block_share="0.12", cap="warn",
                      owner_rulings={
                          "path-media": "D74: sole path_file_access structure in VALIDATION; 100% concentration disclosed",
                          "path-export": "D74: sole path_file_access structure in INTERNAL_TEST; 100% concentration disclosed",
                      })
    for section in ("quota", "placement_shares", "length_bins", "encoder_profiles", "oracle",
                    "token_budget", "trained_categories", "i9"):
        cfg[section]["status"] = "RATIFIED"
    validated_cfg = G.validate_gen_config(cfg)
    config_sha = emit("generator-config.json", cfg)

    split = read(PILOT / "split-config.json")
    split["cluster_share"] = {"warn": "0.08", "block": "0.12", "status": "RATIFIED"}
    S.validate_config(split)
    split_sha = emit("split-config.json", split)

    prereg = {
        "schema": "v5-dataset-preregistration/v1",
        "status": "RATIFIED",
        "spec": "V5-DATA-SPEC-r4",
        "owner_decisions": ["D71", "D74", "D75"],
        "purpose": "EXPERIMENTAL_RESEARCH_TRAINING",
        "version": "v5-dataset-v2",
        "correction": {
            "reason": "L8 probe-pool element overlap in rejected build v1",
            "rejected_v1_manifest_sha256": sha(ROOT / "datasets/v5_sources/final_source_2026-10-25-v1/manifest.json"),
            "pilot_r3_preregistration_sha256": sha(PILOT / "preregistration.json"),
            "probe_overlap_exclusion": read(PILOT / "preregistration.json")["probe_overlap_exclusion"],
        },
        "ratified": {
            "template_id": "V5_CANDIDATE_TEMPLATE",
            "vocabulary_id": "PILOT_VOCABULARY",
            "token_budget": {"B": 415, "max_length": 512, "margin": 8,
                             "template_overhead": 76, "label_budget": 13,
                             "v5_tokenizer_remeasurement_required_before_final_training": True},
            "generator_config_sha256": G.config_sha256(validated_cfg),
            "generator_config_file_sha256": config_sha,
            "split_config_sha256": S.config_sha256(split),
            "split_config_file_sha256": split_sha,
            "attack_pool_sha256": sha(attack),
            "component_bindings_sha256": sha(component_path),
            "policy_table_sha256": sha(policy),
            "template_catalog_sha256": sha(catalog),
            "benign_oracle": {"L": 12, "signatures_sha256": sha(signatures)},
            "denylist_sha256": sha(denylist),
            "source_file_cap": "0.75",
            "quota_pairs_per_cluster_category": 20,
            "pilot_pairs_per_cluster_category": 2,
            "placement_weights": {"replace": 3, "prefix": 1, "suffix": 1, "embedded": 1},
            "cluster_share": {"warn": "0.08", "block": "0.12", "cap": "warn",
                              "owner_rulings": copy.deepcopy(cfg["i9"]["owner_rulings"])},
            "over_limit_stop_share_by_category_class": "0.01",
            "i7": {"seed": 20261013, "random_cases": 2500, "single_byte_sweep": 256,
                   "test_source_sha256": sha(ROOT / "tests/test_canonical_request_review.py")},
            "category_evaluability": {
                "path_file_access": "EVALUABLE",
                "Command Injection": "NOT_EVALUABLE_TRAIN_ONLY",
                "SQL Injection": "NOT_EVALUABLE_TRAIN_ONLY",
                "Server Side Template Injection": "NOT_EVALUABLE_TRAIN_ONLY",
                "XSS Injection": "NOT_EVALUABLE_TRAIN_ONLY",
            },
            "acceptance_thresholds": {
                "C-M3": {"pass_block_share": ["0.48", "0.52"], "block_outside": ["0.45", "0.55"]},
                "C-S1": {"block_margin_gte": "0.10", "block_accuracy_gte": "0.80"},
                "C-S2": {"min_coverage": "0.01", "block_purity_gte": "0.99"},
                "C-S3": {"min_coverage": "0.01", "warn_purity_gte": "0.80", "block_purity_gte": "0.95"},
                "C-S4": {"warn_accuracy_gt": "0.55", "block_accuracy_gt": "0.65"},
                "C-S6": {"pass_ratio_gte": "0.80", "block_ratio_lt": "0.50"},
                "C-S7": {"warn_element_share_gt": "0.01", "block_element_share_gt": "0.03"},
                "C3": {"provider_share_warn_outside": ["0.20", "0.80"]},
                "L10": {"novelty_warning_share_gt": "0.50"},
                "L7_L8_L9": {"blocking_overlap_max": 0},
                "post_filter_audit": {"incorrect_wilson95_upper_max": "0.20",
                                      "uncertain_plus_incorrect_wilson95_upper_max": "0.35",
                                      "coverage": "1.00", "unresolved_gate_items_max": 0},
            },
        },
        "pilot_evidence": {"measurement_sha256": sha(measurement),
                           "manifest_sha256": sha(ROOT / "datasets/v5_sources/pilot_source_2026-10-25-r3/manifest.json"),
                           "gates_ok": True},
        "limitations": ["Four injection categories are TRAIN-only and not evaluable under D60.",
                        "VALIDATION and INTERNAL_TEST each contain one path_file_access cluster with a D74 exception.",
                        "No per-category held-out performance claim for CmdI, SQLi, SSTI or XSS."],
        "training_authorized": False,
    }
    prereg_sha = emit("preregistration.json", prereg)

    auth = {
        "schema": G.REAL_BUILD_AUTH_SCHEMA,
        "scope": "REAL_BUILD",
        "status": "AUTHORIZED",
        "authorized_by": "SebasHT15 (owner, chat authorization)",
        "date": "2026-10-25",
        "owner_decision": "D74+D75 and owner's fix-failures instruction; L8 versioned correction after rejected v1",
        "preregistration_sha256": prereg_sha,
        "generator_config_sha256": G.config_sha256(validated_cfg),
        "split_config_sha256": S.config_sha256(split),
        "assembled_pool_sha256": sha(attack),
        "components": read(component_path)["components"],
        "dataset_spec": "V5-DATA-SPEC-r4",
        "row_contract": "v5-training-reference-contract/v1-PROPOSED",
        "training_authorized": False,
    }
    auth_sha = emit("build-authorization.json", auth)
    print(json.dumps({"status": "PREPARED_NOT_BUILT", "generator_config_file_sha256": config_sha,
                      "split_config_file_sha256": split_sha, "preregistration_sha256": prereg_sha,
                      "build_authorization_sha256": auth_sha}, sort_keys=True))


if __name__ == "__main__":
    main()
