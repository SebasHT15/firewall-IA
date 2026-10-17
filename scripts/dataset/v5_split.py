#!/usr/bin/env python3
"""V5 stage 3 — deterministic split assignment (V5-DATA-SPEC-r3 §4.6, FROZEN by D62; issue #72).

Standard library only. SPL-5: assignment runs on identities only. This module imports neither the
renderer (`canonical_request`), nor the tokenizer, nor any text-level helper; its inputs are
identity strings, strata and categories. A static test enforces the import list.

Procedure (spec §4.6 "Assignment, before rendering"):
  ranks    ascending sha256(SALT NUL kind NUL id) hex digest (ties, impossible in practice, by id)
  cuts     n_test = max(1, floor(0.20·n + 0.5)), n_val = max(1, floor(0.10·n + 0.5)), TRAIN the rest;
           lowest ranks -> INTERNAL_TEST, then VALIDATION, then TRAIN; n < 3 -> all TRAIN.
           Integer arithmetic only (floor((20n + 50) / 100)); Python's round() is never used.
  step 1   clusters ranked within each carrier stratum; n < 3 -> NOT_EVALUABLE_STRUCTURE
  step 2   payload families ranked once on pfid, cut per stratum category:
           attempt 1 with the E6 reserve (only if R = ceil(0.08·n) >= 30; ENC-5 forced families first),
           attempt 2 without it, otherwise NOT_EVALUABLE with every family in TRAIN. Strata run in
           category order; an attempt's evaluability also counts the families of the category placed
           earlier by another stratum (I-8, hybrid reading, owner ruling round 3)
  step 3   value entries ranked per pool; every split needs >= 20 entries or the build stops
  step 5   cluster row shares (thresholds PROPOSED, read from the config, never treated as approved)

Anything that cannot be assigned correctly raises `StopBuild` with every blocking finding listed.
Nothing is ever dropped, fragmented or relaxed to make a build pass.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from fractions import Fraction
from typing import Iterable, Mapping

SCHEMA_CONFIG = "v5-split-config/v3"     # v2: value equivalence, pool precedence (D-3); v3: holds removed, semantic notes (round 3)
SCHEMA_ASSIGNMENT = "v5-split-assignment/v1"
SPEC_ID = "V5-DATA-SPEC-r3"

TRAIN, VALIDATION, INTERNAL_TEST, E6_RESERVE = "TRAIN", "VALIDATION", "INTERNAL_TEST", "E6_RESERVE"
SPLITS = (TRAIN, VALIDATION, INTERNAL_TEST)
EVALUABLE, NOT_EVALUABLE = "EVALUABLE", "NOT_EVALUABLE"
NOT_EVALUABLE_STRUCTURE = "NOT_EVALUABLE_STRUCTURE"
ATTEMPT_WITH_RESERVE, ATTEMPT_NO_RESERVE = "attempt_1_with_reserve", "attempt_2_no_reserve"
OVERFLOW_POLICIES = ("reserve_equals_forced", "enc5_retire")

# Frozen by D60/D62. The config restates them; any difference is an invalid configuration.
FROZEN = {
    "salt": "v5-split-v1",
    "shares_percent": {INTERNAL_TEST: 20, VALIDATION: 10, TRAIN: 70},
    "evaluability": {"min_families": 100, "min_internal_test_families": 30},
    "e6": {"reserve_percent": 8, "min_reserve_families": 30},
    "value_min_per_split": 20,
    "near_duplicate_jaccard": "0.60",
}
CONFIG_KEYS = {"schema", "salt", "master_seed", "shares_percent", "carrier_strata", "pools",
               "category_vocabulary", "evaluability", "e6", "value_min_per_split",
               "near_duplicate_jaccard", "pfid_rules_version", "family_merges", "cluster_merges",
               "cluster_share", "value_equivalence", "value_pool_precedence", "value_equivalence_semantic_notes"}
VALUE_EQUIVALENCES = ("nfc_casefold/v1",)


class InvalidConfig(ValueError):
    pass


class InvalidInput(ValueError):
    pass


class StopBuild(RuntimeError):
    """Correct assignment is impossible (D60: the build reports the problem and stops)."""

    def __init__(self, findings):
        self.findings = sorted(findings, key=lambda f: json.dumps(f, sort_keys=True))
        super().__init__("; ".join(f"{f['code']}: {f['detail']}" for f in self.findings))


class SplitMembershipError(AssertionError):
    """SPL-4: a row's identities do not belong to its split. Asserted, never silently removed."""

    def __init__(self, violations):
        self.violations = violations
        super().__init__(f"{len(violations)} membership violation(s): {violations[:5]}")


# ───────────────────────────── config ─────────────────────────────
def canonical_json(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def config_sha256(cfg: Mapping) -> str:
    return hashlib.sha256(canonical_json(cfg).encode("utf-8")).hexdigest()


def _str_list(v, name, allow_empty=False):
    if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
        raise InvalidConfig(f"{name} must be a list of non-empty strings")
    if len(set(v)) != len(v):
        raise InvalidConfig(f"{name} has duplicates")
    if not v and not allow_empty:
        raise InvalidConfig(f"{name} is empty")
    return v


def _same(a, b) -> bool:
    """Equality that also requires identical types at every level (20.0 is not 20, True is not 1)."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(_same(a[k], b[k]) for k in a)
    return a == b


_DECIMAL = re.compile(r"0\.[0-9]+")


def validate_config(cfg: Mapping) -> dict:
    """Return a validated copy. Frozen values must be restated exactly; PROPOSED values (cluster
    share) are validated for shape only and carry their status."""
    if not isinstance(cfg, Mapping):
        raise InvalidConfig("config must be a JSON object")
    missing, extra = CONFIG_KEYS - set(cfg), set(cfg) - CONFIG_KEYS
    if missing or extra:
        raise InvalidConfig(f"config keys: missing {sorted(missing)}, unknown {sorted(extra)}")
    if cfg["schema"] != SCHEMA_CONFIG:
        raise InvalidConfig(f"schema must be {SCHEMA_CONFIG!r}")
    for key in ("salt", "shares_percent", "evaluability", "value_min_per_split", "near_duplicate_jaccard"):
        if not _same(cfg[key], FROZEN[key]):
            raise InvalidConfig(f"{key} must equal the frozen value {FROZEN[key]!r} (D60/D62)")
    e6 = cfg["e6"]
    if not isinstance(e6, Mapping) or set(e6) != {"reserve_percent", "min_reserve_families", "forced_overflow_policy"}:
        raise InvalidConfig("e6 must have reserve_percent, min_reserve_families, forced_overflow_policy")
    if not _same({k: e6[k] for k in FROZEN["e6"]}, FROZEN["e6"]):
        raise InvalidConfig(f"e6 values must equal the frozen {FROZEN['e6']!r}")
    if e6["forced_overflow_policy"] not in (None,) + OVERFLOW_POLICIES:
        raise InvalidConfig(f"e6.forced_overflow_policy must be null or one of {OVERFLOW_POLICIES}")
    ms = cfg["master_seed"]
    if isinstance(ms, bool) or not isinstance(ms, (int, str)) or ms == "":
        raise InvalidConfig("master_seed must be an int or a non-empty string")
    _str_list(cfg["carrier_strata"], "carrier_strata")
    _str_list(cfg["pools"], "pools")
    cv = cfg["category_vocabulary"]       # I-7 (ratified): the vocabulary is recorded explicitly
    if not isinstance(cv, Mapping) or set(cv) != {"source", "order", "categories"}:
        raise InvalidConfig("category_vocabulary must have source, order, categories")
    if cv["source"] != "stage2_dedup_scope" or cv["order"] != "python_str_code_point":
        raise InvalidConfig("category_vocabulary: source 'stage2_dedup_scope', order 'python_str_code_point'")
    _str_list(cv["categories"], "category_vocabulary.categories")
    if not isinstance(cfg["pfid_rules_version"], str) or not cfg["pfid_rules_version"]:
        raise InvalidConfig("pfid_rules_version must be a non-empty string")
    if cfg["value_equivalence"] not in VALUE_EQUIVALENCES:
        raise InvalidConfig(f"value_equivalence must be one of {VALUE_EQUIVALENCES} (owner ruling D-3)")
    _str_list(cfg["value_pool_precedence"], "value_pool_precedence")
    if not set(cfg["pools"]) <= set(cfg["value_pool_precedence"]):
        raise InvalidConfig("value_pool_precedence must list every configured pool")
    notes = cfg["value_equivalence_semantic_notes"]          # ledger notes only; they never keep a value
    if not isinstance(notes, Mapping) or not all(isinstance(k, str) and k and isinstance(v, str) and v.strip()
                                                 for k, v in notes.items()):
        raise InvalidConfig("value_equivalence_semantic_notes must map equivalence keys to non-empty notes")
    for key in ("family_merges", "cluster_merges"):
        groups = cfg[key]
        if not isinstance(groups, list):
            raise InvalidConfig(f"{key} must be a list of id lists")
        for g in groups:
            _str_list(g, key)
            if len(g) < 2:
                raise InvalidConfig(f"{key}: every merge needs at least two ids")
    cs = cfg["cluster_share"]
    if not isinstance(cs, Mapping) or set(cs) != {"warn", "block", "status"}:
        raise InvalidConfig("cluster_share must have warn, block, status")
    if cs["status"] != "PROPOSED":
        raise InvalidConfig("cluster_share.status must stay 'PROPOSED' until the preregistration (spec §11.2)")
    if not all(isinstance(cs[k], str) and _DECIMAL.fullmatch(cs[k]) for k in ("warn", "block")):
        raise InvalidConfig("cluster_share warn/block must be decimal strings like '0.02'")
    if not 0 < Fraction(cs["warn"]) < Fraction(cs["block"]) < 1:
        raise InvalidConfig("cluster_share needs 0 < warn < block < 1")
    return json.loads(canonical_json(cfg))


# ───────────────────────────── ranks and cuts ─────────────────────────────
def rank_digest(kind: str, ident: str) -> str:
    if not isinstance(ident, str) or not ident:
        raise InvalidInput(f"{kind} id must be a non-empty string")
    if "\0" in kind:
        raise InvalidInput("kind may not contain NUL")
    return hashlib.sha256("\0".join((FROZEN["salt"], kind, ident)).encode("utf-8")).hexdigest()


def ranked(kind: str, ids: Iterable[str]) -> list:
    ids = list(ids)
    if len(set(ids)) != len(ids):
        raise InvalidInput(f"duplicate {kind} ids in one ranking")
    return sorted(ids, key=lambda i: (rank_digest(kind, i), i))


def cuts(n: int) -> tuple:
    """(n_test, n_val, n_train). floor(p·n + 0.5) computed as (pct·n + 50) // 100."""
    if not isinstance(n, int) or isinstance(n, bool) or n < 0:
        raise InvalidInput("n must be an int >= 0")
    if n < 3:
        return 0, 0, n
    test = max(1, (FROZEN["shares_percent"][INTERNAL_TEST] * n + 50) // 100)
    val = max(1, (FROZEN["shares_percent"][VALIDATION] * n + 50) // 100)
    return test, val, n - test - val


def assign_by_rank(order: list) -> dict:
    t, v, _ = cuts(len(order))
    return {x: INTERNAL_TEST if i < t else VALIDATION if i < t + v else TRAIN for i, x in enumerate(order)}


def _evaluable(total: int, test: int) -> bool:
    ev = FROZEN["evaluability"]
    return total >= ev["min_families"] and test >= ev["min_internal_test_families"]


# ───────────────────────────── step 1: clusters ─────────────────────────────
def assign_clusters(cluster_stratum: Mapping[str, str], strata: list) -> tuple:
    unknown = sorted({s for s in cluster_stratum.values() if s not in strata})
    if unknown:
        raise InvalidInput(f"clusters in strata absent from the config: {unknown}")
    by = defaultdict(list)
    for c, s in cluster_stratum.items():
        by[s].append(c)
    assign, report = {}, {}
    for s in strata:
        order = ranked("cluster", by[s])
        a = assign_by_rank(order)
        assign.update(a)
        counts = Counter(a.values())
        report[s] = {"n": len(order), **{k: counts.get(k, 0) for k in SPLITS},
                     "flag": NOT_EVALUABLE_STRUCTURE if len(order) < 3 else "OK"}
    return assign, report


# ───────────────────────────── step 2: payload families + E6 ─────────────────────────────
@dataclass(frozen=True)
class FamilyIdentity:
    """What the split needs from a family: identities, categories and the ENC-5 flag — no text."""
    payload_family_id: str
    categories: tuple
    native_forms: tuple = ()

    @property
    def stratum_category(self):
        return self.categories[0]


def _as_family_identity(f) -> FamilyIdentity:
    cats = tuple(f.categories)
    if not cats or list(cats) != sorted(set(cats)) or not all(isinstance(c, str) and c for c in cats):
        raise InvalidInput(f"family {f.payload_family_id[:40]!r}: categories must be sorted, unique, non-empty")
    return FamilyIdentity(f.payload_family_id, cats, tuple(sorted(set(f.native_forms))))


# I-8 (owner ruling, stage 3 round 3: hybrid reading). §4.6: a family is assigned once, in its stratum
# (the lexicographically first category it occurs in), and counts toward the evaluability of every
# category it occurs in. Strata are processed in category order, so when stratum c runs, every family of c
# stratified elsewhere ("foreign": stratum < c) is already placed. The attempt's evaluability counts the
# stratum's own non-reserve families plus the foreign families in TRAIN / VALIDATION / INTERNAL TEST (a
# foreign reserve family never counts) — the same counts SPL-8 uses, so the outcome and the final flag
# agree. R and the cuts apply to the stratum's own families only: they are the only ones this step
# places; foreign families are never moved or re-cut (no retroactive change to an earlier stratum).
def assign_families(families: Iterable, policy, vocabulary: Iterable[str] | None = None) -> tuple:
    vocab = None if vocabulary is None else set(vocabulary)
    fams = {}
    for f in families:
        fi = _as_family_identity(f)
        if vocab is not None and not set(fi.categories) <= vocab:
            raise InvalidInput(f"family {fi.payload_family_id[:40]!r}: categories {sorted(set(fi.categories) - vocab)} "
                               "are not in the configured category vocabulary")
        if fi.payload_family_id in fams:
            raise InvalidInput(f"duplicate payload_family_id {fi.payload_family_id[:40]!r}")
        fams[fi.payload_family_id] = fi
    order = ranked("payload", fams)              # ranked once, on pfid alone
    by = defaultdict(list)
    for pfid in order:
        by[fams[pfid].stratum_category].append(pfid)
    occurring = defaultdict(list)
    for pfid in order:
        for c in fams[pfid].categories:
            occurring[c].append(pfid)
    assign, report, findings, blocked = {}, {}, [], set()
    pct, rmin = FROZEN["e6"]["reserve_percent"], FROZEN["e6"]["min_reserve_families"]
    for cat in sorted(set(by) | set(occurring)):
        stratum = by.get(cat, [])
        foreign = [p for p in occurring[cat] if fams[p].stratum_category != cat]
        waiting = sorted({fams[p].stratum_category for p in foreign} & blocked)
        if waiting:                                  # an earlier stratum stopped: this one cannot be counted
            blocked.add(cat)
            findings.append({"code": "STRATUM_NOT_EVALUATED",
                             "detail": f"{cat}: depends on families of blocked strata {waiting}"})
            continue
        if any(fams[p].stratum_category > cat or p not in assign for p in foreign):
            raise InvalidInput(f"{cat}: a foreign family is not placed before its stratum runs")
        fcnt = Counter(assign[p] for p in foreign)
        f_splits, f_test = sum(fcnt.get(k, 0) for k in SPLITS), fcnt.get(INTERNAL_TEST, 0)
        foreign_rep = {"n": len(foreign), "in_splits": f_splits, INTERNAL_TEST: f_test,
                       "reserve": fcnt.get(E6_RESERVE, 0)}
        if not stratum:                              # every family of the category is stratified elsewhere
            report[cat] = {"n": 0, "R": 0, "forced_native_form_families": 0, "foreign": foreign_rep,
                           "outcome": "no_own_stratum", "note": "every family is stratified in an earlier category",
                           "counted": {"total": f_splits, INTERNAL_TEST: f_test},
                           "evaluable": _evaluable(f_splits, f_test), "reserve_size": 0,
                           **{k: 0 for k in SPLITS}, "enc5_retired_forms": {}}
            continue
        n = len(stratum)
        R = (pct * n + 99) // 100                    # ceil(0.08·n), integer; own families only
        forced = [p for p in stratum if fams[p].native_forms]
        rep = {"n": n, "R": R, "forced_native_form_families": len(forced), "foreign": foreign_rep}
        chosen, reserve, note = None, [], None
        if R >= rmin:
            if len(forced) > R and policy is None:
                findings.append({"code": "E6_FORCED_OVERFLOW", "detail": f"{cat}: {len(forced)} native-form families > R={R}; "
                                 "the config must choose e6.forced_overflow_policy (spec §4.6 step 2 / ENC-5)"})
                blocked.add(cat)
                continue
            if len(forced) > R and policy == "reserve_equals_forced":
                reserve, note = list(forced), "reserve equals the forced native-form families (> R)"
            elif len(forced) > R:                    # enc5_retire: forcing abandoned, forms retired
                reserve, note = stratum[:R], "ENC-5 alternative: forced placement abandoned"
            else:
                fset = set(forced)
                reserve = forced + [p for p in stratum if p not in fset][:R - len(forced)]
            rset = set(reserve)
            rest = [p for p in stratum if p not in rset]
            t, _, _ = cuts(len(rest))
            rep["attempt_1"] = {"reserve": len(reserve), "remaining": len(rest), "internal_test": t,
                                "counted": {"total": len(rest) + f_splits, INTERNAL_TEST: t + f_test},
                                "evaluable": _evaluable(len(rest) + f_splits, t + f_test)}
            if rep["attempt_1"]["evaluable"]:
                chosen = ATTEMPT_WITH_RESERVE
                assign.update({p: E6_RESERVE for p in reserve})
                assign.update(assign_by_rank(rest))
        else:
            rep["attempt_1"] = {"skipped": f"R = {R} < {rmin}"}
        if chosen is None:
            reserve, note = [], None
            t, _, _ = cuts(n)
            rep["attempt_2"] = {"internal_test": t, "counted": {"total": n + f_splits, INTERNAL_TEST: t + f_test},
                                "evaluable": _evaluable(n + f_splits, t + f_test)}
            if rep["attempt_2"]["evaluable"]:
                chosen, note = ATTEMPT_NO_RESERVE, "no reserve: not defensible"
                assign.update(assign_by_rank(stratum))
            else:
                chosen = NOT_EVALUABLE
                assign.update({p: TRAIN for p in stratum})
        retired = Counter(f for p in stratum if assign[p] != E6_RESERVE for f in fams[p].native_forms)
        counts = Counter(assign[p] for p in stratum)
        rep.update(outcome=chosen, note=note, reserve_size=counts.get(E6_RESERVE, 0),
                   **{k: counts.get(k, 0) for k in SPLITS},
                   enc5_retired_forms=dict(sorted(retired.items())))
        report[cat] = rep
    if findings:
        raise StopBuild(findings)
    return assign, report, fams


def category_evaluability(fams: Mapping[str, FamilyIdentity], assign: Mapping[str, str]) -> dict:
    """SPL-8: computed from counts. A family counts toward every category it occurs in; reserve
    families never count."""
    out = {}
    cats = sorted({c for f in fams.values() for c in f.categories})
    for c in cats:
        members = [p for p, f in fams.items() if c in f.categories]
        cnt = Counter(assign[p] for p in members)
        total = sum(cnt.get(k, 0) for k in SPLITS)
        out[c] = {"families_in_splits": total, **{k: cnt.get(k, 0) for k in SPLITS},
                  "reserve": cnt.get(E6_RESERVE, 0),
                  "flag": EVALUABLE if _evaluable(total, cnt.get(INTERNAL_TEST, 0)) else NOT_EVALUABLE}
    return out


# ───────────────────────────── step 3: value entries ─────────────────────────────
def assign_values(values: Mapping[str, Iterable[str]], pools: list) -> tuple:
    extra = sorted(set(values) - set(pools))
    if extra:
        raise InvalidInput(f"value pools not in the config pool list: {extra}")
    findings, assign, report, seen = [], {}, {}, set()
    for pool in pools:
        if pool not in values:
            findings.append({"code": "POOL_UNAVAILABLE",
                             "detail": f"{pool}: no entries supplied (pool BLOCKED or not built)"})
            continue
        ids = list(values[pool])
        if len(set(ids)) != len(ids):
            raise InvalidInput(f"{pool}: duplicate value_entry_id")
        if set(ids) & seen:
            raise InvalidInput(f"{pool}: value_entry_id also present in another pool")
        seen.update(ids)
        a = assign_by_rank(ranked("value", ids))
        cnt = Counter(a.values())
        per = {k: cnt.get(k, 0) for k in SPLITS}
        ok = all(v >= FROZEN["value_min_per_split"] for v in per.values())
        report[pool] = {"n": len(ids), **per, "meets_minimum": ok}
        if not ok:
            findings.append({"code": "POOL_TOO_SMALL",
                             "detail": f"{pool}: {per} < {FROZEN['value_min_per_split']} per split; "
                                       "enlarge the pool, the minimum is never lowered"})
        assign.update({(pool, v): s for v, s in a.items()})
    if findings:
        raise StopBuild(findings)
    return assign, report


# ───────────────────────────── the assignment ─────────────────────────────
@dataclass(frozen=True)
class Partition:
    split: str
    clusters: tuple
    templates: tuple
    families_by_category: dict
    values_by_pool: dict


class SplitAssignment:
    def __init__(self, cfg, cluster_table, clusters, cluster_report, families, family_report, fams,
                 family_merges, family_member_keys, values, value_report):
        self.config = cfg
        self.clusters, self.cluster_report = clusters, cluster_report
        self.template_cluster = dict(cluster_table.template_cluster)
        self.cluster_stratum = dict(cluster_table.cluster_stratum)
        self.cluster_merges = {k: v for k, v in sorted(cluster_table.cluster_members.items()) if len(v) > 1}
        self.families, self.family_report, self.fams = families, family_report, fams
        self.family_merges = family_merges
        self.family_member_keys = family_member_keys       # root -> pre-merge family keys (SPL-9 compares these)
        self.values, self.value_report = values, value_report
        self.evaluability = category_evaluability(fams, families)

    # step 4 contract: a split draws only from its own partitions; E6 is never a split
    def partition(self, split: str) -> Partition:
        if split not in SPLITS:
            raise InvalidInput(f"{split!r} is not a split (E6_RESERVE is never generated)")
        fam_by_cat = defaultdict(list)
        for p, s in self.families.items():
            if s == split:
                for c in self.fams[p].categories:
                    fam_by_cat[c].append(p)
        val_by_pool = defaultdict(list)
        for (pool, v), s in self.values.items():
            if s == split:
                val_by_pool[pool].append(v)
        clusters = sorted(c for c, s in self.clusters.items() if s == split)
        cset = set(clusters)
        return Partition(split, tuple(clusters),
                         tuple(sorted(t for t, c in self.template_cluster.items() if c in cset)),
                         {k: tuple(sorted(v)) for k, v in sorted(fam_by_cat.items())},
                         {k: tuple(sorted(v)) for k, v in sorted(val_by_pool.items())})

    def split_of_template(self, template_id: str) -> str:
        return self.clusters[self.template_cluster[template_id]]

    def assert_row(self, row: Mapping) -> None:
        """SPL-4 for one row: {split, struct_cluster_id, template_id, payload_family_id?,
        value_entries: [[pool, value_entry_id], ...]}."""
        v = []
        split = row.get("split")
        if split not in SPLITS:
            raise SplitMembershipError([f"row split {split!r} is not a split"])
        c, t = row.get("struct_cluster_id"), row.get("template_id")
        if self.clusters.get(c) != split:
            v.append(f"cluster {c!r} is {self.clusters.get(c)!r}, row is {split}")
        if self.template_cluster.get(t) != c:
            v.append(f"template {str(t)[:16]} belongs to cluster {self.template_cluster.get(t)!r}, not {c!r}")
        p = row.get("payload_family_id")
        if p is not None and self.families.get(p) != split:
            v.append(f"payload family {p[:40]!r} is {self.families.get(p)!r}, row is {split}")
        for pool, ve in row.get("value_entries", ()):
            if self.values.get((pool, ve)) != split:
                v.append(f"value {pool}/{ve[:16]} is {self.values.get((pool, ve))!r}, row is {split}")
        if v:
            raise SplitMembershipError(v)

    def assignment_records(self) -> list:
        recs = [{"kind": "cluster", "id": c, "split": s, "stratum": self.cluster_stratum[c]}
                for c, s in self.clusters.items()]
        recs += [{"kind": "template", "id": t, "split": self.clusters[c], "cluster": c}
                 for t, c in self.template_cluster.items()]
        recs += [{"kind": "payload_family", "id": p, "split": s, "stratum": self.fams[p].stratum_category,
                  "categories": list(self.fams[p].categories)} for p, s in self.families.items()]
        recs += [{"kind": "value_entry", "id": v, "pool": pool, "split": s} for (pool, v), s in self.values.items()]
        return sorted(recs, key=lambda r: (r["kind"], r.get("pool", ""), r["id"]))

    def outcome_vs_flag(self) -> dict:
        """I-8 (hybrid): the attempt counts the stratum's own families plus the category's families
        already placed by earlier strata, as the final flag does, so the two must agree. Reported per
        category; SPL-8 fails on any divergence."""
        out = {}
        for c, e in self.evaluability.items():
            r = self.family_report.get(c)
            outcome = r["outcome"] if r else "missing"
            stratum_ok = bool(r) and (r["outcome"] in (ATTEMPT_WITH_RESERVE, ATTEMPT_NO_RESERVE)
                                      or (r["outcome"] == "no_own_stratum" and r["evaluable"]))
            out[c] = {"stratum_outcome": outcome, "final_flag": e["flag"],
                      "diverges": stratum_ok != (e["flag"] == EVALUABLE)}
        return out

    def manifest(self, assignment_sha256: str, extra: Mapping | None = None) -> dict:
        reserve = sorted(p for p, s in self.families.items() if s == E6_RESERVE)
        m = {
            "schema": SCHEMA_ASSIGNMENT, "spec": SPEC_ID,
            "status": "STAGE3_CONTRACT (not a dataset split)",
            "config_sha256": config_sha256(self.config), "config": self.config,
            "clusters": {"per_stratum": self.cluster_report,
                         "merges": self.cluster_merges},
            "families": {"per_stratum_category": self.family_report,
                         "evaluability": self.evaluability,
                         "stratum_outcome_vs_final_flag": self.outcome_vs_flag(),
                         "e6_reserve": {"size": len(reserve), "payload_family_ids": reserve,
                                        # no reserve family occurs in the category (own or placed by another stratum)
                                        "categories_without_reserve": sorted(
                                            c for c, e in self.evaluability.items() if e["reserve"] == 0),
                                        # the category's own stratum reserved nothing (no defensible reserve of
                                        # its own); a reserve family it shares may still come from another stratum
                                        "categories_without_own_reserve": sorted(
                                            c for c in self.evaluability
                                            if self.family_report.get(c, {}).get("reserve_size", 0) == 0),
                                        "reserve_families_from_other_strata": {
                                            c: r["foreign"]["reserve"] for c, r in sorted(self.family_report.items())
                                            if r["foreign"]["reserve"]}},
                         "enc5_retirements": {c: r["enc5_retired_forms"] for c, r in self.family_report.items()
                                              if r["enc5_retired_forms"]},
                         "merges": self.family_merges},
            "values": {"per_pool": self.value_report},
            "counts": {k: {"clusters": sum(1 for s in self.clusters.values() if s == k),
                           "templates": sum(1 for c in self.template_cluster.values() if self.clusters[c] == k),
                           "payload_families": sum(1 for s in self.families.values() if s == k),
                           "value_entries": sum(1 for s in self.values.values() if s == k)}
                       for k in SPLITS + (E6_RESERVE,)},
            "assignment_sha256": assignment_sha256,
        }
        if extra:
            m.update(extra)
        return m


def build(cfg: Mapping, cluster_table, families: Iterable, values: Mapping[str, Iterable[str]]) -> SplitAssignment:
    """Run steps 1–3 on identities. `cluster_table` is a `v5_identities.ClusterTable`; `families` are
    `v5_identities.Family` (or any object with payload_family_id / categories / native_forms);
    `values` maps pool_id -> value_entry_ids. Blocking findings of all steps are collected first."""
    cfg = validate_config(cfg)
    families = list(families)
    findings = []
    if cluster_table.near_duplicates:
        findings.append({"code": "UNDECLARED_NEAR_DUPLICATE_TEMPLATES",
                         "detail": f"{len(cluster_table.near_duplicates)} template pair(s) with Jaccard >= 0.60 "
                                   "in different clusters; declare a cluster merge (never split)"})
    clusters, cluster_report = assign_clusters(cluster_table.cluster_stratum, cfg["carrier_strata"])
    fam_assign = fam_report = fams = val_assign = val_report = None
    try:
        fam_assign, fam_report, fams = assign_families(families, cfg["e6"]["forced_overflow_policy"],
                                                       cfg["category_vocabulary"]["categories"])
    except StopBuild as e:
        findings += e.findings
    try:
        val_assign, val_report = assign_values(values, cfg["pools"])
    except StopBuild as e:
        findings += e.findings
    if findings:
        raise StopBuild(findings)
    merges = sorted(list(f.merged_from) for f in families if len(getattr(f, "merged_from", ())) > 1)
    if merges != _merge_components(cfg["family_merges"]):
        raise InvalidInput("the families' merges differ from config.family_merges (merge before building)")
    cmerges = sorted(v for v in cluster_table.cluster_members.values() if len(v) > 1)
    if cmerges != _merge_components(cfg["cluster_merges"]):
        raise InvalidInput("the cluster table's merges differ from config.cluster_merges")
    member_keys = {f.payload_family_id: tuple(getattr(f, "merged_from", (f.payload_family_id,))) for f in families}
    return SplitAssignment(cfg, cluster_table, clusters, cluster_report, fam_assign, fam_report, fams,
                           merges, member_keys, val_assign, val_report)


def _merge_components(groups) -> list:
    """Connected components of declared merge groups (each component sorted; list sorted)."""
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    for g in groups:
        for x in g[1:]:
            ra, rb = find(g[0]), find(x)
            if ra != rb:
                parent[max(ra, rb)] = min(ra, rb)
    comps = defaultdict(list)
    for x in list(parent):
        comps[find(x)].append(x)
    return sorted(sorted(v) for v in comps.values() if len(v) > 1)


def assignment_bytes(assignment: SplitAssignment) -> bytes:
    return "".join(canonical_json(r) + "\n" for r in assignment.assignment_records()).encode("utf-8")


def write_assignment(assignment: SplitAssignment, out_dir: str, extra: Mapping | None = None) -> dict:
    """Deterministic artifacts: assignment.jsonl (sorted) and manifest.json (no timestamps)."""
    os.makedirs(out_dir, exist_ok=True)
    data = assignment_bytes(assignment)
    with open(os.path.join(out_dir, "assignment.jsonl"), "wb") as fh:
        fh.write(data)
    digest = hashlib.sha256(data).hexdigest()
    m = assignment.manifest(digest, extra)
    m["artifacts"] = [{"path": "assignment.jsonl", "sha256": digest, "bytes": len(data)}]
    mdata = (json.dumps(m, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    with open(os.path.join(out_dir, "manifest.json"), "wb") as fh:
        fh.write(mdata)
    return {"assignment_sha256": digest, "manifest_sha256": hashlib.sha256(mdata).hexdigest()}


# ───────────────────────────── step 5: cluster share (thresholds PROPOSED) ─────────────────────────────
def cluster_shares(rows: Iterable[Mapping], cfg: Mapping) -> dict:
    """Rows of one cluster ÷ rows of its split, after generation. Classification uses the config's
    PROPOSED thresholds. Quota rebalancing is NOT implemented here: it needs the generator's quota
    model and an integer redistribution rule the frozen text does not fix (report §3 I-9)."""
    cs = validate_config(cfg)["cluster_share"]
    warn, block = Fraction(cs["warn"]), Fraction(cs["block"])
    per = defaultdict(Counter)
    for r in rows:
        per[r["split"]][r["struct_cluster_id"]] += 1
    out = {}
    for split in sorted(per):
        total = sum(per[split].values())
        out[split] = {}
        for c, n in sorted(per[split].items()):
            share = Fraction(n, total)
            out[split][c] = {"rows": n, "split_rows": total, "share": f"{float(share):.6f}",
                             "class": "BLOCK" if share > block else "WARN" if share > warn else "OK",
                             "threshold_status": "PROPOSED"}
    return out
