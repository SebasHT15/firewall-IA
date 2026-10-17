#!/usr/bin/env python3
"""V5 stage 4 — I-9 cluster-share rebalancing of the generator quota plan (issue #74).

Implements the deterministic part of V5-DATA-SPEC-r3 §4.6 step 5 (D62; the rule the step states, which
D64 §5 deferred to stage 4 because "the text does not fix an integer redistribution rule"):

  * cluster share = rows of one cluster ÷ rows of its split (here on the PLAN: rows = 2·pairs);
  * WARN above the warn threshold, BLOCK above the block threshold (values PROPOSED, from the config,
    never ratified here);
  * on a flagged cluster, reduce its quota to the cap and redistribute the removed pairs
    proportionally to the OTHER clusters of the same carrier stratum and split;
  * a cluster is never fragmented and is never reduced below the cap; no identity or row ever moves
    between splits (each split is rebalanced independently);
  * totals are preserved within each (split, carrier) group when a feasible solution exists;
  * if the remaining clusters of the group cannot absorb the excess (too few clusters — the limit is
    mathematically impossible, i.e. the carrier's pairs exceed clusters·cap), the build STOPS, unless
    the owner has recorded a ruling for the offending cluster ("a required concept only expressible in
    that cluster"), in which case the cluster is kept over the cap and the ruling is recorded.

Resolved by implementation (deterministic, documented — NOT arbitrary, NOT ratified):
  R1  the share denominator is the whole split (all carriers), per the frozen text.
  R2  the enforced cap is the `cap` threshold named in the config (`warn` or `block`). The text says
      "On WARN or BLOCK … reduced" without a numeric target; which threshold is the cap is a
      methodological choice and stays PROPOSED (see `needs_owner_approval`).
  R3  a reduction / addition is spread across a cluster's cells (its categories) proportionally to the
      cell's current pairs, by the largest-remainder method, tie-broken by category code-point order.
  R4  the excess is redistributed to eligible same-carrier+split clusters proportionally to their
      current pairs, water-filled so none is pushed over the cap, tie-broken by cluster id.
  R5  `row_rng` / `pair_id` are keyed by (split, cluster, category, i) and NOT by the pair count, so
      changing a cell's target preserves reproducibility (a shorter cell keeps the first i values).

Needs owner approval (surfaced, never decided here): the warn/block numeric values; whether the cap is
warn or block (R2); whether redistribution weights are current pairs (adopted, R4) or headroom.

Stdlib only. Pure quota math: no row, text, identity or split assignment is touched.
"""
from __future__ import annotations

import os
import sys
from collections import defaultdict
from fractions import Fraction

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import v5_split as S  # noqa: E402  (StopBuild, reused)

REBALANCE_SCHEMA = "v5-i9-rebalance/v1"
StopBuild = S.StopBuild

NEEDS_OWNER_APPROVAL = (
    "warn/block threshold values (PROPOSED, spec §11.2)",
    "whether the enforced cap is the WARN or the BLOCK threshold (R2)",
    "redistribution weight: current pairs (adopted) vs cluster headroom (R4)",
)


class RebalanceConfigError(ValueError):
    pass


def classify(share: Fraction, warn: Fraction, block: Fraction) -> str:
    return "BLOCK" if share > block else "WARN" if share > warn else "OK"


def validate_i9_config(cfg) -> dict:
    keys = {"enabled", "warn_share", "block_share", "cap", "max_iterations", "max_rounds", "owner_rulings", "status"}
    if not isinstance(cfg, dict) or set(cfg) != keys:
        raise RebalanceConfigError(f"i9 config keys must be exactly {sorted(keys)}")
    if not isinstance(cfg["enabled"], bool):
        raise RebalanceConfigError("i9.enabled must be a bool")
    import re
    dec = re.compile(r"0\.[0-9]+")
    for k in ("warn_share", "block_share"):
        if not isinstance(cfg[k], str) or not dec.fullmatch(cfg[k]):
            raise RebalanceConfigError(f"i9.{k} must be a decimal string like '0.05'")
    if not 0 < Fraction(cfg["warn_share"]) < Fraction(cfg["block_share"]) < 1:
        raise RebalanceConfigError("i9 needs 0 < warn_share < block_share < 1")
    if cfg["cap"] not in ("warn", "block"):
        raise RebalanceConfigError("i9.cap must be 'warn' or 'block'")
    for k in ("max_iterations", "max_rounds"):
        if isinstance(cfg[k], bool) or not isinstance(cfg[k], int) or cfg[k] < 1:
            raise RebalanceConfigError(f"i9.{k} must be an int >= 1")
    orr = cfg["owner_rulings"]
    if not isinstance(orr, dict) or not all(isinstance(k, str) and k and isinstance(v, str) and v.strip()
                                            for k, v in orr.items()):
        raise RebalanceConfigError("i9.owner_rulings must map each ruled cluster id to a non-empty justification: "
                                   "an exception for an obligatory-concept cluster needs a specific owner decision "
                                   "(§4.6); no blanket or unjustified exceptions")
    if cfg["status"] != "PROPOSED":
        raise RebalanceConfigError("i9.status must stay 'PROPOSED' until the preregistration (spec §11.2)")
    return dict(cfg)


def apportion(total: int, keys: list, weights: dict) -> dict:
    """Distribute a non-negative integer `total` over `keys` (already in deterministic order)
    proportionally to `weights` (non-negative ints), by the largest-remainder method; ties in the
    remainder are broken by the order of `keys`. Returns {key: int} summing to `total`."""
    if total < 0:
        raise ValueError("total must be >= 0")
    if not keys:
        if total:
            raise ValueError("no keys to distribute a positive total over")
        return {}
    w = {k: max(0, weights.get(k, 0)) for k in keys}
    tot_w = sum(w.values())
    if tot_w == 0:
        w = {k: 1 for k in keys}
        tot_w = len(keys)
    base, rema = {}, []
    for k in keys:
        q = Fraction(total * w[k], tot_w)
        fl = int(q)
        base[k] = fl
        rema.append((q - fl, k))
    left = total - sum(base.values())
    # largest remainder first; ties by key order (stable: keys already ordered)
    for _, k in sorted(rema, key=lambda t: (-t[0], keys.index(t[1])))[:left]:
        base[k] += 1
    return base


def _water_fill(excess: int, recipients: list, pairs: dict, cap_pairs: int, max_iterations: int) -> dict:
    """Place `excess` pairs onto `recipients` (ordered), proportional to current pairs, never taking a
    recipient over `cap_pairs`. Returns {recipient: added}. Raises if it cannot place all (caller
    guarantees enough headroom)."""
    add = {r: 0 for r in recipients}
    remaining, it = excess, 0
    while remaining > 0:
        it += 1
        if it > max_iterations:
            raise StopBuild([{"code": "I9_NON_CONVERGENCE",
                              "detail": f"redistribution did not converge within {max_iterations} iterations"}])
        active = [r for r in recipients if pairs[r] + add[r] < cap_pairs]
        if not active:
            break
        headroom = {r: cap_pairs - (pairs[r] + add[r]) for r in active}
        give = apportion(min(remaining, sum(headroom.values())), active, {r: pairs[r] for r in active})
        placed = 0
        for r in active:
            g = min(give[r], headroom[r])
            add[r] += g
            placed += g
        remaining -= placed
        if placed == 0:
            break
    if remaining > 0:
        raise StopBuild([{"code": "I9_INSUFFICIENT_CAPACITY",
                          "detail": f"{remaining} pair(s) could not be placed without exceeding the cap"}])
    return add


def _spread(cluster_cells: dict, delta: int, sign: int) -> dict:
    """Spread a reduction (sign -1) or addition (sign +1) of `delta` pairs across a cluster's cells
    (category -> pairs), proportional to current pairs, largest-remainder, category code-point order.
    For a reduction `delta` is always < the cluster total, so each cell's share is <= its own pairs and
    a cell never goes negative. Returns the new {category: pairs}."""
    cats = sorted(cluster_cells)
    share = apportion(delta, cats, {c: cluster_cells[c] for c in cats})
    return {c: cluster_cells[c] + sign * share[c] for c in cats}


def rebalance(cells: dict, i9cfg: dict) -> tuple:
    """cells: {(split, cluster, category): {"carrier": str, "pairs": int>=0}}.
    Returns (adjusted_cells, report) or raises StopBuild. Pure and deterministic."""
    cfg = validate_i9_config(i9cfg)
    warn, block = Fraction(cfg["warn_share"]), Fraction(cfg["block_share"])
    cap_frac = warn if cfg["cap"] == "warn" else block
    rulings = set(cfg["owner_rulings"])
    adjusted = {k: dict(v) for k, v in cells.items()}
    report = {"schema": REBALANCE_SCHEMA, "cap": cfg["cap"], "warn_share": cfg["warn_share"],
              "block_share": cfg["block_share"], "status": "PROPOSED", "needs_owner_approval": list(NEEDS_OWNER_APPROVAL),
              "splits": {}, "owner_rulings_applied": [], "changed": False}
    findings = []

    by_split = defaultdict(lambda: defaultdict(lambda: defaultdict(dict)))   # split -> carrier -> cluster -> {cat: pairs}
    carrier_of = {}
    for (split, cluster, cat), v in cells.items():
        p = v["pairs"]
        if isinstance(p, bool) or not isinstance(p, int) or p < 0:
            raise RebalanceConfigError(f"cell ({split},{cluster},{cat}): pairs must be a non-negative int, got {p!r}")
        if carrier_of.setdefault((split, cluster), v["carrier"]) != v["carrier"]:
            raise RebalanceConfigError(f"cluster {cluster!r} in split {split!r} spans two carriers "
                                       f"({carrier_of[(split, cluster)]!r} and {v['carrier']!r}); a cluster is one carrier")
        by_split[split][v["carrier"]][cluster][cat] = p

    for split in sorted(by_split):
        P = sum(v["pairs"] for (s, _, _), v in cells.items() if s == split)
        cap_pairs = int(Fraction(cap_frac) * P)            # floor(cap · split pairs)
        srep = {"split_pairs": P, "cap_pairs": cap_pairs, "clusters": {}, "carriers": {}}
        before = {cl: sum(cats.values()) for car in by_split[split].values() for cl, cats in car.items()}
        for carrier in sorted(by_split[split]):
            group = by_split[split][carrier]              # cluster -> {cat: pairs}
            clusters = sorted(group)
            cpairs = {cl: sum(group[cl].values()) for cl in clusters}
            # Owner-ruled clusters are fully exempt: they are kept whole (even over cap) and neither give
            # nor receive. Feasibility and redistribution therefore run over the UN-ruled clusters only.
            unruled = [cl for cl in clusters if cl not in rulings]
            over = [cl for cl in unruled if cpairs[cl] > cap_pairs]           # only un-ruled clusters get reduced
            ruled_over = [cl for cl in clusters if cl in rulings and cpairs[cl] > cap_pairs]
            carrier_rep = {"clusters": len(clusters), "pairs": sum(cpairs.values()), "cap_pairs": cap_pairs,
                           "over_cap": [cl for cl in clusters if cpairs[cl] > cap_pairs], "feasible": True,
                           "rulings": ruled_over}
            if ruled_over:                                 # a ruled cluster stays whole above the cap (recorded)
                report["owner_rulings_applied"].extend(
                    {"split": split, "carrier": carrier, "cluster": cl, "justification": cfg["owner_rulings"][cl]}
                    for cl in ruled_over)
            if not over:
                srep["carriers"][carrier] = carrier_rep    # nothing left to reduce
                continue
            # feasibility over the UN-ruled set: can those clusters hold their pairs with each <= cap_pairs?
            unruled_pairs = sum(cpairs[cl] for cl in unruled)
            recipients = [cl for cl in unruled if cpairs[cl] <= cap_pairs]
            feasible = cap_pairs >= 1 and bool(recipients) and unruled_pairs <= len(unruled) * cap_pairs
            if not feasible:
                carrier_rep["feasible"] = False
                for cl in over:
                    findings.append({"code": "I9_REQUIRED_CONCEPT_RULING_NEEDED",
                                     "detail": f"{split}/{carrier}: cluster {cl!r} holds {cpairs[cl]} of {P} split "
                                               f"pairs ({float(Fraction(cpairs[cl], P)):.1%} of the split) > cap "
                                               f"{cap_pairs} ({cfg['cap']} {cfg[cfg['cap'] + '_share']} of the split "
                                               "total, not of the carrier). Redistribution is within this carrier only "
                                               f"(§4.6), and its {len(unruled)} un-ruled cluster(s) cannot absorb the "
                                               "excess without exceeding the cap. A ruling needs a specific owner "
                                               "decision that an obligatory concept depends on this cluster (§4.6); "
                                               "otherwise change the catalogue or the thresholds."})
                srep["carriers"][carrier] = carrier_rep
                continue
            # feasible: reduce each un-ruled over-cap cluster to cap, water-fill the excess to un-ruled recipients
            excess = sum(cpairs[cl] - cap_pairs for cl in over)
            add = _water_fill(excess, recipients, cpairs, cap_pairs, cfg["max_iterations"]) if excess else {}
            for cl in over:
                group[cl] = _spread(group[cl], cpairs[cl] - cap_pairs, -1)
            for cl, a in add.items():
                if a:
                    group[cl] = _spread(group[cl], a, +1)
            carrier_rep["redistributed_pairs"] = excess
            carrier_rep["recipients"] = {cl: add[cl] for cl in recipients if add.get(cl)}
            srep["carriers"][carrier] = carrier_rep
            report["changed"] = True
        # write the adjusted cells back and report per-cluster shares (before/after)
        for carrier in by_split[split]:
            for cl, cats in by_split[split][carrier].items():
                for cat, pairs in cats.items():
                    adjusted[(split, cl, cat)]["pairs"] = pairs
        after = {cl: sum(cats.values()) for car in by_split[split].values() for cl, cats in car.items()}
        for cl in sorted(before):
            b, a = before[cl], after[cl]
            srep["clusters"][cl] = {
                "carrier": carrier_of[(split, cl)], "pairs_before": b, "pairs_after": a,
                "share_before": f"{float(Fraction(b, P)):.6f}" if P else "0",
                "share_after": f"{float(Fraction(a, P)):.6f}" if P else "0",
                "class_before": classify(Fraction(b, P), warn, block) if P else "OK",
                "class_after": classify(Fraction(a, P), warn, block) if P else "OK",
                "owner_ruled": cl in rulings}
        report["splits"][split] = srep

    if findings:
        raise StopBuild(findings)
    # totals preserved per split
    for split in by_split:
        if sum(v["pairs"] for (s, _, _), v in cells.items() if s == split) != \
                sum(v["pairs"] for (s, _, _), v in adjusted.items() if s == split):
            raise StopBuild([{"code": "I9_TOTAL_NOT_PRESERVED", "detail": f"{split}: pair total changed"}])
    return adjusted, report


def feasibility_analysis(cells: dict, warn: str, block: str) -> dict:
    """Per split: cluster counts (overall and per carrier) and the minimum cluster-share cap that is
    mathematically feasible, given that redistribution is within-carrier only and the share denominator
    is the WHOLE split (§4.6). The cap must satisfy, for every carrier g: carrier_pairs(g) <= K_g · cap,
    i.e. cap >= carrier_share(g) / K_g; and cap >= every single cluster's split share. So the minimum
    feasible cap = max over clusters of the cluster's split share, and over carriers of carrier_share/K_g.
    Reports whether the PROPOSED warn/block caps are feasible without any owner ruling. Pure; no mutation."""
    warn_f, block_f = Fraction(warn), Fraction(block)
    by_split = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
    for (split, cluster, _), v in cells.items():
        by_split[split][v["carrier"]][cluster] += v["pairs"]
    out = {}
    for split in sorted(by_split):
        P = sum(p for car in by_split[split].values() for p in car.values())
        carriers = {}
        min_cap = Fraction(0)
        for carrier in sorted(by_split[split]):
            group = by_split[split][carrier]
            cpairs = {cl: group[cl] for cl in sorted(group)}
            k = len(cpairs)
            carrier_pairs = sum(cpairs.values())
            # binding lower bounds on a feasible cap from this carrier
            per_carrier = Fraction(carrier_pairs, P * k) if P else Fraction(0)          # carrier_share / K
            max_cluster = max((Fraction(p, P) for p in cpairs.values()), default=Fraction(0)) if P else Fraction(0)
            bound = max(per_carrier, max_cluster)
            min_cap = max(min_cap, bound)
            carriers[carrier] = {"clusters": k, "pairs": carrier_pairs,
                                 "carrier_share": f"{float(Fraction(carrier_pairs, P)):.4f}" if P else "0",
                                 "min_feasible_cap": f"{float(bound):.4f}",
                                 "single_cluster": k == 1}
        out[split] = {"split_pairs": P, "clusters": sum(len(c) for c in by_split[split].values()),
                      "carriers": carriers, "min_feasible_cap": f"{float(min_cap):.4f}",
                      "warn_feasible_without_ruling": P > 0 and min_cap <= warn_f,
                      "block_feasible_without_ruling": P > 0 and min_cap <= block_f}
    return out
