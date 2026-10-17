"""Stage-4 I-9 rebalancer tests (issue #74): the deterministic cluster-share quota rebalancing of
V5-DATA-SPEC-r3 §4.6 step 5. Pure quota math on synthetic cell tables — no rows, no catalogue.

Covers the required cases: compliant no-op; one cluster redistributed; several over threshold;
redistribution with rounding; deterministic ties; insufficient remaining capacity; a split with too
few clusters where the cap is mathematically impossible; a required concept only expressible in the
affected cluster (owner ruling); permuted input order; and PYTHONHASHSEED independence.

    python3 -m unittest tests.test_v5_rebalance -v
"""

import json
import os
import subprocess
import sys
import unittest
from fractions import Fraction

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "scripts", "dataset"))

import v5_rebalance as V9  # noqa: E402


def cfg(cap="block", warn="0.02", block="0.05", rulings=(), it=100, rounds=4):
    # `rulings`: an iterable of cluster ids (each gets a test justification) or an explicit {id: why} map
    ruling_map = rulings if isinstance(rulings, dict) else {cl: "test: obligatory concept in this cluster"
                                                            for cl in rulings}
    return {"enabled": True, "warn_share": warn, "block_share": block, "cap": cap, "max_iterations": it,
            "max_rounds": rounds, "owner_rulings": ruling_map, "status": "PROPOSED"}


def cells(split_carrier_clusters):
    """{(split, carrier): {cluster: {category: pairs}}} -> the flat cell map rebalance() takes."""
    out = {}
    for (split, carrier), clusters in split_carrier_clusters.items():
        for cl, cats in clusters.items():
            for cat, pairs in cats.items():
                out[(split, cl, cat)] = {"carrier": carrier, "pairs": pairs}
    return out


def cluster_pairs(adjusted, split):
    out = {}
    for (s, cl, _), v in adjusted.items():
        if s == split:
            out[cl] = out.get(cl, 0) + v["pairs"]
    return out


class Apportion(unittest.TestCase):
    def test_largest_remainder_sums_and_ties_by_key_order(self):
        self.assertEqual(V9.apportion(2, ["b", "c", "d"], {"b": 2, "c": 2, "d": 2}), {"b": 1, "c": 1, "d": 0})
        self.assertEqual(sum(V9.apportion(7, ["a", "b", "c"], {"a": 1, "b": 1, "c": 1}).values()), 7)
        self.assertEqual(V9.apportion(0, ["a"], {"a": 5}), {"a": 0})
        with self.assertRaises(ValueError):
            V9.apportion(-1, ["a"], {"a": 1})


class NoOp(unittest.TestCase):
    def test_compliant_config_is_unchanged(self):
        c = cells({("TRAIN", "q"): {"a": {"X": 5}, "b": {"X": 5}, "c": {"X": 5}, "d": {"X": 5}}})
        adj, rep = V9.rebalance(c, cfg(warn="0.30", block="0.40"))     # each 25% < warn 30%
        self.assertFalse(rep["changed"])
        self.assertEqual(adj, c)
        self.assertEqual({cl: v["class_before"] for cl, v in rep["splits"]["TRAIN"]["clusters"].items()},
                         {"a": "OK", "b": "OK", "c": "OK", "d": "OK"})


class OneCluster(unittest.TestCase):
    def test_single_over_cap_cluster_redistributes_within_carrier(self):
        c = cells({("TRAIN", "q"): {"a": {"X": 12}, "b": {"X": 4}, "c": {"X": 4}}})
        adj, rep = V9.rebalance(c, cfg(block="0.40"))        # P=20, cap_pairs=8
        cp = cluster_pairs(adj, "TRAIN")
        self.assertEqual(cp, {"a": 8, "b": 6, "c": 6})
        self.assertEqual(sum(cp.values()), 20)               # totals preserved
        self.assertTrue(rep["changed"])


class SeveralClusters(unittest.TestCase):
    def test_multiple_over_cap(self):
        c = cells({("TRAIN", "q"): {"a": {"X": 9}, "b": {"X": 9}, "c": {"X": 1}, "d": {"X": 1}}})
        adj, rep = V9.rebalance(c, cfg(block="0.30"))        # P=20, cap_pairs=6
        cp = cluster_pairs(adj, "TRAIN")
        self.assertEqual(cp, {"a": 6, "b": 6, "c": 4, "d": 4})
        self.assertEqual(sum(cp.values()), 20)


class Rounding(unittest.TestCase):
    def test_reduction_spread_across_a_clusters_cells_with_rounding(self):
        c = cells({("TRAIN", "q"): {"a": {"X": 5, "Y": 5, "Z": 2}, "b": {"X": 1}, "c": {"X": 1}}})
        adj, rep = V9.rebalance(c, cfg(block="0.40"))        # P=14, cap_pairs=5; a=12->5 (reduce 7)
        a = {cat: adj[("TRAIN", "a", cat)]["pairs"] for cat in ("X", "Y", "Z")}
        # reduce 7 over {X:5,Y:5,Z:2}: largest-remainder removes 3,3,1 -> exact per-cell values
        self.assertEqual(a, {"X": 2, "Y": 2, "Z": 1})
        self.assertEqual(sum(a.values()), 5)                 # cluster stays whole at the cap
        self.assertEqual(sum(cluster_pairs(adj, "TRAIN").values()), 14)

    def test_cap_warn_uses_the_warn_threshold(self):
        c = cells({("TRAIN", "q"): {"a": {"X": 8}, "b": {"X": 6}, "c": {"X": 6}}})
        adj, _ = V9.rebalance(c, cfg(cap="warn", warn="0.35", block="0.60"))   # P=20, cap=warn -> cap_pairs=7
        self.assertEqual(cluster_pairs(adj, "TRAIN")["a"], 7)
        self.assertEqual(sum(cluster_pairs(adj, "TRAIN").values()), 20)


class Ties(unittest.TestCase):
    def test_deterministic_tie_break_by_key_order(self):
        c = cells({("TRAIN", "q"): {"a": {"X": 9}, "b": {"X": 2}, "c": {"X": 2}, "d": {"X": 2}}})
        adj, rep = V9.rebalance(c, cfg(block="0.47"))        # P=15, cap_pairs=7; a excess 2 over b,c,d equal
        cp = cluster_pairs(adj, "TRAIN")
        self.assertEqual(cp, {"a": 7, "b": 3, "c": 3, "d": 2})  # +1 to b and c (first by key order)


class InsufficientCapacity(unittest.TestCase):
    def test_remaining_clusters_cannot_absorb_stops_and_names_the_cluster(self):
        c = cells({("TRAIN", "q"): {"a": {"X": 10}, "b": {"X": 2}}})     # P=12, cap_pairs=3; 12 > 2*3
        with self.assertRaises(V9.StopBuild) as cm:
            V9.rebalance(c, cfg(block="0.30"))
        self.assertEqual([f["code"] for f in cm.exception.findings], ["I9_REQUIRED_CONCEPT_RULING_NEEDED"])
        self.assertIn("'a'", cm.exception.findings[0]["detail"])         # names the offending cluster


class FewClustersImpossible(unittest.TestCase):
    def test_single_cluster_carrier_is_mathematically_impossible(self):
        c = cells({("VALIDATION", "t"): {"only": {"X": 10}}})
        with self.assertRaises(V9.StopBuild) as cm:
            V9.rebalance(c, cfg(block="0.05"))
        self.assertEqual([f["code"] for f in cm.exception.findings], ["I9_REQUIRED_CONCEPT_RULING_NEEDED"])

    def test_concentration_check_flags_before_after(self):
        c = cells({("VALIDATION", "t"): {"only": {"X": 10}}})
        _, rep = V9.rebalance(c, cfg(block="0.05", rulings=["only"]))
        cl = rep["splits"]["VALIDATION"]["clusters"]["only"]
        self.assertEqual(cl["class_before"], "BLOCK")       # correctly detects the (infeasible) concentration


class OwnerRuling(unittest.TestCase):
    def test_required_concept_only_in_cluster_is_recorded_and_kept_whole(self):
        c = cells({("VALIDATION", "t"): {"only": {"X": 10}}})
        adj, rep = V9.rebalance(c, cfg(block="0.05", rulings=["only"]))
        self.assertEqual(cluster_pairs(adj, "VALIDATION"), {"only": 10})   # kept whole, over cap
        self.assertIn({"split": "VALIDATION", "carrier": "t", "cluster": "only",
                       "justification": "test: obligatory concept in this cluster"}, rep["owner_rulings_applied"])

    def test_ruling_does_not_license_moving_rows_between_splits(self):
        c = cells({("TRAIN", "q"): {"a": {"X": 10}, "b": {"X": 2}},
                   ("VALIDATION", "q"): {"c": {"X": 6}}})
        adj, rep = V9.rebalance(c, cfg(block="0.30", rulings=["a", "c"]))
        # ruled clusters are untouched and nothing crosses the split boundary
        self.assertEqual(cluster_pairs(adj, "TRAIN"), {"a": 10, "b": 2})
        self.assertEqual(cluster_pairs(adj, "VALIDATION"), {"c": 6})

    def test_ruled_cluster_exempt_while_unruled_sibling_is_still_rebalanced(self):
        """Regression: a feasibility test that counted ruled clusters wrongly stopped a feasible build.
        A ruled over-cap cluster must be kept whole AND its un-ruled over-cap sibling still redistributed."""
        c = cells({("TRAIN", "q"): {"A": {"X": 60}, "B": {"X": 14}, "C": {"X": 1},
                                    "D": {"X": 1}, "E": {"X": 1}, "F": {"X": 1}}})
        adj, rep = V9.rebalance(c, cfg(warn="0.05", block="0.15", rulings=["A"]))   # P=78, cap_pairs=11
        cp = cluster_pairs(adj, "TRAIN")
        self.assertEqual(cp["A"], 60)                       # ruled, kept whole above the cap
        self.assertEqual(cp["B"], 11)                       # un-ruled, reduced to the cap
        self.assertEqual(sum(cp.values()), 78)              # B's excess (3) stayed in-carrier
        self.assertEqual([r["cluster"] for r in rep["owner_rulings_applied"]], ["A"])
        self.assertTrue(rep["owner_rulings_applied"][0]["justification"])
        self.assertTrue(rep["changed"])


class CarrierIsolation(unittest.TestCase):
    def test_excess_stays_within_its_carrier(self):
        c = cells({("TRAIN", "q"): {"a": {"X": 8}, "b": {"X": 2}, "c": {"X": 2}},
                   ("TRAIN", "f"): {"x": {"X": 8}, "y": {"X": 2}, "z": {"X": 2}}})
        adj, rep = V9.rebalance(c, cfg(block="0.30"))        # P=24, cap_pairs=7
        cp = cluster_pairs(adj, "TRAIN")
        self.assertEqual(cp["a"], 7)
        self.assertEqual(cp["x"], 7)
        self.assertEqual(cp["b"] + cp["c"], 5)              # q's excess (1) went to q siblings only
        self.assertEqual(cp["y"] + cp["z"], 5)              # f's excess (1) went to f siblings only


class InputValidation(unittest.TestCase):
    def test_config_refusals(self):
        bad = [cfg(warn="0.05", block="0.05"),          # warn not < block
               {**cfg(), "cap": "nope"},
               {**cfg(), "status": "RATIFIED"},         # must stay PROPOSED
               {**cfg(), "max_iterations": 0},
               {k: v for k, v in cfg().items() if k != "cap"}]   # missing key
        for b in bad:
            with self.assertRaises(V9.RebalanceConfigError):
                V9.rebalance(cells({("T", "q"): {"a": {"X": 1}}}), b)

    def test_cluster_spanning_two_carriers_is_refused(self):
        c = {("T", "a", "X"): {"carrier": "q", "pairs": 5}, ("T", "a", "Y"): {"carrier": "f", "pairs": 5}}
        with self.assertRaisesRegex(V9.RebalanceConfigError, "spans two carriers"):
            V9.rebalance(c, cfg())

    def test_negative_pairs_refused(self):
        with self.assertRaisesRegex(V9.RebalanceConfigError, "non-negative int"):
            V9.rebalance({("T", "a", "X"): {"carrier": "q", "pairs": -1}}, cfg())


class WaterFillGuard(unittest.TestCase):
    def test_non_convergence_raises_under_a_tight_iteration_cap(self):
        # a(headroom 1) and b(headroom 5): placing 6 needs two water-fill passes; cap it at 1
        with self.assertRaises(V9.StopBuild) as cm:
            V9._water_fill(6, ["a", "b"], {"a": 5, "b": 1}, 6, max_iterations=1)
        self.assertEqual(cm.exception.findings[0]["code"], "I9_NON_CONVERGENCE")

    def test_happy_path_places_exactly_the_excess(self):
        add = V9._water_fill(6, ["a", "b"], {"a": 5, "b": 1}, 6, max_iterations=100)
        self.assertEqual(sum(add.values()), 6)
        self.assertLessEqual(add["a"], 1)                   # never pushed over the cap
        self.assertLessEqual(add["b"], 5)


class Determinism(unittest.TestCase):
    SCENARIO = {("TRAIN", "q"): {"a": {"X": 9, "Y": 3}, "b": {"X": 4}, "c": {"X": 4}, "d": {"X": 4}}}

    def test_permuted_input_order_gives_identical_output(self):
        import random
        base = cells(self.SCENARIO)
        items = list(base.items())
        adj_ref, _ = V9.rebalance(dict(items), cfg(block="0.35"))
        for seed in range(5):
            random.Random(seed).shuffle(items)
            adj, _ = V9.rebalance(dict(items), cfg(block="0.35"))
            self.assertEqual(adj, adj_ref)

    def test_pythonhashseed_independence(self):
        prog = "\n".join([
            "import sys, json",
            "sys.path.insert(0, %r)" % os.path.join(REPO, "scripts", "dataset"),
            "import v5_rebalance as V9",
            "rows = [('a','X',9),('a','Y',3),('b','X',4),('c','X',4),('d','X',4)]",
            "c = {('TRAIN', cl, cat): {'carrier': 'q', 'pairs': p} for cl, cat, p in rows}",
            "cfg = {'enabled': True, 'warn_share': '0.02', 'block_share': '0.35', 'cap': 'block',",
            "       'max_iterations': 100, 'max_rounds': 4, 'owner_rulings': {}, 'status': 'PROPOSED'}",
            "adj, _ = V9.rebalance(c, cfg)",
            "print(json.dumps(sorted([list(k), v['pairs']] for k, v in adj.items())))",
        ])
        outs = []
        for seed in ("0", "1", "9999"):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            r = subprocess.run([sys.executable, "-c", prog], check=True, capture_output=True, text=True, env=env)
            outs.append(r.stdout)
        self.assertEqual(len(set(outs)), 1, outs)


if __name__ == "__main__":
    unittest.main()
