"""Tests for the V4 minimal-pair probe v2 (v5-minimal-pairs-v2).

Standard library only; no model is loaded. They cover what could silently invalidate the probe:
determinism of the cases, independence of bases, the one-dimension rule for every comparison, D1
rendering, the intended encoding of `#`/`'` per context, disjointness from the frozen v1 probe and
from v1's value pools, and the statistics / pre-registered classification.

    python3 -m unittest tests.test_v4_minimal_pair_probe_v2 -v
"""

import json
import os
import re
import sys
import unittest
from urllib.parse import unquote

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts", "evaluation"))

import minimal_pair_probe_v2_cases as gen  # noqa: E402
import run_v4_minimal_pair_probe_v2 as probe  # noqa: E402

CASES, COMPARISONS, REPEAT = gen.generate()
BY_KEY = {(c["factor"], c["base"], c["level"]): c for c in CASES}
V1_CASES_PATH = os.path.join(REPO_ROOT, "reports", "v5", "minimal-pair-probe-v1", "cases.jsonl")


def split(text):
    head, _, body = text.partition("\n\n")
    lines = head.split("\n")
    return lines[0], lines[1:], (body if "\n\n" in text else None)


def field_and_value(text):
    """(field name, decoded value) of the single manipulated field, or (None, None) when the
    request carries no single-field value (e.g. a v1 GET with no query)."""
    line0, _, body = split(text)
    if line0.startswith("GET"):
        if "?" not in line0:
            return None, None
        q = line0.split("?", 1)[1].rsplit(" ", 1)[0]
        if "=" not in q:
            return None, None
        k, v = q.split("=", 1)
        return k, unquote(v)
    if body is None:
        return None, None
    if body.startswith("{"):
        d = json.loads(body)
        k = list(d)[0]
        return k, str(d[k])
    if "=" not in body:
        return None, None
    k, v = body.split("=", 1)
    return k, unquote(v)


def skeleton(text):
    line0, headers, _ = split(text)
    method = line0.split(" ", 1)[0]
    path = line0.split(" ")[1].split("?", 1)[0]
    hdrs = tuple(h for h in headers if h.startswith(
        ("Host:", "User-Agent:", "Accept:", "Content-Type:")))
    return (method, path, hdrs, "\n\n" in text)


class GeneratorTests(unittest.TestCase):
    def test_deterministic(self):
        again, comps, rep = gen.generate()
        self.assertEqual([c["text"] for c in again], [c["text"] for c in CASES])
        self.assertEqual(rep, REPEAT)

    def test_counts(self):
        self.assertEqual(len(CASES), 590)
        self.assertEqual(len({c["text"] for c in CASES}), 590)
        self.assertEqual(len(COMPARISONS), 11)

    def test_bases_distinct_across_all_factors(self):
        texts = [c["text"] for c in CASES]
        self.assertEqual(len(texts), len(set(texts)))

    def test_main_comparisons_have_at_least_30_bases(self):
        main = {"F2-HASH:base->hash": 60, "F2-APOS:plain->apostrophe": 75,
                "CONTROL-COV2:val_a->val_b": 40}
        n = {c["comparison_id"]: c["n_bases"] for c in COMPARISONS}
        for cid, want in main.items():
            self.assertEqual(n[cid], want, cid)
        for c in COMPARISONS:
            if c["factor"] == "F2-ADDR":
                self.assertGreaterEqual(c["n_bases"], 30, c["comparison_id"])

    def test_every_base_level_skeleton_is_constant(self):
        by_base = {}
        for c in CASES:
            by_base.setdefault((c["factor"], c["base"]), []).append(c)
        for key, cs in by_base.items():
            sk = {skeleton(c["text"]) for c in cs}
            self.assertEqual(len(sk), 1, f"skeleton varies within base {key}")

    def test_addr_name_and_value_contrasts_change_one_locus(self):
        n = gen.FACTORS["F2-ADDR"][1]
        for i in range(n):
            fp, vp = field_and_value(BY_KEY[("F2-ADDR", i, "n_prose")]["text"])
            fa, va = field_and_value(BY_KEY[("F2-ADDR", i, "a_prose")]["text"])
            self.assertEqual((fp, fa), ("detail", "address"))  # name changes
            self.assertEqual(vp, va)                            # value constant
            fs, vs = field_and_value(BY_KEY[("F2-ADDR", i, "n_street")]["text"])
            self.assertEqual(fs, "detail")                      # value changes, name constant
            self.assertNotEqual(vp, vs)
            # n2_prose: neutral->neutral rename control (field remark, same prose value)
            f2, v2 = field_and_value(BY_KEY[("F2-ADDR", i, "n2_prose")]["text"])
            self.assertEqual(f2, "remark")
            self.assertEqual(v2, vp)

    def test_value_only_contrasts_keep_field_name(self):
        pairs = {"F2-HASH": [("base", "hash"), ("base", "punct")],
                 "F2-APOS": [("plain", "apostrophe")],
                 "CONTROL-COV2": [("val_a", "val_b")]}
        for fid, ps in pairs.items():
            for i in range(gen.FACTORS[fid][1]):
                for ref, lv in ps:
                    fr, vr = field_and_value(BY_KEY[(fid, i, ref)]["text"])
                    fl, vl = field_and_value(BY_KEY[(fid, i, lv)]["text"])
                    self.assertEqual(fr, fl, (fid, i, ref, lv))
                    self.assertNotEqual(vr, vl, (fid, i, ref, lv))

    def test_hash_and_apos_single_character_insertion(self):
        # hash/punct insert exactly one character into the base value; apostrophe adds one "'".
        for i in range(gen.FACTORS["F2-HASH"][1]):
            _, base = field_and_value(BY_KEY[("F2-HASH", i, "base")]["text"])
            _, hsh = field_and_value(BY_KEY[("F2-HASH", i, "hash")]["text"])
            _, pun = field_and_value(BY_KEY[("F2-HASH", i, "punct")]["text"])
            self.assertEqual(len(hsh), len(base) + 1)
            self.assertEqual(hsh.count("#"), base.count("#") + 1)
            self.assertEqual(len(pun), len(base) + 1)
            self.assertEqual(pun.count("!"), base.count("!") + 1)
            # hash and punct insert at the SAME position (identical except the inserted char)
            self.assertEqual(hsh.replace("#", "", 1), base)
            self.assertEqual(pun.replace("!", "", 1), base)
        for i in range(gen.FACTORS["F2-APOS"][1]):
            _, plain = field_and_value(BY_KEY[("F2-APOS", i, "plain")]["text"])
            _, apos = field_and_value(BY_KEY[("F2-APOS", i, "apostrophe")]["text"])
            self.assertEqual(apos.count("'"), plain.count("'") + 1)
            self.assertEqual(apos.replace("'", ""), plain.replace("'", ""))

    def test_encoding_per_context(self):
        # %23 in form/query contexts, literal # in the JSON context; likewise %27 vs literal '.
        for i in range(gen.FACTORS["F2-HASH"][1]):
            c = BY_KEY[("F2-HASH", i, "hash")]
            if c["stratum"] == "json_text":
                self.assertIn("#", c["text"])
                self.assertNotIn("%23", c["text"])
            else:
                self.assertIn("%23", c["text"])
        for i in range(gen.FACTORS["F2-APOS"][1]):
            c = BY_KEY[("F2-APOS", i, "apostrophe")]
            if c["stratum"] == "place_json":
                self.assertIn("'", c["text"])
                self.assertNotIn("%27", c["text"])
            else:
                self.assertIn("%27", c["text"])

    def test_d1_rendering(self):
        for c in CASES:
            t = c["text"]
            self.assertNotIn("\r", t)
            self.assertFalse(t.endswith("\n"))
            self.assertTrue(t.split("\n", 1)[0].endswith(" HTTP/1.1"))
            line0, headers, body = split(t)
            if body is not None:
                self.assertTrue(headers[-1].startswith("Content-Type: "))


class IsolationTests(unittest.TestCase):
    def test_disjoint_from_v1_texts(self):
        with open(V1_CASES_PATH, encoding="utf-8") as f:
            v1 = {json.loads(l)["text_sha256"] for l in f}
        v2 = {c["text_sha256"] for c in CASES}
        self.assertEqual(v1 & v2, set())

    def test_hosts_disjoint_from_v1(self):
        with open(V1_CASES_PATH, encoding="utf-8") as f:
            v1 = [json.loads(l) for l in f]
        def hosts(cs):
            return {l[6:].split(":")[0] for c in cs for l in c["text"].split("\n")
                    if l.startswith("Host: ")}
        self.assertEqual(hosts(v1) & hosts(CASES), set())

    def test_field_names_disjoint_from_v1_except_address(self):
        # "address" is the independent variable under test in question A, so it is reused on
        # purpose; every other v2 field name is new and all values/templates/hosts are fresh.
        v2_fields = {field_and_value(c["text"])[0] for c in CASES}
        with open(V1_CASES_PATH, encoding="utf-8") as f:
            v1_fields = {field_and_value(json.loads(l)["text"])[0] for l in f}
        v1_fields.discard(None)
        self.assertEqual((v2_fields & v1_fields), {"address"})

    def test_values_not_drawn_from_v1_pools(self):
        import minimal_pair_probe_cases as v1gen
        v1_streets = set(v1gen.POOLS["streets"])
        v2_streets = set(gen.POOLS["streets"])
        self.assertEqual(v1_streets & v2_streets, set())
        self.assertEqual(set(gen.POOLS["hosts"]) & set(v1gen.POOLS["hosts"]), set())


class StatisticsTests(unittest.TestCase):
    def test_mcnemar_exact_known(self):
        self.assertAlmostEqual(probe.mcnemar_exact(0, 0), 1.0)
        self.assertAlmostEqual(probe.mcnemar_exact(18, 0), 2 * 0.5 ** 18, places=9)

    def test_clopper_pearson_bounds(self):
        lo, hi = probe.clopper_pearson(0, 30)
        self.assertEqual(lo, 0.0)
        self.assertGreater(hi, 0.0)
        lo, hi = probe.clopper_pearson(30, 30)
        self.assertEqual(hi, 1.0)

    def test_effect_class_no_observed_testability(self):
        row = {"A_to_B": 0, "B_to_A": 0, "n_valid_pairs": 30, "flip_rate": 0.0,
               "holm_reject": False, "testable_A_to_B": True}
        self.assertEqual(probe.classify_effect(row, None), "NO OBSERVED EFFECT")
        row["testable_A_to_B"] = False  # reference mostly BLOCK -> cannot falsify
        self.assertEqual(probe.classify_effect(row, None), "NO OBSERVED (UNTESTABLE)")

    def test_effect_class_strong_requires_beating_control_and_labels_direction(self):
        row = {"A_to_B": 20, "B_to_A": 0, "n_valid_pairs": 30, "flip_rate": 0.67,
               "holm_reject": True, "testable_A_to_B": True, "mcnemar_exact_p_two_sided": 0.0}
        self.assertEqual(probe.classify_effect(row, {"flip_rate_ci95": [0.04, 0.27]}),
                         "STRONG EFFECT (A→B)")
        self.assertEqual(probe.classify_effect(row, {"flip_rate_ci95": [0.5, 0.9]}),
                         "WEAK/INCONCLUSIVE")
        rev = {**row, "A_to_B": 0, "B_to_A": 20}
        self.assertEqual(probe.classify_effect(rev, {"flip_rate_ci95": [0.04, 0.27]}),
                         "STRONG EFFECT (B→A)")

    def test_moderate_requires_raw_significance(self):
        # 6 vs 1 passes the count/consistency gates but McNemar p ~ 0.125 -> not MODERATE.
        row = {"A_to_B": 6, "B_to_A": 1, "n_valid_pairs": 30, "flip_rate": 7 / 30,
               "holm_reject": False, "testable_A_to_B": True,
               "mcnemar_exact_p_two_sided": probe.mcnemar_exact(6, 1)}
        self.assertEqual(probe.classify_effect(row, {"flip_rate_ci95": [0.04, 0.10]}),
                         "WEAK/INCONCLUSIVE")


def _synthetic(decide, diverge=False):
    cases, comps, repeat = gen.generate()
    uniq = {c["text_sha256"]: c["text"] for c in cases}
    recs = []
    for rep in range(3):
        for k, sha in enumerate(repeat):
            d = decide(uniq[sha])
            raw = f"{d} | ok" + ("" if not (diverge and rep == 1 and k == 0) else " X")
            recs.append(dict(text_sha256=sha, phase="determinism", rep=rep, order=k, raw=raw,
                             decision=d, reason="r", status="ok", prompt_tokens=5,
                             generated_tokens=4, generate_ms_observation_only=1.0))
    for k, sha in enumerate(sorted(uniq)):
        d = decide(uniq[sha])
        recs.append(dict(text_sha256=sha, phase="main", rep=0, order=k, raw=f"{d} | ok",
                         decision=d, reason="r", status="ok", prompt_tokens=5,
                         generated_tokens=4, generate_ms_observation_only=1.0))
    manifest = {"data_role": "test", "comparisons": comps,
                "repeat_control": {"text_sha256": repeat, "runs": 3}}
    return cases, manifest, recs


class AnalysisTests(unittest.TestCase):
    def test_analyze_end_to_end(self):
        res = probe.analyze(*_synthetic(lambda t: "BLOCK" if ("%23" in t or "#" in t) else "ALLOW"))
        self.assertTrue(res["determinism"]["deterministic"])
        self.assertIn("C_hi", res["instability"])
        content = [r for r in res["comparisons"] if r["block"] == "CONTENT"]
        self.assertEqual(len(content), 10)                 # documented Holm family size
        for r in content:
            self.assertEqual(r["holm_family_size"], 10)
            self.assertIn("stratum_verdicts", r)
            self.assertIn("heterogeneous", r)
        byid = {r["comparison_id"]: r for r in res["comparisons"]}
        h = byid["F2-HASH:base->hash"]
        self.assertEqual((h["A_to_B"], h["B_to_A"]), (60, 0))
        self.assertTrue(h["effect_class"].startswith("STRONG EFFECT (A→B)"), h["effect_class"])
        # the `punct` control (= "!") must NOT fire under a '#'-only rule
        self.assertEqual(byid["F2-HASH:base->punct"]["A_to_B"], 0)

    def test_analyze_withheld_on_determinism_failure(self):
        res = probe.analyze(*_synthetic(lambda t: "ALLOW", diverge=True))
        self.assertFalse(res["determinism"]["deterministic"])
        for r in res["comparisons"]:
            self.assertEqual(r["effect_class"], "WITHHELD (determinism failure)")


if __name__ == "__main__":
    unittest.main()
