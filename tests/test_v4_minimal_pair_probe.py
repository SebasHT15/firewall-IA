"""Tests for the V4 minimal-pair probe (v5-minimal-pairs-v1).

Standard library only; no model is loaded. They cover what could silently invalidate the
probe: determinism of the cases, independence of bases, the one-dimension rule for every
comparison, D1 rendering, lexical purity of the homonym and free-text factors, the forbidden
sources, and the statistics / pre-registered classification.

    python3 -m unittest tests.test_v4_minimal_pair_probe -v
"""

import json
import os
import re
import sys
import unittest
from urllib.parse import unquote

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts", "evaluation"))

import minimal_pair_probe_cases as gen  # noqa: E402
import run_v4_minimal_pair_probe as probe  # noqa: E402

CASES, COMPARISONS, REPEAT = gen.generate()
BY_KEY = {(c["factor"], c["base"], c["level"]): c for c in CASES}
HOMONYMS = [h for _, h, _ in gen.POOLS["homonyms"]]


def split(text):
    head, _, body = text.partition("\n\n")
    lines = head.split("\n")
    return lines[0], lines[1:], (body if "\n\n" in text else None)


def words(text):
    return set(re.findall(r"[a-z0-9]+", unquote(text).lower()))


class GeneratorTests(unittest.TestCase):
    def test_deterministic(self):
        again, comps, rep = gen.generate()
        self.assertEqual([c["text"] for c in again], [c["text"] for c in CASES])
        self.assertEqual(rep, REPEAT)

    def test_bases_are_distinct_across_all_factors(self):
        texts = [c["text"] for c in CASES]
        self.assertEqual(len(texts), len(set(texts)))

    def test_at_least_30_distinct_factor_values(self):
        # Review BLOCKER 2: distinct texts are not enough; the manipulated value must vary too.
        for fid, ref in (("F-APOS", "plain"), ("F-PUNCT", "comma_period"), ("F-FREETEXT", "keyword"),
                         ("F-FREETEXT", "sentence")):
            vals = {unquote(BY_KEY[(fid, i, ref)]["text"]).rsplit("=", 1)[-1].split(" HTTP/1.1")[0]
                    for i in range(gen.FACTORS[fid][1])}
            self.assertGreaterEqual(len(vals), 30, (fid, ref))

    def test_every_homonym_appears_in_both_carriers(self):
        carriers = {}
        for i in range(gen.FACTORS["F-WORD"][1]):
            hom = gen.POOLS["homonyms"][i % len(gen.POOLS["homonyms"])][1]
            method = BY_KEY[("F-WORD", i, "homonym")]["text"].split(" ", 1)[0]
            carriers.setdefault(hom, set()).add("GET" if method == "GET" else "body")
        self.assertTrue(all(v == {"GET", "body"} for v in carriers.values()), carriers)

    def test_at_least_30_bases_per_factor(self):
        for fid, (_, n, _, _, _) in gen.FACTORS.items():
            self.assertGreaterEqual(n, 30, fid)

    def test_d1_rendering(self):
        for c in CASES:
            t = c["text"]
            self.assertNotIn("\r", t)
            self.assertFalse(t.endswith("\n"))
            line, headers, body = split(t)
            self.assertRegex(line, r"^(GET|POST|PUT|PATCH) /\S* HTTP/1\.1$")
            self.assertTrue(headers[0].startswith("Host: "))
            for h in headers:
                self.assertRegex(h, r"^[A-Za-z-]+: \S")
            if body is not None:
                self.assertTrue(headers[-1].startswith("Content-Type: "), c["case_id"])
            else:
                self.assertNotIn("Content-Type", t)
            self.assertNotIn(" ", line.split(" ")[1])

    def test_content_length_only_where_declared_and_correct(self):
        for c in CASES:
            has = "\nContent-Length: " in c["text"]
            declared = (c["factor"] == "F-CL" and c["level"] == "present") or c["level"].endswith("_cl")
            self.assertEqual(has, declared, c["case_id"])
            if has:
                _, headers, body = split(c["text"])
                cl = int(next(h for h in headers if h.startswith("Content-Length")).split(": ")[1])
                self.assertEqual(cl, len(body.encode("utf-8")))

    def test_every_comparison_changes_exactly_one_locus(self):
        for comp in COMPARISONS:
            fid = comp["factor"]
            for i in range(comp["n_bases"]):
                a = BY_KEY[(fid, i, comp["reference"])]["text"]
                b = BY_KEY[(fid, i, comp["level"])]["text"]
                self.assertNotEqual(a, b)
                la, ha, ba = split(a)
                lb, hb, bb = split(b)
                if comp["reference"].endswith("_cl"):
                    # serve-like twins: content changes and Content-Length follows the body
                    self.assertEqual(la, lb)
                    self.assertNotEqual(ba, bb)
                    diff = set(ha) ^ set(hb)
                    self.assertTrue(all(h.startswith("Content-Length: ") for h in diff), comp["comparison_id"])
                elif comp["block"] == "ENVELOPE" or fid == "CONTROL-ENV" or fid == "F-CTB":
                    self.assertEqual((la, ba), (lb, bb), comp["comparison_id"])
                    sa, sb = set(ha), set(hb)
                    diff = (sa - sb) | (sb - sa)
                    # one header added, or one header value changed
                    self.assertIn(len(diff), (1, 2), comp["comparison_id"])
                    self.assertEqual(len({h.split(":")[0] for h in diff}), 1, comp["comparison_id"])
                else:
                    self.assertEqual(ha, hb, comp["comparison_id"])
                    self.assertTrue((la != lb) ^ (ba != bb), comp["comparison_id"])

    def test_single_character_factors_differ_by_one_decoded_character(self):
        single = {"F-PWD", "F-APOS", "F-ADDR", "F-PUNCT"}
        for comp in COMPARISONS:
            # F-ADDR comma -> hash is a swap (two edits), checked below
            if comp["factor"] not in single or comp["reference"] == "comma":
                continue
            for i in range(comp["n_bases"]):
                a = unquote(BY_KEY[(comp["factor"], i, comp["reference"])]["text"])
                b = unquote(BY_KEY[(comp["factor"], i, comp["level"])]["text"])
                if len(a) == len(b):
                    self.assertEqual(sum(x != y for x, y in zip(a, b)), 1, comp["comparison_id"])
                else:   # insertion of one character
                    self.assertEqual(len(b) - len(a), 1)

    def test_homonym_purity(self):
        for i in range(gen.FACTORS["F-WORD"][1]):
            neutral = words(BY_KEY[("F-WORD", i, "neutral")]["text"].split("\n\n")[-1]
                            if "\n\n" in BY_KEY[("F-WORD", i, "neutral")]["text"]
                            else BY_KEY[("F-WORD", i, "neutral")]["text"].split("\n")[0])
            target = gen.POOLS["homonyms"][i % len(gen.POOLS["homonyms"])][1]
            hom_text = BY_KEY[("F-WORD", i, "homonym")]["text"]
            hom = words(hom_text.split("\n\n")[-1] if "\n\n" in hom_text else hom_text.split("\n")[0])
            self.assertFalse(neutral & set(HOMONYMS), (i, neutral & set(HOMONYMS)))
            self.assertEqual(hom & set(HOMONYMS), {target}, i)

    def test_other_content_has_no_homonym(self):
        for c in CASES:
            if c["factor"] == "F-WORD":
                continue
            line, _, body = split(c["text"])
            content = line + " " + (body or "")
            self.assertFalse(words(content) & set(HOMONYMS), (c["case_id"], words(content) & set(HOMONYMS)))

    def test_forbidden_sources_absent(self):
        lab = ("fwlab", "/login", "/checkout", "/search", "/products", "/static", "/api/orders",
               "/api/me", "/cart", "/profile")
        for c in CASES:
            line = c["text"].split("\n")[0]
            self.assertNotIn("fwlab", c["text"])
            for route in lab[1:]:
                self.assertFalse(re.search(re.escape(route) + r"(?![a-z])", line), (c["case_id"], route))

    def test_no_port_from_previous_diagnostics(self):
        self.assertFalse(any(":9100" in c["text"] for c in CASES))

    def test_te_chunked_level_has_no_content_length(self):
        for i in range(gen.FACTORS["F-CL"][1]):
            t = BY_KEY[("F-CL", i, "te_chunked")]["text"]
            self.assertIn("\nTransfer-Encoding: chunked\nContent-Type: ", t)
            self.assertNotIn("Content-Length", t)

    def test_envelope_hosts_not_from_v4_generator(self):
        v4_hosts = {"api.example.com", "app.example.com", "www.example.com", "portal.example.com"}
        self.assertFalse(set(gen.POOLS["hosts"]) & v4_hosts)

    def test_repeat_subset_is_about_ten_percent(self):
        n_unique = len({c["text_sha256"] for c in CASES})
        self.assertAlmostEqual(len(REPEAT) / n_unique, gen.REPEAT_FRACTION, delta=0.01)


class StatisticsTests(unittest.TestCase):
    def test_mcnemar_exact(self):
        self.assertEqual(probe.mcnemar_exact(0, 0), 1.0)
        self.assertAlmostEqual(probe.mcnemar_exact(8, 0), 2 * 0.5 ** 8)
        self.assertEqual(probe.mcnemar_exact(3, 3), 1.0)
        self.assertAlmostEqual(probe.mcnemar_exact(1, 9), probe.mcnemar_exact(9, 1))

    def test_holm(self):
        adj, rej = probe.holm([0.01, 0.04, 0.03])
        self.assertEqual([round(a, 6) for a in adj], [0.03, 0.06, 0.06])
        self.assertEqual(rej, [True, False, False])

    def test_clopper_pearson(self):
        lo, hi = probe.clopper_pearson(0, 30)
        self.assertEqual(lo, 0.0)
        self.assertAlmostEqual(hi, 1 - 0.025 ** (1 / 30), places=6)
        lo, hi = probe.clopper_pearson(30, 30)
        self.assertEqual(hi, 1.0)
        self.assertAlmostEqual(lo, 0.025 ** (1 / 30), places=6)


def row(ab, ba, aa, bb, holm_reject):
    r = probe.paired_table([("ALLOW", "BLOCK")] * ab + [("BLOCK", "ALLOW")] * ba
                           + [("ALLOW", "ALLOW")] * aa + [("BLOCK", "BLOCK")] * bb)
    r["holm_reject"] = holm_reject
    return r


class ClassificationTests(unittest.TestCase):
    CONTROL = row(1, 0, 35, 4, False)       # flip rate 0.025, CP upper ~0.13

    def test_classes(self):
        self.assertEqual(probe.classify_effect(row(0, 0, 25, 5, False), self.CONTROL), "NO OBSERVED EFFECT")
        self.assertEqual(probe.classify_effect(row(12, 0, 15, 3, True), self.CONTROL), "STRONG EFFECT")
        self.assertEqual(probe.classify_effect(row(7, 0, 21, 2, False), self.CONTROL), "MODERATE EFFECT")
        self.assertEqual(probe.classify_effect(row(2, 1, 25, 2, False), self.CONTROL), "WEAK/INCONCLUSIVE")

    def test_moderate_needs_six_dominant_flips(self):
        # Review BLOCKER 1: 3-5 consistent flips are WEAK/INCONCLUSIVE.
        self.assertEqual(probe.classify_effect(row(5, 0, 23, 2, False), self.CONTROL), "WEAK/INCONCLUSIVE")

    def test_matched_controls(self):
        env = {"block": "ENVELOPE", "factor": "F-PORT"}
        self.assertEqual(probe.matched_control(env), probe.ENVELOPE_CONTROL)
        self.assertEqual(probe.matched_control({"block": "CONTENT", "factor": "F-CTB"}), probe.ENVELOPE_CONTROL)
        self.assertEqual(probe.matched_control({"block": "CONTENT", "factor": "F-APOS"}), probe.CONTENT_CONTROL)

    def test_strong_requires_direction_consistency(self):
        self.assertNotEqual(probe.classify_effect(row(8, 6, 10, 6, True), self.CONTROL), "STRONG EFFECT")

    def test_strong_requires_exceeding_instability_control(self):
        noisy = row(8, 4, 24, 4, False)    # flip rate 0.30, upper CI well above 0.2
        self.assertNotEqual(probe.classify_effect(row(7, 0, 20, 3, True), noisy), "STRONG EFFECT")

    def test_invalid_pairs_excluded(self):
        r = probe.paired_table([("ALLOW", None), (None, "BLOCK"), ("ALLOW", "BLOCK")])
        self.assertEqual((r["n_invalid_pairs"], r["n_valid_pairs"], r["A_to_B"]), (2, 1, 1))

    def test_low_sensitivity_flag(self):
        r = row(0, 2, 3, 25, False)
        self.assertTrue(any(f.startswith("LOW_SENSITIVITY_A_TO_B") for f in r["flags"]))


class AnalyzeTests(unittest.TestCase):
    def test_end_to_end_on_synthetic_records(self):
        manifest = {"comparisons": COMPARISONS, "data_role": gen.DATA_ROLE,
                    "repeat_control": {"text_sha256": REPEAT, "runs": 3}}
        recs = []
        # Synthetic V4: BLOCK iff the text has a Content-Length header.
        for sha, text in {c["text_sha256"]: c["text"] for c in CASES}.items():
            d = "BLOCK" if "Content-Length" in text else "ALLOW"
            recs.append({"text_sha256": sha, "phase": "main", "rep": 0, "raw": d + " | r",
                         "decision": d, "reason": "r", "status": "ok"})
            if sha in REPEAT:
                for rep in range(3):
                    recs.append({"text_sha256": sha, "phase": "determinism", "rep": rep,
                                 "raw": d + " | r", "decision": d, "reason": "r", "status": "ok"})
        res = probe.analyze(CASES, manifest, recs)
        self.assertTrue(res["determinism"]["deterministic"])
        by = {r["comparison_id"]: r for r in res["comparisons"]}
        cl = by["F-CL:absent->present"]
        self.assertEqual((cl["A_to_B"], cl["B_to_A"]), (40, 0))
        self.assertEqual(cl["effect_class"], "STRONG EFFECT")
        self.assertEqual(cl["holm_family"], "ENVELOPE")
        self.assertIsNone(by["CONTROL-COV:user_a->user_b"]["holm_family"])
        self.assertEqual(by["F-NFIELDS:n1_cl->n2_cl"]["effect_class"], "NO OBSERVED EFFECT")
        self.assertFalse(res["instability"]["material"])
        self.assertEqual(by["F-APOS:plain->apostrophe"]["effect_class"], "NO OBSERVED EFFECT")
        self.assertEqual(set(cl["strata"]), {"form1", "form2", "json1", "json3"})

    def test_determinism_failure_withholds_classes(self):
        manifest = {"comparisons": COMPARISONS, "data_role": gen.DATA_ROLE,
                    "repeat_control": {"text_sha256": REPEAT, "runs": 3}}
        recs = [{"text_sha256": c["text_sha256"], "phase": "main", "rep": 0, "raw": "ALLOW | r",
                 "decision": "ALLOW", "reason": "r", "status": "ok"} for c in CASES]
        recs += [{"text_sha256": REPEAT[0], "phase": "determinism", "rep": k,
                  "raw": f"ALLOW | r{k}", "decision": "ALLOW", "reason": f"r{k}", "status": "ok"}
                 for k in range(3)]
        res = probe.analyze(CASES, manifest, recs)
        self.assertFalse(res["determinism"]["deterministic"])
        self.assertTrue(all(r["effect_class"].startswith("WITHHELD") for r in res["comparisons"]))


if __name__ == "__main__":
    unittest.main()
