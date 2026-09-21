"""External Test v1 — Phase D gate (scripts/external/phase_d_gate.py).

Offline, no Docker, no model, no /classify. Drives the pure gate functions with tiny
synthetic corpora and pins the contract required by the Phase D task section J.

    python3 -m unittest tests.test_phase_d_gate -v
"""

import copy
import hashlib
import os
import sys
import unittest

EXT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "scripts", "external")
sys.path.insert(0, EXT)
sys.path.insert(0, os.path.join(EXT, "..", "dataset"))

import phase_d_gate as G          # noqa: E402
from parse_dataset_v4 import canonical_key  # noqa: E402


def sha(t):
    return hashlib.sha256(t.encode()).hexdigest()


def cand(case_id, cell, decision, request_text, *, payload="", placement="query",
         review="auto-accepted", confidence="high", host=G.spec_lib.SHOP_HOST):
    is_block = decision == "BLOCK"
    return {
        "case_id": case_id, "primary_slice": cell, "expected_decision": decision,
        "attack_category": cell if is_block else None,
        "benign_slice": None if is_block else cell,
        "request_text": request_text, "request_sha256": sha(request_text),
        "payload_decoded": payload, "payload_placement": placement,
        "technique": "t", "label_confidence": confidence, "review_status": review,
        "host": host, "ground_truth_basis": "basis",
        "capture": {"flow": cell, "seq": 1, "flow_id": "f"},
    }


def v4_from(texts):
    exact = set(texts)
    canon = [canonical_key(t) for t in texts]
    return exact, canon


def diag_from(pairs):
    return [{"id": i, "text": t, "sha": sha(t), "canon": canonical_key(t)}
            for i, t in pairs]


class TestCollisions(unittest.TestCase):
    def setUp(self):
        self.smoke = G.load_smoke()

    def test_exact_collision_detected(self):
        row = "GET /x HTTP/1.1\nHost: h\nUser-Agent: MobileApp/3.1.0"
        c = cand("sqli-0001", "sqli", "BLOCK", row, payload="x' OR '1'='1")
        col = G.collision_check([c], *v4_from([row]), [], self.smoke)
        self.assertEqual(col["sqli-0001"]["exact"]["source"], "v4")

    def test_canonical_collision_detected(self):
        # V4 row contains a payload (not the smoke one); candidate carries a percent-ENCODED
        # variant of it -> the approved canonical_key collapses both to the same key.
        row = "GET /p?q=x' UNION SELECT password FROM members-- - HTTP/1.1\nHost: h"
        enc = ("GET /products?category=x%27%20UNION%20SELECT%20password%20FROM%20members--%20- "
               "HTTP/1.1\nHost: shop.fwlab.test:9100")
        c = cand("sqli-0002", "sqli", "BLOCK", enc,
                 payload="x%27 UNION SELECT password FROM members-- -")
        col = G.collision_check([c], *v4_from([row]), [], self.smoke)
        self.assertIsNone(col["sqli-0002"]["exact"])
        self.assertEqual(col["sqli-0002"]["canonical"]["source"], "v4")
        self.assertEqual(col["sqli-0002"]["canonical"]["kind"], "payload")

    def test_non_collision_accepted(self):
        row = "GET /unrelated HTTP/1.1\nHost: h"
        c = cand("sqli-0003", "sqli", "BLOCK",
                 "GET /products?category=zzz%27%20AND%20updatexml(9) HTTP/1.1\nHost: shop.fwlab.test:9100",
                 payload="zzz' AND updatexml(9)")
        col = G.collision_check([c], *v4_from([row]), [], self.smoke)
        self.assertIsNone(col["sqli-0003"]["exact"])
        self.assertIsNone(col["sqli-0003"]["canonical"])

    def test_prior_diagnostic_and_smoke_detected(self):
        diag_text = "GET /index.html HTTP/1.1\nHost: localhost:9000\nUser-Agent: curl/8.18.0"
        d = cand("xss-0001", "xss", "BLOCK", diag_text, payload="<script>alert(1)</script>")
        cold = G.collision_check([d], *v4_from(["GET /z HTTP/1.1"]),
                                 diag_from([("HOST-001", diag_text)]), self.smoke)
        self.assertEqual(cold["xss-0001"]["exact"]["source"], "real-http-fp-v1")
        # smoke: a candidate reusing the smoke SQLi payload collides canonically
        s = cand("sqli-0009", "sqli", "BLOCK",
                 "GET /products?category=1%27%20OR%20%271%27%3D%271 HTTP/1.1\nHost: shop.fwlab.test:9100",
                 payload="1' OR '1'='1")
        cols = G.collision_check([s], *v4_from(["GET /z HTTP/1.1"]), [], self.smoke)
        self.assertEqual(cols["sqli-0009"]["canonical"]["source"], "smoke")


class TestInternalDuplicates(unittest.TestCase):
    def test_deterministic_keeper(self):
        txt = "GET /search HTTP/1.1\nHost: shop.fwlab.test:9100"
        a = cand("browser-navigation-0005", "browser-navigation", "ALLOW", txt)
        b = cand("browser-forms-session-0002", "browser-forms-session", "ALLOW", txt)
        res, groups = G.internal_duplicates([a, b])
        # lexicographically smallest case_id is the keeper
        keeper = sorted(["browser-navigation-0005", "browser-forms-session-0002"])[0]
        self.assertTrue(res[keeper]["is_keeper"])
        other = "browser-navigation-0005" if keeper != "browser-navigation-0005" \
            else "browser-forms-session-0002"
        self.assertFalse(res[other]["is_keeper"])
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["kind"], "exact")


class TestNearDuplicate(unittest.TestCase):
    def test_near_dup_warns_but_does_not_exclude(self):
        v4_row = "GET /alpha/beta/gamma/delta/epsilon HTTP/1.1\nHost: shop"
        near = "GET /alpha/beta/gamma/delta/zeta HTTP/1.1\nHost: shop.fwlab.test:9100"
        c = cand("api-query-0001", "api-query", "ALLOW", near)
        v4 = v4_from([v4_row])
        warns = G.near_duplicates([c], v4[1])
        self.assertTrue(any(w["case_id"] == "api-query-0001" for w in warns),
                        "expected a near-duplicate WARN")
        # a WARN must not exclude: with no exact/canonical/internal collision it stays eligible
        R = G.run([c], v4, [], G.load_smoke())
        self.assertTrue(R["elig"]["api-query-0001"]["eligible"])


class TestGroundTruthReview(unittest.TestCase):
    def test_header_only_ssrf_without_scheme_excluded(self):
        txt = ("GET /products?category=office HTTP/1.1\nHost: shop.fwlab.test:9100\n"
               "X-Forwarded-For: 127.0.0.1, 169.254.169.254")
        c = cand("ssrf-0051", "ssrf", "BLOCK", txt, payload="169.254.169.254",
                 placement="header", review="needs-review", confidence="medium")
        p1 = G.review_pass1([c])
        p2 = G.review_pass2([c], p1)
        self.assertEqual(p2["ssrf-0051"]["decision"], "EXCLUDE")

    def test_scheme_bearing_ssrf_accepted(self):
        txt = ("GET /products?category=http%3A%2F%2Fcontrol-plane%3A8000%2Fclassify HTTP/1.1\n"
               "Host: shop.fwlab.test:9100")
        c = cand("ssrf-0001", "ssrf", "BLOCK", txt, payload="http://control-plane:8000/classify",
                 placement="query")
        p1 = G.review_pass1([c])
        # not flagged (high confidence, characteristic, payload present) -> no pass2 exclusion
        self.assertNotIn("ssrf-0001", G.review_pass2([c], p1))


class TestEvidencePreserved(unittest.TestCase):
    def test_run_does_not_mutate_candidates(self):
        c = cand("sqli-0001", "sqli", "BLOCK",
                 "GET /products?category=x%27%20UNION%20SELECT%201 HTTP/1.1\nHost: shop.fwlab.test:9100",
                 payload="x' UNION SELECT 1")
        before = copy.deepcopy(c)
        G.run([c], v4_from(["GET /z HTTP/1.1"]), [], G.load_smoke())
        self.assertEqual(c["request_text"], before["request_text"])
        self.assertEqual(c["request_sha256"], before["request_sha256"])

    def test_eligibility_covers_every_candidate_no_deletion(self):
        dup = "GET /cart HTTP/1.1\nHost: shop.fwlab.test:9100"
        cands = [cand("browser-forms-session-0001", "browser-forms-session", "ALLOW", dup),
                 cand("browser-forms-session-0002", "browser-forms-session", "ALLOW", dup),
                 cand("api-json-0001", "api-json", "ALLOW",
                      "GET /api/products HTTP/1.1\nHost: api.fwlab.test:9100")]
        R = G.run(cands, v4_from(["GET /z HTTP/1.1"]), [], G.load_smoke())
        # every candidate still represented; excluded ones are marked, not removed
        self.assertEqual(len(R["elig"]), 3)
        excluded = [cid for cid, e in R["elig"].items() if not e["eligible"]]
        self.assertEqual(len(excluded), 1)
        self.assertEqual(R["elig"][excluded[0]]["primary_exclusion"], "internal_duplicate")


class TestRealDatasetDeficitReporting(unittest.TestCase):
    """Guard the STOP condition: a cell below 40 eligible is reported as a deficit."""

    def test_deficit_detected_when_cell_below_40(self):
        # 39 identical requests in one cell collapse to 1 eligible -> deficit
        txt = "GET /cart HTTP/1.1\nHost: shop.fwlab.test:9100"
        cands = [cand(f"browser-forms-session-{i:04d}", "browser-forms-session", "ALLOW", txt)
                 for i in range(1, 40)]
        R = G.run(cands, v4_from(["GET /z HTTP/1.1"]), [], G.load_smoke())
        self.assertIn("browser-forms-session", R["deficits"])
        self.assertEqual(R["cells"]["browser-forms-session"]["final_eligible"], 1)


if __name__ == "__main__":
    unittest.main()
