"""External Test v1 — Phase F runner (external_v1_run.py), OFFLINE logic only.

No Docker, no model, no /classify. Pins the frozen-integrity gate, the predeclared
consistency subset, the three-level (L1/L2/L3) outcome derivation kept separate, determinism
flagging, data-plane log parsing, and the L1 scoring wiring (with an injected stub scorer so
torch is not required here).

    python3 -m unittest tests.test_external_v1_run -v
"""

import os
import sys
import unittest

EXT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "scripts", "external")
sys.path.insert(0, EXT)
import external_v1_run as R   # noqa: E402


def case(cid, cell, gt, sha="abc"):
    return {"case_id": cid, "primary_cell": cell, "expected_decision": gt,
            "request_sha256": sha, "request_text": "GET / HTTP/1.1"}


class TestFrozenIntegrityGate(unittest.TestCase):
    def test_real_frozen_set_passes(self):
        rows, m, ihash, problems = R.verify_frozen()
        self.assertEqual(problems, [])
        self.assertEqual(len(rows), 400)
        self.assertEqual(ihash, R.FROZEN_INTEGRITY_HASH)

    def test_tampered_case_is_detected(self):
        import tempfile, json, hashlib
        rows = R.load_jsonl(R.FROZEN_CASES)
        rows[0]["request_text"] += " TAMPER"      # sha no longer matches
        tmp = tempfile.mkdtemp()
        cp = os.path.join(tmp, "cases.jsonl")
        with open(cp, "w") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        _, _, _, problems = R.verify_frozen(cases_path=cp)
        self.assertTrue(any("request_sha256 does not recompute" in p for p in problems))


class TestConsistencySubset(unittest.TestCase):
    def setUp(self):
        self.rows, *_ = R.verify_frozen()

    def test_100_balanced_deterministic_seeded(self):
        a = R.consistency_subset(self.rows)
        self.assertEqual(len(a), 100)
        from collections import Counter
        per = Counter(c["primary_cell"] for c in a)
        self.assertTrue(all(per[c] == 10 for c in R.CELLS))

    def test_order_independent_and_seed_sensitive(self):
        a = {c["case_id"] for c in R.consistency_subset(self.rows)}
        b = {c["case_id"] for c in R.consistency_subset(list(reversed(self.rows)))}
        self.assertEqual(a, b)
        c = {x["case_id"] for x in R.consistency_subset(self.rows, seed="another")}
        self.assertNotEqual(a, c)


class TestThreeLevelsKeptSeparate(unittest.TestCase):
    def test_l1_outcomes(self):
        self.assertEqual(R.l1_outcome("BLOCK", "BLOCK", "ok"), "TP")
        self.assertEqual(R.l1_outcome("ALLOW", "ALLOW", "ok"), "TN")
        self.assertEqual(R.l1_outcome("ALLOW", "BLOCK", "ok"), "FP")
        self.assertEqual(R.l1_outcome("BLOCK", "ALLOW", "ok"), "FN")
        self.assertEqual(R.l1_outcome("BLOCK", None, "invalid"), "invalid")

    def test_l2_contract(self):
        self.assertEqual(R.l2_conformant("ALLOW", "ok", 200, True)[0], True)
        self.assertEqual(R.l2_conformant("ALLOW", "ok", 403, False)[0], False)   # blocked an ALLOW
        self.assertEqual(R.l2_conformant("BLOCK", "ok", 403, False)[0], True)
        self.assertEqual(R.l2_conformant("BLOCK", "ok", 200, True)[0], False)    # forwarded a BLOCK
        self.assertEqual(R.l2_conformant(None, "invalid", 503, False)[0], True)
        self.assertEqual(R.l2_conformant(None, "invalid", 200, True)[0], False)

    def test_l3_outcomes(self):
        self.assertEqual(R.l3_outcome("ALLOW", True), "benign_delivered")
        self.assertEqual(R.l3_outcome("ALLOW", False), "benign_broken")
        self.assertEqual(R.l3_outcome("BLOCK", False), "attack_stopped")
        self.assertEqual(R.l3_outcome("BLOCK", True), "attack_delivered")

    def test_protocol_interpretation_example(self):
        # GT=BLOCK, V4=ALLOW, gateway forwards, destination receives:
        #   L1 = FN, L2 = conformant (correctly enforced ALLOW), L3 = attack_delivered
        rec = R.build_record(case("sqli-x", "sqli", "BLOCK"), 1, "gateway",
                             decision="ALLOW", reason="looks benign", status="ok",
                             http_status=200, destination_receipt=True,
                             fail_closed_cause=None, model_latency_ms=231.0, sent_sha256="abc")
        self.assertEqual(rec["l1_outcome"], "FN")
        self.assertTrue(rec["l2_conformant"])
        self.assertEqual(rec["l3_outcome"], "attack_delivered")
        self.assertTrue(rec["text_matches_registered"])


class TestDeterminism(unittest.TestCase):
    def test_flags_differing_repetitions_no_majority_vote(self):
        recs = [
            R.build_record(case("c1", "sqli", "BLOCK"), 1, "gateway", "BLOCK", "", "ok", 403, False, None, 1.0, "abc"),
            R.build_record(case("c1", "sqli", "BLOCK"), 2, "gateway", "ALLOW", "", "ok", 200, True, None, 1.0, "abc"),
            R.build_record(case("c1", "sqli", "BLOCK"), 3, "gateway", "BLOCK", "", "ok", 403, False, None, 1.0, "abc"),
            R.build_record(case("c2", "xss", "BLOCK"), 1, "gateway", "BLOCK", "", "ok", 403, False, None, 1.0, "abc"),
            R.build_record(case("c2", "xss", "BLOCK"), 2, "gateway", "BLOCK", "", "ok", 403, False, None, 1.0, "abc"),
        ]
        flagged = R.determinism_report(recs, "gateway")
        self.assertEqual([f["case_id"] for f in flagged], ["c1"])


class TestDataplaneLogParsing(unittest.TestCase):
    def test_parses_allow_block_failclosed(self):
        log = (
            "[abcd1234] received GET shop.fwlab.test:9100/products (body 0 bytes)\n"
            "[abcd1234] ALLOW GET shop.fwlab.test:9100/products reason='Normal request' (classifier 231 ms)\n"
            "[ef567890] BLOCK GET shop.fwlab.test:9100/search reason='SQL injection' (classifier 240 ms)\n"
            "[11112222] BLOCK (fail-closed) POST api.fwlab.test:9100/api/orders cause=classifier timeout (after 5000 ms)\n"
        )
        out = R.parse_dataplane_log(log)
        self.assertEqual([o["decision"] for o in out], ["ALLOW", "BLOCK", None])
        self.assertEqual([o["status"] for o in out], ["ok", "ok", "invalid"])
        self.assertEqual(out[2]["fail_closed_cause"], "classifier timeout")
        self.assertAlmostEqual(out[0]["model_latency_ms"], 231.0)


class TestScoringWiring(unittest.TestCase):
    def test_uses_rep1_excludes_nondeterministic_and_calls_scorer(self):
        captured = {}

        def stub(records):
            # record what the scorer was fed and return a trivial summary
            captured.setdefault("calls", []).append([r["predicted"] for r in records])
            from collections import Counter
            c = Counter((r["expected"], r["predicted"]) for r in records)
            return {"TP": c[("BLOCK", "BLOCK")], "FN": c[("BLOCK", "ALLOW")],
                    "FP": c[("ALLOW", "BLOCK")], "TN": c[("ALLOW", "ALLOW")], "n": len(records)}

        recs = [
            # deterministic TP
            R.build_record(case("b1", "sqli", "BLOCK"), 1, "gateway", "BLOCK", "", "ok", 403, False, None, 1.0, "abc"),
            R.build_record(case("b1", "sqli", "BLOCK"), 2, "gateway", "BLOCK", "", "ok", 403, False, None, 1.0, "abc"),
            # nondeterministic -> excluded from headline
            R.build_record(case("b2", "sqli", "BLOCK"), 1, "gateway", "BLOCK", "", "ok", 403, False, None, 1.0, "abc"),
            R.build_record(case("b2", "sqli", "BLOCK"), 2, "gateway", "ALLOW", "", "ok", 200, True, None, 1.0, "abc"),
            # deterministic TN
            R.build_record(case("a1", "api-json", "ALLOW"), 1, "gateway", "ALLOW", "", "ok", 200, True, None, 1.0, "abc"),
        ]
        out = R.score_l1(recs, score_fn=stub)
        self.assertEqual(out["headline_n"], 2)               # b1 + a1 (b2 excluded)
        self.assertIn("b2", out["excluded_nondeterministic"])
        self.assertEqual(out["overall"]["TP"], 1)
        self.assertEqual(out["overall"]["TN"], 1)


class TestCLIRegistration(unittest.TestCase):
    def test_all_subcommands_registered(self):
        import argparse
        # main() builds the parser; parse a --help-like path per subcommand without executing
        for cmd in ("verify", "subset", "gateway", "direct", "assemble", "score"):
            with self.subTest(cmd=cmd):
                try:
                    R.main([cmd, "--help"])
                except SystemExit as e:   # --help exits 0 after printing usage
                    self.assertEqual(e.code, 0)


class _FakeResp:
    def __init__(self, body):
        self.status_code = 200
        self.headers = {"content-type": "application/json"}
        self._b = body

    def json(self):
        return self._b


class _FakeClient:
    def __init__(self, *a, **k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def post(self, url, json=None):
        # decision derived from the text so tests can assert; NEVER a real network call
        text = json["request"]
        dec = "BLOCK" if ("script" in text or "union" in text.lower() or "../" in text) else "ALLOW"
        return _FakeResp({"status": "ok", "decision": dec, "reason": "r", "model_latency_ms": 5.0})


class TestLiveSubcommandsMocked(unittest.TestCase):
    """Exercises the LIVE subcommands with mocks — NO socket, NO /classify, NO control-plane."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self._run_dir = R.RUN_DIR
        R.RUN_DIR = self.tmp
        os.makedirs(os.path.join(self.tmp, "raw"), exist_ok=True)
        # predeclared subset must exist for `direct`
        R.cmd_subset  # ensure importable
        rows, *_ = R.verify_frozen()
        self.frozen_ids = {r["case_id"] for r in rows}
        sub = R.consistency_subset(rows)
        import json as _j
        with open(os.path.join(self.tmp, "consistency_subset.json"), "w") as f:
            _j.dump({"case_ids_by_cell": {cell: sorted(c["case_id"] for c in sub
                                                       if c["primary_cell"] == cell)
                                          for cell in R.CELLS}}, f)

    def tearDown(self):
        R.RUN_DIR = self._run_dir

    def _args(self, **kw):
        import types
        base = dict(gateway_host="h", gateway_port=1, repetitions=3, timeout=1.0, delay_ms=0.0,
                    receipt_log=os.path.join(self.tmp, "noexist.jsonl"), force=False,
                    classifier_url="http://x/classify", subset=None)
        base.update(kw)
        return types.SimpleNamespace(**base)

    def test_gateway_cardinality_and_no_reserve_substitution(self):
        import replay
        orig = getattr(replay, "replay_one", None)
        replay.replay_one = lambda h, p, t, to: {"http_status": 200, "response_bytes": 5,
                                                 "elapsed_ms": 1.0}
        try:
            R.cmd_gateway(self._args())
        finally:
            if orig:
                replay.replay_one = orig
        rows = R.load_jsonl(os.path.join(self.tmp, "raw", "gateway_raw.jsonl"))
        self.assertEqual(len(rows), 400 * 3)                       # 400 x 3 = 1200
        self.assertEqual({r["case_id"] for r in rows}, self.frozen_ids)   # never a reserve
        for r in rows[:5]:
            self.assertEqual(r["sent_sha256"], r["registered_sha256"])    # byte-exact

    def test_gateway_refuses_overwrite(self):
        import replay
        replay.replay_one = lambda h, p, t, to: {"http_status": 200, "response_bytes": 5,
                                                 "elapsed_ms": 1.0}
        R.cmd_gateway(self._args())
        with self.assertRaises(SystemExit):
            R.cmd_gateway(self._args())      # D32: refuse to overwrite existing results

    def test_gateway_hardfails_on_bad_integrity(self):
        orig = R.verify_frozen
        R.verify_frozen = lambda **k: ([], {}, "x", ["tampered"])
        try:
            with self.assertRaises(SystemExit):
                R.cmd_gateway(self._args())
        finally:
            R.verify_frozen = orig

    def test_direct_cardinality(self):
        import httpx
        orig = httpx.Client
        httpx.Client = _FakeClient
        try:
            R.cmd_direct(self._args())
        finally:
            httpx.Client = orig
        rows = R.load_jsonl(os.path.join(self.tmp, "raw", "direct_raw.jsonl"))
        self.assertEqual(len(rows), 100 * 3)                       # 100 x 3 = 300
        self.assertTrue({r["case_id"] for r in rows}.issubset(self.frozen_ids))


class TestAssembleCorrelation(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self._run_dir = R.RUN_DIR
        R.RUN_DIR = self.tmp
        rows, *_ = R.verify_frozen()
        self.block = next(r for r in rows if r["expected_decision"] == "BLOCK")
        self.allow = next(r for r in rows if r["expected_decision"] == "ALLOW")

    def tearDown(self):
        R.RUN_DIR = self._run_dir

    def test_l1_l2_l3_kept_separate_with_example(self):
        import json as _j
        import types
        # BLOCK case: V4 said ALLOW, gateway forwarded, receipt present -> FN / conformant / delivered
        gw = [
            {"case_id": self.block["case_id"], "primary_cell": self.block["primary_cell"],
             "ground_truth": "BLOCK", "repetition": 1, "registered_sha256": self.block["request_sha256"],
             "sent_sha256": self.block["request_sha256"], "method": "GET", "route": "/x",
             "http_status": 200, "destination_receipt": True, "error": None},
            {"case_id": self.allow["case_id"], "primary_cell": self.allow["primary_cell"],
             "ground_truth": "ALLOW", "repetition": 1, "registered_sha256": self.allow["request_sha256"],
             "sent_sha256": self.allow["request_sha256"], "method": "GET", "route": "/y",
             "http_status": 200, "destination_receipt": True, "error": None},
        ]
        gwp = os.path.join(self.tmp, "gw.jsonl")
        with open(gwp, "w") as f:
            for r in gw:
                f.write(_j.dumps(r) + "\n")
        # aligned data-plane log: line 1 ALLOW (the misclassified BLOCK case), line 2 ALLOW
        dp = (f"] ALLOW GET x reason='benign' (classifier 231 ms)\n"
              f"] ALLOW GET y reason='benign' (classifier 12 ms)\n")
        dpp = os.path.join(self.tmp, "dp.log")
        open(dpp, "w").write(dp)
        args = types.SimpleNamespace(gateway_raw=gwp, direct_raw=os.path.join(self.tmp, "none"),
                                     dataplane_log=dpp)
        R.cmd_assemble(args)
        res = R.load_jsonl(os.path.join(self.tmp, "results.jsonl"))
        block_res = next(r for r in res if r["case_id"] == self.block["case_id"])
        self.assertEqual(block_res["decision"], "ALLOW")
        self.assertEqual(block_res["l1_outcome"], "FN")
        self.assertTrue(block_res["l2_conformant"])          # correctly enforced ALLOW
        self.assertEqual(block_res["l3_outcome"], "attack_delivered")
        self.assertEqual(block_res["decision_source"], "data-plane-log")


if __name__ == "__main__":
    unittest.main()
