"""External Test v1 — fidelity-gate decision logic (scripts/external/fidelity_check.py).

Pure standard library. No Docker, no proxy, no model.

WHY THIS FILE EXISTS
    The Chromium gate reported, in one run:

        COUNT MISMATCH: 22 captured vs 12 replayed.
        Replay must re-emit every captured request exactly once.
        ...
        RESULT: PASS

    A gate that prints a failure condition and then passes cannot be trusted with the
    decision it exists to make. Two distinct contracts had been collapsed into one:

      FULL REPLAY   every captured request must be replayed; a count mismatch is a FAILURE
      SUBSET        a predeclared N were replayed; the rest were never meant to be, so
                    their absence is normal, but N must be exact on BOTH sides

    These tests pin both contracts so they cannot be merged again.
"""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "scripts", "external"))

import fidelity_check  # noqa: E402

HOST = "shop.fwlab.test"


def rec(seq, path, host=HOST, text=None):
    text = text or (f"GET {path} HTTP/1.1\nHost: {host}\nUser-Agent: HeadlessChrome/131")
    import hashlib
    return {"seq": seq, "host": host, "method": "GET", "path": path,
            "request_text": text,
            "request_sha256": hashlib.sha256(text.encode()).hexdigest()}


class GateTestCase(unittest.TestCase):
    def run_gate(self, captured, replayed, **flags):
        """Write one capture file holding both passes, then run the checker on it."""
        tmp = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False,
                                          encoding="utf-8")
        self.addCleanup(os.unlink, tmp.name)
        with tmp:
            for r in list(captured) + list(replayed):
                tmp.write(json.dumps(r) + "\n")
        argv = ["--capture", tmp.name, "--split-after", str(len(captured))]
        for k, v in flags.items():
            argv += [f"--{k.replace('_', '-')}", str(v)]
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = fidelity_check.main(argv)
        return code, buf.getvalue()


class TestFullReplayContract(GateTestCase):
    """Without --expect, every captured request must be replayed."""

    def test_full_replay_all_matching_passes(self):
        cap = [rec(i, f"/p{i}") for i in range(1, 6)]
        rep = [rec(i + 5, f"/p{i}") for i in range(1, 6)]
        code, out = self.run_gate(cap, rep)
        self.assertEqual(code, 0, out)
        self.assertIn("5/5", out)
        self.assertIn("RESULT: PASS", out)

    def test_full_replay_count_mismatch_still_fails(self):
        # The behaviour that must NOT be weakened by subset support.
        cap = [rec(i, f"/p{i}") for i in range(1, 6)]
        rep = [rec(i + 5, f"/p{i}") for i in range(1, 4)]      # only 3 of 5
        code, out = self.run_gate(cap, rep)
        self.assertEqual(code, 1, out)
        self.assertIn("COUNT MISMATCH", out)
        self.assertIn("RESULT: FAIL", out)

    def test_full_replay_byte_difference_fails(self):
        cap = [rec(i, f"/p{i}") for i in range(1, 4)]
        rep = [rec(4, "/p1"), rec(5, "/p2"), rec(6, "/p3-changed")]
        code, out = self.run_gate(cap, rep)
        self.assertEqual(code, 1, out)
        self.assertIn("MISMATCH", out)
        self.assertIn("RESULT: FAIL", out)


class TestDeclaredSubsetContract(GateTestCase):
    """With --expect N, exactly N must be selected on both sides and all must match.

    This reproduces the Chromium gate: 22 captured, a predeclared 12 replayed.
    """

    def captured_22(self):
        return [rec(i, f"/p{i}") for i in range(1, 23)]

    def replayed_first(self, n, mutate=None):
        out = []
        for i in range(1, n + 1):
            r = rec(100 + i, f"/p{i}")
            if mutate is not None and i == mutate:
                r = rec(100 + i, f"/p{i}", text=r["request_text"] + " X")
            out.append(r)
        return out

    def test_declared_subset_12_of_22_passes(self):
        code, out = self.run_gate(self.captured_22(), self.replayed_first(12), expect=12)
        self.assertEqual(code, 0, out)
        self.assertIn("12/12", out)
        self.assertIn("not replayed by design", out)
        self.assertIn("RESULT: PASS", out)

    def test_declared_subset_does_not_print_a_count_mismatch(self):
        # The exact inconsistency this rewrite removes: a subset is not a mismatch.
        _, out = self.run_gate(self.captured_22(), self.replayed_first(12), expect=12)
        self.assertNotIn("COUNT MISMATCH", out)

    def test_declared_subset_with_one_byte_changed_fails(self):
        code, out = self.run_gate(self.captured_22(),
                                  self.replayed_first(12, mutate=7), expect=12)
        self.assertEqual(code, 1, out)
        self.assertIn("11/12", out)
        self.assertIn("RESULT: FAIL", out)

    def test_declared_subset_with_11_replayed_fails(self):
        code, out = self.run_gate(self.captured_22(), self.replayed_first(11), expect=12)
        self.assertEqual(code, 1, out)
        self.assertIn("predeclared subset is 12", out)
        self.assertIn("RESULT: FAIL", out)

    def test_declared_subset_with_13_replayed_fails(self):
        code, out = self.run_gate(self.captured_22(), self.replayed_first(13), expect=12)
        self.assertEqual(code, 1, out)
        self.assertIn("predeclared subset is 12", out)
        self.assertIn("RESULT: FAIL", out)

    def test_too_few_eligible_originals_fails(self):
        # 12 were replayed but only 8 captured requests exist to have come from.
        code, out = self.run_gate([rec(i, f"/p{i}") for i in range(1, 9)],
                                  self.replayed_first(12), expect=12)
        self.assertEqual(code, 1, out)
        self.assertIn("RESULT: FAIL", out)


class TestHostSelectionRuleMatchesReplay(GateTestCase):
    """The checker must select originals exactly as replay.py did: host filter, then limit.

    replay.py was given `--only-host shop.fwlab.test --limit 12`. If the checker takes the
    first 12 records regardless of host, it compares a different set of requests than the
    one replayed and can agree or disagree by luck.
    """

    def test_off_host_captures_are_excluded_before_the_limit(self):
        captured = [rec(1, "/p1"),
                    rec(2, "/telemetry", host="update.example.net"),   # not lab traffic
                    rec(3, "/p2"), rec(4, "/p3")]
        replayed = [rec(10, "/p1"), rec(11, "/p2"), rec(12, "/p3")]
        code, out = self.run_gate(captured, replayed, expect=3, only_host=HOST)
        self.assertEqual(code, 0, out)
        self.assertIn("3/3", out)
        self.assertIn("dropped 1 captured", out)

    def test_without_the_host_filter_the_same_data_misaligns(self):
        # Same records, no --only-host: record 2 shifts the alignment and the gate fails.
        captured = [rec(1, "/p1"),
                    rec(2, "/telemetry", host="update.example.net"),
                    rec(3, "/p2"), rec(4, "/p3")]
        replayed = [rec(10, "/p1"), rec(11, "/p2"), rec(12, "/p3")]
        code, out = self.run_gate(captured, replayed, expect=3)
        self.assertEqual(code, 1, out)
        self.assertIn("RESULT: FAIL", out)


if __name__ == "__main__":
    unittest.main()
