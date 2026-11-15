#!/usr/bin/env python3
"""Focused tests: constructed pilot pools (determinism/integrity) + the pilot inputs preparer
(compatibility with the existing World/generate/gate APIs). No validator is mocked; the preparer runs the
real generate + run_gates on constructed pools and synthetic (fixture_synthetic) attacks."""
import json
import os
import shutil
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(REPO, "scripts", "dataset"), os.path.join(REPO, "data_plane")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import build_v5_pilot_pools as B  # noqa: E402
import v5_pilot_inputs as P  # noqa: E402
import v5_pools_common as C  # noqa: E402


def build_pools(out, count=80, attack_pool=None):
    argv = ["build", "--out", out, "--count", str(count)]
    if attack_pool:
        argv += ["--attack-pool", attack_pool]
    return B.build_parser().parse_args(argv).func(B.build_parser().parse_args(argv))


class PilotPools(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_build_pool_is_deterministic(self):
        for pid in B.POOL_IDS:
            a, _ = B.build_pool(pid, 100)
            b, _ = B.build_pool(pid, 100)
            self.assertEqual(a, b, pid)

    def test_value_entry_id_matches_spec(self):
        recs, _ = B.build_pool("passwords", 20)
        for r in recs:
            self.assertEqual(r["value_entry_id"], C.value_entry_id("passwords", r["value"]))

    def test_values_are_benign_and_marked_constructed(self):
        for pid in B.POOL_IDS:
            recs, values = B.build_pool(pid, 60)
            self.assertTrue(all(r["constructed"] is True for r in recs))
            for v in values:                       # ACCEPTED values: ascii, no control, no dot-segment
                self.assertTrue(v.isascii() and ".." not in v and all(ord(c) >= 0x20 for c in v), (pid, v))

    def test_addr_data_uses_reserved_ranges_only(self):
        _, values = B.build_pool("addr_data", 120)
        for v in values:
            self.assertTrue(v.startswith(("192.0.2.", "198.51.100.", "203.0.113.", "2001:db8:"))
                            or v.endswith(".example.com"), v)

    def test_flags_exclude_a_dot_segment_or_control(self):
        self.assertIn("dot_segment", B._flags("a/../b"))
        self.assertIn("control_char", B._flags("a\x00b"))
        self.assertEqual(B._flags("clean/value/1"), [])

    def test_manifest_two_runs_byte_identical(self):
        d1, d2 = os.path.join(self.tmp, "a"), os.path.join(self.tmp, "b")
        build_pools(d1, 80)
        build_pools(d2, 80)
        for pid in B.POOL_IDS:
            self.assertEqual(C.sha256_file(os.path.join(d1, f"{pid}.jsonl")),
                             C.sha256_file(os.path.join(d2, f"{pid}.jsonl")), pid)


class PilotInputs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.pools = os.path.join(self.tmp, "pools")
        build_pools(self.pools, 300)   # >= 200 so each split clears the >= 20-per-split minimum (10% VALIDATION)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_l8_removes_probe_pool_elements_before_split(self):
        sys.path.insert(0, os.path.join(REPO, 'scripts', 'evaluation'))
        import minimal_pair_probe_cases as probe
        protected = probe.POOLS['hosts'][0]
        values = {'test_pool': [protected, 'unique-v5-l8-test-element']}
        kept, report = P.exclude_probe_pool_overlap(values)
        self.assertEqual(kept['test_pool'], ['unique-v5-l8-test-element'])
        self.assertEqual(report['excluded_total'], 1)
        self.assertEqual(report['remaining_overlap'], 0)

    def test_verify_pool_manifest_rejects_a_tampered_file(self):
        P._verify_pool_manifest(self.pools, B.POOL_IDS)        # clean: ok
        with open(os.path.join(self.pools, "passwords.jsonl"), "a", encoding="utf-8") as fh:
            fh.write('{"pool_id":"passwords","value":"tampered"}\n')
        with self.assertRaises(P.PilotInputError):
            P._verify_pool_manifest(self.pools, B.POOL_IDS)

    def test_prepare_runs_end_to_end_and_names_missing_attack_pool(self):
        out = os.path.join(self.tmp, "prepared")
        summary = P.prepare(self.pools, out, per_category=40)
        self.assertTrue(summary["gates_ok"])
        self.assertEqual(summary["status"], "PREPARED")
        self.assertTrue(os.path.isfile(os.path.join(out, "manifest.json")))
        self.assertEqual(summary["attack_source"]["source"], "fixture_synthetic")
        self.assertTrue(any(m["input"] == "--attack-pool" for m in summary["missing_inputs"]))
        # all ten pools present
        self.assertEqual(set(summary["pool_counts"]), set(B.POOL_IDS) | set(P.BENIGN_POOL_IDS))

    def test_source_pool_requires_real_authorization_before_any_generation(self):
        apool = os.path.join(self.tmp, "attack.jsonl")
        C.write_jsonl(apool, P.synthetic_attack_records(40), key=lambda r: r["record_id"])
        out = os.path.join(self.tmp, "prepared2")
        with self.assertRaisesRegex(P.PilotInputError,'build-authorization'):
            P.prepare(self.pools,out,attack_pool=apool)
        self.assertFalse(os.path.exists(out))

    def test_measure_assembles_pilot_measurements(self):
        out = os.path.join(self.tmp, "prepared3")
        P.prepare(self.pools, out, per_category=40)
        meas = P.measure(out, os.path.join(out, "pilot_measurements.json"))
        for key in ("distribution", "split_separation", "cluster_share", "exclusions_over_limit",
                    "per_source_contribution", "pending_11_2"):
            self.assertIn(key, meas)
        self.assertTrue(meas["per_source_contribution"])            # rows drew from the pools
        self.assertIn("cluster_share_warn", meas["pending_11_2"])
        self.assertTrue(os.path.isfile(os.path.join(out, "pilot_measurements.json")))

    def test_build_pilot_world_generates_for_real(self):
        import v5_generator as G
        values, _ = P.load_pool_values(self.pools)
        world = P.build_pilot_world(values, P.synthetic_attack_records(40), P.PILOT_CATEGORIES)
        gen = G.generate_balanced(world)
        gates = G.run_gates(world, gen, values)
        self.assertTrue(gates["ok"])
        self.assertGreater(len(gen["rows"]), 0)


if __name__ == "__main__":
    unittest.main()
