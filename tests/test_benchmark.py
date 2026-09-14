"""Tests for the Issue #9 inference benchmark: statistics, comparison
formulas, population separation, experiment identity and the preservation of
inference behaviour.

NO REAL MODEL IS LOADED HERE, and nothing in this file is evidence of
performance. Synthetic samples verify that the instrumentation computes and
separates correctly; only a real run on real hardware produces a latency
result.

Run:  python3.12 -m unittest discover -s tests -v
"""

import json
import os
import statistics
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import benchmark_compare as cmpmod
import benchmark_inference as bench
import inference_core as core
import test_model


# ══════════════════════════════════════════════════════════════════════════
# Statistics
# ══════════════════════════════════════════════════════════════════════════
class TestPercentileMatchesEvaluationHarness(unittest.TestCase):
    """The benchmark and the E5 evaluation must mean the same thing by "P95".

    If these two definitions ever drift, a benchmark percentile could not be
    read next to `reports/v4_clean_eval.json` at all.
    """

    def test_identical_on_many_shapes(self):
        cases = [
            [1.0], [1.0, 2.0], list(range(1, 101)), [5.0] * 40,
            [float(x) for x in (3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5)],
            [float(x) for x in range(6206)],
        ]
        for vals in cases:
            s = sorted(vals)
            for q in (0.0, 0.5, 0.95, 0.99, 1.0):
                self.assertEqual(bench.percentile(s, q), test_model.percentile(s, q),
                                 f"q={q} n={len(s)}")

    def test_empty_is_none_in_both(self):
        self.assertIsNone(bench.percentile([], 0.95))
        self.assertIsNone(test_model.percentile([], 0.95))


class TestSummarize(unittest.TestCase):
    def test_known_distribution(self):
        s = bench.summarize([float(x) for x in range(1, 101)])
        self.assertEqual(s["count"], 100)
        self.assertEqual(s["mean_ms"], 50.5)
        self.assertEqual(s["p50_ms"], 50.0)      # nearest-rank: ceil(.50*100)=50
        self.assertEqual(s["p95_ms"], 95.0)
        self.assertEqual(s["p99_ms"], 99.0)
        self.assertEqual(s["min_ms"], 1.0)
        self.assertEqual(s["max_ms"], 100.0)
        self.assertAlmostEqual(s["stdev_ms"], statistics.stdev(range(1, 101)))

    def test_empty(self):
        self.assertEqual(bench.summarize([])["count"], 0)

    def test_single_sample_has_zero_stdev(self):
        s = bench.summarize([42.0])
        self.assertEqual(s["stdev_ms"], 0.0)
        self.assertEqual(s["p95_ms"], 42.0)

    def test_unit_is_carried_into_key_names(self):
        s = bench.summarize([1, 2, 3], unit="tokens")
        self.assertIn("p95_tokens", s)
        self.assertNotIn("p95_ms", s)
        self.assertEqual(s["unit"], "tokens")

    def test_outliers_are_kept_not_dropped(self):
        """A slow sample is an observation, not noise to be removed."""
        vals = [100.0] * 99 + [9000.0]
        s = bench.summarize(vals)
        self.assertEqual(s["count"], 100, "every sample must survive")
        self.assertEqual(s["max_ms"], 9000.0)
        self.assertEqual(s["samples_above_p99"], 1)
        self.assertIn("none removed", s["outlier_policy"])

    def test_order_of_input_does_not_matter(self):
        a = bench.summarize([3.0, 1.0, 2.0])
        b = bench.summarize([1.0, 2.0, 3.0])
        self.assertEqual(a["p95_ms"], b["p95_ms"])
        self.assertEqual(a["mean_ms"], b["mean_ms"])


class TestSpread(unittest.TestCase):
    def test_run_to_run_variation(self):
        s = bench.spread([100.0, 110.0, 105.0])
        self.assertEqual(s["min"], 100.0)
        self.assertEqual(s["max"], 110.0)
        self.assertEqual(s["range"], 10.0)
        self.assertEqual(s["median"], 105.0)
        self.assertAlmostEqual(s["spread_pct"], 100 * 10.0 / 105.0)

    def test_missing_values_are_skipped_not_counted_as_zero(self):
        s = bench.spread([100.0, None, 110.0])
        self.assertEqual(s["count"], 2)
        self.assertEqual(s["min"], 100.0)

    def test_all_missing(self):
        self.assertEqual(bench.spread([None, None])["count"], 0)


# ══════════════════════════════════════════════════════════════════════════
# Comparison formulas
# ══════════════════════════════════════════════════════════════════════════
class TestPercentReduction(unittest.TestCase):
    def test_improvement(self):
        r = cmpmod.pct_reduction(200.0, 100.0)
        self.assertEqual(r["status"], "ok")
        self.assertAlmostEqual(r["value"], 50.0)

    def test_regression_is_negative_not_hidden(self):
        r = cmpmod.pct_reduction(100.0, 150.0)
        self.assertEqual(r["status"], "ok")
        self.assertAlmostEqual(r["value"], -50.0)

    def test_no_change(self):
        self.assertAlmostEqual(cmpmod.pct_reduction(270.8, 270.8)["value"], 0.0)

    def test_baseline_zero_is_undefined_not_infinite(self):
        r = cmpmod.pct_reduction(0.0, 5.0)
        self.assertIsNone(r["value"])
        self.assertEqual(r["status"], "baseline_zero")
        self.assertEqual(r["absolute_difference"], 5.0)

    def test_baseline_zero_and_candidate_zero(self):
        r = cmpmod.pct_reduction(0.0, 0.0)
        self.assertIsNone(r["value"])
        self.assertEqual(r["status"], "baseline_zero")

    def test_negative_baseline_is_undefined(self):
        r = cmpmod.pct_reduction(-10.0, 5.0)
        self.assertIsNone(r["value"])
        self.assertEqual(r["status"], "baseline_not_positive")

    def test_missing_sides_are_distinguished(self):
        self.assertEqual(cmpmod.pct_reduction(None, 5.0)["status"], "baseline_missing")
        self.assertEqual(cmpmod.pct_reduction(5.0, None)["status"], "candidate_missing")
        self.assertEqual(cmpmod.pct_reduction(None, None)["status"], "both_missing")

    def test_missing_never_becomes_zero(self):
        for r in (cmpmod.pct_reduction(None, 5.0), cmpmod.pct_reduction(5.0, None)):
            self.assertIsNone(r["value"], "a missing value must not read as 0% change")

    def test_ints_are_accepted(self):
        self.assertAlmostEqual(cmpmod.pct_reduction(200, 50)["value"], 75.0)


class TestSpeedup(unittest.TestCase):
    def test_factor(self):
        self.assertAlmostEqual(cmpmod.speedup(200.0, 100.0)["value"], 2.0)
        self.assertAlmostEqual(cmpmod.speedup(200.0, 400.0)["value"], 0.5)

    def test_candidate_zero_is_not_infinite(self):
        r = cmpmod.speedup(200.0, 0.0)
        self.assertIsNone(r["value"])
        self.assertEqual(r["status"], "candidate_zero")

    def test_missing(self):
        self.assertEqual(cmpmod.speedup(None, 1.0)["status"], "missing")

    def test_reduction_and_speedup_are_distinct_quantities(self):
        """50% reduction is 2x; 75% is 4x. They must never be reported as the
        same number."""
        for base, cand, red, factor in ((200.0, 100.0, 50.0, 2.0),
                                        (200.0, 50.0, 75.0, 4.0),
                                        (100.0, 90.0, 10.0, 1 / 0.9)):
            self.assertAlmostEqual(cmpmod.pct_reduction(base, cand)["value"], red)
            self.assertAlmostEqual(cmpmod.speedup(base, cand)["value"], factor)
            self.assertNotAlmostEqual(cmpmod.pct_reduction(base, cand)["value"],
                                      cmpmod.speedup(base, cand)["value"])


class TestCompareMetricVerdict(unittest.TestCase):
    LOWER = {"unit": "ms", "lower_is_better": True, "family": "latency"}
    HIGHER = {"unit": "ratio", "lower_is_better": False, "family": "quality"}

    def test_lower_is_better_improves_when_reduced(self):
        m = cmpmod.compare_metric("steady_generate_p95_ms", 270.0, 200.0, self.LOWER)
        self.assertEqual(m["verdict"], "improved")
        self.assertAlmostEqual(m["absolute_delta"], -70.0)

    def test_lower_is_better_regresses_when_increased(self):
        m = cmpmod.compare_metric("steady_generate_p95_ms", 200.0, 270.0, self.LOWER)
        self.assertEqual(m["verdict"], "regressed")

    def test_higher_is_better_regresses_when_reduced(self):
        """A dropped detection rate is a regression even though the reduction
        formula returns a positive number."""
        m = cmpmod.compare_metric("quality_attack_detection_rate", 0.97, 0.90,
                                  self.HIGHER)
        self.assertGreater(m["percent_reduction"]["value"], 0)
        self.assertEqual(m["verdict"], "regressed")

    def test_unchanged(self):
        self.assertEqual(
            cmpmod.compare_metric("m", 1.0, 1.0, self.LOWER)["verdict"], "unchanged")

    def test_missing_is_not_available(self):
        self.assertEqual(
            cmpmod.compare_metric("m", None, 1.0, self.LOWER)["verdict"],
            "not_available")

    def test_speedup_only_for_durations(self):
        self.assertIn("speedup_factor",
                      cmpmod.compare_metric("m", 2.0, 1.0, self.LOWER))
        self.assertNotIn("speedup_factor",
                         cmpmod.compare_metric("m", 2.0, 1.0, self.HIGHER))

    def test_unknown_direction_is_not_judged(self):
        m = cmpmod.compare_metric("generated_tokens_mean", 10.0, 12.0,
                                  {"unit": "tokens", "lower_is_better": None,
                                   "family": "workload"})
        self.assertEqual(m["verdict"], "changed")


# ══════════════════════════════════════════════════════════════════════════
# Experiment identity and incompatibility
# ══════════════════════════════════════════════════════════════════════════
def _identity(**over):
    base = {
        "experiment_id": "baseline-local-v1",
        "protocol_version": bench.PROTOCOL_VERSION,
        "timing_scope_id": bench.TIMING_SCOPE_ID,
        "measurement_unit": "milliseconds",
        "dataset_sha256": "a" * 64,
        "dataset_path": "datasets/v4_clean/eval.jsonl",
        "n_requests_per_run": 6206,
        "reduced_set": False,
        "selection_policy": "full-split",
        "request_order": "file order",
        "seed": 42,
        "runs": 3,
        "batch_size": 1,
        "concurrency": 1,
        "device": "cuda",
        "gpu_name": "NVIDIA GeForce RTX 4090 Laptop GPU",
        "gpu_vram_mib": 16376,
        "nvidia_driver_version": "595.84",
        "torch_cuda_runtime": "12.4",
        "torch_version": "2.6.0+cu124",
        "transformers_version": "5.8.0",
        "peft_version": "0.19.1",
        "bitsandbytes_version": "0.49.2",
        "python_version": "3.12.13",
        "os": "Ubuntu 26.04.1 LTS",
        "kernel": "7.0.0-31-generic",
        "cpu": "13th Gen Intel(R) Core(TM) i9-13900HX",
        "model_base_repo": "TinyLlama/TinyLlama-1.1B-Chat-v1.0",
        "model_base_revision": "fe8a4ea",
        "adapter_sha256": "b" * 64,
        "quantization": {"bnb_4bit_quant_type": "nf4"},
        "git_commit": "c" * 40,
        "working_tree_clean": True,
        "working_tree_diff_sha256": None,
    }
    base.update(over)
    return base


class TestCompatibility(unittest.TestCase):
    def test_identical_experiments_are_comparable(self):
        c = cmpmod.check_compatibility(_identity(), _identity())
        self.assertTrue(c["comparable"])
        self.assertEqual(c["findings"], [])

    def test_different_dataset_blocks(self):
        c = cmpmod.check_compatibility(_identity(), _identity(dataset_sha256="z" * 64))
        self.assertFalse(c["comparable"])
        self.assertEqual(c["blocking_count"], 1)

    def test_different_timing_scope_blocks(self):
        """Two numbers in milliseconds are not comparable if the stopwatch
        covered different operations."""
        c = cmpmod.check_compatibility(
            _identity(), _identity(timing_scope_id="prompt+generate+decode/v2"))
        self.assertFalse(c["comparable"])
        self.assertIn("timing_scope_id", [f["field"] for f in c["findings"]])

    def test_different_request_count_blocks(self):
        c = cmpmod.check_compatibility(_identity(), _identity(n_requests_per_run=500))
        self.assertFalse(c["comparable"])

    def test_reduced_set_blocks_against_full_split(self):
        c = cmpmod.check_compatibility(
            _identity(), _identity(reduced_set=True, selection_policy="first-N-of-split"))
        self.assertFalse(c["comparable"])

    def test_concurrency_change_blocks(self):
        self.assertFalse(cmpmod.check_compatibility(
            _identity(), _identity(concurrency=8))["comparable"])

    def test_batch_size_change_blocks(self):
        self.assertFalse(cmpmod.check_compatibility(
            _identity(), _identity(batch_size=16))["comparable"])

    def test_absent_field_on_one_side_is_a_finding(self):
        cand = _identity()
        del cand["timing_scope_id"]
        c = cmpmod.check_compatibility(_identity(), cand)
        self.assertFalse(c["comparable"])
        f = next(x for x in c["findings"] if x["field"] == "timing_scope_id")
        self.assertTrue(f["unknown_on_one_side"])

    def test_gpu_change_warns_and_demands_a_rerun_of_the_base_version(self):
        c = cmpmod.check_compatibility(_identity(), _identity(gpu_name="RTX 5090"))
        self.assertTrue(c["comparable"], "a hardware change does not block")
        self.assertIn("gpu_name", c["hardware_changed"])
        self.assertTrue(any("re-run" in n for n in c["attribution_notes"]))

    def test_hardware_plus_software_change_is_reported_as_a_joint_effect(self):
        c = cmpmod.check_compatibility(
            _identity(), _identity(gpu_name="RTX 5090", torch_version="2.9.0"))
        self.assertIn("gpu_name", c["hardware_changed"])
        self.assertIn("torch_version", c["software_changed"])
        joint = " ".join(c["attribution_notes"])
        self.assertIn("JOINT", joint)
        self.assertIn("cannot be attributed to either one alone", joint)

    def test_software_only_change_does_not_claim_a_hardware_effect(self):
        c = cmpmod.check_compatibility(_identity(), _identity(torch_version="2.9.0"))
        self.assertEqual(c["hardware_changed"], [])
        self.assertIn("torch_version", c["software_changed"])
        self.assertFalse(any("HARDWARE CHANGED" in n for n in c["attribution_notes"]))

    def test_git_commit_difference_is_only_informational(self):
        c = cmpmod.check_compatibility(_identity(), _identity(git_commit="d" * 40))
        self.assertTrue(c["comparable"])
        self.assertEqual([f["severity"] for f in c["findings"]], ["INFO"])


def _report(exp_id, identity, metrics):
    return {"summary_schema": "firewall-IA/benchmark-summary/1",
            "experiment_id": exp_id, "created_utc": "2026-09-09T00:00:00+00:00",
            "identity": identity, "metrics": metrics,
            "metric_directions": bench.METRIC_DIRECTIONS}


class TestCompareReports(unittest.TestCase):
    BASE_METRICS = {"steady_generate_p95_ms": 270.0, "steady_generate_p50_ms": 240.0,
                    "quality_attack_detection_rate": 0.97,
                    "quality_false_positive_rate": 0.0006}

    def test_both_experiments_are_identified(self):
        c = cmpmod.compare(_report("baseline-local-v1", _identity(), self.BASE_METRICS),
                           _report("cand-v2", _identity(experiment_id="cand-v2"),
                                   dict(self.BASE_METRICS,
                                        steady_generate_p95_ms=135.0)))
        self.assertEqual(c["baseline"]["experiment_id"], "baseline-local-v1")
        self.assertEqual(c["candidate"]["experiment_id"], "cand-v2")
        self.assertAlmostEqual(c["primary"]["percent_reduction"]["value"], 50.0)
        self.assertAlmostEqual(c["primary"]["speedup_factor"]["value"], 2.0)

    def test_speed_gain_with_quality_loss_is_flagged(self):
        """The requirement: never present a speed improvement without naming
        any quality degradation that came with it."""
        c = cmpmod.compare(
            _report("baseline-local-v1", _identity(), self.BASE_METRICS),
            _report("cand-fast-but-worse", _identity(experiment_id="cand"),
                    dict(self.BASE_METRICS, steady_generate_p95_ms=100.0,
                         quality_attack_detection_rate=0.80)))
        self.assertTrue(c["comparable"])
        joined = " ".join(c["warnings"])
        self.assertIn("SPEED IMPROVED BUT QUALITY DEGRADED", joined)
        self.assertIn("quality_attack_detection_rate", joined)

    def test_speed_gain_with_stable_quality_is_not_flagged(self):
        c = cmpmod.compare(
            _report("baseline-local-v1", _identity(), self.BASE_METRICS),
            _report("cand", _identity(experiment_id="cand"),
                    dict(self.BASE_METRICS, steady_generate_p95_ms=100.0)))
        self.assertEqual(c["warnings"], [])

    def test_metric_only_in_candidate_does_not_fabricate_a_reduction(self):
        c = cmpmod.compare(
            _report("b", _identity(), {"steady_generate_p95_ms": 270.0}),
            _report("c", _identity(experiment_id="c"),
                    {"steady_generate_p95_ms": 270.0, "peak_vram_reserved_mib": 1170.0}))
        m = next(x for x in c["metrics"] if x["metric"] == "peak_vram_reserved_mib")
        self.assertEqual(m["percent_reduction"]["status"], "baseline_missing")
        self.assertIsNone(m["percent_reduction"]["value"])

    def test_incomparable_reports_are_marked_not_comparable(self):
        c = cmpmod.compare(
            _report("b", _identity(), self.BASE_METRICS),
            _report("c", _identity(experiment_id="c", dataset_sha256="z" * 64),
                    self.BASE_METRICS))
        self.assertFalse(c["comparable"])
        self.assertIn("NOT COMPARABLE", cmpmod.render_text(c))
        self.assertIn("NOT COMPARABLE", cmpmod.render_markdown(c))

    def test_renderers_do_not_crash_on_missing_metrics(self):
        c = cmpmod.compare(_report("b", _identity(), {"steady_generate_p95_ms": None}),
                           _report("c", _identity(experiment_id="c"),
                                   {"steady_generate_p95_ms": 100.0}))
        self.assertIn("baseline_missing", cmpmod.render_text(c))
        self.assertIsInstance(cmpmod.render_markdown(c), str)


class TestLegacyReportIsNotSilentlyComparable(unittest.TestCase):
    """The historical 270.8 ms P95 was measured under a different protocol with
    an unsynchronized timer. Loading it must not turn it into a peer."""

    def test_legacy_eval_json_is_blocked_against_a_native_report(self):
        with tempfile.TemporaryDirectory() as d:
            legacy_path = os.path.join(d, "v4_clean_eval.json")
            with open(legacy_path, "w") as f:
                json.dump({"run_metadata": {"date_utc": "2026-08-18T00:03:00+00:00",
                                            "git_commit": "2a188aa",
                                            "dataset_sha256": "a" * 64,
                                            "dataset": "eval.jsonl"},
                           "latency": {"count": 6206, "p95_ms": 270.8449,
                                       "p50_ms": 241.78, "mean_ms": 229.05},
                           "binary": {"attack_detection_rate": 0.9703}}, f)
            legacy = cmpmod.load_report(legacy_path)

        self.assertTrue(legacy["_legacy"])
        self.assertEqual(legacy["identity"]["timing_scope_id"],
                         bench.HISTORICAL_TIMING_SCOPE)
        c = cmpmod.compare(legacy, _report("baseline-local-v1", _identity(),
                                           {"steady_generate_p95_ms": 230.0}))
        self.assertFalse(c["comparable"], "different timing scope must block")
        self.assertTrue(any("legacy" in w for w in c["warnings"]))


# ══════════════════════════════════════════════════════════════════════════
# Population separation
# ══════════════════════════════════════════════════════════════════════════
class TestWarmupSelection(unittest.TestCase):
    def test_deterministic_for_a_fixed_seed(self):
        self.assertEqual(bench.select_warmup(6206), bench.select_warmup(6206))

    def test_cold_start_and_warmup_do_not_overlap(self):
        first, warm = bench.select_warmup(6206)
        self.assertEqual(len(first), bench.N_FIRST_INFERENCE)
        self.assertEqual(len(warm), bench.N_WARMUP)
        self.assertFalse(set(first) & set(warm))

    def test_indices_are_inside_the_split(self):
        for i in sum(bench.select_warmup(6206), []):
            self.assertTrue(0 <= i < 6206)

    def test_a_different_seed_selects_differently(self):
        self.assertNotEqual(bench.select_warmup(6206, seed=42),
                            bench.select_warmup(6206, seed=7))


class TestProtocolDeclaresSeparation(unittest.TestCase):
    def setUp(self):
        self.rows = [{"input": f"GET /{i} HTTP/1.1",
                      "output": ("BLOCK | x" if i % 2 else "ALLOW | y")}
                     for i in range(100)]
        self.proto = bench.build_protocol(
            "t", {"path": "p", "sha256": "a" * 64, "rows": 100}, self.rows)

    def test_excluded_populations_are_named(self):
        self.assertEqual(self.proto["excluded_from_steady_statistics"],
                         ["model_load", "first_inference", "warmup"])

    def test_warmup_requests_are_fixed_in_advance(self):
        pop = self.proto["populations"]
        self.assertEqual(len(pop["first_inference"]["requests"]),
                         bench.N_FIRST_INFERENCE)
        self.assertEqual(len(pop["warmup"]["requests"]), bench.N_WARMUP)
        for r in pop["warmup"]["requests"]:
            self.assertIn("request_sha256", r)
            self.assertIn("row_index", r)

    def test_timing_scope_names_what_is_in_and_out(self):
        t = self.proto["timing"]
        self.assertEqual(t["in_scope"], ["generate()"])
        for stage in ("tokenization", "decoding", "contract parsing"):
            self.assertIn(stage, t["out_of_scope"])

    def test_full_split_is_not_marked_reduced(self):
        self.assertFalse(self.proto["selection"]["reduced_set"])
        self.assertIsNone(self.proto["selection"]["reduction_justification"])

    def test_a_reduced_set_is_labelled_and_justified(self):
        p = bench.build_protocol("t", {"path": "p", "sha256": "a" * 64, "rows": 100},
                                 self.rows, limit=25)
        self.assertTrue(p["selection"]["reduced_set"])
        self.assertEqual(p["selection"]["n_requests_per_run"], 25)
        self.assertIn("not comparable", p["selection"]["reduction_justification"])


class TestAggregationExcludesWarmup(unittest.TestCase):
    """End-to-end check on synthetic samples: cold-start and warm-up values are
    deliberately extreme, so if they leaked into the steady statistics the
    numbers would move visibly."""

    COLD, WARM, STEADY = 5000.0, 900.0, 100.0

    def _experiment(self, d, runs=3, n_steady=10):
        proto = bench.build_protocol(
            "sep-test", {"path": "p", "sha256": "a" * 64, "rows": n_steady},
            [{"input": f"r{i}", "output": "BLOCK | x"} for i in range(n_steady)])
        with open(os.path.join(d, "protocol.json"), "w") as f:
            json.dump(proto, f)

        for run in range(1, runs + 1):
            recs = []
            recs.append(self._rec(run, "first_inference", self.COLD))
            recs += [self._rec(run, "warmup", self.WARM) for _ in range(bench.N_WARMUP)]
            recs += [self._rec(run, "steady", self.STEADY + i)
                     for i in range(n_steady)]
            with open(os.path.join(d, f"run-{run:02d}.samples.jsonl"), "w") as f:
                for r in recs:
                    f.write(json.dumps(r) + "\n")
            steady = [r for r in recs if r["phase"] == "steady"]
            with open(os.path.join(d, f"run-{run:02d}.json"), "w") as f:
                json.dump({
                    "experiment_id": "sep-test", "run_index": run,
                    "started_utc": "2026-09-09T00:00:00+00:00",
                    "finished_utc": "2026-09-09T00:10:00+00:00",
                    "samples_file": f"run-{run:02d}.samples.jsonl",
                    "device": "cuda", "model_load_ms": 2400.0,
                    "model_placement": {"parameter_devices": {"cuda:0": {"share": 1.0}}},
                    "first_inference": {"samples_ms": [self.COLD], "rows": [0]},
                    "warmup": {"samples_ms": [self.WARM] * bench.N_WARMUP,
                               "rows": [1, 2, 3, 4]},
                    "steady_state": {
                        "generate_ms": bench.summarize(
                            [r["generate_ms"] for r in steady])},
                    "memory": {"peak_during_steady_state": {"max_allocated_mib": 892.1,
                                                            "max_reserved_mib": 1170.0}},
                    "quality": {"attack_detection_rate": 1.0, "false_positives": 0,
                                "false_negatives": 0, "invalid_outputs": 0,
                                "accuracy": 1.0,
                                "confusion_matrix": {"TP": n_steady, "FP": 0,
                                                     "FN": 0, "TN": 0}},
                    "conditions_before": {"gpu": [{"temperature_c": 48}]},
                    "conditions_after": {"gpu": [{"temperature_c": 60}]},
                }, f)
        return runs, n_steady

    @staticmethod
    def _rec(run, phase, ms):
        return {"run": run, "phase": phase, "seq": 1, "row_index": 0,
                "expected": "BLOCK", "predicted": "BLOCK", "status": "ok",
                "generate_ms": ms, "pipeline_ms": ms + 0.5,
                "prompt_tokens": 150, "generated_tokens": 12}

    def test_steady_statistics_contain_only_steady_samples(self):
        with tempfile.TemporaryDirectory() as d:
            runs, n = self._experiment(d)
            s = bench.summarize_experiment("sep-test", d)

            self.assertEqual(s["steady_state_pooled"]["n_requests"], runs * n)
            self.assertLess(s["metrics"]["steady_generate_max_ms"], self.WARM,
                            "a warm-up sample leaked into the steady statistics")
            self.assertEqual(s["metrics"]["steady_generate_min_ms"], self.STEADY)

    def test_excluded_samples_are_preserved_not_discarded(self):
        with tempfile.TemporaryDirectory() as d:
            runs, _ = self._experiment(d)
            s = bench.summarize_experiment("sep-test", d)
            ex = s["excluded_populations"]
            self.assertEqual(ex["first_inference_ms"], [self.COLD] * runs)
            self.assertEqual(len(ex["warmup_ms"]), runs * bench.N_WARMUP)
            self.assertEqual(ex["model_load_ms"], [2400.0] * runs)
            self.assertEqual(s["metrics"]["first_inference_ms"], self.COLD)
            self.assertEqual(s["metrics"]["model_load_ms"], 2400.0)

    def test_every_sample_including_excluded_ones_is_on_disk(self):
        with tempfile.TemporaryDirectory() as d:
            runs, n = self._experiment(d)
            bench.summarize_experiment("sep-test", d)
            total = sum(1 for r in range(1, runs + 1)
                        for _ in open(os.path.join(d, f"run-{r:02d}.samples.jsonl")))
            self.assertEqual(total, runs * (n + bench.N_FIRST_INFERENCE + bench.N_WARMUP))

    def test_run_to_run_variation_is_reported(self):
        with tempfile.TemporaryDirectory() as d:
            runs, _ = self._experiment(d)
            s = bench.summarize_experiment("sep-test", d)
            p95 = s["across_runs"]["generate_ms"]["p95_ms"]
            self.assertEqual(p95["count"], runs)
            self.assertEqual(len(p95["values"]), runs)
            self.assertIn("spread_pct", p95)

    def test_identity_block_is_populated_for_comparison(self):
        with tempfile.TemporaryDirectory() as d:
            self._experiment(d)
            s = bench.summarize_experiment("sep-test", d)
            ident = s["identity"]
            self.assertEqual(ident["timing_scope_id"], bench.TIMING_SCOPE_ID)
            self.assertEqual(ident["dataset_sha256"], "a" * 64)
            self.assertEqual(ident["batch_size"], 1)
            self.assertEqual(ident["concurrency"], 1)


# ══════════════════════════════════════════════════════════════════════════
# Preservation of inference behaviour
# ══════════════════════════════════════════════════════════════════════════
class _FakeBatch(dict):
    """Stands in for a tokenizer BatchEncoding: dict-unpackable, movable."""

    def to(self, device):
        self.device = device
        return self


class _FakeTokenizer:
    eos_token_id = 2

    def __init__(self):
        self.seen_prompts = []

    def __call__(self, prompt, return_tensors=None):
        import torch
        self.seen_prompts.append(prompt)
        return _FakeBatch(input_ids=torch.tensor([[1] * 7]))

    def decode(self, ids, skip_special_tokens=False):
        self.decoded_len = int(ids.shape[0])
        return "BLOCK | SQL injection payload detected."


class _FakeModel:
    def __init__(self, n_new=9):
        self.n_new = n_new
        self.calls = []

    def generate(self, **kwargs):
        import torch
        self.calls.append(kwargs)
        prompt_len = kwargs["input_ids"].shape[1]
        return torch.tensor([[1] * prompt_len + [5] * self.n_new])


class TestInferenceBehaviourPreserved(unittest.TestCase):
    """Instrumentation must not have changed what the model is asked to do.

    `classify_raw` is the function the control plane and the evaluation harness
    call; adding timing must leave its contract and its generation call intact.
    """

    def setUp(self):
        self.tok, self.mdl = _FakeTokenizer(), _FakeModel()

    def test_classify_raw_delegates_to_classify_timed(self):
        text, ms = core.classify_raw(self.tok, self.mdl, "GET / HTTP/1.1", "cpu")
        self.assertEqual(text, "BLOCK | SQL injection payload detected.")
        self.assertIsInstance(ms, float)
        self.assertEqual(len(self.mdl.calls), 1, "exactly one generate() per request")

    def test_returned_latency_is_the_generate_stage(self):
        _, ms = core.classify_raw(self.tok, self.mdl, "GET / HTTP/1.1", "cpu")
        _, m = core.classify_timed(self.tok, self.mdl, "GET / HTTP/1.1", "cpu")
        self.assertIn("generate_ms", m)
        # Same stage, same order of magnitude — not the whole pipeline.
        self.assertLessEqual(ms, m["generate_ms"] + m["tokenize_ms"] + 50)

    def test_generation_parameters_are_unchanged(self):
        core.classify_raw(self.tok, self.mdl, "GET / HTTP/1.1", "cpu")
        kw = self.mdl.calls[0]
        self.assertEqual(kw["max_new_tokens"], core.MAX_NEW_TOKENS)
        self.assertIs(kw["do_sample"], False)
        self.assertEqual(kw["pad_token_id"], self.tok.eos_token_id)

    def test_prompt_is_the_frozen_template(self):
        core.classify_raw(self.tok, self.mdl, "GET /x HTTP/1.1", "cpu")
        self.assertEqual(self.tok.seen_prompts[0], core.build_prompt("GET /x HTTP/1.1"))

    def test_only_new_tokens_are_decoded(self):
        core.classify_timed(self.tok, self.mdl, "GET / HTTP/1.1", "cpu")
        self.assertEqual(self.tok.decoded_len, self.mdl.n_new)

    def test_token_counts_are_reported(self):
        _, m = core.classify_timed(self.tok, self.mdl, "GET / HTTP/1.1", "cpu")
        self.assertEqual(m["prompt_tokens"], 7)
        self.assertEqual(m["generated_tokens"], 9)
        self.assertTrue(m["stopped_on_eos"])

    def test_hitting_the_token_cap_is_recorded_not_hidden(self):
        _, m = core.classify_timed(self.tok, _FakeModel(n_new=core.MAX_NEW_TOKENS),
                                   "GET / HTTP/1.1", "cpu")
        self.assertFalse(m["stopped_on_eos"])

    def test_all_stages_are_timed(self):
        _, m = core.classify_timed(self.tok, self.mdl, "GET / HTTP/1.1", "cpu")
        for k in ("prompt_build_ms", "tokenize_ms", "transfer_ms", "generate_ms",
                  "decode_ms"):
            self.assertGreaterEqual(m[k], 0.0)

    def test_device_sync_is_a_noop_on_cpu(self):
        core.device_sync("cpu")          # must not raise without a GPU

    def test_max_new_tokens_is_still_a_safety_bound_not_a_target(self):
        self.assertEqual(core.MAX_NEW_TOKENS, 40)


if __name__ == "__main__":
    unittest.main(verbosity=2)
