#!/usr/bin/env python3
"""Tests for finetune_v5.compute_schedule — the effective V5 training schedule derived from the ratified
recipe + the frozen TRAIN size. No training, no GPU, no dataset rows."""
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(REPO, "scripts", "training"), os.path.join(REPO, "control_plane"),
           os.path.join(REPO, "scripts", "dataset"), os.path.join(REPO, "data_plane")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import finetune_v5 as FV  # noqa: E402
import v5_train_data as D  # noqa: E402


class Schedule(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.recipe, _ = D.load_recipe(os.path.join(REPO, "scripts", "training", "v5_training_recipe_v1.json"))

    def test_invariants_across_sizes(self):
        for rows in (1, 7, 100, 2000, 100000):
            s = FV.compute_schedule(self.recipe, rows)
            self.assertGreaterEqual(s["effective_eval_steps"], 1)
            self.assertLessEqual(s["effective_eval_steps"], s["total_optimizer_steps"])   # at least one eval+save
            self.assertEqual(s["effective_eval_steps"], s["effective_save_steps"])        # load_best_model_at_end
            self.assertGreaterEqual(s["expected_evaluations"], 1)
            self.assertGreaterEqual(s["effective_logging_steps"], 1)

    def test_small_dataset_still_evaluates_and_saves(self):
        s = FV.compute_schedule(self.recipe, 10)                 # far below the recipe's eval_steps=200
        self.assertLess(s["effective_eval_steps"], 200)
        self.assertLessEqual(s["effective_eval_steps"], s["total_optimizer_steps"])

    def test_large_dataset_respects_recipe_eval_cap(self):
        s = FV.compute_schedule(self.recipe, 1_000_000)
        self.assertEqual(s["effective_eval_steps"], int(self.recipe["optimization"]["eval_steps"]))

    def test_effective_batch_counts_devices(self):
        opt = self.recipe["optimization"]
        expect = int(opt["per_device_train_batch_size"]) * int(opt["gradient_accumulation_steps"]) * 2
        self.assertEqual(FV.compute_schedule(self.recipe, 500, num_devices=2)["effective_batch"], expect)

    def test_deterministic(self):
        self.assertEqual(FV.compute_schedule(self.recipe, 321), FV.compute_schedule(self.recipe, 321))

    def test_epochs_batch_accum_come_from_recipe(self):
        opt = self.recipe["optimization"]
        s = FV.compute_schedule(self.recipe, 500)
        self.assertEqual(s["num_train_epochs"], int(opt["num_train_epochs"]))
        self.assertEqual(s["per_device_train_batch_size"], int(opt["per_device_train_batch_size"]))
        self.assertEqual(s["gradient_accumulation_steps"], int(opt["gradient_accumulation_steps"]))


if __name__ == "__main__":
    unittest.main()
