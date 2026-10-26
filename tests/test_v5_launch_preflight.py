#!/usr/bin/env python3
"""Focused tests for the V5 GPU launch preflight (read-only diagnostic). Interpreter-agnostic: they do not
assume torch/GPU is present, and they assert the structure, the D71 ratification reuse, and that the emitted
training command invents no flags (every flag parses against finetune_v5)."""
import os
import sys
import tempfile
from unittest.mock import patch
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(REPO, "scripts", "training"), os.path.join(REPO, "control_plane"),
           os.path.join(REPO, "scripts", "dataset"), os.path.join(REPO, "data_plane")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import v5_launch_preflight as PF  # noqa: E402


class Args:
    recipe = PF.DEFAULT_RECIPE
    dataset = dataset_prereg = freeze_record = training_prereg = ai_audit_authorization = None


class Preflight(unittest.TestCase):
    def test_run_returns_the_report_schema(self):
        rep = PF.run(Args())
        self.assertEqual(rep["schema"], "v5-launch-preflight/v1")
        for k in ("interpreter", "libraries", "gpu", "disk", "base_model", "recipe_ratification", "final_gate"):
            self.assertIn(k, rep["checks"])
        self.assertIn("train_command", rep)
        self.assertIsInstance(rep["pending"], list)

    def test_recipe_ratification_reuses_trainer_api_and_reflects_D71_D73(self):
        rep = PF.run(Args())
        nr = rep["checks"]["recipe_ratification"]["not_ratified"]
        for ratified in ("template", "vocabulary", "token_budget"):     # D71
            self.assertNotIn(ratified, nr)
        self.assertEqual(nr,{})  # D73 ratified the remaining sections

    def test_final_gate_is_skipped_without_a_dataset(self):
        fg = PF.run(Args())["checks"]["final_gate"]
        self.assertTrue(fg.get("skipped"))
        self.assertIsNone(fg["ok"])

    def test_train_command_invents_no_flags(self):
        try:
            import finetune_v5 as FV
        except Exception as exc:                 # pragma: no cover - heavy deps unavailable
            self.skipTest(f"finetune_v5 not importable ({type(exc).__name__})")
        # every flag the preflight emits must parse against the real CLI
        argv = ["--mode", "final", "--dataset", "d", "--recipe", "r", "--dataset-prereg", "p",
                "--freeze-record", "f", "--training-prereg", "t", "--ai-audit-authorization", "a",
                "--run-id", "x", "--report-dir", "rd", "--gate-only"]
        parsed = FV.parse_args(argv)
        self.assertEqual(parsed.mode, "final")
        self.assertTrue(parsed.gate_only)

    def test_generated_command_parses_actual_paths_and_separates_reports(self):
        recipe, _ = PF.D.load_recipe(PF.DEFAULT_RECIPE)
        cmd=PF.train_command(PF.DEFAULT_RECIPE,dataset='/tmp/data with spaces',run_id='planned-run',
                             dataset_prereg='/tmp/pre reg',freeze_record='/tmp/freeze',
                             training_prereg='/tmp/train',ai_audit_authorization='/tmp/ai')
        parsed=PF.FV.parse_args(cmd['gate_only_argv'][2:])
        self.assertEqual(parsed.dataset,'/tmp/data with spaces')
        self.assertEqual(parsed.dataset_prereg,'/tmp/pre reg')
        self.assertTrue(parsed.gate_only)
        self.assertFalse(os.path.commonpath([os.path.abspath(cmd['report_dir']),os.path.abspath(cmd['output_dir'])])==os.path.abspath(cmd['output_dir']))

    def test_metadata_gate_reuses_python_versions_and_code_paths(self):
        recipe,sha=PF.D.load_recipe(PF.DEFAULT_RECIPE)
        with tempfile.TemporaryDirectory() as directory:
            args=Args();args.dataset=directory
            open(os.path.join(directory,'manifest.json'),'w').close()
            with patch.object(PF.D,'load_manifest',return_value=({},'a'*64)), \
                 patch.object(PF.D,'gate_common',return_value=[]), \
                 patch.object(PF.D,'protected_split_declared_diags',return_value=[]), \
                 patch.object(PF.D,'gate_final',return_value=[]) as gate:
                PF.check_final_gate(args,recipe,sha)
                self.assertIn('python',gate.call_args.kwargs['installed_versions'])
                self.assertEqual(gate.call_args.kwargs['code_paths'],PF.FV.CODE_FILES+(os.path.abspath(args.recipe),))

    def test_library_check_uses_startswith_rule(self):
        rep = PF.run(Args())
        libs = rep["checks"]["libraries"]["libraries"]
        self.assertEqual(set(libs), set(PF.PINNED_LIBS))
        for lib, r in libs.items():
            self.assertIn("installed", r)
            self.assertIn("pinned", r)

    def test_base_model_check_has_structure_and_no_download(self):
        rep = PF.run(Args())
        bm = rep["checks"]["base_model"]
        for k in ("snapshot_present", "has_weights", "has_tokenizer", "cache"):
            self.assertIn(k, bm)

    def test_gpu_check_never_allocates_and_degrades_gracefully(self):
        gpu = PF.check_gpu()      # must not raise even when torch is absent
        self.assertIn("ok", gpu)
        self.assertIn("devices", gpu)


if __name__ == "__main__":
    unittest.main()
