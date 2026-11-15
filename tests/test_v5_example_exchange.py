#!/usr/bin/env python3
"""Tests for the V5 TRAIN/VALIDATION EXAMPLE interface (scripts/training/v5_example_exchange.py).

Synthetic stage-4 FIXTURE only (built with `v5_fixture.py generate`). NO real pool, NO real split, NO
protected data, NO training. Covers the clean path and regressions for the two defects Codex reproduced:
  D1 verify + consume use ONE capture — each allowed file is opened exactly once, and a PENDING row with
     coherent hashes can never be returned as trainable;
  D2 an access-gate failure (e.g. missing authorization) opens ZERO rows/meta files;
plus integrity over consumed bytes and the protected-role non-access guarantee.

The file-access spy wraps `builtins.open` in the TEST only; the production module patches no `open()`.
"""
import builtins
import contextlib
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
for _p in (os.path.join(REPO, "scripts", "training"), os.path.join(REPO, "scripts", "dataset")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import v5_example_exchange as E   # noqa: E402
import v5_train_data as D         # noqa: E402
import v5_fixture as F            # noqa: E402

_ALLOWED = ("rows.TRAIN.jsonl", "rows.TRAIN.meta.jsonl", "rows.VALIDATION.jsonl", "rows.VALIDATION.meta.jsonl")


@contextlib.contextmanager
def _open_spy():
    opened = []
    real = builtins.open

    def spy(path, *a, **k):
        try:
            opened.append(os.path.abspath(path))
        except Exception:  # noqa: BLE001 — path may be an int fd
            pass
        return real(path, *a, **k)
    builtins.open = spy
    try:
        yield opened
    finally:
        builtins.open = real


class ExampleExchangeTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = tempfile.mkdtemp(prefix="v5-ex-base-")
        F.main(["generate", "--out", cls.base, "--quiet"])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.base, ignore_errors=True)

    def _copy(self) -> str:
        dst = tempfile.mkdtemp(prefix="v5-ex-copy-")
        for name in os.listdir(self.base):
            src = os.path.join(self.base, name)
            if os.path.isfile(src):
                shutil.copy2(src, os.path.join(dst, name))
        self.addCleanup(shutil.rmtree, dst, ignore_errors=True)
        return dst

    @staticmethod
    def _reseal_artifact(dataset_dir: str, name: str):
        """Recompute the manifest's sha256/bytes for one file (simulate a coherent producer rewrite)."""
        with open(os.path.join(dataset_dir, name), "rb") as fh:
            raw = fh.read()
        mp = os.path.join(dataset_dir, "manifest.json")
        with open(mp, encoding="utf-8") as fh:
            m = json.load(fh)
        for art in m.get("artifacts", []):
            if art.get("path") == name:
                art["sha256"] = hashlib.sha256(raw).hexdigest()
                art["bytes"] = len(raw)
        with open(mp, "w", encoding="utf-8") as fh:
            json.dump(m, fh)

    # -- clean path -------------------------------------------------------------
    def test_clean_load_returns_documented_schema(self):
        ex = E.load_examples(self.base)
        self.assertEqual(set(ex), {"TRAIN", "VALIDATION"})
        self.assertTrue(len(ex["TRAIN"]) > 0 and len(ex["VALIDATION"]) > 0)
        sample = ex["TRAIN"][0]
        for key in ("split", "row_index", "text", "output", "label", "label_status",
                    "label_basis", "text_sha256", "identities", "manifest_sha256", "eligibility"):
            self.assertIn(key, sample)
        self.assertEqual(set(sample["identities"]), set(D.IDENTITY_KEYS))

    def test_examples_are_eligible_and_label_consistent(self):
        for rows in E.load_examples(self.base).values():
            for r in rows:
                self.assertIn(r["label_status"], D.TRAINABLE_LABEL_STATUSES)
                self.assertIn(r["label"], ("ALLOW", "BLOCK"))
                self.assertTrue(r["output"].startswith(f"{r['label']} | "))
                self.assertEqual(hashlib.sha256(r["text"].encode("utf-8")).hexdigest(), r["text_sha256"])

    def test_no_model_decision_is_used_as_a_label(self):
        sample = E.load_examples(self.base)["TRAIN"][0]
        for forbidden in ("prediction", "model_decision", "v4_decision", "v5_decision", "score"):
            self.assertNotIn(forbidden, sample)

    # -- D1: single capture — each allowed file opened exactly once; no protected role opened ----
    def test_single_capture_opens_each_allowed_file_exactly_once(self):
        with _open_spy() as opened:
            E.load_examples(self.base)
        local = [os.path.basename(p) for p in opened if p.startswith(os.path.abspath(self.base))]
        for name in _ALLOWED:
            self.assertEqual(local.count(name), 1, f"{name} opened {local.count(name)}x (want 1)")
        for p in opened:
            low = p.lower()
            self.assertNotIn("internal_test", low)
            self.assertNotIn("e6_reserve", low)
            self.assertFalse(os.path.basename(p).startswith("slices."), p)
            self.assertNotEqual(os.path.basename(p), "assignment.jsonl")

    def test_pending_label_via_facade_with_coherent_hashes_fails(self):
        d = self._copy()
        mp = os.path.join(d, "rows.VALIDATION.meta.jsonl")
        with open(mp, encoding="utf-8") as fh:
            lines = [ln for ln in fh if ln.strip()]
        m0 = json.loads(lines[0])
        m0["label_status"] = "PENDING"
        lines[0] = json.dumps(m0) + "\n"
        with open(mp, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
        self._reseal_artifact(d, "rows.VALIDATION.meta.jsonl")   # coherent hash: isolate the eligibility defect
        codes = {diag.code for diag in E.gate_diagnostics(d)}
        self.assertIn("LABEL_NOT_TRAINABLE", codes)
        self.assertNotIn("ARTIFACT_HASH_MISMATCH", codes)
        with self.assertRaises(E.ExampleExchangeError):
            E.load_examples(d)

    # -- D2: an access-gate failure opens ZERO rows/meta files ------------------
    def test_authorization_failure_opens_no_rows_or_meta(self):
        d = self._copy()
        mp = os.path.join(d, "manifest.json")
        with open(mp, encoding="utf-8") as fh:
            m = json.load(fh)
        m["status"] = "REAL"
        m.setdefault("generator_config", {})["mode"] = "real"
        m["attack_label_basis"] = "post_filter_audit"
        with open(mp, "w", encoding="utf-8") as fh:
            json.dump(m, fh)
        with _open_spy() as opened:
            codes = {diag.code for diag in E.gate_diagnostics(d)}
            with self.assertRaises(E.ExampleExchangeError):
                E.load_examples(d)
        self.assertIn("AUTHORIZATION_MISSING", codes)
        rowmeta = [os.path.basename(p) for p in opened if os.path.basename(p) in _ALLOWED]
        self.assertEqual(rowmeta, [], f"rows/meta opened despite auth failure: {rowmeta}")

    # -- integrity over consumed bytes ------------------------------------------
    def test_tampered_consumed_text_is_refused(self):
        d = self._copy()
        rp = os.path.join(d, "rows.TRAIN.jsonl")
        with open(rp, encoding="utf-8") as fh:
            lines = [ln for ln in fh if ln.strip()]
        first = json.loads(lines[0])
        first["text"] = first["text"] + "X-TAMPER"
        lines[0] = json.dumps(first) + "\n"
        with open(rp, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
        # file edited, manifest NOT resealed -> the consumed bytes fail the manifest hash, so no row is returned
        self.assertIn("ARTIFACT_HASH_MISMATCH", {diag.code for diag in E.gate_diagnostics(d)})
        with self.assertRaises(E.ExampleExchangeError):
            E.load_examples(d)

    # -- eligibility rule reused from v5_train_data (unit) -----------------------
    def test_pending_label_is_not_trainable_unit(self):
        row = {"text": "x", "output": "ALLOW | ok", "split": "TRAIN", "index": 0,
               "meta": {"label": "ALLOW", "label_status": "PENDING"}}
        self.assertIn("LABEL_NOT_TRAINABLE", {d.code for d in D.check_rows([row], ["ALLOW | ok"])})

    # -- regression: JSONL split on LF only, not on Unicode line/para separators -
    def test_parse_split_preserves_unicode_line_separators(self):
        for ch in ("\u0085", " ", " "):   # NEL, LINE SEPARATOR, PARAGRAPH SEPARATOR
            text = f"a{ch}b"
            row = {"text": text, "output": "ALLOW | ok"}
            meta = {"split": "TRAIN", "disposition": "split", "output": "ALLOW | ok",
                    "label": "ALLOW", "label_status": "VERIFIED",
                    "text_sha256": D.sha256_bytes(text.encode("utf-8"))}
            rows_text = json.dumps(row, ensure_ascii=False) + "\n"
            meta_text = json.dumps(meta, ensure_ascii=False) + "\n"
            rows, diags = D.parse_split(rows_text, meta_text, "TRAIN")
            self.assertEqual([d.code for d in diags], [], f"U+{ord(ch):04X}")
            self.assertEqual(len(rows), 1, f"U+{ord(ch):04X} split a single row")
            self.assertEqual(rows[0]["text"], text)

    def test_facade_preserves_literal_unicode_separator_with_coherent_hashes(self):
        d = self._copy()
        ch = " "
        rp = os.path.join(d, "rows.TRAIN.jsonl")
        with open(rp, encoding="utf-8") as fh:
            rlines = [ln for ln in fh if ln.strip()]
        r0 = json.loads(rlines[0])
        r0["text"] = r0["text"] + ch
        rlines[0] = json.dumps(r0, ensure_ascii=False) + "\n"       # literal char in the file (not \\u2028)
        with open(rp, "w", encoding="utf-8") as fh:
            fh.writelines(rlines)
        mp = os.path.join(d, "rows.TRAIN.meta.jsonl")
        with open(mp, encoding="utf-8") as fh:
            mlines = [ln for ln in fh if ln.strip()]
        m0 = json.loads(mlines[0])
        m0["text_sha256"] = hashlib.sha256(r0["text"].encode("utf-8")).hexdigest()
        mlines[0] = json.dumps(m0, ensure_ascii=False) + "\n"
        with open(mp, "w", encoding="utf-8") as fh:
            fh.writelines(mlines)
        self._reseal_artifact(d, "rows.TRAIN.jsonl")
        self._reseal_artifact(d, "rows.TRAIN.meta.jsonl")
        ex = E.load_examples(d)                                      # must not JSONDecodeError / misalign
        self.assertTrue(ex["TRAIN"][0]["text"].endswith(ch))


if __name__ == "__main__":
    unittest.main()
