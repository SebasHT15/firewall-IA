"""Tests for the V5 training gates and example builder (`scripts/training/v5_train_data.py`).

Every dataset here is the stage-4 SYNTHETIC fixture, built in a throwaway directory. Where a test needs
a dataset that looks REAL or provisional (to exercise the EXPERIMENTAL / FINAL logic), it edits a COPY of
the fixture manifest in the temp dir: a test double of the gate inputs, never a dataset. No real data is
generated or read; INTERNAL TEST and External Test are never opened.

Pure tests run everywhere; tokenizer tests skip without transformers or the local base snapshot.

    python3 -m unittest tests.test_v5_training_gates -v
    HF_HUB_OFFLINE=1 python3.12 -m unittest tests.test_v5_training_gates -v
"""

import builtins
import copy
import glob
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "scripts", "training"))
sys.path.insert(0, os.path.join(REPO, "scripts", "dataset"))
sys.path.insert(0, os.path.join(REPO, "data_plane"))

import v5_train_data as D  # noqa: E402
import v5_fixture  # noqa: E402
import v5_generator as G  # noqa: E402

RECIPE = os.path.join(REPO, "scripts", "training", "v5_training_recipe_v1.json")
_FIXTURE_DIR = None


def setUpModule():
    global _FIXTURE_DIR
    _FIXTURE_DIR = tempfile.mkdtemp(prefix="v5-train-gates-")
    world, gen, gates = v5_fixture.generate()
    assert gates["ok"]
    G.write_outputs(world, gen, gates, os.path.join(_FIXTURE_DIR, "fixture"), extra={"fixture": True})


def tearDownModule():
    shutil.rmtree(_FIXTURE_DIR, ignore_errors=True)


def out(mode, name="t"):
    return os.path.join(D.OUTPUT_ROOT, mode.lower(), name)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="v5-train-case-")
        self.ds = os.path.join(self.tmp, "ds")
        shutil.copytree(os.path.join(_FIXTURE_DIR, "fixture"), self.ds)
        self.recipe, self.rsha = D.load_recipe(RECIPE)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def edit_manifest(self, fn):
        p = os.path.join(self.ds, "manifest.json")
        with open(p, encoding="utf-8") as fh:
            m = json.load(fh)
        fn(m)
        data = (json.dumps(m, sort_keys=True, indent=2) + "\n").encode()
        with open(p, "wb") as fh:
            fh.write(data)
        return hashlib.sha256(data).hexdigest()

    def rewrite_meta(self, fn):
        """Apply fn(meta) to every TRAIN/VALIDATION meta line, re-hash the files into the manifest; return its sha."""
        shas = {}
        for split in ("TRAIN", "VALIDATION"):
            name = f"rows.{split}.meta.jsonl"
            path = os.path.join(self.ds, name)
            with open(path, encoding="utf-8") as fh:
                metas = [json.loads(ln) for ln in fh if ln.strip()]
            for m in metas:
                fn(m)
            data = ("\n".join(json.dumps(m, sort_keys=True) for m in metas) + "\n").encode()
            with open(path, "wb") as fh:
                fh.write(data)
            shas[name] = (hashlib.sha256(data).hexdigest(), len(data))

        def fix(m):
            for a in m["artifacts"]:
                if a["path"] in shas:
                    a["sha256"], a["bytes"] = shas[a["path"]]
        return self.edit_manifest(fix)

    def refused(self, mode, **kw):
        with self.assertRaises(D.GateRefused) as cm:
            D.prepare(mode, self.ds, kw.pop("out_dir", out(mode)), self.recipe, self.rsha, **kw)
        return {d.code for d in cm.exception.diagnostics}, cm.exception


class Smoke(Base):
    def test_fixture_passes_smoke_and_loads_only_train_and_validation(self):
        p = D.prepare(D.SMOKE, self.ds, out(D.SMOKE), self.recipe, self.rsha)
        self.assertEqual({r["split"] for r in p.train_rows}, {"TRAIN"})
        self.assertEqual({r["split"] for r in p.validation_rows}, {"VALIDATION"})
        self.assertGreater(len(p.train_rows), 0)
        self.assertGreater(len(p.validation_rows), 0)

    def test_internal_test_and_slices_are_never_opened(self):
        opened, real_open = [], builtins.open

        def spy(path, *a, **k):
            opened.append(str(path))
            return real_open(path, *a, **k)
        with mock.patch("builtins.open", spy):
            D.prepare(D.SMOKE, self.ds, out(D.SMOKE), self.recipe, self.rsha)
        touched = [os.path.basename(p) for p in opened if p.startswith(self.ds)]
        self.assertTrue(touched)
        for name in touched:
            self.assertNotIn("INTERNAL_TEST", name)
            self.assertFalse(name.startswith("slices."), name)
            self.assertNotIn("assignment", name)

    def test_load_split_refuses_protected_splits(self):
        for split in ("INTERNAL_TEST", "E6_RESERVE"):
            with self.assertRaises(PermissionError):
                D.load_split(self.ds, split)

    def test_smoke_refuses_a_non_fixture_manifest(self):
        self.edit_manifest(lambda m: m.update(status="REAL", fixture=False))
        codes, _ = self.refused(D.SMOKE)
        self.assertIn("SMOKE_REQUIRES_FIXTURE", codes)

    def test_tampered_row_is_refused_by_artifact_hash(self):
        p = os.path.join(self.ds, "rows.TRAIN.jsonl")
        with open(p, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"text": "GET / HTTP/1.1\n", "output": "BLOCK | SQL injection payload detected."}) + "\n")
        codes, _ = self.refused(D.SMOKE)
        self.assertIn("ARTIFACT_HASH_MISMATCH", codes)

    def test_output_dir_must_be_the_exclusive_v5_path(self):
        codes, _ = self.refused(D.SMOKE, out_dir=os.path.join(REPO, "model-output-v4-clean", "x"))
        self.assertIn("OUTPUT_DIR_NOT_EXCLUSIVE", codes)
        codes, _ = self.refused(D.SMOKE, out_dir=out(D.EXPERIMENTAL))   # another mode's tree
        self.assertIn("OUTPUT_DIR_NOT_EXCLUSIVE", codes)

    def test_protected_dataset_path_is_refused(self):
        prot = os.path.join(self.tmp, "internal_test_copy")
        shutil.copytree(self.ds, prot)
        self.ds = prot
        codes, _ = self.refused(D.SMOKE)
        self.assertIn("PROTECTED_PATH", codes)

    def test_missing_manifest(self):
        os.remove(os.path.join(self.ds, "manifest.json"))
        codes, _ = self.refused(D.SMOKE)
        self.assertEqual(codes, {"MANIFEST_MISSING"})


class RowChecks(Base):
    def rows(self):
        return D.load_split(self.ds, "TRAIN")[0]

    def test_pending_or_excluded_labels_are_not_trainable(self):
        rows = self.rows()
        rows[0]["meta"] = dict(rows[0]["meta"], label_status="PENDING_ADJUDICATION")
        rows[1]["meta"] = dict(rows[1]["meta"], exclusion_reason="AMBIGUOUS")
        codes = {d.code for d in D.check_rows(rows, D.recipe_vocabulary(self.recipe))}
        self.assertEqual(codes, {"LABEL_NOT_TRAINABLE", "EXCLUDED_ROW_IN_SPLIT"})

    def test_output_outside_vocabulary_or_inconsistent_with_label(self):
        rows = self.rows()
        rows[0] = dict(rows[0], output="BLOCK | NoSQL injection payload detected.")   # ALT_A only
        rows[1] = dict(rows[1], meta=dict(rows[1]["meta"], label="BLOCK" if rows[1]["meta"]["label"] == "ALLOW" else "ALLOW"))
        codes = {d.code for d in D.check_rows(rows, D.recipe_vocabulary(self.recipe))}
        self.assertIn("OUTPUT_NOT_IN_VOCABULARY", codes)
        self.assertIn("LABEL_OUTPUT_INCONSISTENT", codes)

    def test_fixture_is_disjoint_and_injected_leakage_is_caught(self):
        train = self.rows()
        val = D.load_split(self.ds, "VALIDATION")[0]
        self.assertEqual(D.check_disjoint(train, val), [])
        for key in D.IDENTITY_KEYS:
            if val[0]["meta"].get(key) is None:
                continue
            leaked = copy.deepcopy(train)
            leaked[0]["meta"][key] = val[0]["meta"][key]
            diags = D.check_disjoint(leaked, val)
            self.assertTrue(any(d.code == "SPLIT_LEAKAGE" and d.detail.startswith(key) for d in diags), key)


class Experimental(Base):
    def provisional(self):
        def f(m):
            m.update(status="REAL", fixture=False, attack_label_basis="post_filter_audit",audit_type="human")
            m["generator_config"]["mode"] = "real"
        return self.edit_manifest(f)

    def test_missing_provenance_is_refused_before_rows(self):
        self.provisional();msha=self.edit_manifest(lambda m:m.pop('audit_type'))
        auth=self.auth(msha)
        with mock.patch.object(D,'capture_and_parse_split',side_effect=AssertionError('row read')):
            codes,_=self.refused(D.EXPERIMENTAL,authorization=auth)
        self.assertIn('F3_AUDIT_TYPE_UNKNOWN',codes)

    def auth(self, msha, **over):
        a = {"schema": D.AUTH_SCHEMA, "scope": "EXPERIMENTAL", "provisional": True, "dataset_manifest_sha256": msha,
             "authorized_by": "test", "date": "2026-10-19", "reference": "test-double", "purpose": "unit test",
             "uses_pending_labels_as_verified": False}
        a.update(over)
        p = os.path.join(self.tmp, "auth.json")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(a, fh)
        return p

    def test_refuses_fixture_and_missing_authorization(self):
        codes, _ = self.refused(D.EXPERIMENTAL)
        self.assertTrue({"EXPERIMENTAL_REFUSES_FIXTURE", "AUTHORIZATION_MISSING"} <= codes)

    def test_authorization_must_name_this_manifest_and_be_provisional(self):
        msha = self.provisional()
        codes, _ = self.refused(D.EXPERIMENTAL, authorization=self.auth("0" * 64, provisional=False,
                                                                        uses_pending_labels_as_verified=True))
        self.assertTrue({"AUTHORIZATION_DATASET_MISMATCH", "AUTHORIZATION_NOT_PROVISIONAL",
                         "AUTHORIZATION_LABEL_POLICY"} <= codes)
        p = D.prepare(D.EXPERIMENTAL, self.ds, out(D.EXPERIMENTAL), self.recipe, self.rsha,
                      authorization=self.auth(msha))
        self.assertEqual(p.mode, D.EXPERIMENTAL)

    def test_pending_labels_refused_even_when_authorized(self):
        msha = self.provisional()
        meta = os.path.join(self.ds, "rows.TRAIN.meta.jsonl")
        with open(meta, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        first = json.loads(lines[0])
        first["label_status"] = "PENDING_ADJUDICATION"
        lines[0] = json.dumps(first, sort_keys=True)
        data = ("\n".join(lines) + "\n").encode()
        with open(meta, "wb") as fh:
            fh.write(data)

        def fix_art(m):
            for a in m["artifacts"]:
                if a["path"] == "rows.TRAIN.meta.jsonl":
                    a.update(sha256=hashlib.sha256(data).hexdigest(), bytes=len(data))
        msha = self.edit_manifest(fix_art)
        codes, _ = self.refused(D.EXPERIMENTAL, authorization=self.auth(msha))
        self.assertIn("LABEL_NOT_TRAINABLE", codes)


class Final(Base):
    def test_fixture_and_proposed_recipe_are_refused_with_every_reason(self):
        self.recipe["status"]="PROPOSED"  # explicit negative control after D73
        self.recipe["lora"]["status"]="PROPOSED"
        codes, exc = self.refused(D.FINAL, installed_versions={}, git={"clean": True, "commit": "x"})
        for c in ("F1_NOT_A_REAL_BUILD", "F2_VALUE_NOT_RATIFIED", "F3_LABEL_BASIS", "F4_DATASET_PREREG",
                  "F5_DATASET_FREEZE", "F6_TRAINING_PREREG", "F7_RECIPE_NOT_RATIFIED", "F9_LIBRARY_PIN"):
            self.assertIn(c, codes)
        self.assertIn("training NOT started", str(exc))
        # gate-level diagnostics are never truncated: one F7 line per unratified entry (recipe top-level +
        # each unratified section). Computed from the loaded recipe so it tracks D71's partial ratification.
        self.assertEqual(sum(d.code == "F7_RECIPE_NOT_RATIFIED" for d in exc.diagnostics),
                         len(D.unratified_recipe_sections(self.recipe)))

    # ── positive path on a TEST DOUBLE: all gate inputs satisfied, git checks mocked ──
    def ratified_world(self, freeze_items=None, spec="V5-DATA-SPEC-r3", audit_type="human", outcomes=None,
                       item_audit_type="same", auth=None, row_basis=None):
        """Test double of every FINAL input. `audit_type` is the manifest provenance; `auth` = dict of overrides
        for a PROPOSED ai-audit authorization record (None = none supplied, True = a fully valid one)."""
        prereg = os.path.join(self.tmp, "prereg.json")
        # F8′: the dataset preregistration must carry the manifest's token budget B (and the ratified
        # vocabulary id, for the FINAL reader's vocabulary binding).
        with open(os.path.join(self.ds, "manifest.json"), encoding="utf-8") as fh:
            man_B = (json.load(fh).get("token_budget") or {}).get("B")
        with open(prereg, "w", encoding="utf-8") as fh:
            json.dump({"schema": "v5-dataset-preregistration/v1",
                       "ratified": {"token_budget": {"B": man_B}, "vocabulary_id": self.recipe["vocabulary"]["id"]}}, fh)
        prereg_sha = D.sha256_file(prereg)
        audit_bundle=None
        if audit_type == 'ai_audited':
            from tests.v5_audit_fixture import make_bundle
            audit_bundle=make_bundle(os.path.join(self.tmp,'final-audit-evidence'),
                records=list(v5_fixture.build_world().records.values()),outcomes=outcomes or {})

        def f(m):
            m.update(status="REAL", fixture=False, attack_label_basis="post_filter_audit",
                     preregistration_sha256=prereg_sha, spec=spec)
            if audit_type is not None:
                m["audit_type"] = audit_type
            m["generator_config"]["mode"] = "real"
            if audit_bundle:m['attack_pool_sha256']=audit_bundle['pool']['sha256']
            m["value_statuses"] = {k: "RATIFIED" for k in m["value_statuses"]}
        msha = self.edit_manifest(f)
        if row_basis is not None:
            msha = self.rewrite_meta(row_basis)
        recipe = copy.deepcopy(self.recipe)
        recipe["status"] = "RATIFIED"
        for s in D.RECIPE_SECTIONS:
            recipe[s]["status"] = "RATIFIED"
        rsha = "r" * 64
        ev_path = os.path.relpath(prereg, D.REPO_ROOT)
        items = freeze_items or D.FREEZE_ITEMS.get(spec, D.FREEZE_ITEMS["V5-DATA-SPEC-r3"])
        freeze = {"schema": D.FREEZE_SCHEMA, "status": "FROZEN", "spec": spec, "dataset_manifest_sha256": msha,
                  "owner_decision": "D-test", "items": {i: {"status": "DONE", "evidence": [
                      {"path": ev_path, "sha256": prereg_sha}]} for i in items}}
        if "post_filter_audit" in freeze["items"]:
            freeze["items"]["post_filter_audit"]["audit_type"] = audit_type if item_audit_type == "same" else item_audit_type
            if outcomes is not None:
                freeze["items"]["post_filter_audit"]["category_outcomes"] = outcomes
            if audit_bundle:freeze['items']['post_filter_audit']['audit_evidence']=audit_bundle
        tprereg = {"schema": D.TRAINING_PREREG_SCHEMA, "status": "RATIFIED", "recipe_sha256": rsha,
                   "template_fingerprint": D.template_fingerprint(recipe), "dataset_manifest_sha256": msha,
                   "owner_decision": "D-test"}
        paths = {}
        pending = [("freeze", freeze), ("tprereg", tprereg)]
        if auth is not None:
            pending.append(("auth", {"schema": D.PROPOSED_AI_AUDIT_AUTH_SCHEMA, "scope": "FINAL", "audit_type": "ai_audited",
                                     "dataset_manifest_sha256": msha, "authorized_by": "test", "date": "2026-10-20",
                                     "owner_decision": "D-test", "authorizes_ai_audited_final_training": True,
                                     "acknowledges_not_human_validation": True,
                                     "freeze_record_sha256": None, **(auth if isinstance(auth, dict) else {})}))
        for name, obj in pending:
            paths[name] = os.path.join(self.tmp, f"{name}.json")
            if name == "auth" and obj["freeze_record_sha256"] is None:
                obj["freeze_record_sha256"] = D.sha256_file(paths["freeze"])
            with open(paths[name], "w", encoding="utf-8") as fh:
                json.dump(obj, fh)
        versions = {k: v for k, v in recipe["library_pins"].items() if k not in ("status", "source")}
        kw = dict(dataset_prereg=prereg, freeze_record=paths["freeze"], training_prereg=paths["tprereg"],
                  installed_versions=versions, git={"clean": True, "commit": "x"})
        if "auth" in paths:
            kw["ai_audit_authorization"] = paths["auth"]
        return recipe, rsha, kw

    def test_final_passes_only_when_every_condition_holds(self):
        recipe, rsha, kw = self.ratified_world()
        with mock.patch.object(D, "git_committed_unmodified", return_value=True), \
                mock.patch.object(D, "DATASET_PREREG_DIR", os.path.relpath(self.tmp, D.REPO_ROOT)):
            p = D.prepare(D.FINAL, self.ds, out(D.FINAL), recipe, rsha, **kw)
            self.assertEqual(p.mode, D.FINAL)
            # each single violation flips it back to REFUSED
            for breaker, code in ((dict(git={"clean": False, "commit": "x", "tracked_dirty_files": ["a"]}),
                                   "F9_GIT_NOT_CLEAN"),
                                  (dict(installed_versions={}), "F9_LIBRARY_PIN")):
                with self.assertRaises(D.GateRefused) as cm:
                    D.prepare(D.FINAL, self.ds, out(D.FINAL), recipe, rsha, **{**kw, **breaker})
                self.assertIn(code, {d.code for d in cm.exception.diagnostics})
            r2 = copy.deepcopy(recipe)
            r2["loss"]["status"] = "PROPOSED"
            with self.assertRaises(D.GateRefused) as cm:
                D.prepare(D.FINAL, self.ds, out(D.FINAL), r2, rsha, **kw)
            self.assertIn("F7_RECIPE_NOT_RATIFIED", {d.code for d in cm.exception.diagnostics})
        # uncommitted preregistration / records are refused
        with mock.patch.object(D, "DATASET_PREREG_DIR", os.path.relpath(self.tmp, D.REPO_ROOT)):
            with self.assertRaises(D.GateRefused) as cm:
                D.prepare(D.FINAL, self.ds, out(D.FINAL), recipe, rsha, **kw)
        self.assertTrue({"F4_DATASET_PREREG", "F5_DATASET_FREEZE", "F6_TRAINING_PREREG"}
                        <= {d.code for d in cm.exception.diagnostics})

    def test_missing_section_11_3_item_is_refused(self):
        items = D.FREEZE_ITEMS["V5-DATA-SPEC-r3"][1:]           # human review missing
        recipe, rsha, kw = self.ratified_world(freeze_items=items)
        with mock.patch.object(D, "git_committed_unmodified", return_value=True), \
                mock.patch.object(D, "DATASET_PREREG_DIR", os.path.relpath(self.tmp, D.REPO_ROOT)):
            with self.assertRaises(D.GateRefused) as cm:
                D.prepare(D.FINAL, self.ds, out(D.FINAL), recipe, rsha, **kw)
        details = [d.detail for d in cm.exception.diagnostics if d.code == "F5_DATASET_FREEZE"]
        self.assertTrue(any("human_review_prefilter_sample" in x for x in details), details)

    def test_unknown_spec_revision_is_not_silently_accepted(self):
        # An unknown revision remains rejected after D72 activates r4.
        recipe, rsha, kw = self.ratified_world(spec="V5-DATA-SPEC-r999")
        with mock.patch.object(D, "git_committed_unmodified", return_value=True), \
                mock.patch.object(D, "DATASET_PREREG_DIR", os.path.relpath(self.tmp, D.REPO_ROOT)):
            with self.assertRaises(D.GateRefused) as cm:
                D.prepare(D.FINAL, self.ds, out(D.FINAL), recipe, rsha, **kw)
        codes = {d.code for d in cm.exception.diagnostics}
        self.assertIn("SPEC_UNSUPPORTED", codes)
        self.assertIn("F3_AUDIT_TYPE_SPEC_MISMATCH", codes)       # r4 does not accept a `human` claim


class AiAuditGate(Base):
    """PROPOSAL tests (D67 / r4): audit provenance, category outcome, row status and the owner authorization are
    four separate facts. r4 is not in SUPPORTED_SPECS, no authorization schema is ratified, and no ai_audit row
    status is authorized, so every positive path below patches those THREE constants explicitly — the module
    defaults stay refuse."""

    ratified_world = Final.ratified_world

    R4 = "V5-DATA-SPEC-r4"

    def ctx(self, *, r4=True, schema=True, row_status=True, committed=lambda path: True):
        from contextlib import ExitStack
        st = ExitStack()
        st.enter_context(mock.patch.object(D, "git_committed_unmodified", side_effect=committed))
        st.enter_context(mock.patch.object(D, "DATASET_PREREG_DIR", os.path.relpath(self.tmp, D.REPO_ROOT)))
        st.enter_context(mock.patch.object(D,"SUPPORTED_SPECS",("V5-DATA-SPEC-r3",self.R4) if r4 else ("V5-DATA-SPEC-r3",)))
        st.enter_context(mock.patch.object(D,"AI_AUDIT_AUTH_SCHEMA",D.PROPOSED_AI_AUDIT_AUTH_SCHEMA if schema else None))
        if row_status:   # the ai_audit + POLICY_DEFINED row status is refused by default; a positive path enables it
            st.enter_context(mock.patch.object(D, "AI_AUDIT_ROW_STATUS_ALLOWED", ("POLICY_DEFINED",)))
        return st

    def train_statuses(self):
        with open(os.path.join(self.ds, "rows.TRAIN.meta.jsonl"), encoding="utf-8") as fh:
            return [json.loads(ln)["label_status"] for ln in fh if ln.strip()]

    def attack_categories(self):
        cats = set()
        for split in ("TRAIN", "VALIDATION"):
            with open(os.path.join(self.ds, f"rows.{split}.meta.jsonl"), encoding="utf-8") as fh:
                cats |= {m["attack_category"] for m in map(json.loads, fh) if m["label"] == "BLOCK"}
        return sorted(cats)

    @staticmethod
    def ai_rows(m):
        if m["label"] == "BLOCK":
            m.update(label_status="POLICY_DEFINED", label_status_basis="ai_audit")

    def ai_world(self, outcomes="pass", row_basis="default", auth=True, **kw):
        if outcomes == "pass":
            outcomes = {c: D.OUTCOME_PASS for c in self.attack_categories()}
        return self.ratified_world(spec=self.R4, audit_type="ai_audited", outcomes=outcomes, auth=auth,
                                   row_basis=self.ai_rows if row_basis == "default" else row_basis, **kw)

    def run_final(self, recipe, rsha, kw, **ctxkw):
        with self.ctx(**ctxkw):
            return D.prepare(D.FINAL, self.ds, out(D.FINAL), recipe, rsha, **kw)

    def refused_final(self, recipe, rsha, kw, **ctxkw):
        with self.assertRaises(D.GateRefused) as cm:
            self.run_final(recipe, rsha, kw, **ctxkw)
        return {d.code for d in cm.exception.diagnostics}, [d.detail for d in cm.exception.diagnostics]

    # (a) the retired gate item is removed deliberately, only in the r4 table
    def test_r4_retires_human_prefilter_item_explicitly_and_r3_is_untouched(self):
        r3, r4 = D.FREEZE_ITEMS["V5-DATA-SPEC-r3"], D.FREEZE_ITEMS[self.R4]
        self.assertIn("human_review_prefilter_sample", r3)
        self.assertNotIn("human_review_prefilter_sample", r4)
        self.assertEqual(r4, tuple(i for i in r3 if i != "human_review_prefilter_sample"))
        self.assertEqual(D.SUPPORTED_SPECS, ("V5-DATA-SPEC-r3", self.R4))  # D72

    # positive control: the whole proposed chain is satisfiable on a test double, and only then
    def test_ai_audited_final_passes_only_with_every_separate_input(self):
        recipe, rsha, kw = self.ai_world()
        p = self.run_final(recipe, rsha, kw)
        self.assertEqual(p.gate_evidence["audit_type"], "ai_audited")
        self.assertTrue(p.gate_evidence["ai_audit_authorization_supplied"])

    def test_revoking_contract_activation_refuses_even_with_a_complete_record(self):
        recipe, rsha, kw = self.ai_world()
        codes, details = self.refused_final(recipe, rsha, kw, r4=False, schema=False)
        self.assertIn("SPEC_UNSUPPORTED", codes)
        self.assertIn("F10_AI_AUDIT_AUTHORIZATION", codes)
        # r4 activated but authorization schema still unratified: the record alone cannot authorize
        codes, details = self.refused_final(recipe, rsha, kw, r4=True, schema=False)
        self.assertEqual(codes, {"F10_AI_AUDIT_AUTHORIZATION"})
        self.assertTrue(any("no ratified" in x for x in details))

    # (c) no authorization -> FINAL refused, even when every other record is valid and every row is POLICY_DEFINED
    def test_ai_audited_without_authorization_is_refused(self):
        recipe, rsha, kw = self.ai_world(auth=None)
        codes, details = self.refused_final(recipe, rsha, kw)
        self.assertEqual(codes, {"F10_AI_AUDIT_AUTHORIZATION"})
        self.assertTrue(any("--ai-audit-authorization" in x for x in details))

    def test_invalid_authorization_records_are_refused(self):
        cases = {
            "wrong dataset": {"dataset_manifest_sha256": "0" * 64},
            "unbound freeze record": {"freeze_record_sha256": "1" * 64},
            "wrong scope": {"scope": "EXPERIMENTAL"},
            "wrong audit_type": {"audit_type": "human"},
            "wrong schema": {"schema": "v5-ai-audit-training-authorization/v9"},
            "not authorizing": {"authorizes_ai_audited_final_training": False},
            "no human-validation ack": {"acknowledges_not_human_validation": "yes"},
            "empty owner decision": {"owner_decision": " "},
        }
        for name, over in cases.items():
            with self.subTest(name):
                self.setUp()
                recipe, rsha, kw = self.ai_world(auth=over)
                codes, _ = self.refused_final(recipe, rsha, kw)
                self.assertEqual(codes, {"F10_AI_AUDIT_AUTHORIZATION"}, name)

    def test_authorization_must_be_committed_and_a_separate_file(self):
        recipe, rsha, kw = self.ai_world()
        auth = kw["ai_audit_authorization"]
        codes, _ = self.refused_final(recipe, rsha, kw, committed=lambda path: path != auth)
        self.assertEqual(codes, {"F10_AI_AUDIT_AUTHORIZATION"})
        for other in ("training_prereg", "freeze_record", "dataset_prereg"):     # bundled into another record
            codes, details = self.refused_final(recipe, rsha, {**kw, "ai_audit_authorization": kw[other]})
            self.assertIn("F10_AI_AUDIT_AUTHORIZATION", codes, other)
            self.assertTrue(any("its own record" in x for x in details), other)

    # (b) provenance is its own fact: missing / unknown / not allowed by the spec revision / inconsistent
    def test_missing_or_unknown_audit_type_is_refused(self):
        for bad in (None, "", "AI", "ai", "model_consensus", "human+ai", ["ai_audited"], 1):
            with self.subTest(audit_type=bad):
                self.setUp()
                recipe, rsha, kw = self.ratified_world(audit_type=None)       # manifest without the field ...
                if bad is not None:
                    self.edit_manifest(lambda m: m.update(audit_type=bad))      # ... or with a bad value
                    # re-sign the records to the edited manifest so ONLY provenance is wrong
                    msha = D.sha256_file(os.path.join(self.ds, "manifest.json"))
                    for k in ("freeze_record", "training_prereg"):
                        with open(kw[k], encoding="utf-8") as fh:
                            rec = json.load(fh)
                        rec["dataset_manifest_sha256"] = msha
                        with open(kw[k], "w", encoding="utf-8") as fh:
                            json.dump(rec, fh)
                codes, _ = self.refused_final(recipe, rsha, kw)
                self.assertIn("F3_AUDIT_TYPE_UNKNOWN", codes)

    def test_attack_label_basis_alone_never_implies_provenance(self):
        recipe, rsha, kw = self.ratified_world(audit_type=None)
        with open(os.path.join(self.ds, "manifest.json"), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["attack_label_basis"], "post_filter_audit")
        codes, _ = self.refused_final(recipe, rsha, kw)
        self.assertIn("F3_AUDIT_TYPE_UNKNOWN", codes)

    def test_audit_type_must_match_the_spec_revision(self):
        recipe, rsha, kw = self.ratified_world(audit_type="ai_audited")                 # r3 demands human review
        codes, _ = self.refused_final(recipe, rsha, kw, r4=False)
        self.assertIn("F3_AUDIT_TYPE_SPEC_MISMATCH", codes)
        recipe, rsha, kw = self.ratified_world(spec=self.R4, audit_type="human")        # r4 is the AI protocol
        codes, _ = self.refused_final(recipe, rsha, kw)
        self.assertIn("F3_AUDIT_TYPE_SPEC_MISMATCH", codes)

    def test_freeze_record_and_manifest_must_agree_on_provenance(self):
        for item_type in ("human", None, "unknown"):
            self.setUp()
            recipe, rsha, kw = self.ai_world(item_audit_type=item_type)
            codes, details = self.refused_final(recipe, rsha, kw)
            self.assertIn("F5_DATASET_FREEZE", codes, item_type)
            self.assertTrue(any("post_filter_audit.audit_type" in x for x in details), item_type)

    # (2) category outcome: only PASS_AI_AUDITED for categories that actually have rows
    def test_non_pass_or_missing_category_outcome_is_refused(self):
        cats = self.attack_categories()
        self.assertGreaterEqual(len(cats), 2)
        for label, value, code in (("FAIL", "FAIL", "AUDIT_CATEGORY_NOT_PASSED"),
                                   ("INSUFFICIENT_EVIDENCE", "INSUFFICIENT_EVIDENCE", "AUDIT_CATEGORY_NOT_PASSED"),
                                   ("PENDING", "PENDING", "F5_DATASET_FREEZE"),
                                   ("VERIFIED as outcome", "VERIFIED", "F5_DATASET_FREEZE"),
                                   ("missing", None, "AUDIT_CATEGORY_OUTCOME_MISSING")):
            with self.subTest(label):
                self.setUp()
                outcomes = {c: D.OUTCOME_PASS for c in cats}
                if value is None:
                    del outcomes[cats[0]]
                else:
                    outcomes[cats[0]] = value
                recipe, rsha, kw = self.ai_world(outcomes=outcomes)
                codes, _ = self.refused_final(recipe, rsha, kw)
                self.assertIn(code, codes)

    def test_failed_category_without_rows_does_not_block(self):
        cats = self.attack_categories()
        outcomes = {c: D.OUTCOME_PASS for c in cats} | {"Server Side Request Forgery": "FAIL"}   # excluded, no rows
        recipe, rsha, kw = self.ai_world(outcomes=outcomes)
        self.assertEqual(self.run_final(recipe, rsha, kw).mode, D.FINAL)

    # (3) row status: an audit pass never sets / implies VERIFIED, and no other accepted status is a back door
    def test_audit_based_label_cannot_be_verified(self):
        def verified(m):
            if m["label"] == "BLOCK":
                m.update(label_status="VERIFIED", label_status_basis="ai_audit")
        recipe, rsha, kw = self.ai_world(row_basis=verified)
        codes, _ = self.refused_final(recipe, rsha, kw)
        self.assertIn("AUDIT_CONFERRED_VERIFIED", codes)

    def test_attack_rows_of_an_ai_audited_dataset_need_a_known_consistent_basis(self):
        for name, fn, code in (
                ("missing", lambda m: m.update(label_status="POLICY_DEFINED") if m["label"] == "BLOCK" else None,
                 "AUDIT_ROW_BASIS_MISSING"),
                ("unknown", lambda m: m.update(label_status="POLICY_DEFINED", label_status_basis="vibes") if m["label"] == "BLOCK" else None,
                 "AUDIT_ROW_BASIS_MISSING"),
                ("independent-but-policy", lambda m: m.update(label_status="POLICY_DEFINED", label_status_basis="independent_evidence")
                 if m["label"] == "BLOCK" else None, "AUDIT_ROW_BASIS_INCONSISTENT")):
            with self.subTest(name):
                self.setUp()
                recipe, rsha, kw = self.ai_world(row_basis=fn)
                codes, _ = self.refused_final(recipe, rsha, kw)
                self.assertIn(code, codes)

    def test_audit_outcome_tokens_are_not_row_statuses(self):
        self.assertFalse(set(D.TRAINABLE_LABEL_STATUSES) & D.AUDIT_OUTCOME_TOKENS)
        self.assertEqual(D.TRAINABLE_LABEL_STATUSES, ("VERIFIED", "POLICY_DEFINED"))
        rows = D.load_split(self.ds, "TRAIN")[0]
        for token in ("PASS_AI_AUDITED", "AI_AUDITED", "INSUFFICIENT_EVIDENCE", "FAIL"):
            r = copy.deepcopy(rows[:1])
            r[0]["meta"]["label_status"] = token
            codes = {d.code for d in D.check_rows(r, D.recipe_vocabulary(self.recipe))}
            self.assertTrue({"LABEL_NOT_TRAINABLE", "LABEL_STATUS_IS_AUDIT_OUTCOME"} <= codes, token)

    def test_gates_never_rewrite_row_statuses(self):
        recipe, rsha, kw = self.ai_world()
        p = self.run_final(recipe, rsha, kw)
        on_disk = self.train_statuses()
        self.assertEqual([r["meta"]["label_status"] for r in p.train_rows], on_disk)
        self.assertNotIn("VERIFIED", {r["meta"]["label_status"] for r in p.train_rows if r["meta"]["label"] == "BLOCK"})

    def test_ai_audit_row_cannot_hide_inside_a_human_declared_dataset(self):
        recipe, rsha, kw = self.ratified_world(audit_type="human", row_basis=self.ai_rows)   # POLICY_DEFINED rows
        codes, _ = self.refused_final(recipe, rsha, kw, r4=False)
        self.assertIn("AUDIT_ROW_BASIS_CONTRADICTS_MANIFEST", codes)

    def test_policy_defined_rows_are_no_path_around_the_authorization(self):
        recipe, rsha, kw = self.ai_world(auth=None)
        kw.pop("ai_audit_authorization", None)
        self.assertIn("POLICY_DEFINED", self.train_statuses())
        self.assertEqual(self.refused_final(recipe, rsha, kw)[0], {"F10_AI_AUDIT_AUTHORIZATION"})

    def test_experimental_refuses_unknown_audit_type(self):
        self.edit_manifest(lambda m: m.update(status="REAL", fixture=False, attack_label_basis="post_filter_audit",
                                              audit_type="model_consensus"))
        self.edit_manifest(lambda m: m["generator_config"].update(mode="real"))
        codes, _ = self.refused(D.EXPERIMENTAL)
        self.assertIn("F3_AUDIT_TYPE_UNKNOWN", codes)

    # ── reproduced-defect fixes (handoff 2026-10-23) ──
    def test_experimental_refuses_audit_type_spec_mismatch(self):
        # an EXPERIMENTAL authorization must not turn an ai_audited (r4) provenance into r3; spec stays r3.
        self.edit_manifest(lambda m: m.update(status="REAL", fixture=False, attack_label_basis="post_filter_audit",
                                              audit_type="ai_audited"))
        self.edit_manifest(lambda m: m["generator_config"].update(mode="real"))
        codes, _ = self.refused(D.EXPERIMENTAL)
        self.assertIn("F3_AUDIT_TYPE_SPEC_MISMATCH", codes)

    def test_ai_audit_policy_defined_row_status_refused_by_default(self):
        # the ai_audit + POLICY_DEFINED assignment is an OPEN OWNER DECISION: refused unless explicitly enabled.
        recipe, rsha, kw = self.ai_world()
        codes, details = self.refused_final(recipe, rsha, kw, row_status=False)
        self.assertIn("AUDIT_ROW_STATUS_NOT_AUTHORIZED", codes)
        self.assertTrue(any("allowed by D72" in x for x in details))
        # and WITH the explicit enable it is accepted (positive control uses a test-double only)
        self.assertEqual(self.run_final(recipe, rsha, kw).mode, D.FINAL)

    def test_ai_audit_verified_is_refused_even_in_an_allow_row(self):
        def allow_verified(m):
            if m["label"] == "BLOCK":
                m.update(label_status="POLICY_DEFINED", label_status_basis="ai_audit")
            else:  # an ai_audit basis smuggled onto a VERIFIED ALLOW row must still be caught
                m.update(label_status="VERIFIED", label_status_basis="ai_audit")
        recipe, rsha, kw = self.ai_world(row_basis=allow_verified)
        codes, _ = self.refused_final(recipe, rsha, kw)
        self.assertIn("AUDIT_CONFERRED_VERIFIED", codes)

    def test_block_row_without_attack_category_is_refused(self):
        # a BLOCK row whose attack_category is missing must NOT slip through with an empty outcomes map.
        def no_cat(m):
            if m["label"] == "BLOCK":
                m.update(label_status="POLICY_DEFINED", label_status_basis="ai_audit", attack_category=None)
        recipe, rsha, kw = self.ai_world(row_basis=no_cat)
        codes, _ = self.refused_final(recipe, rsha, kw)
        self.assertIn("BLOCK_ROW_WITHOUT_CATEGORY", codes)

    # ── the DATASET FINAL consumption path (reader), separate from the model recipe ──
    def _reader(self):
        sys.path.insert(0, os.path.join(REPO, "scripts", "training"))
        import v5_example_exchange as E
        return E

    def test_load_final_examples_consumes_dataset_without_model_recipe(self):
        E = self._reader()
        recipe, rsha, kw = self.ai_world()
        with self.ctx():
            out = E.load_final_examples(self.ds, dataset_prereg=kw["dataset_prereg"],
                                        freeze_record=kw["freeze_record"],
                                        ai_audit_authorization=kw["ai_audit_authorization"], recipe_path=RECIPE)
        ev = out["dataset_final_evidence"]
        self.assertEqual(ev["mode"], "FINAL")
        self.assertEqual(ev["audit_type"], "ai_audited")
        self.assertEqual(ev["attack_label_basis"], "post_filter_audit")
        self.assertTrue(out["examples"]["TRAIN"] and out["examples"]["VALIDATION"])
        self.assertEqual(ev["splits_never_opened"][:2], ["INTERNAL_TEST", "E6_RESERVE"])
        # the model-recipe gates are explicitly NOT run here; no LoRA/TinyLlama imposed
        self.assertIn("LoRA/TinyLlama_pins", ev["model_recipe_gates_not_run"])
        # the returned vocabulary is bound to the dataset preregistration's ratified contract
        self.assertTrue(ev["vocabulary_bound_to_preregistration"])
        # evidence shas are the CAPTURED bytes' shas (match the files on disk)
        self.assertEqual(ev["freeze_record_sha256"], D.sha256_file(kw["freeze_record"]))
        self.assertEqual(ev["preregistration_sha256"], D.sha256_file(kw["dataset_prereg"]))
        # audit metadata flows to the consumer, never promoted to VERIFIED
        self.assertTrue(all(e["label_status"] != "VERIFIED" or e["label"] != "BLOCK"
                            for e in out["examples"]["TRAIN"]))

    def test_f8_prime_binds_manifest_B_to_dataset_preregistration_B(self):
        base = {"schema": D.MANIFEST_SCHEMA, "spec": "V5-DATA-SPEC-r3", "status": "REAL",
                "generator_config": {"mode": "real"}, "gates": {"ok": True}, "value_statuses": {"x": "RATIFIED"},
                "attack_label_basis": "post_filter_audit", "audit_type": "human",
                "preregistration_sha256": "p" * 64, "token_budget": {"B": 415}}
        match = {"prereg": ("p" * 64, {"ratified": {"token_budget": {"B": 415}}}, None),
                 "freeze": (None, None, None), "auth": (None, None, None)}
        codes = {d.code for d in D.gate_dataset_final(base, "m" * 64, dataset_prereg="prereg.json",
                                                      freeze_record=None, captured=match)}
        self.assertNotIn("F8_DATASET_TOKEN_BUDGET_MISMATCH", codes)
        mism = dict(match, prereg=("p" * 64, {"ratified": {"token_budget": {"B": 1}}}, None))
        codes = {d.code for d in D.gate_dataset_final(base, "m" * 64, dataset_prereg="prereg.json",
                                                      freeze_record=None, captured=mism)}
        self.assertIn("F8_DATASET_TOKEN_BUDGET_MISMATCH", codes)

    def test_load_final_examples_captures_freeze_exactly_once(self):
        E = self._reader()
        recipe, rsha, kw = self.ai_world()
        freeze, real_open, n = kw["freeze_record"], open, {"c": 0}

        def counting(path, *a, **k):
            if path == freeze:
                n["c"] += 1
            return real_open(path, *a, **k)
        with self.ctx(), mock.patch("builtins.open", counting):
            E.load_final_examples(self.ds, dataset_prereg=kw["dataset_prereg"], freeze_record=freeze,
                                  ai_audit_authorization=kw["ai_audit_authorization"], recipe_path=RECIPE)
        self.assertEqual(n["c"], 1)   # single capture (previously read in the gate AND via audit_item AND _sha)

    def test_load_final_examples_rejects_a_changed_freeze_record(self):
        E = self._reader()
        recipe, rsha, kw = self.ai_world()
        with open(kw["freeze_record"], "a", encoding="utf-8") as fh:
            fh.write(" ")                       # mutate the bytes after the authorization bound its sha
        with self.ctx(), self.assertRaises(E.ExampleExchangeError) as cm:
            E.load_final_examples(self.ds, dataset_prereg=kw["dataset_prereg"], freeze_record=kw["freeze_record"],
                                  ai_audit_authorization=kw["ai_audit_authorization"], recipe_path=RECIPE)
        self.assertIn("F10_AI_AUDIT_AUTHORIZATION", str(cm.exception))

    def test_load_final_examples_refuses_a_fixture_build(self):
        E = self._reader()
        with self.assertRaises(E.ExampleExchangeError) as cm:
            # no ratified_world edits: self.ds is still the stage-4 FIXTURE, so dataset-FINAL gates refuse it
            E.load_final_examples(self.ds, dataset_prereg=None, freeze_record=None, recipe_path=RECIPE)
        self.assertIn("F1_NOT_A_REAL_BUILD", str(cm.exception))

    # ── item 4: category eligibility also in an authorized EXPERIMENTAL (provisional) ai_audited dataset ──
    def _experimental_ai(self, outcomes):
        self.rewrite_meta(self.ai_rows)                       # BLOCK rows → ai_audit / POLICY_DEFINED
        def f(m):
            m.update(status="REAL", fixture=False, attack_label_basis="post_filter_audit",
                     spec=self.R4, audit_type="ai_audited")
            m["generator_config"]["mode"] = "real"
        from tests.v5_audit_fixture import make_bundle
        self.audit_bundle=make_bundle(os.path.join(self.tmp,'audit-evidence'),records=list(v5_fixture.build_world().records.values()),outcomes=outcomes or {})
        msha = self.edit_manifest(lambda m:(f(m),m.update(attack_pool_sha256=self.audit_bundle['pool']['sha256'])))
        auth = os.path.join(self.tmp, "expauth.json")
        rec = {"schema": D.AUTH_SCHEMA, "scope": "EXPERIMENTAL", "provisional": True,
               "uses_pending_labels_as_verified": False, "dataset_manifest_sha256": msha,
               "authorized_by": "o", "date": "2026-10-23", "reference": "r", "purpose": "p",
               "audit_evidence":self.audit_bundle}
        if outcomes is not None:
            rec["category_outcomes"] = outcomes
        with open(auth, "w", encoding="utf-8") as fh:
            json.dump(rec, fh)
        return auth

    def test_experimental_ai_audited_enforces_category_eligibility(self):
        cats = self.attack_categories()
        self.assertGreaterEqual(len(cats), 2)
        # all PASS → the provisional run is consumable
        auth = self._experimental_ai({c: D.OUTCOME_PASS for c in cats})
        with self.ctx():
            p = D.prepare(D.EXPERIMENTAL, self.ds, out(D.EXPERIMENTAL), self.recipe, self.rsha, authorization=auth)
        self.assertEqual(p.mode, D.EXPERIMENTAL)
        # a FAIL / INSUFFICIENT category is refused EVEN with a valid authorization (provisional is not a bypass)
        for value, code in (("FAIL", "AUDIT_CATEGORY_NOT_PASSED"),
                            ("INSUFFICIENT_EVIDENCE", "AUDIT_CATEGORY_NOT_PASSED"),
                            (None, "AUTHORIZATION_AUDIT_EVIDENCE")):
            self.setUp()
            cats = self.attack_categories()
            outs = None if value is None else {**{c: D.OUTCOME_PASS for c in cats}, cats[0]: value}
            auth = self._experimental_ai(outs)
            with self.ctx(), self.assertRaises(D.GateRefused) as cm:
                D.prepare(D.EXPERIMENTAL, self.ds, out(D.EXPERIMENTAL), self.recipe, self.rsha, authorization=auth)
            self.assertIn(code, {d.code for d in cm.exception.diagnostics})

    def test_final_requires_an_explicit_vocabulary_binding(self):
        E=self._reader();_,_,kw=self.ai_world()
        prereg=kw['dataset_prereg'];doc=D._load_json(prereg);doc['ratified'].pop('vocabulary_id')
        with open(prereg,'w') as fh:json.dump(doc,fh)
        sha=D.sha256_file(prereg)
        msha=self.edit_manifest(lambda m:m.update(preregistration_sha256=sha))
        freeze=D._load_json(kw['freeze_record']);freeze['dataset_manifest_sha256']=msha
        for item in freeze['items'].values():
            for ev in item.get('evidence',[]):ev['sha256']=sha
        with open(kw['freeze_record'],'w') as fh:json.dump(freeze,fh)
        auth=D._load_json(kw['ai_audit_authorization']);auth.update(dataset_manifest_sha256=msha,
            freeze_record_sha256=D.sha256_file(kw['freeze_record']))
        with open(kw['ai_audit_authorization'],'w') as fh:json.dump(auth,fh)
        with self.ctx(),self.assertRaisesRegex(E.ExampleExchangeError,'VOCABULARY_NOT_BOUND'):
            E.load_final_examples(self.ds,dataset_prereg=prereg,freeze_record=kw['freeze_record'],
                ai_audit_authorization=kw['ai_audit_authorization'],recipe_path=RECIPE)

    def test_experimental_rejects_unbound_audit_before_reading_rows(self):
        cats=self.attack_categories();auth=self._experimental_ai({c:D.OUTCOME_PASS for c in cats})
        doc=D._load_json(auth);doc.pop('audit_evidence')
        with open(auth,'w') as fh:json.dump(doc,fh)
        with self.ctx(),mock.patch.object(D,'capture_and_parse_split',side_effect=AssertionError('row read')):
            with self.assertRaises(D.GateRefused) as cm:
                D.prepare(D.EXPERIMENTAL,self.ds,out(D.EXPERIMENTAL),self.recipe,self.rsha,authorization=auth)
        self.assertIn('AUTHORIZATION_AUDIT_EVIDENCE',{d.code for d in cm.exception.diagnostics})

    def test_final_trainer_captures_freeze_once(self):
        recipe,rsha,kw=self.ai_world();freeze=kw['freeze_record'];real_open=open;calls=[]
        def counting(path,*args,**kwargs):
            if path==freeze:calls.append(path)
            return real_open(path,*args,**kwargs)
        with self.ctx(),mock.patch('builtins.open',counting):
            D.prepare(D.FINAL,self.ds,out(D.FINAL),recipe,rsha,**kw)
        self.assertEqual(len(calls),1)

    def test_experimental_captures_authorization_once(self):
        cats=self.attack_categories();auth=self._experimental_ai({c:D.OUTCOME_PASS for c in cats})
        E=self._reader();real_open=open;calls=[]
        def counting(path,*args,**kwargs):
            if path==auth:calls.append(path)
            return real_open(path,*args,**kwargs)
        with self.ctx(),mock.patch('builtins.open',counting):E.load_examples(self.ds,authorization=auth,recipe_path=RECIPE)
        self.assertEqual(len(calls),1)

    def test_final_freeze_cannot_override_pinned_audit_outcomes(self):
        _,_,kw=self.ai_world();freeze=D._load_json(kw['freeze_record'])
        cat=self.attack_categories()[0];freeze['items']['post_filter_audit']['category_outcomes'][cat]='FAIL'
        with open(kw['freeze_record'],'w') as fh:json.dump(freeze,fh)
        auth=D._load_json(kw['ai_audit_authorization']);auth['freeze_record_sha256']=D.sha256_file(kw['freeze_record'])
        with open(kw['ai_audit_authorization'],'w') as fh:json.dump(auth,fh)
        E=self._reader()
        with self.ctx(),self.assertRaisesRegex(E.ExampleExchangeError,'F5_DATASET_FREEZE'):
            E.load_final_examples(self.ds,dataset_prereg=kw['dataset_prereg'],freeze_record=kw['freeze_record'],
                ai_audit_authorization=kw['ai_audit_authorization'],recipe_path=RECIPE)

    def test_final_row_must_name_an_audited_record(self):
        _,_,kw=self.ai_world();changed=[]
        def corrupt(meta):
            if meta['label']=='BLOCK' and not changed:
                meta['payload_record_id']='not-in-audited-pool';changed.append(True)
        msha=self.rewrite_meta(corrupt)
        freeze=D._load_json(kw['freeze_record']);freeze['dataset_manifest_sha256']=msha
        with open(kw['freeze_record'],'w') as fh:json.dump(freeze,fh)
        auth=D._load_json(kw['ai_audit_authorization']);auth.update(dataset_manifest_sha256=msha,
            freeze_record_sha256=D.sha256_file(kw['freeze_record']))
        with open(kw['ai_audit_authorization'],'w') as fh:json.dump(auth,fh)
        E=self._reader()
        with self.ctx(),self.assertRaisesRegex(E.ExampleExchangeError,'AUDIT_POOL_MEMBERSHIP'):
            E.load_final_examples(self.ds,dataset_prereg=kw['dataset_prereg'],freeze_record=kw['freeze_record'],
                ai_audit_authorization=kw['ai_audit_authorization'],recipe_path=RECIPE)

    def test_record_and_manifest_symlinks_cannot_open_reserved_roles(self):
        protected=os.path.join(self.tmp,'E6_RESERVE','data.json');os.makedirs(os.path.dirname(protected))
        with open(protected,'w') as fh:json.dump({},fh)
        real_open=open
        def guarded(path,*args,**kwargs):
            if os.path.realpath(path)==protected:raise AssertionError('reserved role opened')
            return real_open(path,*args,**kwargs)
        with mock.patch('builtins.open',guarded):
            self.assertIsNotNone(D._capture_record(protected)[2])
            with self.assertRaises(ValueError):D.load_recipe(protected)
            path=os.path.join(self.ds,'manifest.json');os.unlink(path);os.symlink(protected,path)
            with self.assertRaises(ValueError):D.load_manifest(self.ds)

    def test_e6_and_stab_symlinks_are_refused_before_open(self):
        manifest,_=D.load_manifest(self.ds)
        row=os.path.join(self.ds,D.ROWS_FILE.format(split='TRAIN'))
        with open(row,'rb') as fh:original=fh.read()
        real_open=open
        for role in ('E6_RESERVE','STAB-HELD'):
            target=os.path.join(self.tmp,role,'data.jsonl');os.makedirs(os.path.dirname(target))
            with open(target,'wb') as fh:fh.write(original)
            os.unlink(row);os.symlink(target,row)
            def guarded(path,*a,**kw):
                if os.path.realpath(path)==target:raise AssertionError('protected target opened')
                return real_open(path,*a,**kw)
            with mock.patch('builtins.open',guarded):
                _,diags=D.capture_and_parse_split(self.ds,manifest,'TRAIN')
            self.assertIn('PROTECTED_PATH',{d.code for d in diags})
            os.unlink(row)
            with open(row,'wb') as fh:fh.write(original)

    # ── item 5: path protection on public readers and before opening artifacts (symlinks included) ──
    def test_symlink_to_a_protected_role_is_refused_before_open(self):
        manifest, _ = D.load_manifest(self.ds)
        prot = os.path.join(self.tmp, "internal_test_payloads.jsonl")   # protected-named target
        with open(prot, "w", encoding="utf-8") as fh:
            fh.write('{"text":"x","output":"y"}\n')
        tgt = os.path.join(self.ds, "rows.TRAIN.jsonl")
        os.remove(tgt)
        os.symlink(prot, tgt)                                           # rows file now points at a protected role
        real_open, hit = open, {"opened": False}

        def spy(path, *a, **k):
            if os.path.realpath(path) == os.path.realpath(prot):
                hit["opened"] = True
            return real_open(path, *a, **k)
        with mock.patch("builtins.open", spy):
            _, diags = D.capture_and_parse_split(self.ds, manifest, "TRAIN")
        self.assertIn("PROTECTED_PATH", {d.code for d in diags})
        self.assertFalse(hit["opened"])                                 # the protected target is never opened

    def test_public_reader_checks_path_protection_at_entry(self):
        E = self._reader()
        with mock.patch.object(D.C, "assert_not_protected", side_effect=SystemExit("protected material")):
            diags = E.gate_diagnostics(self.ds)
        self.assertIn("PROTECTED_PATH", {getattr(d, "code", None) for d in diags})

    def test_cli_exposes_the_authorization_flag_default_none(self):
        sys.path.insert(0, os.path.join(REPO, "scripts", "training"))
        try:
            import finetune_v5
        except Exception as exc:          # pragma: no cover - heavy imports unavailable
            self.skipTest(f"finetune_v5 not importable ({type(exc).__name__})")
        a = finetune_v5.parse_args(["--mode", "final", "--dataset", "x"])
        self.assertIsNone(a.ai_audit_authorization)
        a = finetune_v5.parse_args(["--mode", "final", "--dataset", "x", "--ai-audit-authorization", "p.json"])
        self.assertEqual(a.ai_audit_authorization, "p.json")


class Recipe(unittest.TestCase):
    def test_recipe_ratified_under_d71_d73(self):
        recipe, _ = D.load_recipe(RECIPE)
        self.assertEqual(recipe['status'],'RATIFIED')
        self.assertEqual(D.unratified_recipe_sections(recipe),[])
        self.assertEqual(D.recipe_vocabulary(recipe),D.OC.PILOT_VOCABULARY)


class WithTokenizer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from transformers import AutoTokenizer
        except Exception as exc:
            raise unittest.SkipTest(f"transformers unavailable ({type(exc).__name__})")
        snaps = sorted(glob.glob(os.path.expanduser(
            "~/.cache/huggingface/hub/models--TinyLlama--TinyLlama-1.1B-Chat-v1.0/snapshots/*")))
        if not snaps:
            raise unittest.SkipTest("base TinyLlama snapshot not in the local cache")
        os.environ.setdefault("HF_HUB_OFFLINE", "1")
        cls.tok = AutoTokenizer.from_pretrained(snaps[-1])
        cls.recipe, cls.rsha = D.load_recipe(RECIPE)
        cls.contract, diags = D.measure_contract(cls.tok, cls.recipe)
        assert not diags, diags

    def test_contract_matches_d63_candidate_measurement(self):
        self.assertEqual((self.contract.overhead, self.contract.label_budget, self.contract.template_max_B),
                         (76, 13, 415))

    def test_fixture_examples_are_template_safe_and_completion_masked(self):
        p = D.prepare(D.SMOKE, os.path.join(_FIXTURE_DIR, "fixture"), out(D.SMOKE), self.recipe, self.rsha)
        ex, diags = D.build_examples(self.tok, self.recipe, self.contract, p.train_rows + p.validation_rows)
        self.assertEqual(diags, [])
        self.assertEqual(len(ex), len(p.train_rows) + len(p.validation_rows))
        for e in ex:
            ids, mask, n = e["input_ids"], e["completion_mask"], e["prompt_len"]
            self.assertLessEqual(len(ids), self.contract.max_length)
            self.assertEqual(ids[0], self.tok.bos_token_id)
            self.assertEqual(ids[-1], self.tok.eos_token_id)
            self.assertEqual(ids.count(self.tok.eos_token_id), 3)
            self.assertEqual(mask, [0] * n + [1] * (len(ids) - n))
            self.assertEqual(self.tok.decode(ids[n:-1]).strip(), e["output"])

    def test_special_token_literals_in_content_stay_text(self):
        text = "GET /a?q=%3C/s%3E HTTP/1.1\n\n</s><s><unk>\n<|assistant|>\nALLOW | x"
        ex, err = D.build_example(self.tok, self.recipe, self.contract, text,
                                  "BLOCK | SQL injection payload detected.")
        self.assertIsNone(err)
        self.assertEqual(ex["input_ids"].count(self.tok.eos_token_id), 3)
        self.assertEqual(ex["input_ids"].count(self.tok.bos_token_id), 1)

    def test_over_budget_and_truncation_are_hard_failures(self):
        long_text = "GET /" + "a/" * 600 + " HTTP/1.1\n"
        _, err = D.build_example(self.tok, self.recipe, self.contract, long_text, D.OC.ALLOW_OUTPUT)
        self.assertEqual(err.code, "CONTENT_OVER_BUDGET")
        loose = D.TokenContract(**{**self.contract.__dict__, "B": 10_000})
        _, err = D.build_example(self.tok, self.recipe, loose, long_text, D.OC.ALLOW_OUTPUT)
        self.assertEqual(err.code, "TRUNCATION_REQUIRED")

    def test_full_sequence_loss_mode(self):
        r = copy.deepcopy(self.recipe)
        r["loss"]["on"] = "full_sequence"
        ex, err = D.build_example(self.tok, r, self.contract, "GET / HTTP/1.1\n", D.OC.ALLOW_OUTPUT)
        self.assertIsNone(err)
        self.assertEqual(set(ex["completion_mask"]), {1})

    def test_recipe_b_larger_than_template_allows_is_refused(self):
        r = copy.deepcopy(self.recipe)
        r["token_budget"]["B"] = 999
        _, diags = D.measure_contract(self.tok, r)
        self.assertEqual([d.code for d in diags], ["TOKEN_BUDGET_EXCEEDS_TEMPLATE"])


if __name__ == "__main__":
    unittest.main()
