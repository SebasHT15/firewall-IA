"""Delivery of a model candidate: manifest v2, its binding to the runtime profile, and what happens when
any part of the identity does not match. Doubles and fixtures only, no model and no GPU.

    .venv-dataplane/bin/python -B -m unittest discover -s tests -p 'test_cascade_candidate.py'
"""
import contextlib
import copy
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(REPO, "data_plane"), os.path.join(REPO, "scripts", "gateway_ops"),
                os.path.join(REPO, "control_plane")]

import cascade as C                 # noqa: E402
import cascade_manifest as CM       # noqa: E402
import candidate_check as CC        # noqa: E402
import live_stack as L              # noqa: E402
import make_candidate_manifest as MC  # noqa: E402
import model2_policy as mp          # noqa: E402

DOUBLES = os.path.join(REPO, "scripts", "gateway_ops", "service_doubles.py")
OLD_ADAPTER = "0" * 64
VERIFIED_SUFFIX = os.path.join(REPO, "scripts", "v5_successor", "verified_suffix.py")


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Candidate(unittest.TestCase):
    """A complete delivery in a temporary directory: adapter, recipe, profile, evidence, Model 2."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.adapter_dir = os.path.join(self.dir.name, "adapter")
        os.makedirs(self.adapter_dir)
        self.write_bytes("adapter/adapter_model.safetensors", b"new weights")
        self.adapter_sha = digest(b"new weights")
        self.recipe_path = self.write_bytes("recipe.json", b'{"recipe": 1}')
        self.recipe_sha = digest(b'{"recipe": 1}')
        artifact = self.write_bytes("model2.json", b"artifact")
        policy = {"schema": mp.POLICY_SCHEMA, "policy_id": "lab", "status": "LAB_EXPERIMENTAL",
                  "feature_view": "baseline_34", "model_artifact_sha256": digest(b"artifact"),
                  "threshold": 0.9}
        policy_path = self.write_json("policy.json", policy)
        self.doc = {
            "schema": CM.CANDIDATE_SCHEMA, "manifest_id": "candidate-1", "status": "EXPERIMENTAL",
            "canonical": {"contract": "canonical-request/v1", "max_decoded_body": 4800,
                          "token_budget_B": 100, "max_bytes_per_token": 48},
            "v5": {"adapter_path": self.adapter_dir, "adapter_sha256": self.adapter_sha,
                   "recipe_path": self.recipe_path, "recipe_sha256": self.recipe_sha,
                   "template_fingerprint": "c" * 64, "base_model": "base", "base_revision": "rev",
                   "vocabulary": ["ALLOW | fine.", "BLOCK | bad."], "token_budget_B": 100,
                   "max_length": 200, "margin": 8, "overhead": 76, "label_budget": 13,
                   "max_new_tokens": 17, "runtime": None},
            "model2": {"artifact_path": artifact, "artifact_sha256": digest(b"artifact"),
                       "feature_view": "baseline_34", "policy_path": policy_path,
                       "policy_sha256": mp.load_policy(policy_path).sha256}}

    def path(self, name):
        return os.path.join(self.dir.name, name)

    def write_bytes(self, name, data):
        with open(self.path(name), "wb") as fh:
            fh.write(data)
        return self.path(name)

    def write_json(self, name, document):
        return self.write_bytes(name, json.dumps(document).encode("utf-8"))

    def profile(self, name="profile.json", **changes):
        document = {"schema": "v5-inference-profile/v1", "profile_id": "nf4-new", "status": "EXPERIMENTAL",
                    "precision": "nf4", "double_quant": False, "recipe_sha256": self.recipe_sha,
                    "adapter_sha256": self.adapter_sha, **changes}
        return self.write_json(name, document)

    def verified_profile(self, **changes):
        with open(VERIFIED_SUFFIX, "rb") as fh:
            decoder = digest(fh.read())
        return self.profile(**{"schema": "v5-inference-profile/v2", "decoder": "verified_suffix/v1",
                               "decoder_sha256": decoder, **changes})

    def use_runtime(self, path, evidence=None):
        self.doc["v5"]["runtime"] = {
            "profile_path": path, "profile_sha256": CM.sha256_file(path),
            "verification_evidence_path": evidence,
            "verification_evidence_sha256": CM.sha256_file(evidence) if evidence else None}

    def evidence_for(self, profile):
        return self.write_json("evidence.json", {"profile_sha256": CM.sha256_file(profile),
                                                 "output_mismatches": 0})

    def served(self, manifest):
        """What a service with exactly this identity reports."""
        v5 = manifest.v5
        health = {"model_loaded": True, "adapter_sha256": v5.adapter_sha256,
                  "template_fingerprint": v5.template_fingerprint}
        if v5.runtime is not None:
            health["runtime_profile"] = {
                "sha256": v5.runtime.profile_sha256, "adapter_sha256": v5.adapter_sha256,
                "recipe_sha256": v5.recipe_sha256, "precision": v5.runtime.precision,
                "double_quant": v5.runtime.double_quant}
            if v5.runtime.decoder != CM.NATIVE_DECODER:
                health["runtime_profile"].update(decoder=v5.runtime.decoder,
                                                 decoder_sha256=v5.runtime.decoder_sha256)
        contract = {"template_fingerprint": v5.template_fingerprint, "recipe_sha256": v5.recipe_sha256,
                    "token_budget_B": v5.token_budget_B, "vocabulary": list(v5.vocabulary),
                    "base_model": v5.base_model, "base_revision": v5.base_revision,
                    "max_length": 200, "margin": 8, "overhead": 76, "label_budget": 13,
                    "max_new_tokens": 17}
        return health, contract

    def assertRefused(self, fragment):
        with self.assertRaises(CM.ManifestError) as caught:
            CM.parse_manifest(self.doc)
        self.assertIn(fragment, str(caught.exception))


class AcceptanceTests(Candidate):
    def test_a_complete_candidate_with_the_recipe_runtime(self):
        manifest = CM.parse_manifest(self.doc)
        self.assertTrue(manifest.is_candidate)
        self.assertIsNone(manifest.v5.runtime)
        self.assertEqual(CM.candidate_file_problems(manifest), ())
        self.assertEqual(CM.v5_contract_problems(manifest, *self.served(manifest)), ())

    def test_nothing_is_a_value_of_the_current_candidate(self):
        self.doc["canonical"].update(token_budget_B=120, max_decoded_body=5760)
        self.doc["v5"].update(token_budget_B=120, max_length=512, label_budget=25, max_new_tokens=29,
                              vocabulary=[f"ALLOW {i}" for i in range(2)] + ["BLOCK x"])
        manifest = CM.parse_manifest(self.doc)
        self.assertEqual(manifest.canonical.token_budget_B, 120)
        self.assertEqual(len(manifest.v5.vocabulary), 3)

    def test_a_native_profile_of_these_weights(self):
        self.use_runtime(self.profile())
        manifest = CM.parse_manifest(self.doc)
        self.assertEqual((manifest.v5.runtime.decoder, manifest.v5.runtime.status),
                         (CM.NATIVE_DECODER, "EXPERIMENTAL"))
        self.assertEqual(CM.v5_contract_problems(manifest, *self.served(manifest)), ())

    def test_a_verified_decoder_with_its_evidence(self):
        profile = self.verified_profile()
        self.use_runtime(profile, self.evidence_for(profile))
        manifest = CM.parse_manifest(self.doc)
        self.assertEqual(manifest.v5.runtime.decoder, "verified_suffix/v1")
        self.assertEqual(CM.candidate_file_problems(manifest), ())
        self.assertEqual(CM.v5_contract_problems(manifest, *self.served(manifest)), ())

    def test_v1_stays_readable_for_what_already_uses_it(self):
        manifest = CM.load_manifest(os.path.join(
            REPO, "reports/v5/hybrid/gateway-integration-v1/manifests/dev_fixture_baseline34.json"))
        self.assertFalse(manifest.is_candidate)
        self.assertEqual(CM.candidate_file_problems(manifest), ())


class ProfileBindingTests(Candidate):
    """The fast profile of the old adapter must not travel with a copied manifest."""

    def test_the_real_fast_profile_is_refused_for_new_weights(self):
        real = os.path.join(REPO, "reports/v5/successor-2026-10-30/verified-suffix/service-final/"
                                  "verified-suffix.EXPERIMENTAL.json")
        self.use_runtime(real, self.write_json("e.json", {"profile_sha256": CM.sha256_file(real)}))
        self.assertRefused("bound to another adapter")

    def test_a_profile_of_another_adapter(self):
        self.use_runtime(self.profile(adapter_sha256=OLD_ADAPTER))
        self.assertRefused("another adapter")

    def test_a_profile_of_another_recipe(self):
        self.use_runtime(self.profile(recipe_sha256=OLD_ADAPTER))
        self.assertRefused("another recipe")

    def test_profile_bytes_are_checked(self):
        path = self.profile()
        self.use_runtime(path)
        self.doc["v5"]["runtime"]["profile_sha256"] = "a" * 64
        self.assertRefused("profile bytes")

    def test_a_profile_that_is_not_there(self):
        self.use_runtime(self.profile())
        self.doc["v5"]["runtime"]["profile_path"] = self.path("missing.json")
        self.assertRefused("unreadable")

    def test_a_disabled_profile(self):
        self.use_runtime(self.profile(status="DRAFT"))
        self.assertRefused("not enabled")

    def test_an_unknown_profile_schema(self):
        self.use_runtime(self.profile(schema="v5-inference-profile/v9"))
        self.assertRefused("schema")

    def test_a_verified_decoder_without_evidence(self):
        self.use_runtime(self.verified_profile())
        self.assertRefused("verification_evidence_path")

    def test_evidence_of_another_profile(self):
        profile = self.verified_profile()
        self.use_runtime(profile, self.write_json("e.json", {"profile_sha256": "f" * 64}))
        self.assertRefused("does not name this profile")

    def test_evidence_bytes_are_checked(self):
        profile = self.verified_profile()
        self.use_runtime(profile, self.evidence_for(profile))
        self.doc["v5"]["runtime"]["verification_evidence_sha256"] = "a" * 64
        self.assertRefused("evidence bytes")

    def test_native_profile_claims_no_evidence(self):
        self.use_runtime(self.profile(), self.write_json("e.json", {}))
        self.assertRefused("native profile")

    def test_runtime_must_be_stated(self):
        del self.doc["v5"]["runtime"]
        self.assertRefused("missing")

    def test_v1_field_does_not_exist_in_a_candidate(self):
        self.doc["v5"]["runtime_profile_sha256"] = "a" * 64
        self.assertRefused("unknown")


class IncompatibilityTests(Candidate):
    def test_vocabulary_needs_both_outcomes(self):
        self.doc["v5"]["vocabulary"] = ["BLOCK | bad."]
        self.assertRefused("no ALLOW")
        self.doc["v5"]["vocabulary"] = ["ALLOW | fine."]
        self.assertRefused("no BLOCK")

    def test_a_label_must_fit_the_generation_bound(self):
        self.doc["v5"]["max_new_tokens"] = 12
        self.assertRefused("label_budget")

    def test_token_budget_must_fit_max_length(self):
        self.doc["v5"]["max_length"] = 196
        self.assertRefused("max_length")

    def test_budget_of_v5_and_canonical_must_agree(self):
        self.doc["v5"]["token_budget_B"] = 101
        self.assertRefused("token_budget_B")

    def test_every_candidate_key_is_required(self):
        for key in ("adapter_path", "recipe_path", "base_model", "base_revision", "max_length", "margin",
                    "overhead", "label_budget", "max_new_tokens"):
            document = copy.deepcopy(self.doc)
            del document["v5"][key]
            with self.assertRaises(CM.ManifestError):
                CM.parse_manifest(document)

    def test_files_are_compared_offline(self):
        self.doc["v5"]["adapter_sha256"] = "a" * 64
        self.doc["v5"]["recipe_sha256"] = "b" * 64
        self.assertEqual(CM.candidate_file_problems(CM.parse_manifest(self.doc)),
                         ("adapter_bytes_mismatch", "recipe_bytes_mismatch"))

    def test_missing_files_are_problems_not_crashes(self):
        self.doc["v5"].update(adapter_path=self.path("nothing"), recipe_path=self.path("nothing.json"))
        self.assertEqual(CM.candidate_file_problems(CM.parse_manifest(self.doc)),
                         ("adapter_unreadable", "recipe_unreadable"))

    def test_a_decoder_that_changed_after_verification(self):
        profile = self.verified_profile(decoder_sha256="a" * 64)
        self.use_runtime(profile, self.evidence_for(profile))
        self.assertEqual(CM.candidate_file_problems(CM.parse_manifest(self.doc)),
                         ("decoder_bytes_mismatch",))

    def test_each_served_identity_field_is_compared(self):
        manifest = CM.parse_manifest(self.doc)
        health, contract = self.served(manifest)
        for key, value, reason in (("recipe_sha256", "d" * 64, "v5_recipe_sha256_mismatch"),
                                   ("vocabulary", ["ALLOW"], "v5_vocabulary_mismatch"),
                                   ("token_budget_B", 99, "v5_token_budget_B_mismatch"),
                                   ("template_fingerprint", "d" * 64, "v5_template_fingerprint_mismatch"),
                                   ("base_model", "other", "v5_base_model_mismatch"),
                                   ("base_revision", "other", "v5_base_revision_mismatch"),
                                   ("max_length", 1, "v5_max_length_mismatch"),
                                   ("margin", 1, "v5_margin_mismatch"),
                                   ("overhead", 1, "v5_overhead_mismatch"),
                                   ("label_budget", 1, "v5_label_budget_mismatch"),
                                   ("max_new_tokens", 1, "v5_max_new_tokens_mismatch")):
            self.assertIn(reason, CM.v5_contract_problems(manifest, health, {**contract, key: value}))
        self.assertIn("v5_adapter_mismatch",
                      CM.v5_contract_problems(manifest, {**health, "adapter_sha256": "e" * 64}, contract))

    def test_the_recipe_runtime_refuses_a_service_with_any_profile(self):
        manifest = CM.parse_manifest(self.doc)
        health, contract = self.served(manifest)
        self.assertEqual(CM.v5_contract_problems(
            manifest, {**health, "runtime_profile": {"sha256": "d" * 64}}, contract),
            ("v5_runtime_profile_mismatch",))

    def test_a_named_profile_refuses_a_service_without_it(self):
        self.use_runtime(self.profile())
        manifest = CM.parse_manifest(self.doc)
        health, contract = self.served(manifest)
        del health["runtime_profile"]
        self.assertEqual(CM.v5_contract_problems(manifest, health, contract),
                         ("v5_runtime_profile_mismatch",))

    def test_served_profile_must_state_this_binding(self):
        self.use_runtime(self.profile())
        manifest = CM.parse_manifest(self.doc)
        health, contract = self.served(manifest)
        for key, value, reason in (("adapter_sha256", OLD_ADAPTER, "v5_runtime_adapter_sha256_mismatch"),
                                   ("recipe_sha256", OLD_ADAPTER, "v5_runtime_recipe_sha256_mismatch"),
                                   ("precision", "bf16", "v5_runtime_precision_mismatch"),
                                   ("double_quant", True, "v5_runtime_double_quant_mismatch"),
                                   ("decoder", "verified_suffix/v1", "v5_runtime_decoder_mismatch")):
            changed = {**health, "runtime_profile": {**health["runtime_profile"], key: value}}
            self.assertIn(reason, CM.v5_contract_problems(manifest, changed, contract))

    def test_experimental_runtime_is_not_for_production(self):
        self.use_runtime(self.profile())
        problems = CM.enablement_problems(CM.parse_manifest(self.doc), C.V5_ONLY, "production")
        self.assertIn("runtime_profile_not_approved_for_production", problems)


class BuilderTests(Candidate):
    def setUp(self):
        super().setUp()
        self.recipe = os.path.join(REPO, "scripts", "training", "v5_training_recipe_v1.json")
        self.tokens = self.write_json("tokens.json", {"measured": {
            "max_length": 512, "margin": 8, "overhead": 76, "label_budget": 13, "B": 415}})
        self.out = self.path("manifest.json")
        self.base = ["--out", self.out, "--manifest-id", "candidate-2", "--adapter-dir", self.adapter_dir,
                     "--recipe", self.recipe, "--token-measurement", self.tokens,
                     "--model2-artifact", self.doc["model2"]["artifact_path"],
                     "--model2-policy", self.doc["model2"]["policy_path"]]

    def run_builder(self, *extra):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            code = MC.main(self.base + list(extra))
        return code, err.getvalue()

    def test_identity_comes_from_the_files_of_this_candidate(self):
        self.assertEqual(self.run_builder("--native-runtime")[0], 0)
        manifest = CM.load_manifest(self.out)
        self.assertEqual(manifest.status, "EXPERIMENTAL")
        self.assertEqual(manifest.v5.adapter_sha256, self.adapter_sha)
        self.assertEqual(manifest.canonical.max_decoded_body, 48 * 415)
        self.assertEqual(manifest.v5.token_contract.max_new_tokens, 17)
        self.assertIsNone(manifest.v5.runtime)

    def test_the_recipe_of_the_successor_gives_a_manifest_of_its_own(self):
        recipe = os.path.join(REPO, "reports/v5/successor-training-2026-10-31-reviewed/recipe.EXPERIMENTAL.json")
        tokens = os.path.join(REPO, "reports/v5/successor-2026-10-30/expanded_vocabulary_token_contract.json")
        self.base[self.base.index(self.recipe)] = recipe
        self.base[self.base.index(self.tokens)] = tokens
        self.assertEqual(self.run_builder("--native-runtime")[0], 0)
        v5 = CM.load_manifest(self.out).v5
        with open(tokens, encoding="utf-8") as fh:
            self.assertEqual(list(v5.vocabulary), json.load(fh)["vocabulary"])
        self.assertEqual(v5.recipe_sha256, CM.sha256_file(recipe))

    def test_the_runtime_has_no_default(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            MC.main(self.base)

    def test_the_old_fast_profile_cannot_be_written_into_a_new_manifest(self):
        real = os.path.join(REPO, "reports/v5/successor-2026-10-30/verified-suffix/service-final/"
                                  "verified-suffix.EXPERIMENTAL.json")
        code, error = self.run_builder("--runtime-profile", real)
        self.assertEqual(code, 2)
        self.assertIn("bound to another adapter", error)
        self.assertFalse(os.path.exists(self.out))

    def test_token_measurement_of_another_budget_is_refused(self):
        self.base[self.base.index(self.tokens)] = self.write_json("t2.json", {"measured": {
            "max_length": 512, "margin": 8, "overhead": 76, "label_budget": 13, "B": 400}})
        self.assertEqual(self.run_builder("--native-runtime")[0], 2)

    def test_never_overwrites(self):
        self.assertEqual(self.run_builder("--native-runtime")[0], 0)
        with self.assertRaises(FileExistsError):
            self.run_builder("--native-runtime")


class CheckAndDoubleTests(Candidate):
    """candidate_check against a double that serves the manifest, including what it does wrong."""

    def setUp(self):
        super().setUp()
        recipe = os.path.join(REPO, "scripts", "training", "v5_training_recipe_v1.json")
        tokens = self.write_json("tokens.json", {"measured": {
            "max_length": 512, "margin": 8, "overhead": 76, "label_budget": 13, "B": 415}})
        self.manifest_path = self.path("manifest.json")
        with contextlib.redirect_stdout(io.StringIO()):
            code = MC.main(["--out", self.manifest_path, "--manifest-id", "candidate-3", "--adapter-dir",
                            self.adapter_dir, "--recipe", recipe, "--token-measurement", tokens,
                            "--model2-artifact", self.doc["model2"]["artifact_path"], "--model2-policy",
                            self.doc["model2"]["policy_path"], "--native-runtime"])
        self.assertEqual(code, 0)
        self.port = L.free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self.proc = subprocess.Popen([sys.executable, DOUBLES, "--role", "v5", "--port", str(self.port),
                                      "--manifest", self.manifest_path], stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
        self.addCleanup(self.proc.wait)
        self.addCleanup(self.proc.terminate)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and L.http_get(self.url + "/health", 0.2)[0] != 200:
            time.sleep(0.02)

    def check(self, *extra):
        out = self.path(f"check-{len(os.listdir(self.dir.name))}.json")
        with contextlib.redirect_stdout(io.StringIO()):
            code = CC.main(["--manifest", self.manifest_path, "--v5-url", self.url, "--out", out, *extra])
        with open(out, encoding="utf-8") as fh:
            return code, json.load(fh)

    def test_the_right_candidate_is_accepted(self):
        code, report = self.check()
        self.assertEqual((code, report["status"]), (0, "IDENTITY_CONSISTENT"))
        self.assertEqual(report["failed"], [])
        self.assertIn("not_an_approval", report)

    def test_each_wrong_service_is_refused_with_its_reason(self):
        for behavior, reason in (("adapter_mismatch", "v5_adapter_mismatch"),
                                 ("recipe_mismatch", "v5_recipe_sha256_mismatch"),
                                 ("vocabulary_mismatch", "v5_vocabulary_mismatch"),
                                 ("budget_mismatch", "v5_token_budget_B_mismatch"),
                                 ("token_contract_mismatch", "v5_label_budget_mismatch"),
                                 ("profile_mismatch", "v5_runtime_profile_mismatch")):
            L.http_post_json(self.url + "/__control", {"behavior": behavior})
            code, report = self.check()
            self.assertEqual((behavior, code, report["status"]), (behavior, 1, "REFUSED"))
            found = next(c for c in report["checks"] if c["check"].startswith("V5 service serves"))
            self.assertIn(reason, found["problems"])

    def test_a_v1_manifest_is_not_a_candidate(self):
        out = self.path("v1.json")
        with contextlib.redirect_stdout(io.StringIO()):
            code = CC.main(["--manifest", os.path.join(
                REPO, "reports/v5/hybrid/gateway-integration-v1/manifests/dev_fixture_baseline34.json"),
                "--out", out])
        self.assertEqual(code, 1)

    def test_same_weights_as_the_previous_candidate_is_reported(self):
        previous = self.path("previous.json")
        with open(self.manifest_path, encoding="utf-8") as fh:
            document = json.load(fh)
        document["manifest_id"] = "candidate-0"
        with open(previous, "w", encoding="utf-8") as fh:
            json.dump(document, fh)
        code, report = self.check("--previous", previous)
        self.assertEqual(code, 1)
        self.assertTrue(any("new weights" in name for name in report["failed"]))


class LauncherTests(Candidate):
    def test_the_launcher_refuses_a_manifest_whose_files_do_not_match(self):
        import launch
        self.doc["v5"]["adapter_sha256"] = "a" * 64
        path = self.write_json("m.json", self.doc)
        config = L.gateway_config(mode="CASCADE_ACTIVE", manifest=path, listen_port=1, guard_port=2,
                                  sink_port=3, admin_port=4, v4_url="http://h", v5_url="http://h",
                                  workdir=self.dir.name)["cascade_gateway"]
        report = launch.check(CM.parse_gateway_config(config))
        self.assertIn("adapter_bytes_mismatch", report["problems"])


class BodyLimitTests(Candidate):
    def test_body_limit_follows_the_manifest(self):
        path = self.write_json("m.json", self.doc)
        config = L.gateway_config(mode="CASCADE_ACTIVE", manifest=path, listen_port=1, guard_port=2,
                                  sink_port=3, admin_port=4, v4_url="http://h", v5_url="http://h",
                                  workdir=self.dir.name)
        self.assertEqual(config["cascade_gateway"]["canonical"]["max_received_body"], 4800)


if __name__ == "__main__":
    unittest.main()
