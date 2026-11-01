"""Strict parsing of the versioned cascade manifest and gateway configuration.

Standard library + the data-plane modules only:
    .venv-dataplane/bin/python -m unittest discover -s tests -p 'test_cascade_manifest.py' -v

A manifest or configuration that does not fit must be refused. Nothing here reads a model.
"""
import copy
import hashlib
import json
import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(REPO, "data_plane"), os.path.join(REPO, "scripts", "gateway_ops")]

import cascade as C               # noqa: E402
import cascade_manifest as CM     # noqa: E402
import fast_path as fp            # noqa: E402
import model2_policy as mp        # noqa: E402

A64 = "a" * 64


class Fixture(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        artifact = os.path.join(self.dir.name, "model.json")
        with open(artifact, "wb") as fh:
            fh.write(b"not a real model")
        self.artifact_sha = hashlib.sha256(b"not a real model").hexdigest()
        self.policy_doc = {"schema": mp.POLICY_SCHEMA, "policy_id": "lab-1",
                           "status": "LAB_EXPERIMENTAL", "feature_view": "baseline_34",
                           "model_artifact_sha256": self.artifact_sha, "threshold": 0.9}
        self.policy_path = self.write("policy.json", self.policy_doc)
        policy = mp.load_policy(self.policy_path)
        self.manifest = {
            "schema": CM.MANIFEST_SCHEMA, "manifest_id": "m-1", "status": "EXPERIMENTAL",
            "canonical": {"contract": "canonical-request/v1", "max_decoded_body": 480,
                          "token_budget_B": 10, "max_bytes_per_token": 48},
            "v5": {"adapter_sha256": A64, "recipe_sha256": "b" * 64,
                   "template_fingerprint": "c" * 64, "vocabulary": ["ALLOW", "BLOCK x"],
                   "token_budget_B": 10},
            "model2": {"artifact_path": artifact, "artifact_sha256": self.artifact_sha,
                       "feature_view": "baseline_34", "policy_path": self.policy_path,
                       "policy_sha256": policy.sha256}}

    def write(self, name, doc):
        path = os.path.join(self.dir.name, name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        return path


class ManifestTests(Fixture):
    def test_valid_manifest_parses_without_hardcoded_values(self):
        doc = self.manifest
        doc["canonical"].update(max_decoded_body=48 * 999, token_budget_B=999)
        doc["v5"]["token_budget_B"] = 999
        m = CM.parse_manifest(doc)
        self.assertEqual(m.canonical.token_budget_B, 999)
        self.assertEqual(m.v5.vocabulary, ("ALLOW", "BLOCK x"))
        self.assertEqual(m.model2.policy_status, "LAB_EXPERIMENTAL")

    def assertRefused(self, doc, fragment=""):
        with self.assertRaises(CM.ManifestError) as caught:
            CM.parse_manifest(doc)
        self.assertIn(fragment, str(caught.exception))

    def test_unknown_or_missing_keys_refused(self):
        doc = copy.deepcopy(self.manifest)
        doc["extra"] = 1
        self.assertRefused(doc, "unknown")
        doc = copy.deepcopy(self.manifest)
        del doc["v5"]["recipe_sha256"]
        self.assertRefused(doc, "missing")

    def test_budget_disagreement_refused(self):
        doc = copy.deepcopy(self.manifest)
        doc["v5"]["token_budget_B"] = 11
        self.assertRefused(doc, "token_budget_B")

    def test_decode_cap_below_reverse_bound_refused(self):
        doc = copy.deepcopy(self.manifest)
        doc["canonical"]["max_decoded_body"] = 479
        self.assertRefused(doc, "max_decoded_body")

    def test_other_canonical_contract_refused(self):
        doc = copy.deepcopy(self.manifest)
        doc["canonical"]["contract"] = "canonical-request/v2"
        self.assertRefused(doc, "contract")

    def test_artifact_bytes_are_checked(self):
        doc = copy.deepcopy(self.manifest)
        doc["model2"]["artifact_sha256"] = A64
        self.assertRefused(doc, "artifact bytes")

    def test_policy_must_be_the_pinned_one(self):
        doc = copy.deepcopy(self.manifest)
        doc["model2"]["policy_sha256"] = A64
        self.assertRefused(doc, "policy_sha256")

    def test_policy_bound_to_another_artifact_refused(self):
        other = dict(self.policy_doc, model_artifact_sha256=A64)
        path = self.write("other.json", other)
        doc = copy.deepcopy(self.manifest)
        doc["model2"].update(policy_path=path, policy_sha256=mp.load_policy(path).sha256)
        self.assertRefused(doc, "not bound")

    def test_feature_view_must_match_policy(self):
        doc = copy.deepcopy(self.manifest)
        doc["model2"]["feature_view"] = "target-path-neutralized/v1"
        self.assertRefused(doc, "not bound")

    def test_approved_needs_a_record(self):
        doc = copy.deepcopy(self.manifest)
        doc["status"] = "APPROVED"
        self.assertRefused(doc, "approval")

    def test_enablement_by_mode_and_profile(self):
        m = CM.parse_manifest(self.manifest)
        self.assertEqual(CM.enablement_problems(m, C.CASCADE_ACTIVE, "lab"), ())
        self.assertIn("manifest_not_approved_for_production",
                      CM.enablement_problems(m, C.CASCADE_ACTIVE, "production"))
        self.assertIn("model2_policy_not_approved_for_production",
                      CM.enablement_problems(m, C.CASCADE_ACTIVE, "production"))
        self.assertEqual(CM.enablement_problems(m, C.CASCADE_OBSERVE, "production"), ())
        doc = copy.deepcopy(self.manifest)
        doc["model2"] = None
        self.assertEqual(CM.enablement_problems(CM.parse_manifest(doc), C.CASCADE_ACTIVE, "lab"),
                         ("model2_required_for_cascade_active",))

    def test_a_named_runtime_profile_must_be_the_one_served(self):
        doc = copy.deepcopy(self.manifest)
        doc["v5"]["runtime_profile_sha256"] = "d" * 64
        m = CM.parse_manifest(doc)
        v5 = m.v5
        health = {"model_loaded": True, "adapter_sha256": v5.adapter_sha256,
                  "template_fingerprint": v5.template_fingerprint}
        contract = {"template_fingerprint": v5.template_fingerprint,
                    "recipe_sha256": v5.recipe_sha256, "token_budget_B": v5.token_budget_B,
                    "vocabulary": list(v5.vocabulary)}
        self.assertIn("v5_runtime_profile_mismatch", CM.v5_contract_problems(m, health, contract))
        other = {**health, "runtime_profile": {"sha256": "e" * 64}}
        self.assertIn("v5_runtime_profile_mismatch", CM.v5_contract_problems(m, other, contract))
        served = {**health, "runtime_profile": {"sha256": "d" * 64}}
        self.assertEqual(CM.v5_contract_problems(m, served, contract), ())

    def test_an_experimental_profile_is_never_picked_up_silently(self):
        m = CM.parse_manifest(self.manifest)      # names no runtime profile
        v5 = m.v5
        health = {"model_loaded": True, "adapter_sha256": v5.adapter_sha256,
                  "template_fingerprint": v5.template_fingerprint, "runtime_profile": None}
        contract = {"template_fingerprint": v5.template_fingerprint,
                    "recipe_sha256": v5.recipe_sha256, "token_budget_B": v5.token_budget_B,
                    "vocabulary": list(v5.vocabulary)}
        self.assertEqual(CM.v5_contract_problems(m, health, contract), ())
        experimental = {**health, "runtime_profile": {"sha256": "d" * 64, "status": "EXPERIMENTAL"}}
        self.assertEqual(CM.v5_contract_problems(m, experimental, contract),
                         ("v5_runtime_profile_mismatch",))

    def test_v5_contract_comparison(self):
        m = CM.parse_manifest(self.manifest)
        v5 = m.v5
        health = {"model_loaded": True, "adapter_sha256": v5.adapter_sha256,
                  "template_fingerprint": v5.template_fingerprint}
        contract = {"template_fingerprint": v5.template_fingerprint,
                    "recipe_sha256": v5.recipe_sha256, "token_budget_B": v5.token_budget_B,
                    "vocabulary": list(v5.vocabulary), "base_model": "ignored"}
        self.assertEqual(CM.v5_contract_problems(m, health, contract), ())
        for key, value, reason in (("recipe_sha256", "d" * 64, "v5_recipe_sha256_mismatch"),
                                   ("token_budget_B", 11, "v5_token_budget_B_mismatch"),
                                   ("vocabulary", ["ALLOW"], "v5_vocabulary_mismatch")):
            self.assertIn(reason, CM.v5_contract_problems(m, health, {**contract, key: value}))
        self.assertIn("v5_adapter_mismatch",
                      CM.v5_contract_problems(m, {**health, "adapter_sha256": "e" * 64}, contract))
        self.assertEqual(CM.v5_contract_problems(m, {"model_loaded": False}, contract),
                         ("v5_model_not_loaded",))
        self.assertIn("v5_contract_unavailable", CM.v5_contract_problems(m, health, None))


class GatewayConfigTests(Fixture):
    def setUp(self):
        super().setUp()
        import live_stack as L
        self.doc = L.gateway_config(
            mode="CASCADE_ACTIVE", manifest="m.json", listen_port=8080, guard_port=8081,
            sink_port=8082, admin_port=8083, v4_url="http://127.0.0.1:8000",
            v5_url="http://127.0.0.1:8001", workdir=self.dir.name)["cascade_gateway"]

    def assertRefused(self, doc, fragment=""):
        with self.assertRaises(CM.ManifestError) as caught:
            CM.parse_gateway_config(doc)
        self.assertIn(fragment, str(caught.exception))

    def test_valid(self):
        cfg = CM.parse_gateway_config(self.doc)
        self.assertEqual(cfg.mode, C.CASCADE_ACTIVE)
        self.assertEqual(cfg.fast_path.activation, "disabled")
        self.assertIsNone(CM.resolve_fast_path_policy(cfg.fast_path))

    def test_no_key_has_a_default(self):
        for key in list(self.doc):
            doc = copy.deepcopy(self.doc)
            del doc[key]
            self.assertRefused(doc, "missing")

    def test_unknown_mode_refused(self):
        self.doc["mode"] = "ACTIVE"
        self.assertRefused(self.doc, "mode")

    def test_deadline_must_cover_the_stages(self):
        self.doc["admission"]["decision_deadline_seconds"] = 1.0
        self.assertRefused(self.doc, "decision_deadline_seconds")

    def test_wire_digest_is_lab_only(self):
        self.doc["deployment_profile"] = "production"
        self.doc["observability"]["log_wire_sha256"] = True
        self.assertRefused(self.doc, "lab profile")

    def test_verified_evidence_outside_the_lab_needs_a_ruling(self):
        self.doc["deployment_profile"] = "production"
        self.doc["observability"]["log_wire_sha256"] = False
        self.doc["framing"]["verified_evidence"] = True
        self.assertRefused(self.doc, "owner_ruling_ref")

    def fast_path(self, **changes):
        policy_doc = {"schema": fp.POLICY_SCHEMA, "policy_id": "fixture", "status": "PROPOSED",
                      "canonical_contract": "canonical-request/v1",
                      "rules": [{"id": "health", "methods": ["GET"], "path": ["healthz"],
                                 "query": {}, "required_query": [], "headers": {}}]}
        policy_doc.update(changes)
        path = self.write("fast_path.json", policy_doc)
        section = self.doc["fast_path"]
        section.update(activation="experimental_fixture", policy_file=path,
                       policy_sha256=fp.parse_policy(policy_doc).sha256)
        self.doc["framing"]["verified_evidence"] = True
        return section

    def test_experimental_fixture_only_in_lab(self):
        self.fast_path()
        cfg = CM.parse_gateway_config(self.doc)
        self.assertEqual(CM.resolve_fast_path_policy(cfg.fast_path).status, "PROPOSED")
        self.doc["deployment_profile"] = "production"
        self.doc["observability"]["log_wire_sha256"] = False
        self.doc["framing"]["owner_ruling_ref"] = "D-x"
        self.assertRefused(self.doc, "lab profile")

    def test_activation_without_framing_evidence_refused(self):
        self.fast_path()
        self.doc["framing"]["verified_evidence"] = False
        self.assertRefused(self.doc, "verified_evidence")

    def test_policy_digest_is_pinned(self):
        section = self.fast_path()
        section["policy_sha256"] = A64
        cfg = CM.parse_gateway_config(self.doc)
        with self.assertRaises(CM.ManifestError):
            CM.resolve_fast_path_policy(cfg.fast_path)

    def test_production_activation_needs_application_contract_and_approval(self):
        section = self.fast_path()
        self.doc["deployment_profile"] = "production"
        self.doc["observability"]["log_wire_sha256"] = False
        self.doc["framing"]["owner_ruling_ref"] = "D-x"
        section["activation"] = "production"
        self.assertRefused(self.doc, "application_contract_ref")
        section["application_contract_ref"] = "app-contract-1"
        cfg = CM.parse_gateway_config(self.doc)
        with self.assertRaises(CM.ManifestError) as caught:
            CM.resolve_fast_path_policy(cfg.fast_path)
        self.assertIn("APPROVED", str(caught.exception))

    def test_disabled_fast_path_carries_no_policy(self):
        self.doc["fast_path"]["policy_file"] = "x.json"
        self.assertRefused(self.doc, "disabled")

    def test_consistency_of_the_two_documents(self):
        cfg = CM.parse_gateway_config(self.doc)
        manifest = CM.parse_manifest(self.manifest)   # max_decoded_body=480
        self.assertIn("max_received_body_over_max_decoded_body",
                      CM.validate_consistency(cfg, manifest))


class LauncherTests(Fixture):
    def setUp(self):
        super().setUp()
        import live_stack as L
        self.make = lambda mode: CM.parse_gateway_config(L.gateway_config(
            mode=mode, manifest="m.json", listen_port=8080, guard_port=8081, sink_port=8082,
            admin_port=8083, v4_url="http://127.0.0.1:8000", v5_url="http://127.0.0.1:8001",
            workdir=self.dir.name)["cascade_gateway"])

    def test_the_example_configuration_stays_valid_and_conservative(self):
        cfg = CM.load_gateway_config(os.path.join(REPO, "config.cascade.example.yaml"))
        self.assertEqual(cfg.mode, C.CASCADE_OBSERVE)
        self.assertEqual(cfg.deployment_profile, "lab")
        self.assertEqual(cfg.fast_path.activation, "disabled")
        self.assertFalse(cfg.framing.verified_evidence)
        self.assertFalse(cfg.observability.log_wire_sha256)

    def test_only_authoritative_modes_put_the_guard_in_the_path(self):
        import launch
        target = lambda mode: launch.mitmdump_argv(self.make(mode))[  # noqa: E731
            launch.mitmdump_argv(self.make(mode)).index("--mode") + 1]
        self.assertEqual(target(C.CASCADE_ACTIVE), "reverse:http://127.0.0.1:8081")
        self.assertEqual(target(C.V5_ONLY), "reverse:http://127.0.0.1:8081")
        self.assertEqual(target(C.CASCADE_OBSERVE), "reverse:http://127.0.0.1:8082")
        self.assertEqual(target(C.V4_ONLY), "reverse:http://127.0.0.1:8082")

    def test_launcher_passes_every_scalar_of_the_profile(self):
        import gateway_framing as GF
        import launch
        argv = launch.mitmdump_argv(self.make(C.CASCADE_ACTIVE))
        passed = {argv[i + 1].split("=", 1)[0] for i, a in enumerate(argv) if a == "--set"}
        scalars = {k for k, v in GF.REQUIRED_OPTIONS.items() if v not in ([], None)}
        self.assertEqual(scalars - passed, set())


if __name__ == "__main__":
    unittest.main()
