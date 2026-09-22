"""External Test v1 — Phase C authoring specs (scripts/external/*_specs.py).

Offline, no Docker, no model. Pins the invariants of the DRAFT candidate pool that must
hold BEFORE capture: composition, in-lab scope, canonical replay-ability, label integrity,
and the courtesy independence pre-check being clean going into Phase D.

    python3 -m unittest tests.test_external_specs -v
"""

import os
import sys
import unittest

EXT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "scripts", "external")
sys.path.insert(0, EXT)

import wire            # noqa: E402
import spec_lib        # noqa: E402
import benign_specs    # noqa: E402
import attack_specs    # noqa: E402


class TestComposition(unittest.TestCase):
    def setUp(self):
        self.benign = benign_specs.build()
        self.attacks = attack_specs.build()
        self.all = self.benign + self.attacks

    def test_block_categories_have_draft_buffer(self):
        # target 40 final, draft ~48; require a real buffer above 40 per category.
        from collections import Counter
        c = Counter(s.group for s in self.attacks)
        for cat in spec_lib.ATTACK_CATEGORIES:
            with self.subTest(cat=cat):
                self.assertGreaterEqual(c[cat], 46, f"{cat} draft below buffer")

    def test_enumerable_benign_slices_meet_target(self):
        from collections import Counter
        c = Counter(s.group for s in self.benign)
        for slc in ("api-json", "api-query", "unseen-structure"):
            with self.subTest(slc=slc):
                self.assertGreaterEqual(c[slc], 40, f"{slc} below final target")

    def test_decisions_and_categories_consistent(self):
        for s in self.all:
            if s.expected_decision == "BLOCK":
                self.assertIn(s.attack_category, spec_lib.ATTACK_CATEGORIES)
                self.assertIsNone(s.benign_slice)
            else:
                self.assertEqual(s.expected_decision, "ALLOW")
                self.assertIn(s.benign_slice, spec_lib.BENIGN_SLICES)
                self.assertIsNone(s.attack_category)


class TestInLabScope(unittest.TestCase):
    """Every authored request targets a lab alias; nothing leaves the lab, including SSRF
    whose payload only *names* an external/internal host in a parameter value."""

    def test_all_hosts_are_lab_aliases(self):
        for s in benign_specs.build() + attack_specs.build():
            with self.subTest(group=s.group, path=s.path):
                self.assertIn(s.host, spec_lib.LAB_HOSTS)
                self.assertEqual(s.port, spec_lib.LAB_PORT)

    def test_ssrf_destination_is_lab_not_payload(self):
        ssrf = [s for s in attack_specs.build() if s.group == "ssrf"]
        self.assertTrue(ssrf)
        for s in ssrf:
            # the request is delivered to a lab alias; the SSRF target is only text
            self.assertIn(s.host, spec_lib.LAB_HOSTS)


class TestCanonicalReplayable(unittest.TestCase):
    def test_every_preview_is_canonical(self):
        for case_id, spec in spec_lib.assign_case_ids(benign_specs.build() + attack_specs.build()):
            with self.subTest(case_id=case_id):
                wire.assert_canonical(spec.render_preview())   # raises on failure

    def test_no_cr_in_any_authored_body(self):
        for s in benign_specs.build() + attack_specs.build():
            if s.body is not None:
                with self.subTest(group=s.group):
                    self.assertNotIn("\r", s.body,
                                     "CR in a body would break byte-exact replay")


class TestLabels(unittest.TestCase):
    def test_block_specs_have_basis_and_placement(self):
        for s in attack_specs.build():
            self.assertTrue(s.ground_truth_basis)
            self.assertIn(s.payload_placement,
                          {"query", "form", "json", "path", "header", "cookie"})
            self.assertTrue(s.payload, f"{s.group}/{s.technique} has empty payload")

    def test_confidence_and_review_are_valid(self):
        for s in benign_specs.build() + attack_specs.build():
            self.assertIn(s.label_confidence, {"high", "medium", "review"})
            self.assertIn(s.review_status, {"auto-accepted", "needs-review"})

    def test_ambiguous_specs_are_flagged_for_review(self):
        # a spec authored at reduced confidence must not be silently auto-accepted
        for s in benign_specs.build() + attack_specs.build():
            if s.label_confidence == "review":
                self.assertEqual(s.review_status, "needs-review")

    def test_case_ids_unique_and_stable(self):
        ids = [cid for cid, _ in spec_lib.assign_case_ids(
            benign_specs.build() + attack_specs.build())]
        self.assertEqual(len(ids), len(set(ids)))


class TestIndependencePrecheckInternal(unittest.TestCase):
    """Fast screen: no internal canonical duplicates and no reuse of the diagnostic or smoke
    fixtures. (The V4-corpus screen is exercised by preview_specs.py; it is slower and is not
    repeated here.) This is a COURTESY check, not the Phase D gate."""

    def test_no_internal_or_forbidden_collisions(self):
        rep = spec_lib.precheck_independence(
            benign_specs.build() + attack_specs.build(), check_v4=False)
        self.assertTrue(rep["clean"],
                        f"collisions: {rep['collisions'][:10]}")

    def test_smoke_fixture_sqli_not_reused(self):
        # the smoke BLOCK fixture is "1' OR '1'='1"; it must not appear verbatim as a payload
        for s in attack_specs.build():
            self.assertNotEqual(s.payload.strip().lower(), "1' or '1'='1")


if __name__ == "__main__":
    unittest.main()
