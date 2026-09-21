"""External Test v1 — Phase E deterministic selection + freeze (freeze_external_v1.py).

Offline, no Docker, no model, no /classify. Pins the selection determinism and the freeze
invariants required by the Phase E task section H.

    python3 -m unittest tests.test_freeze_external_v1 -v
"""

import hashlib
import os
import random
import sys
import unittest

EXT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "scripts", "external")
sys.path.insert(0, EXT)

import freeze_external_v1 as F   # noqa: E402

CELLS = F.CELLS


def sha(t):
    return hashlib.sha256(t.encode()).hexdigest()


def rec(cell, i, seed=F.SEED, decision=None):
    cid = f"{cell}-{i:04d}"
    text = f"GET /{cell}/{i} HTTP/1.1\nHost: shop.fwlab.test:9100"
    rsha = sha(text)
    dec = decision or ("BLOCK" if cell in F.spec_lib.ATTACK_CATEGORIES else "ALLOW")
    return {"case_id": cid, "primary_cell": cell, "request_sha256": rsha,
            "request_text": text, "expected_decision": dec, "source": "original",
            "capture": {}, "selection_key": F.selection_key(cell, cid, rsha, seed)}


def full_pool(n_per=45, seed=F.SEED):
    return {cell: [rec(cell, i, seed) for i in range(n_per)] for cell in CELLS}


class TestDeterministicSelection(unittest.TestCase):
    def test_repeatable_and_order_independent(self):
        pool = full_pool()
        s1, _ = F.select_per_cell(pool)
        # shuffle every cell's input order; selection must be identical
        shuffled = {cell: random.Random(7).sample(v, len(v)) for cell, v in pool.items()}
        s2, _ = F.select_per_cell(shuffled)
        self.assertEqual(sorted(r["case_id"] for r in s1),
                         sorted(r["case_id"] for r in s2))
        self.assertEqual(len(s1), 40 * len(CELLS))

    def test_exactly_40_per_cell_and_400_total(self):
        selected, reserves = F.select_per_cell(full_pool())
        from collections import Counter
        per = Counter(r["primary_cell"] for r in selected)
        for cell in CELLS:
            self.assertEqual(per[cell], 40)
        self.assertEqual(len(selected), 400)
        self.assertEqual(sum(len(v) for v in reserves.values()), (45 - 40) * len(CELLS))

    def test_seed_change_changes_selection(self):
        a, _ = F.select_per_cell(full_pool(seed=F.SEED))
        b, _ = F.select_per_cell(full_pool(seed="different-seed-xyz"))
        self.assertNotEqual([r["case_id"] for r in a], [r["case_id"] for r in b],
                            "a different seed must change the selection ordering")

    def test_selection_is_content_independent(self):
        # two pools identical except request_text content; keys depend on sha, not text body,
        # but sha is derived from text -> use same text, assert selection stable across a
        # cosmetic field that is NOT part of the key
        pool = full_pool()
        tampered = {cell: [dict(r, technique="totally-different") for r in v]
                    for cell, v in pool.items()}
        s1 = [r["case_id"] for r in F.select_per_cell(pool)[0]]
        s2 = [r["case_id"] for r in F.select_per_cell(tampered)[0]]
        self.assertEqual(sorted(s1), sorted(s2))


class TestSupplementParticipatesUniformly(unittest.TestCase):
    def test_supplement_and_original_ranked_by_same_key(self):
        cell = "browser-forms-session"
        pool = {c: [] for c in CELLS}
        pool[cell] = ([rec(cell, i) for i in range(37)] +
                      [dict(rec(cell, 900 + i), source="supplement",
                            case_id=f"{cell}-supp-{i:04d}",
                            capture={"run_tag": "pre-freeze-supplement-browser-forms-session"})
                       for i in range(13)])
        # recompute keys for the renamed supplement ids
        for r in pool[cell]:
            r["selection_key"] = F.selection_key(cell, r["case_id"], r["request_sha256"])
        selected, _ = F.select_per_cell({cell: pool[cell]}, cells=[cell])
        self.assertEqual(len(selected), 40)
        # both sources can appear; selection purely by key
        ordered = sorted(pool[cell], key=lambda r: r["selection_key"])[:40]
        self.assertEqual({r["case_id"] for r in selected}, {r["case_id"] for r in ordered})


class TestValidationInvariants(unittest.TestCase):
    def _good(self):
        selected, _ = F.select_per_cell(full_pool())
        eligible = {r["case_id"] for r in selected}
        review = {r["case_id"]: None for r in selected}
        return selected, eligible, review

    def test_valid_set_passes(self):
        selected, eligible, review = self._good()
        self.assertEqual(F.validate(selected, eligible, set(), set(), review), [])

    def test_ineligible_case_fails(self):
        selected, eligible, review = self._good()
        eligible.discard(selected[0]["case_id"])
        probs = F.validate(selected, eligible, set(), set(), review)
        self.assertTrue(any("NOT Phase-D eligible" in p for p in probs))

    def test_duplicate_case_id_fails(self):
        selected, eligible, review = self._good()
        selected[1] = dict(selected[0])   # duplicate id
        probs = F.validate(selected, eligible, set(), set(), review)
        self.assertTrue(any("duplicate case_id" in p for p in probs))

    def test_changed_request_text_fails(self):
        selected, eligible, review = self._good()
        selected[0] = dict(selected[0], request_text=selected[0]["request_text"] + " TAMPERED")
        probs = F.validate(selected, eligible, set(), set(), review)
        self.assertTrue(any("SHA-256 does not recompute" in p for p in probs))

    def test_unresolved_needs_review_fails(self):
        selected, eligible, review = self._good()
        review[selected[0]["case_id"]] = "NEEDS_REVIEW"
        probs = F.validate(selected, eligible, set(), set(), review)
        self.assertTrue(any("unresolved NEEDS_REVIEW" in p for p in probs))

    def test_gt_exclusion_and_collision_fail(self):
        selected, eligible, review = self._good()
        probs = F.validate(selected, eligible, {selected[0]["case_id"]},
                           {selected[1]["case_id"]}, review)
        self.assertTrue(any("ground-truth exclusion" in p for p in probs))
        self.assertTrue(any("collision" in p for p in probs))

    def test_wrong_total_fails(self):
        selected, eligible, review = self._good()
        probs = F.validate(selected[:399], eligible, set(), set(), review)
        self.assertTrue(any("!= 400" in p for p in probs))

    def test_supplement_missing_run_tag_fails(self):
        selected, eligible, review = self._good()
        selected[0] = dict(selected[0], source="supplement", capture={})
        probs = F.validate(selected, eligible, set(), set(), review)
        self.assertTrue(any("supplement provenance" in p for p in probs))


class TestIntegrityHash(unittest.TestCase):
    def test_integrity_hash_deterministic_and_order_independent(self):
        selected, _ = F.select_per_cell(full_pool())
        h1, _ = F.integrity_hash(selected)
        h2, _ = F.integrity_hash(random.Random(3).sample(selected, len(selected)))
        self.assertEqual(h1, h2)
        # changing a request_sha256 changes the hash
        tampered = [dict(r) for r in selected]
        tampered[0]["request_sha256"] = "deadbeef"
        h3, _ = F.integrity_hash(tampered)
        self.assertNotEqual(h1, h3)


if __name__ == "__main__":
    unittest.main()
