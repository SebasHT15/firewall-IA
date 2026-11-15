"""Mutation test for the independent STAB-HELD construction and seal gate."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.evaluation.build_v5_stab_held import build, chunked_source_wire
from scripts.evaluation.check_v5_stab_held import check, flatten, P1

ROOT = Path(__file__).resolve().parents[1]
PILOT = Path("/home/sebas/Documents/Codex/2026-10-22/firewall-c1-model2-continuidad/work/pilot-integration-007/pools")


class StabilityConstructionTest(unittest.TestCase):
    def test_counts_and_chunked_frame(self):
        rows = build()
        self.assertEqual(len(rows), 1260)
        self.assertEqual(len({r["case_id"] for r in rows}), len(rows))
        chunked = [r for r in rows if r["source_framing"] == "chunked"]
        self.assertEqual(len(chunked), 30)
        self.assertTrue(all(hashlib.sha256(chunked_source_wire(r["text"])).hexdigest()
                            == r["source_wire_sha256"] for r in chunked))

    @unittest.skipUnless(PILOT.is_dir(), "source pool checkout unavailable")
    def test_probe_element_mutation_is_rejected(self):
        rows = build()
        rows[0]["value_element"] = next(flatten(P1.POOLS))
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            data = b"".join((json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n").encode() for r in rows)
            (folder / "cases.jsonl").write_bytes(data)
            (folder / "manifest.json").write_text(json.dumps({"cases_sha256": hashlib.sha256(data).hexdigest(),
                                                               "cases": len(rows)}))
            result = check(folder, PILOT, ROOT / "datasets/v5_sources/benign",
                           ROOT / "datasets/v5_sources/final_candidate/attack_pool.jsonl")
            self.assertGreater(result["L8_overlap_probe_pool_elements"], 0)
            self.assertFalse(result["preseal_pass"])


if __name__ == "__main__":
    unittest.main()
