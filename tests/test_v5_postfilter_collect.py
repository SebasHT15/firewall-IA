"""Tests for scripts/dataset/collect_v5_postfilter_annotations.py (verbatim collection of LLM annotations, D58 §7).

Synthetic round directories and synthetic Claude Code transcripts only; no real annotation is produced here.
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts", "dataset"))
import collect_v5_postfilter_annotations as K  # noqa: E402

MODEL = "model-test-1"


def transcript(path, reads, handback, model=MODEL, extra_tool=None):
    ev = [{"type": "user", "message": {"content": "prompt"}}]
    for p in reads:
        ev.append({"type": "assistant", "message": {"model": model, "content": [
            {"type": "tool_use", "name": "Read", "input": {"file_path": p}}]}})
    if extra_tool:
        ev.append({"type": "assistant", "message": {"model": model, "content": [
            {"type": "tool_use", "name": extra_tool, "input": {"command": "ls"}}]}})
    ev.append({"type": "assistant", "message": {"model": model, "content": [
        {"type": "tool_use", "name": "SubagentHandback", "input": {"message": handback}}]}})
    with open(path, "w", encoding="utf-8") as fh:
        for e in ev:
            fh.write(json.dumps(e) + "\n")
    return path


class Collect(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.t)
        self.r = os.path.join(self.t, "round-1")
        d = os.path.join(self.r, "annotation_a1")
        os.makedirs(d)
        with open(os.path.join(d, "README.md"), "w") as fh:
            fh.write("instructions\n")
        with open(os.path.join(d, "packet.jsonl"), "w") as fh:
            for i in range(1, 6):
                fh.write(json.dumps({"sample_id": f"PF1-{i:04d}", "category": "X", "payload_wire": f"synthmark {i}"}) + "\n")
        self.man = K.make_batches(self.r, "a1", 3)
        self.d = d
        self.allowed = [os.path.join(d, "README.md"), os.path.join(d, "batches", "batch_01.jsonl")]

    def hb(self, ids, label="VERIFIABLE"):
        return "\n".join(json.dumps({"sample_id": i, "label_class": label, "failure_mode": None,
                                     "better_category": None, "note": "n"}) for i in ids)

    def test_batches_deterministic_and_never_rewritten(self):
        self.assertEqual([b["rows"] for b in self.man["batches"]], [3, 2])
        self.assertEqual(self.man["batches"][1]["sample_ids"], ["PF1-0004", "PF1-0005"])
        with self.assertRaises(FileExistsError):
            K.make_batches(self.r, "a1", 3)

    def test_accept_verbatim_then_assemble(self):
        ids1 = self.man["batches"][0]["sample_ids"]
        tr = transcript(os.path.join(self.t, "t1.jsonl"), self.allowed, "```\n" + self.hb(ids1) + "\n```")
        rec = K.collect(self.r, "a1", 1, tr, MODEL, 1, "agent-1")
        self.assertEqual(rec["status"], "ACCEPTED")
        with open(os.path.join(self.d, "raw", "batch_01.attempt_1.handback.txt")) as fh:
            self.assertTrue(fh.read().startswith("```"))           # stored verbatim, fences included
        with self.assertRaises(SystemExit):                           # raw never overwritten
            K.collect(self.r, "a1", 1, tr, MODEL, 1, "agent-1")
        with self.assertRaises(SystemExit):                           # batch 2 missing
            K.assemble(self.r, "a1")
        ids2 = self.man["batches"][1]["sample_ids"]
        tr2 = transcript(os.path.join(self.t, "t2.jsonl"),
                         [self.allowed[0], os.path.join(self.d, "batches", "batch_02.jsonl")], self.hb(ids2, "INCORRECT"))
        self.assertEqual(K.collect(self.r, "a1", 2, tr2, MODEL, 1, "agent-2")["status"], "REFUSED")  # no failure_mode
        hb2 = "\n".join(json.dumps({"sample_id": i, "label_class": "INCORRECT", "failure_mode": "prose",
                                    "better_category": None, "note": "n"}) for i in ids2)
        tr3 = transcript(os.path.join(self.t, "t3.jsonl"),
                         [self.allowed[0], os.path.join(self.d, "batches", "batch_02.jsonl")], hb2)
        self.assertEqual(K.collect(self.r, "a1", 2, tr3, MODEL, 2, "agent-3")["status"], "ACCEPTED")
        res = K.assemble(self.r, "a1")
        self.assertEqual(res["rows"], 5)
        rows = [json.loads(x) for x in open(os.path.join(self.r, "annotations_a1.jsonl"))]
        self.assertEqual([r["sample_id"] for r in rows], [f"PF1-{i:04d}" for i in range(1, 6)])
        self.assertEqual({r["attempt"] for r in rows if r["batch"] == 2}, {2})

    def test_partial_assembly_never_writes_the_official_file(self):
        ids1 = self.man["batches"][0]["sample_ids"]
        tr = transcript(os.path.join(self.t, "p.jsonl"), self.allowed, self.hb(ids1))
        K.collect(self.r, "a1", 1, tr, MODEL, 1, "x")
        res = K.assemble(self.r, "a1", partial=True)
        self.assertEqual((res["rows"], res["missing_batches"], res["missing_rows"]), (3, [2], 2))
        self.assertFalse(os.path.exists(os.path.join(self.r, "annotations_a1.jsonl")))
        self.assertTrue(os.path.exists(os.path.join(self.r, "annotations_a1.partial.jsonl")))

    def test_refusals_are_recorded_not_accepted(self):
        ids1 = self.man["batches"][0]["sample_ids"]
        cases = [("a.jsonl", dict(model="other"), self.allowed, self.hb(ids1)),           # wrong model
                 ("b.jsonl", {}, self.allowed + ["/etc/hosts"], self.hb(ids1)),           # another file
                 ("c.jsonl", dict(extra_tool="Bash"), self.allowed, self.hb(ids1)),       # any other tool
                 ("d.jsonl", {}, self.allowed, self.hb(ids1[:2])),                        # missing item
                 ("e.jsonl", {}, self.allowed, self.hb(ids1 + ["PF1-0099"]))]             # extra item
        for attempt, (name, kw, reads, hb) in enumerate(cases, start=1):
            rec = K.collect(self.r, "a1", 1, transcript(os.path.join(self.t, name), reads, hb, **kw), MODEL,
                            attempt, "x")
            self.assertEqual(rec["status"], "REFUSED", name)
            self.assertTrue(os.path.isfile(os.path.join(self.d, "raw", f"batch_01.attempt_{attempt}.handback.txt")))
        with self.assertRaises(SystemExit):                            # no accepted attempt for batch 1
            K.assemble(self.r, "a1")

    def test_mixed_model_fallback_refused(self):
        ids1 = self.man["batches"][0]["sample_ids"]
        tr = transcript(os.path.join(self.t, "m.jsonl"), self.allowed, self.hb(ids1))
        ev = [json.loads(x) for x in open(tr)]
        ev[-1]["message"]["model"] = "model-fallback"                  # hand-back produced by another model
        with open(tr, "w") as fh:
            fh.write("".join(json.dumps(e) + "\n" for e in ev))
        rec = K.collect(self.r, "a1", 1, tr, MODEL, 1, "x")
        self.assertEqual(rec["status"], "REFUSED")
        self.assertEqual(rec["models_served"], ["model-fallback", MODEL])
        self.assertEqual([t["model"] for t in rec["turns"]][-1], "model-fallback")

    def test_tampered_batch_refused(self):
        with open(os.path.join(self.d, "batches", "batch_01.jsonl"), "a") as fh:
            fh.write("\n")
        with self.assertRaises(SystemExit):
            K.collect(self.r, "a1", 1, transcript(os.path.join(self.t, "f.jsonl"), self.allowed, "x"), MODEL, 1, "x")


if __name__ == "__main__":
    unittest.main()
