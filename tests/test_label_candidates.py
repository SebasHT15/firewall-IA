"""External Test v1 — Phase C assembler (scripts/external/label_candidates.py).

Offline, no Docker, no model. Synthesises a capture (in the exact shape capture_addon.py
emits) plus a boundaries manifest, then runs the assembler and pins its contract: correct
per-flow labelling by offset window, verbatim request_text passthrough, SHA re-verification,
off-lab-host skipping for browser flows, and refusal to mislabel a window whose size does
not match its Spec count.

    python3 -m unittest tests.test_label_candidates -v
"""

import datetime
import hashlib
import json
import os
import sys
import tempfile
import unittest

EXT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "scripts", "external")
sys.path.insert(0, EXT)

import spec_lib        # noqa: E402
import benign_specs    # noqa: E402
import attack_specs    # noqa: E402
import label_candidates  # noqa: E402


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def rec_from_spec(seq, spec, flow):
    text = spec.render_preview()
    return {
        "seq": seq, "tag": flow,
        "captured_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "flow_id": f"flow-{seq}", "method": spec.method, "host": spec.host,
        "port": spec.port, "path": spec.path, "http_version": "HTTP/1.1",
        "request_text": text, "request_sha256": sha(text),
        "request_bytes": len(text.encode("utf-8")),
        "body_bytes": len(spec.body.encode("utf-8")) if spec.body else 0,
    }


def browser_rec(seq, path, host=spec_lib.SHOP_HOST):
    text = f"GET {path} HTTP/1.1\nHost: {host}:{spec_lib.LAB_PORT}\nUser-Agent: Chromium"
    return {
        "seq": seq, "tag": "browser", "captured_utc": "2026-09-21T00:00:00+00:00",
        "flow_id": f"b-{seq}", "method": "GET", "host": host, "port": spec_lib.LAB_PORT,
        "path": path, "http_version": "HTTP/1.1", "request_text": text,
        "request_sha256": sha(text), "request_bytes": len(text.encode()), "body_bytes": 0,
    }


def synth_capture(tmp, off_host=True, break_flow=None):
    """Write a synthetic capture + boundaries covering all flows in run_capture order."""
    records, flows = [], []
    seq = 0

    def add_browser(name, paths, extra_off_host=False):
        nonlocal seq
        start = len(records)
        for p in paths:
            seq += 1
            records.append(browser_rec(seq, p))
        if extra_off_host:                       # a request the browser made off-lab
            seq += 1
            records.append(browser_rec(seq, "/favicon.ico", host="example.com"))
        flows.append({"flow": name, "kind": "browser", "group": name,
                      "start": start, "end": len(records), "count": len(records) - start,
                      "expected": None, "count_matches_expected": True})

    add_browser("browser-navigation", ["/", "/products", "/products/1"],
                extra_off_host=off_host)
    add_browser("browser-forms-session", ["/login", "/profile"])

    grouped = label_candidates.grouped_specs()
    order = [("api-json", benign_specs.api_json), ("api-query", benign_specs.api_query),
             ("unseen-structure", benign_specs.unseen_structure),
             ("sqli", attack_specs.sqli), ("cmdi", attack_specs.cmdi),
             ("xss", attack_specs.xss), ("path-traversal", attack_specs.path_traversal),
             ("ssrf", attack_specs.ssrf)]
    for group, fn in order:
        specs = [s for _, s in grouped[group]]
        start = len(records)
        for spec in specs:
            seq += 1
            records.append(rec_from_spec(seq, spec, group))
        end = len(records)
        if break_flow == group:                  # drop one record to force a size mismatch
            records.pop()
            end -= 1
        flows.append({"flow": group, "kind": "enumerable", "group": group,
                      "start": start, "end": end, "count": end - start,
                      "expected": len(specs),
                      "count_matches_expected": (end - start) == len(specs)})

    cap = os.path.join(tmp, "capture.jsonl")
    bnd = os.path.join(tmp, "boundaries.json")
    with open(cap, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with open(bnd, "w", encoding="utf-8") as f:
        json.dump({"schema": "external-v1-capture-boundaries/1", "capture_file": cap,
                   "flows": flows}, f)
    return cap, bnd


class TestAssembler(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.out = os.path.join(self.tmp, "candidates")

    def _load(self, name):
        with open(os.path.join(self.out, name), encoding="utf-8") as f:
            return [json.loads(l) for l in f if l.strip()]

    def test_clean_capture_labels_everything(self):
        cap, bnd = synth_capture(self.tmp, off_host=True)
        rc = label_candidates.main(["--capture", cap, "--boundaries", bnd, "--out", self.out])
        self.assertEqual(rc, 0)
        realized = json.load(open(os.path.join(self.out, "realized_counts.json")))
        self.assertEqual(realized["status"], "DRAFT")
        self.assertEqual(realized["problems"], [])
        # off-lab-host favicon was skipped
        self.assertEqual(realized["skipped_off_lab_host"], 1)
        # attack categories present at full draft count
        cells = realized["by_primary_cell"]
        self.assertGreaterEqual(cells["sqli"], 46)
        self.assertEqual(cells["browser-navigation"], 3)   # 3 lab paths, favicon skipped

    def test_block_candidates_carry_category_and_verbatim_text(self):
        cap, bnd = synth_capture(self.tmp)
        label_candidates.main(["--capture", cap, "--boundaries", bnd, "--out", self.out])
        sqli = self._load("sqli.jsonl")
        self.assertTrue(sqli)
        for c in sqli:
            self.assertEqual(c["expected_decision"], "BLOCK")
            self.assertEqual(c["attack_category"], "sqli")
            self.assertEqual(c["primary_slice"], "sqli")
            self.assertTrue(c["request_text"].startswith(c["method"]))
            self.assertEqual(c["request_sha256"], sha(c["request_text"]))
            self.assertIn("capture", c)
            self.assertEqual(c["capture"]["flow"], "sqli")

    def test_benign_candidates_are_allow(self):
        cap, bnd = synth_capture(self.tmp)
        label_candidates.main(["--capture", cap, "--boundaries", bnd, "--out", self.out])
        for name in ("api-json.jsonl", "browser-navigation.jsonl"):
            for c in self._load(name):
                self.assertEqual(c["expected_decision"], "ALLOW")
                self.assertIsNone(c["attack_category"])

    def test_size_mismatch_leaves_flow_unlabelled(self):
        cap, bnd = synth_capture(self.tmp, break_flow="cmdi")
        rc = label_candidates.main(["--capture", cap, "--boundaries", bnd, "--out", self.out])
        self.assertEqual(rc, 1)
        realized = json.load(open(os.path.join(self.out, "realized_counts.json")))
        self.assertTrue(any("cmdi" in p for p in realized["problems"]))
        # cmdi was not written because the window did not align
        self.assertNotIn("cmdi", realized["by_primary_cell"])


if __name__ == "__main__":
    unittest.main()
