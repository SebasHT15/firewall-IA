"""External Test v1 — pre-freeze browser-forms-session SUPPLEMENT (assembler + gate).

Offline, no Docker, no model, no /classify. Proves:
  - the supplement assembler labels captured rows ALLOW with the run tag and session context,
    copying request_text verbatim;
  - the supplement gate keeps genuinely NEW distinct requests, drops requests that duplicate
    the existing DRAFT (existing wins, so other cells cannot be displaced), dedups within the
    supplement deterministically, and applies the SAME collision checks;
  - updated eligible = existing eligible + new supplement eligible.

    python3 -m unittest tests.test_forms_supplement -v
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
sys.path.insert(0, os.path.join(EXT, "..", "dataset"))

import phase_d_gate as G          # noqa: E402
import label_supplement           # noqa: E402


def sha(t):
    return hashlib.sha256(t.encode()).hexdigest()


def existing(case_id, cell, request_text):
    return {"case_id": case_id, "primary_slice": cell, "expected_decision": "ALLOW",
            "attack_category": None, "benign_slice": cell,
            "request_text": request_text, "request_sha256": sha(request_text),
            "payload_decoded": "", "payload_placement": "none", "technique": "t",
            "label_confidence": "high", "review_status": "auto-accepted",
            "host": G.spec_lib.SHOP_HOST, "ground_truth_basis": "b",
            "capture": {"flow": cell}}


def supp(case_id, request_text):
    return existing(case_id, "browser-forms-session", request_text)


class TestSupplementGate(unittest.TestCase):
    def test_distinct_new_survive_dups_excluded(self):
        # existing DRAFT: a navigation GET /products/3 (other cell) and an authenticated
        # profile as lab-user in forms-session
        ex = [
            existing("browser-navigation-0010", "browser-navigation",
                     "GET /products/3 HTTP/1.1\nHost: shop.fwlab.test:9100"),
            existing("browser-forms-session-0020", "browser-forms-session",
                     "GET /profile HTTP/1.1\nHost: shop.fwlab.test:9100\nCookie: fwlab_session=u=lab-user"),
        ]
        sp = [
            supp("browser-forms-session-supp-0001",
                 "POST /login HTTP/1.1\nHost: shop.fwlab.test:9100\n\nusername=shopper2&password=s2-pass"),
            supp("browser-forms-session-supp-0002",
                 "GET /profile HTTP/1.1\nHost: shop.fwlab.test:9100\nCookie: fwlab_session=u=shopper2"),
            supp("browser-forms-session-supp-0003",   # duplicates existing nav GET /products/3
                 "GET /products/3 HTTP/1.1\nHost: shop.fwlab.test:9100"),
            supp("browser-forms-session-supp-0004",
                 "POST /cart HTTP/1.1\nHost: shop.fwlab.test:9100\nCookie: fwlab_session=u=shopper2\n\nproduct_id=3&quantity=2"),
            supp("browser-forms-session-supp-0005",   # internal supplement duplicate of 0004
                 "POST /cart HTTP/1.1\nHost: shop.fwlab.test:9100\nCookie: fwlab_session=u=shopper2\n\nproduct_id=3&quantity=2"),
        ]
        S = G.supplement_gate(ex, sp, (set(), []), [], G.load_smoke())
        e = S["elig"]
        self.assertTrue(e["browser-forms-session-supp-0001"]["eligible"])
        self.assertTrue(e["browser-forms-session-supp-0002"]["eligible"])
        self.assertTrue(e["browser-forms-session-supp-0004"]["eligible"])
        # duplicate of an EXISTING draft request -> excluded (existing wins)
        self.assertFalse(e["browser-forms-session-supp-0003"]["eligible"])
        self.assertEqual(S["dup"]["browser-forms-session-supp-0003"]["kind"],
                         "duplicate_of_existing_draft")
        # internal supplement duplicate -> excluded, keeper is the lowest supp id
        self.assertFalse(e["browser-forms-session-supp-0005"]["eligible"])
        self.assertEqual(S["dup"]["browser-forms-session-supp-0005"]["keeper"],
                         "browser-forms-session-supp-0004")
        self.assertEqual(sorted(S["new_eligible"]),
                         ["browser-forms-session-supp-0001",
                          "browser-forms-session-supp-0002",
                          "browser-forms-session-supp-0004"])

    def test_collision_still_enforced_on_supplement(self):
        row = "GET /leak HTTP/1.1\nHost: h"
        ex = []
        sp = [supp("browser-forms-session-supp-0009", row)]   # equals a V4 row
        S = G.supplement_gate(ex, sp, ({row}, [G.canonical_key(row)]), [], G.load_smoke())
        self.assertFalse(S["elig"]["browser-forms-session-supp-0009"]["eligible"])
        self.assertEqual(S["elig"]["browser-forms-session-supp-0009"]["primary_exclusion"],
                         "exact_collision")


class TestSupplementAssembler(unittest.TestCase):
    def _cap(self, tmp):
        def rec(seq, method, path, body=None, cookie=None):
            lines = [f"{method} {path} HTTP/1.1", "Host: shop.fwlab.test:9100",
                     "User-Agent: Chromium"]
            if cookie:
                lines.append(f"Cookie: {cookie}")
            text = "\n".join(lines) + (("\n\n" + body) if body else "")
            return {"seq": seq, "tag": "supp",
                    "captured_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "flow_id": f"f{seq}", "method": method, "host": "shop.fwlab.test",
                    "port": 9100, "path": path, "http_version": "HTTP/1.1",
                    "request_text": text, "request_sha256": sha(text),
                    "request_bytes": len(text.encode()),
                    "body_bytes": len(body.encode()) if body else 0}
        records = [
            rec(1, "POST", "/login", "username=shopper2&password=s2-pass"),
            rec(2, "GET", "/profile", cookie="fwlab_session=u=shopper2"),
            rec(3, "GET", "/cart", cookie="fwlab_cart=2x5"),          # guest (no session)
        ]
        cap = os.path.join(tmp, "sup.jsonl")
        bnd = os.path.join(tmp, "bnd.json")
        with open(cap, "w") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")
        with open(bnd, "w") as f:
            json.dump({"run_tag": "pre-freeze-supplement-browser-forms-session",
                       "flows": [{"start": 0, "end": len(records)}]}, f)
        return cap, bnd

    def test_assembly_labels_allow_with_run_tag(self):
        tmp = tempfile.mkdtemp()
        cap, bnd = self._cap(tmp)
        out = os.path.join(tmp, "candidates_supplement")
        rc = label_supplement.main(["--capture", cap, "--boundaries", bnd, "--out", out])
        self.assertEqual(rc, 0)
        rows = [json.loads(l) for l in
                open(os.path.join(out, "browser-forms-session-supplement.jsonl"))]
        self.assertEqual(len(rows), 3)
        for r in rows:
            self.assertEqual(r["expected_decision"], "ALLOW")
            self.assertEqual(r["primary_slice"], "browser-forms-session")
            self.assertEqual(r["run_tag"], "pre-freeze-supplement-browser-forms-session")
            self.assertTrue(r["case_id"].startswith("browser-forms-session-supp-"))
            self.assertEqual(r["request_sha256"], sha(r["request_text"]))
        # session context detection
        ctx = {r["case_id"]: r["session_context"] for r in rows}
        self.assertEqual(ctx["browser-forms-session-supp-0001"], "login-submit")
        self.assertEqual(ctx["browser-forms-session-supp-0002"], "authenticated")
        self.assertEqual(ctx["browser-forms-session-supp-0003"], "guest")


if __name__ == "__main__":
    unittest.main()
