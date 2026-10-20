"""Tests for scripts/dataset/audit_v5_postfilter.py (V5-DATA-SPEC-r3 §7 post-filter audit, D58).

Fixture pools are SYNTHETIC: abstract markers (`synthmark sqli 0007`) with no exploit content, every record
`synthetic: true`, so a fixture round is always reported FIXTURE and never as a §7 gate result. Annotation and
human labels below are test inputs written by the test, not reviews.
"""
import csv
import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts", "dataset"))
import audit_v5_postfilter as A  # noqa: E402
import build_v5_attack_pool as B  # noqa: E402

C = A.C
LAYOUT = {"SQL Injection": {"SQL Injection/a.txt": 60, "SQL Injection/b.md": 25, "SQL Injection/c.txt": 1},
          "CRLF Injection": {"hardcoded:CRLF_PAYLOADS": 22},
          "path_file_access": {"Directory Traversal/d.txt": 30, "File Inclusion/e.txt": 40}}


def write_denylist(path, status="APPROVED", approval=True, entry_status=None):
    doc = {"schema": "v5-patt-third-party-denylist/v1", "status": status, "reviewed_not_denied": [],
           "denied": [{"path": "SQL Injection/Intruder/FUZZDB_X.txt", "reason": "fuzzdb_prefix", "evidence": "name",
                       "basis": "spec_initial_list", "status": entry_status or status}]}
    if approval:
        doc["approval"] = {"approved_by": "owner (test)", "date": "2026-10-19", "decision_ref": "test"}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    return path


def make_pool(root, layout=LAYOUT, status="APPROVED", synthetic=True, mutate=None):
    """Write attack_pool.jsonl + manifest.json + deny-list under root; return (attack_dir, denylist)."""
    attack = os.path.join(root, "attack")
    os.makedirs(attack, exist_ok=True)
    dl = write_denylist(os.path.join(root, "denylist.json"), status=status)
    recs = []
    for ci, (cat, files) in enumerate(sorted(layout.items())):
        for fi, (f, n) in enumerate(sorted(files.items())):
            for i in range(n):
                r = {"record_id": f"r{ci}{fi}{i:04d}", "status": C.ACCEPTED, "label_status": C.LABEL_PENDING,
                     "dedup_scope": cat, "category_v4": cat, "source_file": f, "line_index": i, "block_index": None,
                     "payload_wire": f"synthmark c{ci} f{fi} {i:04d}", "payload_logical": f"synthmark c{ci} f{fi} {i:04d}"}
                if synthetic:
                    r["synthetic"] = True
                recs.append(r)
    if mutate:
        mutate(recs)
    info = C.write_jsonl(os.path.join(attack, "attack_pool.jsonl"), recs, key=lambda r: r["record_id"])
    _, _, dl_sha = B.load_denylist(dl)
    C.write_json(os.path.join(attack, "manifest.json"), {
        "artifacts": [{"path": "attack_pool.jsonl", "sha256": info["sha256"], "records": info["records"]}],
        "denylist": {"path": "denylist.json", "sha256": dl_sha, "status": status}})
    return attack, dl


def sample_args(attack, dl, out_root, seed="pf-test-seed-1", k=1, doc=None):
    return ["sample", "--attack-dir", attack, "--denylist", dl, "--out-root", out_root, "--round", str(k),
            "--seed", seed] + (["--filter-change-doc", doc] if doc else [])


class TestAllocation(unittest.TestCase):
    def test_whole_pool_when_small(self):
        self.assertEqual(A.allocate_by_file({"a": 3, "b": 2}, 50), {"a": 3, "b": 2})

    def test_every_file_represented_sum_exact_and_bounded(self):
        sizes = {f"f{i}": s for i, s in enumerate([500, 40, 3, 1, 1, 90, 7])}
        q = A.allocate_by_file(sizes, 50)
        self.assertEqual(sum(q.values()), 50)
        self.assertTrue(all(1 <= q[f] <= sizes[f] for f in sizes))
        self.assertGreater(q["f0"], q["f5"])

    def test_more_files_than_n(self):
        q = A.allocate_by_file({f"f{i:02d}": 1 for i in range(60)}, 50)
        self.assertEqual(sum(q.values()), 50)
        self.assertTrue(all(v in (0, 1) for v in q.values()))

    def test_deterministic_tie_break(self):
        self.assertEqual(A.allocate_by_file({"b": 5, "a": 5}, 3), A.allocate_by_file({"a": 5, "b": 5}, 3))


class TestDenylistApproval(unittest.TestCase):
    def test_approved_needs_approval_record(self):
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaises(SystemExit):
                B.load_denylist(write_denylist(os.path.join(t, "d.json"), approval=False))
            doc, denied, _ = B.load_denylist(write_denylist(os.path.join(t, "e.json")))
            self.assertEqual(doc["status"], "APPROVED")

    def test_mixed_entry_status_refused(self):
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaises(SystemExit):
                B.load_denylist(write_denylist(os.path.join(t, "d.json"), entry_status="PROPOSED"))
            with self.assertRaises(SystemExit):
                B.load_denylist(write_denylist(os.path.join(t, "e.json"), status="DRAFT", approval=False))

    def test_repository_lists_status(self):
        d = os.path.join(ROOT, "scripts", "dataset", "v5_lexicon")
        for name, status in (("patt_third_party_denylist_v1.json", "PROPOSED"),     # superseded
                             ("patt_third_party_denylist_v2.json", "APPROVED")):    # D66
            doc, denied, _ = B.load_denylist(os.path.join(d, name))
            self.assertEqual(doc["status"], status, name)
            self.assertTrue(all(e["evidence"] for e in denied.values()))
        self.assertEqual(B.DEFAULT_DENYLIST, os.path.join(d, "patt_third_party_denylist_v2.json"))

    def test_v2_is_v1_plus_three_evidenced_denials(self):
        d = os.path.join(ROOT, "scripts", "dataset", "v5_lexicon")
        _, v1, _ = B.load_denylist(os.path.join(d, "patt_third_party_denylist_v1.json"))
        doc2, v2, _ = B.load_denylist(os.path.join(d, "patt_third_party_denylist_v2.json"))
        self.assertEqual(set(v2) - set(v1), {"SQL Injection/Intruder/Auth_Bypass.txt",
                                             "SQL Injection/Intruder/Auth_Bypass2.txt",
                                             "XSS Injection/Intruders/jsonp_endpoint.txt"})
        self.assertTrue(set(v1) <= set(v2))
        self.assertFalse(set(v2) & {e["path"] for e in doc2["reviewed_not_denied"]})


class TestLoadPool(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.t)

    def test_proposed_denylist_refused_for_sampling_but_plan_allowed(self):
        attack, dl = make_pool(self.t, status="PROPOSED")
        with self.assertRaises(SystemExit):
            A.load_pool(attack, dl)
        pool = A.load_pool(attack, dl, require_approved=False)
        p = A.plan(pool["records"])
        self.assertEqual((p["SQL Injection"]["sample"], p["CRLF Injection"]["sample"]), (50, 22))
        self.assertTrue(p["CRLF Injection"]["whole_pool"])
        self.assertEqual(p["CRLF Injection"]["human"], 20)

    def test_tampered_pool_and_foreign_denylist_refused(self):
        attack, dl = make_pool(self.t)
        self.assertEqual(A.load_pool(attack, dl)["mode"], A.FIXTURE)
        other = write_denylist(os.path.join(self.t, "other.json"), status="APPROVED")
        with open(other, "a", encoding="utf-8") as fh:
            fh.write("\n")
        with self.assertRaises(SystemExit):
            A.load_pool(attack, other)
        with open(os.path.join(attack, "attack_pool.jsonl"), "a", encoding="utf-8") as fh:
            fh.write("\n")
        with self.assertRaises(SystemExit):
            A.load_pool(attack, dl)

    def test_non_pending_and_mixed_records_refused(self):
        def adjudicated(recs):
            recs[0]["label_status"] = C.LABEL_VERIFIED

        def mixed(recs):
            recs[0].pop("synthetic")
        for mut in (adjudicated, mixed):
            with tempfile.TemporaryDirectory() as t:
                attack, dl = make_pool(t, mutate=mut)
                with self.assertRaises(SystemExit):
                    A.load_pool(attack, dl)

    def test_protected_path_refused(self):
        with self.assertRaises(SystemExit):
            A.load_pool(os.path.join(self.t, "external_v1", "attack"))


class TestSampling(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.t)
        self.attack, self.dl = make_pool(self.t)
        self.out = os.path.join(self.t, "audit")
        A.main(sample_args(self.attack, self.dl, self.out))
        self.d = A.round_dir(self.out, 1)
        self.sample = C.read_jsonl(os.path.join(self.d, "sample.jsonl"))
        with open(os.path.join(self.d, "human_review", "human_review_sample.csv"), encoding="utf-8") as fh:
            self.human = list(csv.DictReader(fh))
        with open(os.path.join(self.d, "audit_state.json"), encoding="utf-8") as fh:
            self.state = json.load(fh)

    def test_sizes_strata_and_provenance(self):
        by = {}
        for s in self.sample:
            by.setdefault(s["category"], []).append(s)
        self.assertEqual({c: len(v) for c, v in by.items()},
                         {"CRLF Injection": 22, "SQL Injection": 50, "path_file_access": 50})
        self.assertEqual({s["source_file"] for s in by["SQL Injection"]}, set(LAYOUT["SQL Injection"]))
        self.assertEqual(len({s["record_id"] for s in self.sample}), len(self.sample))
        self.assertTrue(all(s["payload_wire_sha256"] == C.sha256_bytes(s["payload_wire"].encode()) for s in self.sample))
        self.assertEqual(self.state["mode"], A.FIXTURE)
        self.assertEqual(self.state["denylist"]["status"], "APPROVED")
        self.assertEqual(self.state["params_status"], A.PARAMS_STATUS)

    def test_human_subsample_blind_stratified_within_sample(self):
        ids = {s["sample_id"] for s in self.sample}
        self.assertTrue({h["sample_id"] for h in self.human} <= ids)
        self.assertEqual(sorted(self.human[0]), sorted(["sample_id", "category", "source_file", "payload",
                                                        "payload_logical"]))
        per = {}
        for h in self.human:
            per[h["category"]] = per.get(h["category"], 0) + 1
        self.assertEqual(per, {"CRLF Injection": 20, "SQL Injection": 20, "path_file_access": 20})

    def test_byte_identical_and_order_independent(self):
        out2 = os.path.join(self.t, "audit2")
        recs = C.read_jsonl(os.path.join(self.attack, "attack_pool.jsonl"))
        s1, h1 = A.draw(recs, "pf-test-seed-1", 1)
        s2, h2 = A.draw(list(reversed(recs)), "pf-test-seed-1", 1)
        self.assertEqual((s1, h1), (s2, h2))
        A.main(sample_args(self.attack, self.dl, out2))
        for rel in ("sample.jsonl", "audit_state.json", "human_review/human_review_sample.csv"):
            with open(os.path.join(self.d, rel), "rb") as fa, \
                    open(os.path.join(A.round_dir(out2, 1), rel), "rb") as fb:
                self.assertEqual(fa.read(), fb.read(), rel)
        s3, _ = A.draw(recs, "pf-test-seed-2", 1)
        self.assertNotEqual([r["record_id"] for r in s1], [r["record_id"] for r in s3])

    def test_annotation_packets_blind_separate_and_not_rewritten(self):
        A.main(["annotation-packets", "--out-root", self.out, "--round", "1"])
        p1 = C.read_jsonl(os.path.join(self.d, "annotation_a1", "packet.jsonl"))
        p2 = C.read_jsonl(os.path.join(self.d, "annotation_a2", "packet.jsonl"))
        self.assertEqual(sorted(r["sample_id"] for r in p1), sorted(s["sample_id"] for s in self.sample))
        self.assertEqual(sorted(p1, key=lambda r: r["sample_id"]), sorted(p2, key=lambda r: r["sample_id"]))
        self.assertNotEqual([r["sample_id"] for r in p1], [r["sample_id"] for r in p2])   # independent orders
        self.assertEqual(set(p1[0]), {"sample_id", "category", "source_file", "payload_wire", "payload_logical"})
        with open(os.path.join(self.d, "annotation_a1", "README.md"), encoding="utf-8") as fh:
            self.assertIn("annotations_a1.jsonl", fh.read())
        with self.assertRaises(FileExistsError):
            A.main(["annotation-packets", "--out-root", self.out, "--round", "1"])

    def test_round_rules(self):
        with self.assertRaises(SystemExit):                       # never redrawn
            A.main(sample_args(self.attack, self.dl, self.out))
        with self.assertRaises(SystemExit):                       # pre-filter seed reused
            A.main(sample_args(self.attack, self.dl, os.path.join(self.t, "x"), seed=A.PRE.DEFAULT_SEED))
        with self.assertRaises(SystemExit):                       # beyond one re-audit
            A.main(sample_args(self.attack, self.dl, self.out, seed="s3", k=3))
        with self.assertRaises(SystemExit):                       # round 2 before round 1 is reported
            A.main(sample_args(self.attack, self.dl, self.out, seed="s2", k=2))
        with self.assertRaises(SystemExit):                       # seed of round 1 reused
            A.check_round(self.out, 2, "pf-test-seed-1", "x", None)


def write_annotations(d, labels_a1, labels_a2, models=("model-A", "model-B")):
    C.write_json(os.path.join(d, "annotators.json"), {"a1": {"model": models[0]}, "a2": {"model": models[1]}})
    for name, labels in (("a1", labels_a1), ("a2", labels_a2)):
        rows = [{"sample_id": sid, "label_class": lc,
                 "failure_mode": "other" if lc == "INCORRECT" else None} for sid, lc in sorted(labels.items())]
        C.write_jsonl(os.path.join(d, f"annotations_{name}.jsonl"), rows, key=lambda r: r["sample_id"])


def write_human(d, labels, reviewer="reviewer-X"):
    with open(os.path.join(d, "human_review", "human_review_sample.csv"), encoding="utf-8") as fh:
        ids = [r["sample_id"] for r in csv.DictReader(fh)]
    with open(os.path.join(d, "human_review", "human_labels.csv"), "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=A.HUMAN_FIELDS)
        w.writeheader()
        for sid in ids:
            lc = labels.get(sid, "")
            w.writerow({"batch": 1, "sample_id": sid, "reviewer": reviewer if lc else "", "label_class": lc,
                        "failure_mode": "other" if lc == "INCORRECT" else ""})
    return ids


class TestReport(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.t)
        self.attack, self.dl = make_pool(self.t)
        self.out = os.path.join(self.t, "audit")
        A.main(sample_args(self.attack, self.dl, self.out))
        self.d = A.round_dir(self.out, 1)
        self.sample = C.read_jsonl(os.path.join(self.d, "sample.jsonl"))
        self.ids = {c: [s["sample_id"] for s in self.sample if s["category"] == c]
                    for c in ("CRLF Injection", "SQL Injection", "path_file_access")}
        self.all_v = {s["sample_id"]: "VERIFIABLE" for s in self.sample}

    def status(self):
        return {c: v["status"] for c, v in A.report(self.out, 1)["categories"].items()}

    def test_pending_annotation_then_human(self):
        self.assertEqual(set(self.status().values()), {A.PENDING_ANNOTATION})
        write_annotations(self.d, self.all_v, self.all_v)
        self.assertEqual(set(self.status().values()), {A.PENDING_HUMAN_REVIEW})
        rep = A.report(self.out, 1)
        self.assertFalse(rep["real_gate_run"])                   # fixture: never a gate result
        self.assertIn("FIXTURE", rep["note"])
        self.assertTrue(os.path.isfile(os.path.join(self.d, "report.md")))

    def test_agreement_interim_lists_every_disagreement_and_resolves_nothing(self):
        ids = [s["sample_id"] for s in self.sample]
        a1 = dict(self.all_v)
        a2 = {i: "VERIFIABLE" for i in ids[:-10]}                     # a2 incomplete: last 10 missing
        a2[ids[0]] = "INCORRECT"                                      # needs adjudication
        a2[ids[1]] = "PROBABLY_CORRECT"                               # V/P split: rule candidate only
        write_annotations(self.d, a1, {})
        rows = [{"sample_id": i, "label_class": lc, "failure_mode": "other" if lc == "INCORRECT" else None}
                for i, lc in sorted(a2.items())]
        C.write_jsonl(os.path.join(self.d, "annotations_a2.partial.jsonl"), rows, key=lambda r: r["sample_id"])
        os.remove(os.path.join(self.d, "annotations_a2.jsonl"))
        res = A.agreement(self.d)
        self.assertTrue(res["status"].startswith("INTERIM"))
        self.assertEqual((res["paired"], len(res["missing"]["a2"])), (len(ids) - 10, 10))
        kinds = {r["sample_id"]: r["kind"] for r in res["_sheet"]}
        self.assertEqual(kinds, {ids[0]: "needs_adjudication", ids[1]: "vp_split_rule_candidate"})
        self.assertEqual(set(A.report(self.out, 1)["summary"]), {A.PENDING_ANNOTATION})  # partial never gates

    def test_same_model_refused(self):
        write_annotations(self.d, self.all_v, self.all_v, models=("m", "M"))
        with self.assertRaises(SystemExit):
            A.report(self.out, 1)

    def test_adjudication_rules(self):
        sid = self.ids["SQL Injection"][0]
        sid2 = self.ids["SQL Injection"][1]
        a2 = dict(self.all_v, **{sid: "INCORRECT", sid2: "PROBABLY_CORRECT"})
        write_annotations(self.d, self.all_v, a2)
        st = self.status()
        self.assertEqual(st["SQL Injection"], A.PENDING_ADJUDICATION)  # V vs I needs an adjudicator
        self.assertEqual(st["CRLF Injection"], A.PENDING_HUMAN_REVIEW)
        A.main(["adjudication-sheet", "--out-root", self.out, "--round", "1"])
        pend = C.read_jsonl(os.path.join(self.d, "adjudication_pending.jsonl"))
        self.assertEqual(sorted(p["sample_id"] for p in pend), sorted([sid, sid2]))  # V/P rule not approved
        C.write_json(os.path.join(self.d, "adjudication_rules.json"),
                     {"vp_split_to_probably_correct": {"approved": True, "approved_by": "owner (test)", "date": "d"}})
        A.main(["adjudication-sheet", "--out-root", self.out, "--round", "1"])
        pend = C.read_jsonl(os.path.join(self.d, "adjudication_pending.jsonl"))
        self.assertEqual([p["sample_id"] for p in pend], [sid])   # V vs P resolved by the approved rule
        adj = os.path.join(self.d, "adjudication.jsonl")
        C.write_jsonl(adj, [{"sample_id": sid, "label_class": "INCORRECT", "adjudicator": "",
                             "adjudicator_role": "owner", "rationale": "r"}], key=lambda r: r["sample_id"])
        with self.assertRaises(SystemExit):                         # anonymous adjudication refused
            A.report(self.out, 1)
        C.write_jsonl(adj, [{"sample_id": self.ids["CRLF Injection"][0], "label_class": "INCORRECT",
                             "adjudicator": "coord", "adjudicator_role": "coordinator", "rationale": "r"}],
                      key=lambda r: r["sample_id"])
        with self.assertRaises(SystemExit):                         # agreed labels are not overridden
            A.report(self.out, 1)
        C.write_jsonl(adj, [{"sample_id": sid, "label_class": "INCORRECT", "adjudicator": "coord",
                             "adjudicator_role": "coordinator", "rationale": "r"}], key=lambda r: r["sample_id"])
        rep = A.report(self.out, 1)["categories"]["SQL Injection"]
        self.assertEqual(rep["status"], A.PENDING_HUMAN_REVIEW)
        self.assertEqual((rep["counts"]["INCORRECT"], rep["counts"]["PROBABLY_CORRECT"]), (1, 1))

    def test_vp_rule_scope_trace_and_no_verified(self):
        ids = self.ids["SQL Injection"]
        a2 = dict(self.all_v, **{ids[0]: "PROBABLY_CORRECT", ids[1]: "UNCERTAIN", ids[2]: "INCORRECT"})
        write_annotations(self.d, self.all_v, a2)
        C.write_json(os.path.join(self.d, "adjudication_rules.json"),
                     {"vp_split_to_probably_correct": {"approved": True, "approved_by": "owner (test)", "date": "d",
                                                       "decision_ref": "t"}})
        A.main(["adjudication-sheet", "--out-root", self.out, "--round", "1"])
        pend = {p["sample_id"] for p in C.read_jsonl(os.path.join(self.d, "adjudication_pending.jsonl"))}
        self.assertEqual(pend, {ids[1], ids[2]})                  # V/U and V/I never resolved by the rule
        trace = C.read_jsonl(os.path.join(self.d, "adjudication_rule_applied.jsonl"))
        self.assertEqual([t["sample_id"] for t in trace], [ids[0]])
        t = trace[0]
        self.assertEqual((t["a1"]["label_class"], t["a2"]["label_class"], t["resolved_label"], t["rule"]),
                         ("VERIFIABLE", "PROBABLY_CORRECT", "PROBABLY_CORRECT", A.VP_RULE_ID))
        self.assertEqual(t["approval"]["approved_by"], "owner (test)")
        rows = C.read_jsonl(os.path.join(self.d, "annotations_a2.jsonl"))   # originals untouched
        self.assertEqual({r["sample_id"]: r["label_class"] for r in rows}[ids[0]], "PROBABLY_CORRECT")
        rep = A.report(self.out, 1)
        self.assertNotIn("VERIFIED", json.dumps(rep))
        self.assertEqual(rep["categories"]["SQL Injection"]["status"], A.PENDING_ADJUDICATION)

    def test_adjudication_workbooks_protect_blind_review(self):
        hids = write_human(self.d, {})
        ids = [s["sample_id"] for s in self.sample if s["category"] == "SQL Injection"]
        inside = [i for i in ids if i in set(hids)][:2]
        outside = [i for i in ids if i not in set(hids)][:2]
        a2 = dict(self.all_v, **{i: "UNCERTAIN" for i in inside + outside})
        write_annotations(self.d, self.all_v, a2)
        A.main(["adjudication-sheet", "--out-root", self.out, "--round", "1"])
        p1 = A.adjudication_workbook(self.d, 1)
        with open(p1, encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(sorted(r["sample_id"] for r in rows), sorted(outside))
        self.assertEqual(rows[0]["a1_label"], "VERIFIABLE")
        with self.assertRaises(SystemExit):                         # never overwritten
            A.adjudication_workbook(self.d, 1)
        with self.assertRaises(SystemExit):                         # human review not done yet
            A.adjudication_workbook(self.d, 2)
        rows[0].update(label_class="UNCERTAIN", adjudicator="owner (test)", adjudicator_role="owner", rationale="r")
        rows[1].update(label_class="INCORRECT", adjudicator="owner (test)", adjudicator_role="owner", rationale="r")
        def save(rs):
            with open(p1, "w", encoding="utf-8", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=A.WORKBOOK_FIELDS)
                w.writeheader()
                w.writerows(rs)
        save(rows)
        with self.assertRaises(SystemExit):                         # INCORRECT without failure_mode
            A.adjudication_import(self.d)
        rows[1]["failure_mode"] = "other"
        rows[0]["adjudicator"] = ""
        save(rows)
        with self.assertRaises(SystemExit):                         # anonymous adjudication
            A.adjudication_import(self.d)
        rows[0]["adjudicator"] = "owner (test)"
        save(rows)
        self.assertEqual(A.adjudication_import(self.d)["adjudicated"], 2)
        write_human(self.d, {i: "VERIFIABLE" for i in hids})
        p2 = A.adjudication_workbook(self.d, 2)
        with open(p2, encoding="utf-8") as fh:
            self.assertEqual(sorted(r["sample_id"] for r in csv.DictReader(fh)), sorted(inside))

    def test_pass_fail_and_human_prevails(self):
        C.write_json(os.path.join(self.d, "adjudication_rules.json"),
                     {"vp_split_to_probably_correct": {"approved": False}})
        hids = write_human(self.d, {})
        outside = {c: [i for i in v if i not in set(hids)] for c, v in self.ids.items()}
        sql = self.ids["SQL Injection"]
        a = dict(self.all_v, **{i: "INCORRECT" for i in outside["SQL Injection"][:4]})  # 4/50: upper 18.8%
        a.update({i: "INCORRECT" for i in outside["path_file_access"][:5]})            # 5/50: upper 21.4%
        sql_h = [i for i in hids if i in set(sql)]
        a.update({i: "INCORRECT" for i in sql_h[:3]})       # LLM says INCORRECT, the human says VERIFIABLE
        write_annotations(self.d, a, a)
        hl = {i: "VERIFIABLE" for i in hids}
        crlf_h = [i for i in hids if i in set(self.ids["CRLF Injection"])]
        hl.update({i: "INCORRECT" for i in crlf_h[:5]})               # human 5/20 = 25% > 20% on CRLF
        write_human(self.d, hl)
        rep = A.report(self.out, 1)["categories"]
        self.assertEqual(rep["path_file_access"]["status"], A.FAIL)
        self.assertFalse(rep["path_file_access"]["criterion_1_incorrect_upper"])
        self.assertEqual(rep["CRLF Injection"]["status"], A.FAIL)
        self.assertFalse(rep["CRLF Injection"]["criterion_3_human_incorrect_share"])
        self.assertEqual(rep["CRLF Injection"]["counts"]["INCORRECT"], 5)   # human labels substituted
        self.assertEqual(rep["SQL Injection"]["counts"]["INCORRECT"], 4)  # 7 LLM, 3 overridden by the human
        self.assertEqual(rep["SQL Injection"]["status"], A.PASS)

    def test_human_sheet_is_blind_and_never_overwrites_labels(self):
        write_annotations(self.d, self.all_v, self.all_v)
        lab = A.human_sheet(self.d)
        with open(lab, encoding="utf-8") as fh:
            text = fh.read()
        self.assertNotIn("VERIFIABLE", text)                          # no LLM label anywhere
        with open(lab, encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(len(rows), 60)
        self.assertEqual(list(rows[0])[:6], ["batch", "sample_id", "category", "source_file", "payload",
                                             "payload_logical"])
        self.assertIn(A.PENDING_HUMAN_REVIEW, {v["status"] for v in A.report(self.out, 1)["categories"].values()})
        rows[0].update(reviewer="r", label_class="VERIFIABLE")
        with open(lab, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=A.HUMAN_SHEET_FIELDS)
            w.writeheader()
            w.writerows(rows)
        with self.assertRaises(SystemExit):
            A.human_sheet(self.d)

    def test_partial_human_is_pending_and_reviewer_required(self):
        write_annotations(self.d, self.all_v, self.all_v)
        hids = write_human(self.d, {})
        write_human(self.d, {hids[0]: "VERIFIABLE"})
        self.assertIn(A.PENDING_HUMAN_REVIEW, self.status().values())
        write_human(self.d, {i: "VERIFIABLE" for i in hids}, reviewer="")
        with self.assertRaises(SystemExit):
            A.report(self.out, 1)

    def test_tampered_sample_refused(self):
        with open(os.path.join(self.d, "sample.jsonl"), "a", encoding="utf-8") as fh:
            fh.write("\n")
        with self.assertRaises(SystemExit):
            A.report(self.out, 1)

    def test_reaudit_only_failed_after_documented_change(self):
        a = dict(self.all_v, **{i: "INCORRECT" for i in self.ids["path_file_access"][:6]})
        write_annotations(self.d, a, a)
        write_human(self.d, {i: "VERIFIABLE" for i in write_human(self.d, {})})
        A.report(self.out, 1)
        with self.assertRaises(SystemExit):                          # pool unchanged / no doc
            A.main(sample_args(self.attack, self.dl, self.out, seed="pf-r2", k=2))
        doc = os.path.join(self.t, "filter_change.md")
        with open(doc, "w", encoding="utf-8") as fh:
            fh.write("documented filter change (test)\n")
        attack2, dl2 = make_pool(os.path.join(self.t, "v2"), mutate=lambda r: r.pop())
        with self.assertRaises(SystemExit):
            A.main(sample_args(attack2, dl2, self.out, seed="pf-r2", k=2))     # no doc
        A.main(sample_args(attack2, dl2, self.out, seed="pf-r2", k=2, doc=doc))
        with open(os.path.join(A.round_dir(self.out, 2), "audit_state.json"), encoding="utf-8") as fh:
            st = json.load(fh)
        self.assertEqual(st["categories_audited"], ["path_file_access"])
        self.assertTrue(all(s["sample_id"].startswith("PF2-")
                            for s in C.read_jsonl(os.path.join(A.round_dir(self.out, 2), "sample.jsonl"))))


if __name__ == "__main__":
    unittest.main()
