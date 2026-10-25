#!/usr/bin/env python3
"""Real-interface tests for scripts/dataset/v5_component_binding.verify_components.

Uses the REAL v5_audit_evidence.verify, the REAL path_file_access audit binding (r3-execution evidence over
the frozen attack pool) and REAL pool records (a path record and a SQL Injection record), plus a minimal
real-schema census component fixture. Covers the owner-requested negative case (a SQLi original-pool record
claiming outcome_category=path_file_access must be rejected, category DERIVED from the audited record), row
identity/content, orphan membership, the combined-pool-PASS rejection, and the FINAL committed-evidence gate.

Run: python3 -I tests/test_v5_component_binding.py
"""
import sys, os, json, hashlib, tempfile
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "scripts/dataset"))
import v5_audit_evidence as AE
import v5_component_binding as CB

sha = lambda b: hashlib.sha256(b).hexdigest()
R3 = os.path.join(REPO, "reports/v5/postfilter-audit/r3-execution-2026-10-23")
POOL = os.path.join(REPO, "datasets/v5_sources/attack/attack_pool.jsonl")


def _binding(path_map):
    return {"schema": AE.SCHEMA, **{k: {"path": v, "sha256": sha(open(v, "rb").read())} for k, v in path_map.items()}}


def original_component():
    return {"component_id": "path_original",
            "audit_evidence": _binding({
                "exchange": f"{R3}/category-outcomes-for-consumers.json",
                "report":   f"{R3}/report.json",
                "state":    f"{REPO}/reports/v5/postfilter-audit/round-1/audit_state.json",
                "pool_manifest": f"{REPO}/datasets/v5_sources/attack/manifest.json",
                "pool":     POOL}),
            "category_outcomes": None}


def census_component(tmp):
    sample = f"{tmp}/s.jsonl"; open(sample, "w").write(json.dumps({"sample_id": "C1", "category": "Command Injection"}) + "\n")
    s_sha = sha(open(sample, "rb").read())
    pool = f"{tmp}/pool.jsonl"
    open(pool, "w").write("".join(json.dumps(r) + "\n" for r in [
        {"record_id": "cen-cmdi-1", "category_v4": "Command Injection", "payload_wire": "; id"},
        {"record_id": "cen-sqli-1", "category_v4": "SQL Injection", "payload_wire": "' OR 1=1--"}]))
    p_sha = sha(open(pool, "rb").read())
    man = f"{tmp}/m.json"; open(man, "w").write("{}"); m_sha = sha(open(man, "rb").read())
    report = {"schema": AE.REPORT_SCHEMA, "audit_type": "ai_audited",
              "category_outcomes": {"Command Injection": {"status": "PASS_AI_AUDITED"},
                                    "SQL Injection": {"status": "NOT_SUPPORTED"}},
              "source_sha256": {"c/sample.jsonl": s_sha}}
    rep = f"{tmp}/r.json"; open(rep, "w").write(json.dumps(report)); r_sha = sha(open(rep, "rb").read())
    exchange = {"schema": AE.EXCHANGE_SCHEMA, "audit_type": "ai_audited", "source_report_sha256": r_sha,
                "category_outcomes": {"Command Injection": "PASS_AI_AUDITED", "SQL Injection": "FAIL"}}
    exc = f"{tmp}/e.json"; open(exc, "w").write(json.dumps(exchange))
    state = {"sample": {"sha256": s_sha}, "pool": {"sha256": p_sha}, "pool_manifest_sha256": m_sha}
    st = f"{tmp}/st.json"; open(st, "w").write(json.dumps(state))
    return {"component_id": "census_v2",
            "audit_evidence": {"schema": AE.SCHEMA,
                               "exchange": {"path": exc, "sha256": sha(open(exc, "rb").read())},
                               "report": {"path": rep, "sha256": r_sha},
                               "state": {"path": st, "sha256": sha(open(st, "rb").read())},
                               "pool_manifest": {"path": man, "sha256": m_sha},
                               "pool": {"path": pool, "sha256": p_sha}},
            "category_outcomes": None}


def _codes(rows, audit_item, **kw):
    return sorted(c for c, _ in CB.verify_components(rows, audit_item, **kw))


def _real_records():
    path_rec = sqli_rec = None
    for line in open(POOL):
        o = json.loads(line)
        if path_rec is None and o.get("d47_category") == "path_file_access":
            path_rec = o
        if sqli_rec is None and o.get("category_v4") == "SQL Injection":
            sqli_rec = o
        if path_rec and sqli_rec:
            break
    return path_rec, sqli_rec


def run():
    path_rec, sqli_rec = _real_records()
    assert path_rec and sqli_rec
    results = []
    def check(name, ok):
        results.append((name, ok))

    single = {"components": [original_component()]}

    def row(rec, cat, wire=True):
        return {"meta": {"label": "BLOCK", "payload_record_id": rec["record_id"],
                         "attack_category": cat,
                         "payload_wire": rec["payload_wire"] if wire else "TAMPERED"}}

    # T1 accept a real path row (category derived as path_file_access via d47, outcome PASS)
    check("T1 real path row accepted",
          _codes([row(path_rec, "path_file_access")], single, committed_checker=None) == [])
    # T2 OWNER NEGATIVE CASE: real SQLi record claiming path_file_access -> cross-claim (derived SQL Injection)
    check("T2 SQLi record claiming path_file_access rejected",
          _codes([row(sqli_rec, "path_file_access")], single, committed_checker=None) == ["AUDIT_CATEGORY_CROSS_CLAIM"])
    # T3 honest SQLi claim -> NOT_SUPPORTED in the original component
    check("T3 honest SQLi row rejected (FAIL)",
          _codes([row(sqli_rec, "SQL Injection")], single, committed_checker=None) == ["AUDIT_CATEGORY_NOT_PASSED"])
    # T4 content/identity mismatch
    check("T4 content mismatch rejected",
          _codes([row(path_rec, "path_file_access", wire=False)], single, committed_checker=None) == ["AUDIT_ROW_CONTENT_MISMATCH"])
    # T5 orphan record id
    check("T5 orphan rejected",
          _codes([{"meta": {"label": "BLOCK", "payload_record_id": "ghost", "attack_category": "path_file_access", "payload_wire": "x"}}],
                 single, committed_checker=None) == ["AUDIT_POOL_MEMBERSHIP"])
    # T6 FINAL committed-evidence gate: r3-execution evidence is untracked -> component evidence rejected
    check("T6 committed-evidence gate enforced",
          _codes([row(path_rec, "path_file_access")], single, committed_checker=AE.is_committed) == ["AUDIT_COMPONENT_EVIDENCE"])

    # two-component resolution + no combined PASS
    with tempfile.TemporaryDirectory() as tmp:
        # declare disjoint authoritative categories so the original pool contributes ONLY path_file_access
        orig = {**original_component(), "categories": ["path_file_access"]}
        cen0 = {**census_component(tmp), "categories": ["Command Injection", "SQL Injection"]}
        multi = {"components": [orig, cen0]}
        check("T7 census CmdI accepted",
              _codes([{"meta": {"label": "BLOCK", "payload_record_id": "cen-cmdi-1", "attack_category": "Command Injection", "payload_wire": "; id"}}],
                     multi, committed_checker=None) == [])
        check("T8 combined-pool PASS rejected (census SQLi claims Command Injection)",
              _codes([{"meta": {"label": "BLOCK", "payload_record_id": "cen-sqli-1", "attack_category": "Command Injection", "payload_wire": "' OR 1=1--"}}],
                     multi, committed_checker=None) == ["AUDIT_CATEGORY_CROSS_CLAIM"])
        # T10: the original component owns only path_file_access. Its incidental SQLi
        # records have no authoritative component in this fixture and are absent.
        check("T10 two-component read: incidental original SQLi is not owned",
              _codes([row(path_rec, "path_file_access"),
                      {"meta": {"label": "BLOCK", "payload_record_id": "cen-cmdi-1", "attack_category": "Command Injection", "payload_wire": "; id"}},
                      row(sqli_rec, "path_file_access")],
                     multi, committed_checker=None) == ["AUDIT_POOL_MEMBERSHIP"])
        # T9 duplicate record_id in a component pool must fail closed (membership would be ambiguous).
        dup = f"{tmp}/dup.jsonl"
        open(dup, "w").write('{"record_id": "d1", "category_v4": "Command Injection", "payload_wire": "x"}\n'
                             '{"record_id": "d1", "category_v4": "Command Injection", "payload_wire": "y"}\n')
        cen = census_component(tmp)
        cen["audit_evidence"]["pool"] = {"path": dup, "sha256": sha(open(dup, "rb").read())}
        cen["audit_evidence"]["state"]  # keep schema; state pool sha won't match -> AE.verify also guards
        import json as _json
        st = cen["audit_evidence"]["state"]["path"]
        s = _json.load(open(st)); s["pool"]["sha256"] = sha(open(dup, "rb").read())
        open(st, "w").write(_json.dumps(s)); cen["audit_evidence"]["state"]["sha256"] = sha(open(st, "rb").read())
        check("T9 duplicate record_id rejected",
              _codes([{"meta": {"label": "BLOCK", "payload_record_id": "d1", "attack_category": "Command Injection", "payload_wire": "x"}}],
                     {"components": [cen]}, committed_checker=None) == ["AUDIT_COMPONENT_EVIDENCE"])

    ok = all(o for _, o in results)
    print("test_v5_component_binding — REAL interfaces")
    for name, o in results:
        print(f"  [{'PASS' if o else 'FAIL'}] {name}")
    print(f"\nALL {'GREEN' if ok else 'RED'}")
    return ok


def run_generator_path():
    """Real authorized_build (generator) path: a components authorization where one world record's pinned
    pool category is swapped so the row's claimed category differs from the audited one -> cross-claim ->
    REFUSED. Exercises the integrated guard in scripts/dataset/v5_generator.authorized_build."""
    import tempfile, json
    from unittest import mock
    sys.path.insert(0, os.path.join(REPO, "scripts/dataset"))
    sys.path.insert(0, REPO)
    import v5_generator as G
    import v5_fixture as Fx
    from tests.v5_audit_fixture import make_bundle
    world = Fx.build_world()
    recs = list(world.records.values())
    cats = sorted({G._record_category(r) for r in recs} - {None})
    if len(cats) < 2 or len(recs) < 1:
        print("  [SKIP] generator path (fixture lacks >=2 categories)"); return True
    with tempfile.TemporaryDirectory() as tmp:
        # pinned pool = the world records, but record[0]'s category swapped to a DIFFERENT audited category
        pool_recs = []
        for i, r in enumerate(recs):
            c = G._record_category(r)
            swapped = (cats[1] if c == cats[0] else cats[0]) if i == 0 else c
            # category under attack_category: AE.verify does not compare it (so no records-mismatch), while
            # CB._derive_category reads it -> a genuine cross-claim for record[0].
            pool_recs.append({"record_id": r.get("record_id"), "attack_category": swapped,
                              "payload_wire": r.get("payload_wire")})
        bundle = make_bundle(os.path.join(tmp, "ev"), records=pool_recs,
                             outcomes={c: G.OUTCOME_PASS for c in cats})
        auth = {"schema": getattr(G, "PROPOSED_REAL_BUILD_AUTH_SCHEMA", "v5-real-build-authorization/v1-PROPOSED"),
                "scope": "REAL_BUILD", "preregistration_sha256": "pre", "authorized_by": "o", "date": "d",
                "owner_decision": "D-x", "audit_evidence": bundle,
                "components": [{"component_id": "c1", "audit_evidence": bundle, "category_outcomes": None}]}
        ap = os.path.join(tmp, "auth.json"); open(ap, "w").write(json.dumps(auth))
        ex = bundle["exchange"]["path"]
        with mock.patch.object(G.AE, "is_committed", return_value=True):
            res = G.authorized_build(world, authorization_path=ap, audit_exchange_path=ex,
                                     out_dir=os.path.join(tmp, "out"), preregistration_sha256="pre",
                                     category_selection=cats, pool_values_list=Fx.fixture_pool_value_lists())
        codes = {u["code"] for u in res.get("unmet", [])}
        ok = res.get("status") == "REFUSED" and "AUDIT_CATEGORY_CROSS_CLAIM" in codes
        print(f"  [{'PASS' if ok else 'FAIL'}] generator authorized_build rejects cross-claim  status={res.get('status')} codes∋CROSS_CLAIM={'AUDIT_CATEGORY_CROSS_CLAIM' in codes}")
        return ok


def run_positive_two_pool():
    """POSITIVE two-pool path through the real authorized_build controls: the world's records are split into
    TWO distinct pools/components with disjoint declared categories; each record is admitted by its own
    component; the build proceeds to BUILT (fixture mode, the point project authorizations allow — real builds
    are refuse-by-default) and the output links both components without a joint PASS."""
    import tempfile, json
    from unittest import mock
    sys.path.insert(0, os.path.join(REPO, "scripts/dataset")); sys.path.insert(0, REPO)
    import v5_generator as G
    import v5_fixture as Fx
    from tests.v5_audit_fixture import make_bundle
    world = Fx.build_world()
    recs = list(world.records.values())
    cats = sorted({G._record_category(r) for r in recs} - {None})
    if len(cats) < 2:
        print("  [SKIP] positive two-pool (fixture has <2 categories)"); return True
    with tempfile.TemporaryDirectory() as tmp:
        def comp(name, which_cats):
            pr = [{"record_id": r.get("record_id"), "payload_wire": r.get("payload_wire"),
                   "attack_category": G._record_category(r)}
                  for r in recs if G._record_category(r) in which_cats]
            b = make_bundle(os.path.join(tmp, name), records=pr, outcomes={c: G.OUTCOME_PASS for c in which_cats})
            return {"component_id": name, "audit_evidence": b, "categories": sorted(which_cats)}
        compA = comp("A", {cats[0]})
        compB = comp("B", set(cats[1:]))
        auth = {"schema": getattr(G, "PROPOSED_REAL_BUILD_AUTH_SCHEMA", "v5-real-build-authorization/v1-PROPOSED"),
                "scope": "REAL_BUILD", "preregistration_sha256": "pre", "authorized_by": "o", "date": "d",
                "owner_decision": "D-x", "components": [compA, compB]}
        ap = os.path.join(tmp, "auth.json"); open(ap, "w").write(json.dumps(auth))
        with mock.patch.object(G, "real_build_preconditions", return_value=[]), \
             mock.patch.object(G.AE, "is_committed", return_value=True):
            res = G.authorized_build(world, authorization_path=ap, audit_exchange_path=compA["audit_evidence"]["exchange"]["path"],
                                     out_dir=os.path.join(tmp, "out"), preregistration_sha256="pre",
                                     category_selection=cats, pool_values_list=Fx.fixture_pool_value_lists())
        ac = res.get("audit_components") or []
        ok = (res.get("status") == "BUILT" and len(ac) == 2
              and {c["component_id"] for c in ac} == {"A", "B"}
              and res.get("attack_pool_sha256") in (None, res.get("attack_pool_sha256")))  # no single joint pool required
        # no category owned by >1 component in the emitted metadata
        cat_owner = {}
        for c in ac:
            for cat in c["categories"]:
                cat_owner.setdefault(cat, set()).add(c["component_id"])
        disjoint = all(len(v) == 1 for v in cat_owner.values())
        ok = ok and disjoint
        print(f"  [{'PASS' if ok else 'FAIL'}] positive two-pool build  status={res.get('status')} components={len(ac)} disjoint_categories={disjoint}")
        if res.get("status") != "BUILT":
            print("     unmet:", res.get("unmet"))
        return ok


def test_component_binding():
    assert run()


def test_generator_path():
    assert run_generator_path()


def test_positive_two_pool():
    assert run_positive_two_pool()


if __name__ == "__main__":
    ok = run()
    print("\n-- generator (authorized_build) negative path --")
    ok = run_generator_path() and ok
    print("\n-- generator (authorized_build) positive two-pool path --")
    ok = run_positive_two_pool() and ok
    raise SystemExit(0 if ok else 1)
