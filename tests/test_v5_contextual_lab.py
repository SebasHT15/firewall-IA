#!/usr/bin/env python3
"""Tests for the offline contextual-validator lab — SYNTHETIC fixtures only. No network, no real package,
no audit labels, no training. Verifies the result contract, the execution origin-guard, and that each
context_kind reports the correct level/limits (static-only vs confined behavioral demo)."""
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(REPO, "scripts", "dataset"),):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import v5_contextual_lab as LAB  # noqa: E402

NEVER = {"PASS_AI_AUDITED", "VERIFIED", "label_class", "ALLOW", "BLOCK", "authorization", "audit_label"}


def unit(payload, category, profile_id, **over):
    u = {"record_id": over.pop("record_id", "U-0001"), "payload_wire": payload, "category_key": category,
         "profile_id": profile_id, "parameters": {}, "construction_family_id": "F-1",
         "label_status": "PENDING_ADJUDICATION", "training_eligible": False, "audit_label": None,
         "fixture_synthetic": True}
    u.update(over)
    return u


def profile(context_kind, sink, control, profile_id="P-1", scope="context_check", **over):
    p = {"profile_id": profile_id, "context_kind": context_kind, "sink_template": sink,
         "benign_control_template": control, "mechanism": "synthetic", "assumptions": ["synthetic fixture"],
         "expected_observation": "synthetic", "validation_scope": scope,
         "allowed_request_slot_types": ["query_value"]}
    p.update(over)
    return p


def _no_forbidden_tokens(res):
    import json
    blob = json.dumps(res)
    # the result must never carry a label/authorization verdict
    assert "PASS_AI_AUDITED" not in blob and "VERIFIED" not in blob and '"label_class"' not in blob, blob


class Contract(unittest.TestCase):
    def test_status_and_level_are_closed_vocab_and_no_label(self):
        r = LAB.evaluate_unit(unit("<script>alert(1)</script>", "xss", "P-1"),
                              profile("html_fragment", "<div>{INPUT}</div>", "<div>escaped</div>"))
        self.assertIn(r["status"], LAB.STATUS)
        self.assertIn(r["validation_level"], LAB.LEVELS)
        self.assertEqual(r["candidate"], {"record_id": "U-0001", "profile_id": "P-1"})
        _no_forbidden_tokens(r)

    def test_integrity_failure_is_rejected(self):
        bad = unit("x", "xss", "P-1"); del bad["record_id"]
        r = LAB.evaluate_unit(bad, profile("html_fragment", "<div>{INPUT}</div>", "ctl"))
        self.assertEqual(r["status"], "REJECTED")
        self.assertEqual(r["validation_level"], "integrity_only")

    def test_category_context_mismatch_rejected(self):
        r = LAB.evaluate_unit(unit("x", "xss", "P-1"),
                              profile("sqlite_quoted_value", "SELECT * FROM t WHERE name='{INPUT}'", "ctl"))
        self.assertEqual(r["status"], "REJECTED")
        self.assertFalse(next(c for c in r["checks"] if c["name"] == "category_context_coherent")["ok"])

    def test_unit_that_is_a_vote_or_trainable_is_rejected(self):
        for bad in ({"label_status": "VERIFIABLE"}, {"training_eligible": True}, {"audit_label": "VERIFIABLE"}):
            u = unit("<b>{INPUT}</b>", "xss", "P-1", **bad)
            r = LAB.evaluate_unit(u, profile("html_fragment", "<div>{INPUT}</div>", "ctl"))
            self.assertEqual(r["status"], "REJECTED", bad)

    def test_sink_without_input_marker_rejected(self):
        r = LAB.evaluate_unit(unit("x", "xss", "P-1"), profile("html_fragment", "<div>no marker</div>", "ctl"))
        self.assertEqual(r["status"], "REJECTED")


class OriginGuard(unittest.TestCase):
    def test_execution_requires_fixture_synthetic(self):
        u = unit("x' OR '1'='1", "sql_injection", "P-1", fixture_synthetic=False)
        r = LAB.evaluate_unit(u, profile("sqlite_quoted_value", "SELECT * FROM t WHERE name='{INPUT}'",
                                         "SELECT * FROM t WHERE name = ?"), allow_lab_execution=True)
        self.assertEqual(r["status"], "REJECTED")
        self.assertTrue(any(c["name"] == "origin_guard" and not c["ok"] for c in r["checks"]))

    def test_missing_fixture_flag_also_rejected_under_execution(self):
        u = unit("x", "sql_injection", "P-1"); del u["fixture_synthetic"]
        r = LAB.evaluate_unit(u, profile("sqlite_quoted_value", "SELECT * FROM t WHERE name='{INPUT}'", "ctl"),
                              allow_lab_execution=True)
        self.assertEqual(r["status"], "REJECTED")


class StaticDefault(unittest.TestCase):
    """allow_lab_execution=False: functional parts NOT_RUN; static context diagnostics only."""
    def test_sqlite_default_not_run(self):
        r = LAB.evaluate_unit(unit("x' OR '1'='1", "sql_injection", "P-1"),
                              profile("sqlite_quoted_value", "SELECT * FROM t WHERE name='{INPUT}'", "ctl"))
        self.assertEqual(r["status"], "NOT_RUN")
        self.assertEqual(r["validation_level"], "static_context")

    def test_html_static_supported(self):
        r = LAB.evaluate_unit(unit("<img src=x onerror=alert(1)>", "xss", "P-1"),
                              profile("html_fragment", "<div>{INPUT}</div>", "ctl"))
        self.assertEqual((r["status"], r["validation_level"]), ("SUPPORTED", "static_context"))
        self.assertTrue(next(c for c in r["checks"] if c["name"] == "introduces_executing_construct")["ok"])
        self.assertTrue(any("NOT JavaScript execution" in x for x in r["limitations"]))

    def test_shell_is_unsupported_static(self):
        r = LAB.evaluate_unit(unit("; id", "command_injection", "P-1"),
                              profile("posix_shell_unquoted_argument", "echo {INPUT}", "ctl"))
        self.assertEqual((r["status"], r["validation_level"]), ("UNSUPPORTED", "static_context"))
        self.assertTrue(next(c for c in r["checks"] if c["name"] == "contains_unquoted_metacharacters")["ok"])

    def test_paths_static_supported_and_escape_detected(self):
        r = LAB.evaluate_unit(unit("../../etc/passwd", "path_traversal", "P-1"),
                              profile("posix_file_path", "base/dir/{INPUT}", "ctl"))
        self.assertEqual((r["status"], r["validation_level"]), ("SUPPORTED", "static_context"))
        self.assertTrue(next(c for c in r["checks"] if c["name"] == "escapes_base_dir")["ok"])
        r2 = LAB.evaluate_unit(unit("..\\..\\windows\\win.ini", "path_traversal", "P-1"),
                               profile("windows_file_path", "base\\dir\\{INPUT}", "ctl"))
        self.assertTrue(next(c for c in r2["checks"] if c["name"] == "escapes_base_dir")["ok"])

    def test_php_include_unavailable(self):
        r = LAB.evaluate_unit(unit("../../etc/passwd", "file_inclusion", "P-1"),
                              profile("php_local_include", "include('{INPUT}')", "ctl"))
        self.assertEqual((r["status"], r["validation_level"]), ("UNSUPPORTED", "unavailable"))


class SqliteBehavior(unittest.TestCase):
    """Confined read-only demonstration (allow_lab_execution=True, fixture_synthetic)."""
    def test_quoted_value_injection_shows_effect_vs_control(self):
        r = LAB.evaluate_unit(unit("x' OR '1'='1", "sql_injection", "P-1"),
                              profile("sqlite_quoted_value", "SELECT * FROM t WHERE name = '{INPUT}'",
                                      "SELECT * FROM t WHERE name = ?"), allow_lab_execution=True)
        self.assertEqual((r["status"], r["validation_level"]), ("SUPPORTED", "local_behavior"))
        self.assertTrue(next(c for c in r["checks"] if c["name"] == "input_changes_read_result_vs_control")["ok"])
        self.assertTrue(next(c for c in r["checks"] if c["name"] == "benign_control_parameterized")["ok"])
        _no_forbidden_tokens(r)

    def test_numeric_expression_injection(self):
        r = LAB.evaluate_unit(unit("1 OR 1=1", "sql_injection", "P-1"),
                              profile("sqlite_numeric_expression", "SELECT * FROM t WHERE id = {INPUT}",
                                      "SELECT * FROM t WHERE id = ?"), allow_lab_execution=True)
        self.assertEqual(r["status"], "SUPPORTED")
        self.assertEqual(r["validation_level"], "local_behavior")

    def test_forbidden_token_is_unsupported(self):
        r = LAB.evaluate_unit(unit("x'; DROP TABLE t; --", "sql_injection", "P-1"),
                              profile("sqlite_quoted_value", "SELECT * FROM t WHERE name = '{INPUT}'",
                                      "SELECT * FROM t WHERE name = ?"), allow_lab_execution=True)
        self.assertEqual(r["status"], "UNSUPPORTED")
        self.assertFalse(next(c for c in r["checks"] if c["name"] == "read_sublanguage_confined")["ok"])

    def test_non_select_sink_unsupported(self):
        r = LAB.evaluate_unit(unit("x' OR '1'='1", "sql_injection", "P-1"),
                              profile("sqlite_quoted_value", "UPDATE t SET name='{INPUT}'",
                                      "SELECT * FROM t WHERE name = ?"), allow_lab_execution=True)
        self.assertEqual(r["status"], "UNSUPPORTED")


class JinjaBehavior(unittest.TestCase):
    def test_arithmetic_is_supported_or_unavailable(self):
        r = LAB.evaluate_unit(unit("{{7*7}}", "ssti", "P-1"),
                              profile("jinja2_template_source", "{INPUT}", "{{ value }}"), allow_lab_execution=True)
        if LAB.capabilities()["jinja2"] is None:
            self.assertEqual((r["status"], r["validation_level"]), ("UNSUPPORTED", "unavailable"))
        else:
            self.assertEqual((r["status"], r["validation_level"]), ("SUPPORTED", "local_behavior"))
            self.assertTrue(any("NOT an RCE" in x for x in r["limitations"]))

    def test_non_arithmetic_is_not_supported(self):
        if LAB.capabilities()["jinja2"] is None:
            self.skipTest("jinja2 not installed")
        r = LAB.evaluate_unit(unit("{{ config.items() }}", "ssti", "P-1"),
                              profile("jinja2_template_source", "{INPUT}", "{{ value }}"), allow_lab_execution=True)
        self.assertEqual(r["status"], "UNSUPPORTED")   # outside the closed arithmetic sublanguage

    def test_default_mode_not_run(self):
        r = LAB.evaluate_unit(unit("{{7*7}}", "ssti", "P-1"),
                              profile("jinja2_template_source", "{INPUT}", "{{ value }}"))
        self.assertEqual(r["status"], "NOT_RUN")


class Capabilities(unittest.TestCase):
    def test_matrix_covers_every_context_kind(self):
        cap = LAB.capabilities()
        self.assertEqual(set(cap["matrix"]), set(LAB.CONTEXT_KINDS))
        self.assertTrue(cap["sqlite_engine"] and cap["python"])


if __name__ == "__main__":
    unittest.main()
