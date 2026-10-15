"""Tests for scripts/dataset/build_v5_benign_pools.py (V5 stage 2, benign source pools).

Fixtures are invented text in tests/fixtures/v5_benign (real file layout, fake content).  No test
touches the network: urllib.request.urlopen is replaced by a function that raises.

    python3 -m unittest tests.test_v5_benign_pools -v
"""

import bz2
import contextlib
import hashlib
import io
import json
import os
import sys
import tarfile
import tempfile
import unittest
import unicodedata
from unittest import mock

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts", "dataset"))

import build_v5_benign_pools as B  # noqa: E402
import v5_pools_common as C  # noqa: E402

FIX = os.path.join(REPO_ROOT, "tests", "fixtures", "v5_benign")


def _read(path, mode="rb"):
    with open(path, mode) as fh:
        return fh.read()


def _no_network(*a, **k):
    raise AssertionError("network access attempted in a test")


class NoNetwork(unittest.TestCase):
    def setUp(self):
        p = mock.patch("urllib.request.urlopen", _no_network)
        p.start()
        self.addCleanup(p.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def path(self, *parts):
        return os.path.join(self.tmp.name, *parts)

    def run_main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = B.main(argv)
            except SystemExit as exc:
                rc = exc.code if isinstance(exc.code, int) else 2
                err.write(str(exc.code))
        return rc, out.getvalue(), err.getvalue()

    def build(self, raw_dir, out_dir, *extra):
        rc, out, err = self.run_main(["build", "--raw-dir", raw_dir, "--out-dir", out_dir, *extra])
        return rc, out, err

    def read_pool(self, out_dir, name):
        return C.read_jsonl(os.path.join(out_dir, "benign", name + ".jsonl"))

    def manifest(self, out_dir):
        with open(os.path.join(out_dir, "benign", "manifest.json"), encoding="utf-8") as fh:
            return json.load(fh)

    def make_raw(self, name, data, query=None, **side_over):
        """Write a pinned raw file (+ sidecar) into <tmp>/raw and return that dir."""
        raw = self.path("raw")
        os.makedirs(raw, exist_ok=True)
        with open(os.path.join(raw, name), "wb") as fh:
            fh.write(data)
        side = {"url": "https://fixture.invalid/x", "retrieved_at": "1970-01-01T00:00:00Z",
                "sha256": C.sha256_bytes(data), "bytes": len(data), "licence": "CC0-1.0",
                "licence_evidence_url": "https://fixture.invalid/licence"}
        if query:
            side["query"] = query
        side.update(side_over)
        C.write_json(os.path.join(raw, name + ".source.json"), side)
        return raw


# ─────────────────────────────── name filters ───────────────────────────────
class NameFilters(unittest.TestCase):
    def test_raw_control_char_in_wdqs_label_is_parsed_then_excluded(self):
        # The live WDQS response carried raw control characters inside label strings (strict
        # JSON rejects them); they must reach the control_char filter, not abort or be kept.
        doc = ('{"head":{"vars":["item","label"]},"results":{"bindings":['
               '{"item":{"type":"uri","value":"http://www.wikidata.org/entity/Q1"},'
               '"label":{"type":"literal","xml:lang":"en","value":"Ab\x07c"}}]}}').encode()
        rows, malformed = B.parse_wdqs(doc)
        self.assertEqual((len(rows), malformed), (1, []))
        self.assertEqual(B.name_reason(rows[0]["label"], "family"), "control_char")

    CASES = [
        # (value, kind, expected reason)
        ("", "given", "empty"),
        ("Ana\x00", "given", "control_char"),
        ("Ana​Mae", "given", "control_char"),
        ("Name123", "given", "contains_digit"),
        ("Anna (given name)", "given", "parenthesis_or_disambiguation"),
        ("x@y", "given", "at_or_url"),
        ("example.com", "given", "at_or_url"),
        ("Category:Names", "given", "contains_colon"),
        ("Doe/Roe", "family", "non_name_char"),
        ("A" * 41, "given", "too_long"),
        ("Mary Ann", "given", "looks_like_full_name"),
        ("a b c d e", "family", "too_many_tokens"),
        # positives (must pass): apostrophes, hyphens, non-ASCII, multi-token family
        ("O'Brien", "family", None),
        ("D’Angelo", "given", None),
        ("Jean-Luc", "given", None),
        ("Åsa", "given", None),
        ("Nguyễn", "family", None),
        ("van der Berg", "family", None),
        ("de la Cruz", "family", None),
        ("Anna", "given", None),
        ("A" * 40, "given", None),
    ]

    def test_cases(self):
        for value, kind, expected in self.CASES:
            with self.subTest(value=value, kind=kind):
                self.assertEqual(B.name_reason(B.norm(value), kind), expected)

    def test_family_multi_token_ok_given_lowercase_particle_ok(self):
        self.assertIsNone(B.name_reason("van der Berg", "family"))
        self.assertIsNone(B.name_reason("Anna van", "given"))   # only one capitalised token


# ─────────────────────────────── prose filters ───────────────────────────────
class ReviewDFixes(NoNetwork):
    """Fixes from the independent stage-2 review (privacy, label hygiene, licence, guard)."""

    def test_descriptive_and_lowercase_given_labels_excluded(self):
        self.assertEqual(B.name_reason("female given name", "given"), "descriptive_label")
        self.assertEqual(B.name_reason("Christian name", "given"), "descriptive_label")
        self.assertEqual(B.name_reason("c", "given"), "not_capitalised")
        self.assertIsNone(B.name_reason("Ana", "given"))
        self.assertIsNone(B.name_reason("van der Berg", "family"))  # lowercase family names stay

    def test_possible_full_name_sentence_dropped_single_first_name_kept(self):
        self.assertEqual(B.prose_reason("Bulgarian tennis star Grigor Dimitrov is ill."), "possible_full_name")
        self.assertEqual(B.prose_reason("People believe Paul Wexler's nonsense."), "possible_full_name")
        self.assertIsNone(B.prose_reason("Tom said that I was right."))
        self.assertIsNone(B.prose_reason("I think a<b; -- it's fine."))

    def test_sidecar_licence_must_match(self):
        with tempfile.TemporaryDirectory() as d:
            for f in os.listdir(FIX):
                with open(os.path.join(FIX, f), "rb") as src, open(os.path.join(d, f), "wb") as dst:
                    dst.write(src.read())
            side = next(f for f in os.listdir(d) if f.endswith(".source.json"))
            path = os.path.join(d, side)
            with open(path, encoding="utf-8") as fh:
                meta = json.load(fh)
            meta["licence"] = "CC-BY-2.0-FR"
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(meta, fh)
            source_id = next(k for k, v in B.SOURCES.items() if v["file"] + ".source.json" == side)
            with self.assertRaises(SystemExit):
                B.load_pinned(d, source_id)

    def test_protected_guard_covers_directories(self):
        for p in ("datasets/csic/data.csv", "datasets/CSIC/a.csv", "datasets/v4_clean/train.jsonl"):
            with self.assertRaises(SystemExit, msg=p):
                C.assert_not_protected(os.path.join(REPO_ROOT, p))


class ProseFilters(unittest.TestCase):
    CASES = [
        ("", "empty"),
        ("Bad\x0bchar here.", "control_char"),
        ("Hi", "too_short"),
        ("x" * 201, "too_long"),
        ("Write to someone@example.org soon.", "email_like"),
        ("Meet @ noon.", "at_sign"),
        ("Visit www.example.org today.", "url_like"),
        ("Open https://example.org now.", "url_like"),
        ("See example.com for more.", "url_like"),
        ("The code is 1234567 today.", "digit_run_ge6"),
        ("Call 555-123-4567 anytime.", "phone_like"),
        ("She was born on 3 March 1987.", "dated_event"),
        ("In March 1987 it rained.", "dated_event"),
        ("It was 1987, March, a cold day.", "dated_event"),
        # kept on purpose (spec 2.1): homonyms and partial syntax
        ("Select the one you like; drop the rest.", None),
        ("If a<b and b<c, then a<c.", None),
        ("Don't use -- twice.", None),
        ("I paid 50% of the bill.", None),
        ("He was born in 1987.", None),            # a bare year is not a dated event
        ("March is cold.", None),
        ("I have 3 apples and 12 pears.", None),
        ("Tom likes rock'n'roll.", None),
        ("x" * 200, None),
        ("Yes!", None),
    ]

    def test_cases(self):
        for text, expected in self.CASES:
            with self.subTest(text=text[:40]):
                self.assertEqual(B.prose_reason(B.norm(text)), expected)

    def test_bounds_configurable(self):
        self.assertEqual(B.prose_reason("abcdef", min_len=10), "too_short")
        self.assertIsNone(B.prose_reason("abcdef", min_len=3, max_len=6))
        self.assertEqual(B.prose_reason("abcdefg", min_len=3, max_len=6), "too_long")


# ─────────────────────────────── lexicons ───────────────────────────────
class Lexicons(unittest.TestCase):
    def test_streets_expand_deterministic_distinct_and_large(self):
        lex = B.load_json(B.STREETS_LEXICON)
        a, b = B.expand_streets(lex), B.expand_streets(lex)
        self.assertEqual(a, b)
        values = [v for _, v in a]
        self.assertEqual(len(values), len(set(values)))
        self.assertGreaterEqual(len(values), 2000)
        self.assertGreaterEqual(len(values), lex["min_pool_size"])
        self.assertEqual([k for k, _ in a], sorted(k for k, _ in a))
        self.assertTrue(all(v == unicodedata.normalize("NFC", v) for v in values))
        self.assertIn("fingerprint", " ".join(lex["notes"]).lower())

    def test_streets_have_no_house_number_prefix_or_city(self):
        # No value starts with a bare house number followed by a street: numbered roads
        # ("Route 9", "Calle 45") and ordinals ("1st Street") are the only digit-leading shapes.
        lex = B.load_json(B.STREETS_LEXICON)
        for key, v in B.expand_streets(lex):
            if v[0].isdigit():
                self.assertIn("plain|ordinals", key, v)
        joined = "\n".join(v for _, v in B.expand_streets(lex))
        for city in ("London", "Paris", "Madrid", "New York"):
            self.assertNotIn(city, joined)

    def test_streets_diversity(self):
        values = [v for _, v in B.expand_streets(B.load_json(B.STREETS_LEXICON))]
        for needle in ("O'Connell", "Saint-Laurent", "Calle ", "Rue ", "straße", "Via ", "Avenida ",
                       "Apt #4", "Piso 2º", "Unit 3B", "Suite 200", " St.", " Ave", " Rd", "Ñ"):
            self.assertTrue(any(needle in v for v in values), needle)
        self.assertTrue(any(v.startswith("N ") for v in values))                   # directional
        self.assertTrue(any(" & " in v for v in values))                           # cross street

    def test_symbols_lexicon(self):
        lex = B.load_json(B.SYMBOLS_LEXICON)
        values = [v for g in lex["groups"].values() for v in g]
        self.assertGreaterEqual(len(set(values)), 150)
        for needle in B.SURVIVAL_FIXTURE:
            self.assertIn(needle, values)
        for v in values:
            self.assertNotIn("@", v)
            self.assertIsNone(B.URL_RE.search(v), v)
        for sym in ("'", "#", "!", "&", ";", "%", "+", "<", ">", "--", "/", "\""):
            self.assertTrue(any(sym in v for v in values), sym)
        self.assertEqual(lex["license"], "MIT")

    def test_lexicon_licence_and_notes_documented(self):
        for p in (B.STREETS_LEXICON, B.SYMBOLS_LEXICON):
            lex = B.load_json(p)
            self.assertEqual(lex["license"], "MIT")
            self.assertTrue(lex["notes"])
            self.assertTrue(lex["authored_by"])


# ─────────────────────────────── build on fixtures ───────────────────────────────
class BuildFixtures(NoNetwork):
    def setUp(self):
        super().setUp()
        self.out = self.path("out")
        rc, _, err = self.build(FIX, self.out)
        self.assertEqual(rc, 0, err)

    def test_survival_fixture_survives(self):
        symbols = {r["value"] for r in self.read_pool(self.out, "symbols")}
        for v in ("O'Neil", "Apt #4", "AT&T", "100%", "a<b"):
            self.assertIn(v, symbols)
        self.assertTrue(self.manifest(self.out)["survival_fixture"]["all_survive"])

    def test_names_given_results(self):
        got = {r["value"]: r for r in self.read_pool(self.out, "names_given")}
        self.assertEqual(set(got), {"Maria", "Anna", "Dae'Shaun", "Jean-Luc", "Åsa", "Zoë", "Ana-Mae"})
        self.assertEqual(got["Maria"]["source_ref"], "Q99")      # smaller QID wins the duplicate
        self.assertIn("has_apostrophe", got["Dae'Shaun"]["flags"])
        self.assertIn("has_hyphen", got["Jean-Luc"]["flags"])
        self.assertIn("non_ascii", got["Åsa"]["flags"])
        self.assertEqual(got["Zoë"]["value"], unicodedata.normalize("NFC", "Zoë"))

    def test_names_family_results(self):
        got = {r["value"] for r in self.read_pool(self.out, "names_family")}
        self.assertEqual(got, {"van der Berg", "O'Brien", "Müller", "Nguyễn", "Smith-Jones",
                               "Hernández Ruiz"})

    def test_prose_results(self):
        got = [r["value"] for r in self.read_pool(self.out, "prose_en")]
        self.assertEqual(sorted(got), sorted([
            "Tom likes rock'n'roll music.", "Where is the nearest station?",
            "I paid 50% of the bill; the rest is yours.", "If a<b and b<c, then a<c.",
            "Don't use -- twice.", "Select the one you like; drop the rest."]))
        rec = next(r for r in self.read_pool(self.out, "prose_en") if r["source_ref"] == "1")
        self.assertEqual(rec["source_lang"], "eng")

    def test_exclusion_reasons_recorded(self):
        pools = self.manifest(self.out)["pools"]
        reasons = pools["prose_en"]["exclusion_reasons"]
        for r in ("email_like", "url_like", "digit_run_ge6", "phone_like", "dated_event", "at_sign",
                  "control_char", "empty", "too_short", "too_long", "duplicate_value"):
            self.assertIn(r, reasons)
        self.assertEqual(reasons["not_selected_language(counted_only)"], 2)
        excluded = C.read_jsonl(os.path.join(self.out, "benign", "benign_excluded.jsonl"))
        self.assertTrue(all(r["status"] == C.EXCLUDED and r["exclusion_reason"] for r in excluded))

    def test_malformed_json_rows_excluded_not_crash(self):
        excluded = C.read_jsonl(os.path.join(self.out, "benign", "benign_excluded.jsonl"))
        mal = [r for r in excluded if r["exclusion_reason"] == "malformed_row" and r["pool_id"] == "names_given"]
        self.assertEqual(len(mal), 3)
        self.assertTrue(all(r["value"] is None and r["value_entry_id"] is None for r in mal))

    def test_provenance_fields(self):
        for name in ("names_given", "names_family", "prose_en", "streets", "symbols"):
            for r in self.read_pool(self.out, name)[:50]:
                for k in ("pool_id", "value", "value_entry_id", "source_id", "source_ref", "license",
                          "status", "exclusion_reason", "flags"):
                    self.assertIn(k, r)
                self.assertEqual(r["status"], C.ACCEPTED)
                self.assertIsNone(r["exclusion_reason"])
                self.assertEqual(r["value"], unicodedata.normalize("NFC", r["value"]))
        g = self.read_pool(self.out, "names_given")[0]
        self.assertEqual((g["source_id"], g["license"]), ("wikidata_given_names", "CC0-1.0"))
        self.assertRegex(g["source_ref"], r"^Q[0-9]+$")
        s = self.read_pool(self.out, "streets")[0]
        self.assertEqual((s["source_id"], s["license"]), ("streets_v1", "MIT"))
        self.assertIn("|", s["source_ref"])
        y = self.read_pool(self.out, "symbols")[0]
        self.assertEqual((y["source_id"], y["license"]), ("benign_symbols_v1", "MIT"))
        t = self.read_pool(self.out, "prose_en")[0]
        self.assertEqual((t["source_id"], t["license"]), ("tatoeba_cc0", "CC0-1.0"))

    def test_value_entry_id_matches_spec_formula(self):
        for name in ("names_given", "prose_en", "symbols"):
            for r in self.read_pool(self.out, name):
                expect = hashlib.sha256(
                    f"{r['pool_id']}\0{unicodedata.normalize('NFC', r['value'])}".encode("utf-8")).hexdigest()
                self.assertEqual(r["value_entry_id"], expect)
                self.assertEqual(r["pool_id"], name)

    def test_dedupe_within_pool(self):
        for name in ("names_given", "names_family", "prose_en", "streets", "symbols"):
            values = [r["value"] for r in self.read_pool(self.out, name)]
            self.assertEqual(len(values), len(set(values)), name)
            ids = [r["value_entry_id"] for r in self.read_pool(self.out, name)]
            self.assertEqual(len(ids), len(set(ids)))

    def test_flags_describe_never_filter(self):
        flagged = [r for r in self.read_pool(self.out, "symbols") if "has_symbol" in r["flags"]]
        self.assertGreater(len(flagged), 100)
        self.assertEqual(self.manifest(self.out)["pools"]["symbols"]["accepted"], 295)   # none dropped by flags

    def test_pool_id_stable_across_filter_config(self):
        out2 = self.path("out2")
        rc, _, err = self.build(FIX, out2, "--prose-min-len", "20", "--prose-max-len", "60")
        self.assertEqual(rc, 0, err)
        a = {r["value"]: r["value_entry_id"] for r in self.read_pool(self.out, "prose_en")}
        b = {r["value"]: r["value_entry_id"] for r in self.read_pool(out2, "prose_en")}
        self.assertTrue(b)
        self.assertLess(len(b), len(a))
        for v, vid in b.items():
            self.assertEqual(a[v], vid)

    def test_manifest_contents(self):
        m = self.manifest(self.out)
        self.assertEqual(m["blocked_pools"], [])
        self.assertEqual(m["oracle"]["containment_ge_L"][:7], "PENDING")
        self.assertEqual(m["oracle"]["breakout_signatures"][:7], "PENDING")
        self.assertTrue(m["oracle"]["exact_canonical_key"].startswith("NOT_APPLIED"))
        for sid in ("wikidata_given_names", "wikidata_family_names", "tatoeba_cc0"):
            pin = m["sources"][sid]
            for k in ("url", "sha256", "licence", "retrieved_at", "bytes", "licence_evidence_url"):
                self.assertIn(k, pin)
        self.assertIn("query_sha256", m["sources"]["wikidata_given_names"])
        for lid in ("streets_v1", "benign_symbols_v1"):
            self.assertEqual(len(m["lexicons"][lid]["sha256"]), 64)
        self.assertIn("scripts/dataset/build_v5_benign_pools.py", m["code_fingerprint"])
        self.assertIn("environment", m)
        self.assertFalse(m["pools"]["names_given"]["meets_min_pool_size"])    # report only
        self.assertTrue(m["pools"]["streets"]["meets_min_pool_size"])
        self.assertIn("has_apostrophe", m["pools"]["names_given"]["flags_accepted"])
        self.assertNotIn("generated_at", m)

    def test_manifest_artifact_hashes_match_files(self):
        m = self.manifest(self.out)
        for art in m["artifacts"]:
            p = os.path.join(self.out, "benign", art["path"])
            self.assertEqual(C.sha256_file(p), art["sha256"])
            self.assertEqual(os.path.getsize(p), art["bytes"])
        self.assertEqual({a["path"] for a in m["artifacts"]},
                         {f"{n}.jsonl" for n in ("names_given", "names_family", "prose_en", "streets",
                                                  "symbols", "benign_excluded")})

    def test_determinism_two_builds_byte_identical(self):
        out2 = self.path("elsewhere", "out")
        rc, _, err = self.build(FIX, out2)
        self.assertEqual(rc, 0, err)
        for name in B.MANAGED_FILES:
            with open(os.path.join(self.out, "benign", name), "rb") as a, \
                    open(os.path.join(out2, "benign", name), "rb") as b:
                self.assertEqual(a.read(), b.read(), name)


# ─────────────────────────────── blocked / refusals ───────────────────────────────
class SourcesAndRefusals(NoNetwork):
    def test_missing_raw_dir_blocks_pools_not_substituted(self):
        out = self.path("out")
        rc, _, err = self.build(self.path("no_such_raw"), out)
        self.assertEqual(rc, 0, err)
        m = self.manifest(out)
        for pool in ("names_given", "names_family", "prose_en"):
            self.assertEqual(m["pools"][pool]["status"], "BLOCKED: source not acquired")
            self.assertFalse(os.path.exists(os.path.join(out, "benign", pool + ".jsonl")))
        self.assertEqual(m["blocked_pools"], ["names_family", "names_given", "prose_en"])
        self.assertEqual(m["pools"]["streets"]["status"], B.BUILT)
        self.assertGreaterEqual(m["pools"]["streets"]["accepted"], 2000)
        self.assertGreaterEqual(m["pools"]["symbols"]["accepted"], 150)

    def test_partial_sources_only_missing_pool_blocked(self):
        raw = self.make_raw("sentences_CC0.csv", b"1\teng\tHello there.\t\\N\n")
        out = self.path("out")
        rc, _, err = self.build(raw, out)
        self.assertEqual(rc, 0, err)
        m = self.manifest(out)
        self.assertEqual(m["blocked_pools"], ["names_family", "names_given"])
        self.assertEqual(m["pools"]["prose_en"]["accepted"], 1)

    def test_stale_pool_removed_when_source_disappears(self):
        out = self.path("out")
        self.assertEqual(self.build(FIX, out)[0], 0)
        self.assertTrue(os.path.exists(os.path.join(out, "benign", "names_given.jsonl")))
        self.assertEqual(self.build(self.path("none"), out)[0], 0)
        self.assertFalse(os.path.exists(os.path.join(out, "benign", "names_given.jsonl")))

    def test_sidecar_sha_mismatch_refused(self):
        raw = self.make_raw("sentences_CC0.csv", b"1\teng\tHello there.\t\\N\n", sha256="0" * 64)
        rc, _, err = self.build(raw, self.path("out"))
        self.assertNotEqual(rc, 0)
        self.assertIn("sha256", err)

    def test_modified_file_after_pinning_refused(self):
        raw = self.make_raw("sentences_CC0.csv", b"1\teng\tHello there.\t\\N\n")
        with open(os.path.join(raw, "sentences_CC0.csv"), "ab") as fh:
            fh.write(b"2\teng\tTampered line.\t\\N\n")
        rc, _, err = self.build(raw, self.path("out"))
        self.assertNotEqual(rc, 0)
        self.assertIn("REFUSED", err)

    def test_file_without_sidecar_refused(self):
        raw = self.path("raw")
        os.makedirs(raw)
        with open(os.path.join(raw, "sentences_CC0.csv"), "wb") as fh:
            fh.write(b"1\teng\tHello there.\t\\N\n")
        rc, _, err = self.build(raw, self.path("out"))
        self.assertNotEqual(rc, 0)
        self.assertIn("sidecar", err)

    def test_sidecar_missing_fields_refused(self):
        raw = self.make_raw("sentences_CC0.csv", b"1\teng\tHello there.\t\\N\n")
        side_path = os.path.join(raw, "sentences_CC0.csv.source.json")
        side = json.loads(_read(side_path, "r"))
        del side["licence"]
        C.write_json(side_path, side)
        rc, _, err = self.build(raw, self.path("out"))
        self.assertNotEqual(rc, 0)

    def test_wdqs_sidecar_with_different_query_refused(self):
        data = json.dumps({"results": {"bindings": []}}).encode()
        raw = self.make_raw("wikidata_given_names.json", data, query="SELECT * WHERE {?s ?p ?o}")
        rc, _, err = self.build(raw, self.path("out"))
        self.assertNotEqual(rc, 0)
        self.assertIn("query", err)

    def test_malformed_csv_rows_excluded_with_reason(self):
        data = (b"1\teng\tA fine sentence here.\t\\N\n"
                b"just one column\n"
                b"x\teng\tbad id\t\\N\n"
                b"3\teng\tbad \xff utf8\t\\N\n"
                b"4\teng\ttoo\tmany\tcolumns\n"
                b"5\teng\tAnother fine sentence.\t\\N\n")
        raw = self.make_raw("sentences_CC0.csv", data)
        out = self.path("out")
        rc, _, err = self.build(raw, out)
        self.assertEqual(rc, 0, err)
        self.assertEqual(sorted(r["value"] for r in self.read_pool(out, "prose_en")),
                         ["A fine sentence here.", "Another fine sentence."])
        reasons = self.manifest(out)["pools"]["prose_en"]["exclusion_reasons"]
        self.assertEqual(reasons["malformed_row"], 3)
        self.assertEqual(reasons["invalid_utf8"], 1)

    def test_wdqs_non_json_refused_cleanly(self):
        raw = self.make_raw("wikidata_given_names.json", b"<html>not json</html>", query=B.GIVEN_NAME_QUERY)
        rc, _, err = self.build(raw, self.path("out"))
        self.assertNotEqual(rc, 0)
        self.assertIn("SPARQL JSON", err)

    def test_wdqs_bad_binding_shapes_excluded(self):
        bindings = [None, 7, {"item": 5, "label": {"value": "X"}},
                    {"item": {"value": "http://www.wikidata.org/entity/Q5"}, "label": {"value": 12, "xml:lang": "en"}},
                    {"item": {"value": "http://www.wikidata.org/entity/Q6"},
                     "label": {"value": "Fine", "xml:lang": "en"}}]
        data = json.dumps({"results": {"bindings": bindings}}).encode()
        raw = self.make_raw("wikidata_given_names.json", data, query=B.GIVEN_NAME_QUERY)
        out = self.path("out")
        rc, _, err = self.build(raw, out)
        self.assertEqual(rc, 0, err)
        self.assertEqual([r["value"] for r in self.read_pool(out, "names_given")], ["Fine"])
        self.assertEqual(self.manifest(out)["pools"]["names_given"]["exclusion_reasons"]["malformed_row"], 4)

    def test_protected_paths_refused(self):
        for bad in ("/x/external_v1/raw", "/x/reports/external/z", "/x/eval.jsonl", "/x/csic_database.csv"):
            with self.subTest(bad=bad):
                rc, _, err = self.run_main(["build", "--raw-dir", bad, "--out-dir", self.path("out")])
                self.assertNotEqual(rc, 0)
                self.assertIn("REFUSED", err)
        rc, _, err = self.run_main(["build", "--raw-dir", FIX, "--out-dir", self.path("o"),
                                    "--attack-pool", "/x/external_v1/attack_pool.jsonl"])
        self.assertNotEqual(rc, 0)
        rc, _, err = self.run_main(["acquire", "--raw-dir", "/x/external_v1/raw", "--dry-run"])
        self.assertNotEqual(rc, 0)


# ─────────────────────────────── oracle (exact rule) ───────────────────────────────
class OracleExact(NoNetwork):
    def attack_pool(self, keys):
        p = self.path("attack_pool.jsonl")
        with open(p, "w", encoding="utf-8") as fh:
            for k in keys:
                fh.write(json.dumps({"canonical_key": k, "payload": k}) + "\n")
            fh.write(json.dumps({"payload": "no key"}) + "\n")
        return p

    def test_exact_collision_excluded(self):
        # canonical_key lower-cases and decodes: the benign "Anna" collides with attack key "anna"
        ap = self.attack_pool(["anna", "q&a", "union select"])
        out = self.path("out")
        rc, _, err = self.build(FIX, out, "--attack-pool", ap)
        self.assertEqual(rc, 0, err)
        names = {r["value"] for r in self.read_pool(out, "names_given")}
        self.assertNotIn("Anna", names)
        self.assertIn("Maria", names)
        symbols = {r["value"] for r in self.read_pool(out, "symbols")}
        self.assertNotIn("Q&A", symbols)
        excluded = C.read_jsonl(os.path.join(out, "benign", "benign_excluded.jsonl"))
        self.assertIn("oracle_exact_collision", {r["exclusion_reason"] for r in excluded})
        m = self.manifest(out)
        self.assertEqual(m["oracle"]["exact_canonical_key"], "APPLIED")
        self.assertEqual(m["oracle"]["attack_pool"]["canonical_keys"], 3)
        self.assertEqual(m["oracle"]["attack_pool"]["records"], 4)
        self.assertEqual(m["oracle"]["containment_ge_L"][:7], "PENDING")
        self.assertIn("scripts/dataset/parse_dataset_v4.py", m["code_fingerprint"])

    def test_survival_fixture_survives_with_attack_pool(self):
        ap = self.attack_pool(["' or 1=1 --", "<script>alert(1)</script>", "../../etc/passwd", "; ls"])
        out = self.path("out")
        rc, _, err = self.build(FIX, out, "--attack-pool", ap)
        self.assertEqual(rc, 0, err)
        self.assertTrue(self.manifest(out)["survival_fixture"]["all_survive"])

    def test_survival_collision_fails_build(self):
        ap = self.attack_pool(["o'neil"])
        rc, _, err = self.build(FIX, self.path("out"), "--attack-pool", ap)
        self.assertEqual(rc, 3)
        self.assertIn("survival", err)

    def test_missing_or_keyless_attack_pool_refused(self):
        rc, _, err = self.build(FIX, self.path("o1"), "--attack-pool", self.path("nope.jsonl"))
        self.assertNotEqual(rc, 0)
        empty = self.path("empty.jsonl")
        with open(empty, "w") as fh:
            fh.write('{"payload": "x"}\n')
        rc, _, err = self.build(FIX, self.path("o2"), "--attack-pool", empty)
        self.assertNotEqual(rc, 0)


# ─────────────────────────────── acquire (never networked here) ───────────────────────────────
class Acquire(NoNetwork):
    def test_dry_run_prints_plan_without_network(self):
        rc, out, err = self.run_main(["acquire", "--raw-dir", self.path("raw"), "--dry-run"])
        self.assertEqual(rc, 0, err)
        plan = json.loads(out)
        self.assertTrue(plan["dry_run"])
        by = {i["source_id"]: i for i in plan["items"]}
        self.assertEqual(set(by), {"wikidata_given_names", "wikidata_family_names", "tatoeba_cc0"})
        self.assertEqual(by["tatoeba_cc0"]["url"], "https://downloads.tatoeba.org/exports/sentences_CC0.tar.bz2")
        self.assertEqual(by["tatoeba_cc0"]["expected_bytes"], 7959741)
        self.assertEqual(by["wikidata_given_names"]["url"], "https://query.wikidata.org/sparql")
        self.assertIn("wd:Q202444", by["wikidata_given_names"]["query"])
        self.assertIn("wd:Q101352", by["wikidata_family_names"]["query"])
        self.assertIn("LIMIT 50000", by["wikidata_family_names"]["query"])
        self.assertFalse(os.path.exists(self.path("raw")))

    def test_queries_never_touch_person_items(self):
        for q in (B.GIVEN_NAME_QUERY, B.FAMILY_NAME_QUERY):
            self.assertNotIn("Q5 ", q + " ")
            self.assertNotIn("wd:Q5\n", q)
            for forbidden in ("schema:description", "P569", "P570", "P27", "P735", "P734", "schema:about"):
                self.assertNotIn(forbidden, q)
            self.assertIn('LANG(?label) IN ("en","mul")', q)

    def test_acquire_without_flag_refused_and_offline(self):
        rc, out, err = self.run_main(["acquire", "--raw-dir", self.path("raw")])
        self.assertEqual(rc, 2)
        self.assertIn("--yes-download", err)
        self.assertFalse(os.path.exists(self.path("raw")))

    def test_dry_run_wins_over_yes_download(self):
        rc, out, err = self.run_main(["acquire", "--raw-dir", self.path("raw"), "--dry-run", "--yes-download"])
        self.assertEqual(rc, 0, err)
        self.assertTrue(json.loads(out)["dry_run"])

    def test_yes_download_would_hit_the_network_stub(self):
        # With the flag the code does try to open a URL; the stub proves the only network call site.
        with self.assertRaises(AssertionError):
            B.main(["acquire", "--raw-dir", self.path("raw"), "--yes-download", "--only", "tatoeba_cc0"])
        self.assertFalse(os.path.exists(os.path.join(self.path("raw"), "sentences_CC0.csv")))

    def test_existing_pin_never_overwritten(self):
        raw = self.make_raw("sentences_CC0.csv", b"1\teng\tHello there.\t\\N\n")
        with self.assertRaises(SystemExit) as cm:
            B.main(["acquire", "--raw-dir", raw, "--yes-download", "--only", "tatoeba_cc0"])
        self.assertIn("never overwritten", str(cm.exception))

    def test_http_get_enforces_size_limit(self):
        class Resp:
            headers = {"Content-Length": "999999"}

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n):
                return b""
        with mock.patch("urllib.request.urlopen", lambda req, timeout=None: Resp()):
            with self.assertRaises(SystemExit):
                B.http_get("https://example.invalid/x", "*/*", 5, 1000)

        class Big(Resp):
            headers = {}

            def __init__(self):
                self.n = 0

            def read(self, n):
                self.n += 1
                return b"x" * 600
        with mock.patch("urllib.request.urlopen", lambda req, timeout=None: Big()):
            with self.assertRaises(SystemExit):
                B.http_get("https://example.invalid/x", "*/*", 5, 1000)

    def test_http_get_sends_descriptive_user_agent(self):
        seen = {}

        class Resp:
            headers = {}

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n):
                return b""

        def fake(req, timeout=None):
            seen["ua"] = req.get_header("User-agent")
            seen["timeout"] = timeout
            return Resp()
        with mock.patch("urllib.request.urlopen", fake):
            B.http_get("https://example.invalid/x", "*/*", 7, 1000)
        self.assertEqual(seen["ua"], "firewall-IA-v5-dataset/0.1 (research; contact via repo)")
        self.assertEqual(seen["timeout"], 7)


# ─────────────────────────────── tar extraction safety ───────────────────────────────
class TarSafety(NoNetwork):
    def make_tar(self, members, name="a.tar.bz2"):
        path = self.path(name)
        with tarfile.open(path, "w:bz2") as tf:
            for ti, data in members:
                tf.addfile(ti, io.BytesIO(data) if data is not None else None)
        return path

    @staticmethod
    def reg(name, data):
        ti = tarfile.TarInfo(name)
        ti.size = len(data)
        return ti, data

    def test_good_archive_extracts_only_requested_member(self):
        arch = self.make_tar([self.reg("sentences_CC0.csv", b"1\teng\tHi there.\t\\N\n"),
                              self.reg("other.txt", b"zzz")])
        dest = self.path("out.csv")
        B.safe_extract_member(arch, "sentences_CC0.csv", dest, 10_000)
        self.assertEqual(_read(dest), b"1\teng\tHi there.\t\\N\n")

    def test_dot_slash_member_name_ok(self):
        arch = self.make_tar([self.reg("./sentences_CC0.csv", b"data")])
        dest = self.path("out.csv")
        B.safe_extract_member(arch, "sentences_CC0.csv", dest, 100)
        self.assertEqual(_read(dest), b"data")

    def test_absolute_path_rejected(self):
        arch = self.make_tar([self.reg("/etc/evil", b"x"), self.reg("sentences_CC0.csv", b"ok")])
        with self.assertRaises(SystemExit) as cm:
            B.safe_extract_member(arch, "sentences_CC0.csv", self.path("o"), 100)
        self.assertIn("unsafe path", str(cm.exception))
        self.assertFalse(os.path.exists(self.path("o")))

    def test_parent_traversal_rejected(self):
        arch = self.make_tar([self.reg("../evil.csv", b"x"), self.reg("sentences_CC0.csv", b"ok")])
        with self.assertRaises(SystemExit):
            B.safe_extract_member(arch, "sentences_CC0.csv", self.path("o"), 100)
        arch = self.make_tar([self.reg("a/../../evil.csv", b"x")], "b.tar.bz2")
        with self.assertRaises(SystemExit):
            B.safe_extract_member(arch, "sentences_CC0.csv", self.path("o"), 100)

    def test_links_rejected(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            ti = tarfile.TarInfo("link")
            ti.type = kind
            ti.linkname = "/etc/passwd"
            arch = self.make_tar([(ti, None), self.reg("sentences_CC0.csv", b"ok")], f"l{kind!r}.tar.bz2")
            with self.assertRaises(SystemExit) as cm:
                B.safe_extract_member(arch, "sentences_CC0.csv", self.path("o"), 100)
            self.assertIn("link", str(cm.exception))

    def test_missing_member_and_size_limit(self):
        arch = self.make_tar([self.reg("other.csv", b"x")])
        with self.assertRaises(SystemExit):
            B.safe_extract_member(arch, "sentences_CC0.csv", self.path("o"), 100)
        arch = self.make_tar([self.reg("sentences_CC0.csv", b"x" * 500)], "big.tar.bz2")
        with self.assertRaises(SystemExit):
            B.safe_extract_member(arch, "sentences_CC0.csv", self.path("o"), 100)


# ─────────────────────────────── common helpers ───────────────────────────────
class CommonHelpers(unittest.TestCase):
    def test_value_entry_id_formula(self):
        v = "Zoë"
        self.assertEqual(C.value_entry_id("names_given", v),
                         hashlib.sha256("names_given\0Zoë".encode("utf-8")).hexdigest())
        self.assertNotEqual(C.value_entry_id("names_given", "x"), C.value_entry_id("names_family", "x"))

    def test_fixture_sidecars_match_files(self):
        for name in os.listdir(FIX):
            if name.endswith(".source.json"):
                side = json.loads(_read(os.path.join(FIX, name), "r"))
                data = _read(os.path.join(FIX, name[:-len(".source.json")]))
                self.assertEqual(side["sha256"], C.sha256_bytes(data))
                self.assertEqual(side["bytes"], len(data))
                self.assertTrue(side["fixture"])


if __name__ == "__main__":
    unittest.main()
