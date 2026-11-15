#!/usr/bin/env python3
"""firewall-IA — V5 benign source pools (stage 2, dataset foundation).  Standard library only.

Builds the benign VALUE pools of spec r3 (reports/v5/v5-data-spec-draft/README.md section 2.1/3):

    names_given   Wikidata CC0 given-name items (Q202444)         BLOCKED until acquired
    names_family  Wikidata CC0 family-name items (Q101352)        pinned snapshot adopted (#75); built once installed
    prose_en      Tatoeba `sentences_CC0` export, lang `eng`      BLOCKED until acquired
    streets       synthetic street lexicon (repo MIT)             always built
    symbols       benign values containing special symbols (MIT)  always built

Sub-commands
    acquire   download + pin the raw files (NOT run in CI; needs an explicit --yes-download)
    build     read ONLY pinned raw files and the committed lexicons; write the pools + manifest

Nothing here assigns a split, a family or a label.  A pool whose raw source is missing is reported
`BLOCKED: source not acquired` in the manifest and is never substituted.  Filters describe or
remove values; flags never filter.  Output is deterministic: no build-time timestamps.

Privacy policy (D58, freeze-prep/D_sources_provenance.md section 4): names are recombined later and a
name is never emitted as one person's record; Wikidata is queried for NAME items only (never Q5,
never descriptions or person properties); street values never carry a house number or a city;
sentences with long digit runs, phone numbers, e-mail addresses, URLs or dated events are dropped.

    python3 scripts/dataset/build_v5_benign_pools.py acquire --dry-run
    python3 scripts/dataset/build_v5_benign_pools.py build [--raw-dir DIR] [--out-dir DIR]
"""

import argparse
import collections
import datetime
import json
import os
import posixpath
import re
import sys
import tarfile
import unicodedata
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import v5_pools_common as C  # noqa: E402

BUILDER_SCHEMA = "v5-benign-pools/v1"
LEXICON_DIR = os.path.join(HERE, "v5_lexicon")
STREETS_LEXICON = os.path.join(LEXICON_DIR, "streets_v1.json")
SYMBOLS_LEXICON = os.path.join(LEXICON_DIR, "benign_symbols_v1.json")
DEFAULT_RAW_DIR = os.path.join(C.DEFAULT_OUT_DIR, "raw")
BENIGN_SUBDIR = "benign"
BLOCKED = "BLOCKED: source not acquired"
BUILT = "BUILT"
MIN_POOL_SIZE = 200          # spec 4.6 step 3 (report only)
# Wikimedia User-Agent policy: client/version (contact) library/version. The contact is the public
# project repository (no personal data). Changed 2026-10-19 (issue #75): the earlier "(research;
# contact via repo)" carried no usable contact; the given-name sidecar keeps the UA it was fetched with.
USER_AGENT = ("firewall-IA-v5-dataset/0.2 (https://github.com/SebasHT15/firewall-IA; research dataset build) "
              f"Python-urllib/{sys.version_info[0]}.{sys.version_info[1]}")

# Spec 4.4: these must survive the benign oracle.  The build fails if one is not ACCEPTED.
SURVIVAL_FIXTURE = ["O'Neil", "Apt #4", "AT&T", "100%", "a<b"]

# ───────────────────────────────── acquisition plan ─────────────────────────────────
WDQS_ENDPOINT = "https://query.wikidata.org/sparql"
# First-party Wikimedia WDQS endpoints only (same Wikidata CC0 data, same pinned query). The
# main-graph host serves every non-scholarly item, which includes all given/family-name items.
# On 2026-10-19 query.wikidata.org still answered HTTP 429 under the 2026-10-14 outage rule while
# query-main.wikidata.org answered normally (issue #75). The endpoint used is recorded in the
# sidecar; third-party mirrors (e.g. QLever) are NOT accepted here.
WDQS_ENDPOINTS = (WDQS_ENDPOINT, "https://query-main.wikidata.org/sparql")
TATOEBA_URL = "https://downloads.tatoeba.org/exports/sentences_CC0.tar.bz2"
WIKIDATA_LICENCE_URL = "https://www.wikidata.org/wiki/Wikidata:Licensing"
TATOEBA_LICENCE_URL = "https://tatoeba.org/en/downloads"

# Exact query text (recorded verbatim in the sidecar and checked at build time).  Only NAME items
# (instances of given name / family name) and their labels are read.  Q5 (human) and every person
# property, description or date are deliberately absent.  No ORDER BY: when LIMIT binds, the subset
# is arbitrary but pinned by the SHA-256 of the response.
GIVEN_NAME_QUERY = (
    "SELECT ?item ?label WHERE {\n"
    "  ?item wdt:P31 wd:Q202444 ;\n"
    "        rdfs:label ?label .\n"
    "  FILTER(LANG(?label) IN (\"en\",\"mul\"))\n"
    "}\n"
    "LIMIT 100000"
)
# LIMIT 20000 (was 50000, originally 200000): the pinned query must finish inside the WDQS 60 s
# query timeout, otherwise the server truncates the JSON (issue #75). On 2026-10-19 and 2026-10-20
# LIMIT 50000 was truncated (~1-2 MB of ~11 MB expected); LIMIT 20000 completed twice (26 s, 19 s).
# Without ORDER BY the subset is arbitrary and a re-run returns a DIFFERENT subset (93% item
# overlap measured), so reproducibility is the archived raw file + its SHA-256, never a re-run, and
# the subset carries no representativeness claim. 20,000 rows far exceed the >= 200-element pool
# minimum (spec §4.6 step 3). The pool is built only from a complete, pinned raw file; without one
# it stays BLOCKED (snapshot: reports/v5/data-readiness/names_family-candidate/).
FAMILY_NAME_QUERY = (
    "SELECT ?item ?label WHERE {\n"
    "  ?item wdt:P31 wd:Q101352 ;\n"
    "        rdfs:label ?label .\n"
    "  FILTER(LANG(?label) IN (\"en\",\"mul\"))\n"
    "}\n"
    "LIMIT 20000"
)

SOURCES = {
    "wikidata_given_names": {
        "file": "wikidata_given_names.json", "kind": "wdqs", "query": GIVEN_NAME_QUERY,
        "url": WDQS_ENDPOINT, "licence": "CC0-1.0", "licence_evidence_url": WIKIDATA_LICENCE_URL,
        "expected_bytes": None, "max_bytes": 128 * 1024 * 1024, "timeout_s": 120,
    },
    "wikidata_family_names": {
        "file": "wikidata_family_names.json", "kind": "wdqs", "query": FAMILY_NAME_QUERY,
        "url": WDQS_ENDPOINT, "licence": "CC0-1.0", "licence_evidence_url": WIKIDATA_LICENCE_URL,
        "expected_bytes": None, "max_bytes": 128 * 1024 * 1024, "timeout_s": 300,
    },
    "tatoeba_cc0": {
        "file": "sentences_CC0.csv", "kind": "tatoeba", "archive": "sentences_CC0.tar.bz2",
        "url": TATOEBA_URL, "licence": "CC0-1.0", "licence_evidence_url": TATOEBA_LICENCE_URL,
        "expected_bytes": 7959741,           # measured 2026-10-11 (D_sources_provenance 2.3); informational
        "expected_extracted_bytes": 41860119,
        "max_bytes": 64 * 1024 * 1024, "max_extracted_bytes": 256 * 1024 * 1024, "timeout_s": 120,
    },
}
POOL_SOURCE = {"names_given": "wikidata_given_names", "names_family": "wikidata_family_names",
               "prose_en": "tatoeba_cc0"}
SIDECAR_REQUIRED = ("url", "retrieved_at", "sha256", "bytes", "licence", "licence_evidence_url")

# ───────────────────────────────── text helpers & flags ─────────────────────────────────
SYMBOL_CHARS = set("'#!&;%+<>\"/") | {"’"}
APOSTROPHES = ("'", "’", "ʼ")
HYPHENS = ("-", "‐", "‑")


def norm(text):
    """NFC + strip: the value stored in every pool."""
    return C.nfc(text).strip()


def flags_for(value):
    out = []
    if any(a in value for a in APOSTROPHES):
        out.append("has_apostrophe")
    if any(h in value for h in HYPHENS):
        out.append("has_hyphen")
    if any(ord(ch) > 127 for ch in value):
        out.append("non_ascii")
    if any(ch in SYMBOL_CHARS for ch in value) or "--" in value:
        out.append("has_symbol")
    if any(ch.isdigit() for ch in value):
        out.append("has_digit")
    return out


def has_control(text):
    # Cc control, Cf format (zero-width, bidi), Zl/Zp line/paragraph separators, Cs/Co/Cn
    return any(unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp", "Cs", "Co", "Cn") for ch in text)


# ───────────────────────────────── name filters ─────────────────────────────────
NAME_MAX_LEN = 40
FAMILY_MAX_TOKENS = 4
BRACKETS = set("()[]{}")
URL_RE = re.compile(r"(?:[a-z][a-z0-9+.-]*://|\bwww\.|\b[a-z0-9-]+\.(?:com|net|org|edu|gov|info|io|co)\b)", re.I)
NAME_EXTRA_OK = set("'’ʼ-‐‑. ")
NAME_WORD_RE = re.compile(r"\bnames?\b", re.I)


def name_reason(value, kind):
    """First matching reason code, or None.  `kind` is 'given' or 'family'.  Order is fixed."""
    if not value:
        return "empty"
    if has_control(value):
        return "control_char"
    if any(ch.isdigit() for ch in value):
        return "contains_digit"
    if any(ch in BRACKETS for ch in value):
        return "parenthesis_or_disambiguation"
    if "@" in value or URL_RE.search(value):
        return "at_or_url"
    if ":" in value:
        return "contains_colon"
    if any(not (unicodedata.category(ch)[0] in ("L", "M") or ch in NAME_EXTRA_OK) for ch in value):
        return "non_name_char"
    if len(value) > NAME_MAX_LEN:
        return "too_long"
    # Review D (stage 2): WDQS labels include descriptions such as "female given name" and
    # one-letter or lowercase non-names. Family names may legitimately start lowercase ("van").
    if NAME_WORD_RE.search(value):
        return "descriptive_label"
    if kind == "given" and not value[0].isupper():
        return "not_capitalised"
    tokens = value.split()
    if kind == "given":
        if len(tokens) >= 2 and sum(1 for t in tokens if t[0].isupper()) >= 2:
            return "looks_like_full_name"
    elif len(tokens) > FAMILY_MAX_TOKENS:
        return "too_many_tokens"
    return None


# ───────────────────────────────── prose filters ─────────────────────────────────
PROSE_MIN_LEN = 3
PROSE_MAX_LEN = 200
MONTHS = ("january|february|march|april|may|june|july|august|september|october|november|december|"
          "jan|feb|mar|apr|jun|jul|aug|sep|sept|oct|nov|dec")
YEAR = r"(?:1[0-9]{3}|20[0-9]{2})"
DATE_RE = re.compile(rf"(?:\b(?:{MONTHS})\b\.?\s+(?:[0-9]{{1,2}}(?:st|nd|rd|th)?,?\s+)?{YEAR}\b|"
                     rf"\b{YEAR}\b[,\s]+(?:\b(?:{MONTHS})\b)|"
                     rf"\b[0-9]{{1,2}}(?:st|nd|rd|th)?\s+(?:of\s+)?(?:{MONTHS})\b\.?,?\s+{YEAR}\b)", re.I)
EMAIL_RE = re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+")
DIGIT_RUN_RE = re.compile(r"[0-9]{6,}")
PHONE_RE = re.compile(r"\+?[0-9](?:[\s().\-]?[0-9]){7,}")
FULL_NAME_RE = re.compile(r"\b(?!I\b)[A-Z][a-z]+(?:['’]s)?\s+[A-Z][a-z]+")


def prose_reason(text, min_len=PROSE_MIN_LEN, max_len=PROSE_MAX_LEN):
    if not text:
        return "empty"
    if has_control(text):
        return "control_char"
    if len(text) < min_len:
        return "too_short"
    if len(text) > max_len:
        return "too_long"
    if EMAIL_RE.search(text):
        return "email_like"
    if "@" in text:
        return "at_sign"
    if URL_RE.search(text):
        return "url_like"
    if DIGIT_RUN_RE.search(text):
        return "digit_run_ge6"
    if PHONE_RE.search(text):
        return "phone_like"
    if DATE_RE.search(text):
        return "dated_event"
    # Privacy (D §4, review D): two adjacent capitalised words are treated as a possible full
    # name of a real person and the sentence is dropped. Deliberately conservative: it also drops
    # place names ("New York"); single first names ("Tom") are kept and disclosed.
    if FULL_NAME_RE.search(text):
        return "possible_full_name"
    return None


# ───────────────────────────────── records ─────────────────────────────────
def make_record(pool_id, value, source_id, source_ref, license_, status, reason, extra=None):
    rec = {"pool_id": pool_id, "value": value,
           "value_entry_id": C.value_entry_id(pool_id, value) if value is not None else None,
           "source_id": source_id, "source_ref": source_ref, "license": license_,
           "status": status, "exclusion_reason": reason,
           "flags": flags_for(value) if value is not None else []}
    if extra:
        rec.update(extra)
    return rec


def _num(ref):
    m = re.search(r"([0-9]+)", ref or "")
    return int(m.group(1)) if m else 0


def sort_key(rec):
    return (rec["pool_id"], _num(rec["source_ref"]), rec["source_ref"], rec.get("source_lang") or "",
            rec["value"] or "", rec["value_entry_id"] or "")


# ───────────────────────────────── raw input (pinned) ─────────────────────────────────
def load_pinned(raw_dir, source_id):
    """Return (bytes, sidecar) of a pinned raw file, or None if the file was never acquired.

    Refuses (SystemExit) a present-but-unpinned file, a malformed sidecar, a SHA-256 / size
    mismatch, or a WDQS sidecar whose query differs from the query in this code."""
    spec = SOURCES[source_id]
    path = os.path.join(raw_dir, spec["file"])
    if not os.path.isfile(path):
        return None
    side_path = path + ".source.json"
    if not os.path.isfile(side_path):
        raise SystemExit(f"REFUSED: {path} has no pin sidecar {os.path.basename(side_path)}")
    try:
        with open(side_path, encoding="utf-8") as fh:
            side = json.load(fh)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"REFUSED: sidecar {side_path} unreadable: {exc}")
    if not isinstance(side, dict) or any(k not in side for k in SIDECAR_REQUIRED):
        raise SystemExit(f"REFUSED: sidecar {side_path} lacks one of {SIDECAR_REQUIRED}")
    with open(path, "rb") as fh:
        data = fh.read()
    if C.sha256_bytes(data) != side["sha256"]:
        raise SystemExit(f"REFUSED: {path} does not match the pinned sha256 of its sidecar")
    if side["bytes"] != len(data):
        raise SystemExit(f"REFUSED: {path} size {len(data)} differs from sidecar bytes {side['bytes']}")
    if side.get("licence") != spec["licence"]:
        raise SystemExit(f"REFUSED: sidecar licence of {path} is {side.get('licence')!r}, expected {spec['licence']!r}")
    if spec["kind"] == "wdqs" and side.get("query") != spec["query"]:
        raise SystemExit(f"REFUSED: sidecar query of {path} differs from the query pinned in this builder")
    return data, side


def source_pin(side, source_id):
    spec = SOURCES[source_id]
    pin = {k: side[k] for k in SIDECAR_REQUIRED}
    pin["file"] = spec["file"]
    if "query" in side:
        pin["query"] = side["query"]
        pin["query_sha256"] = C.sha256_bytes(side["query"].encode("utf-8"))
    if "archive" in side:
        pin["archive"] = side["archive"]
    return pin


# ───────────────────────────────── parsing ─────────────────────────────────
QID_RE = re.compile(r"^http://www\.wikidata\.org/entity/Q([1-9][0-9]*)$")
LANG_RANK = {"en": 0, "mul": 1}


def parse_wdqs(data):
    """-> (rows, malformed).  rows: dicts qid, qnum, label, lang.  malformed: (ref, reason)."""
    try:
        # strict=False: the live WDQS response (2026-10-14) carries raw control characters
        # inside some label strings, which strict JSON rejects. They are parsed here and the
        # label is then excluded by the `control_char` name filter, never kept silently.
        doc = json.loads(data.decode("utf-8"), strict=False)
        bindings = doc["results"]["bindings"]
        if not isinstance(bindings, list):
            raise TypeError("bindings is not a list")
    except (UnicodeDecodeError, ValueError, KeyError, TypeError) as exc:
        raise SystemExit(f"REFUSED: pinned WDQS file is not valid SPARQL JSON results: {exc}")
    rows, malformed = [], []
    for i, b in enumerate(bindings):
        ref = f"binding[{i}]"
        try:
            item_uri = b["item"]["value"]
            label = b["label"]["value"]
            lang = b["label"].get("xml:lang")
        except (KeyError, TypeError, AttributeError):
            malformed.append((ref, "malformed_row"))
            continue
        m = QID_RE.match(item_uri) if isinstance(item_uri, str) else None
        if not m or not isinstance(label, str) or lang not in LANG_RANK:
            malformed.append((ref, "malformed_row"))
            continue
        rows.append({"qid": f"Q{m.group(1)}", "qnum": int(m.group(1)), "label": label, "lang": lang})
    return rows, malformed


def parse_tatoeba(data):
    """-> (rows, malformed).  rows: dicts id, lang, text.  Columns: id, lang, text, date (TAB)."""
    rows, malformed = [], []
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    for i, raw in enumerate(lines):
        ref = f"line[{i + 1}]"
        if raw.endswith(b"\r"):
            raw = raw[:-1]
        try:
            line = raw.decode("utf-8")
        except UnicodeDecodeError:
            malformed.append((ref, "invalid_utf8"))
            continue
        cols = line.split("\t")
        if len(cols) != 4:
            malformed.append((ref, "malformed_row"))
            continue
        if not re.fullmatch(r"[0-9]+", cols[0]) or not re.fullmatch(r"[a-z]{2,4}", cols[1]):
            malformed.append((ref, "malformed_row"))
            continue
        rows.append({"id": int(cols[0]), "lang": cols[1], "text": cols[2]})
    return rows, malformed


# ───────────────────────────────── generic pool pipeline ─────────────────────────────────
def run_pipeline(candidates, reason_fn, oracle_keys=None):
    """candidates: list of (pool_id, raw_value, source_id, source_ref, license, extra) already in
    deterministic first-wins order.  Returns (accepted, excluded) record lists."""
    accepted, excluded, seen = [], [], set()
    canon = None
    if oracle_keys is not None:
        import parse_dataset_v4  # noqa: E402  (V4 canonical_key, imported, never edited)
        canon = parse_dataset_v4.canonical_key
    for pool_id, raw, source_id, source_ref, license_, extra in candidates:
        value = norm(raw)
        reason = reason_fn(value)
        if reason is None and value in seen:
            reason = "duplicate_value"
        if reason is None and canon is not None and canon(value) in oracle_keys:
            reason = "oracle_exact_collision"
        if reason is None:
            seen.add(value)
        rec = make_record(pool_id, value, source_id, source_ref, license_,
                          C.ACCEPTED if reason is None else C.EXCLUDED, reason, extra)
        (accepted if reason is None else excluded).append(rec)
    return accepted, excluded


def malformed_records(pool_id, source_id, license_, malformed):
    return [make_record(pool_id, None, source_id, ref, license_, C.EXCLUDED, reason)
            for ref, reason in malformed]


def build_name_pool(pool_id, kind, source_id, loaded, oracle_keys):
    data, side = loaded
    rows, malformed = parse_wdqs(data)
    rows.sort(key=lambda r: (r["qnum"], LANG_RANK[r["lang"]], r["label"]))
    cands = [(pool_id, r["label"], source_id, r["qid"], side["licence"], {"source_lang": r["lang"]})
             for r in rows]
    acc, exc = run_pipeline(cands, lambda v: name_reason(v, kind), oracle_keys)
    exc += malformed_records(pool_id, source_id, side["licence"], malformed)
    return acc, exc, {"rows_read": len(rows) + len(malformed), "other_language_rows": 0}


def build_prose_pool(pool_id, lang, loaded, oracle_keys, min_len, max_len):
    data, side = loaded
    rows, malformed = parse_tatoeba(data)
    sel = sorted((r for r in rows if r["lang"] == lang), key=lambda r: r["id"])
    other = len(rows) - len(sel)
    cands = [(pool_id, r["text"], "tatoeba_cc0", str(r["id"]), side["licence"], {"source_lang": lang})
             for r in sel]
    acc, exc = run_pipeline(cands, lambda v: prose_reason(v, min_len, max_len), oracle_keys)
    exc += malformed_records(pool_id, "tatoeba_cc0", side["licence"], malformed)
    return acc, exc, {"rows_read": len(rows) + len(malformed), "other_language_rows": other}


# ───────────────────────────────── lexicons ─────────────────────────────────
def load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def expand_streets(lex):
    """Deterministic expansion of the street lexicon -> sorted [(expansion_key, string)].

    Patterns: plain (stem + type form), directional prefix/suffix (English), unit designator
    (every `unit_every`-th plain street), numbered road, fixed phrase, cross street (every
    `every`-th English / Spanish plain street).  Strings are de-duplicated (first key wins).  House
    numbers and cities are never produced here (D58 privacy)."""
    langs = lex["languages"]
    out = {}
    seen_values = set()

    def add(key, s):
        s = C.nfc(" ".join(s.split()))
        if s and s not in seen_values:
            seen_values.add(s)
            out[key] = s

    plain = {}
    for lang in sorted(langs):
        L = langs[lang]
        stems = [(g, s) for g in ("names", "nouns", "ordinals") for s in L["stems"].get(g, [])]
        for ti, t in enumerate(L["types"]):
            for fi, form in enumerate(t["forms"]):
                for g, stem in stems:
                    if t["pos"] == "suffix":
                        s = f"{stem} {form}"
                    elif t["pos"] == "prefix":
                        s = f"{form} {stem}"
                    else:
                        s = f"{stem}{form}"
                    key = f"{lang}|plain|{g}:{stem}|{t['forms'][0]}|{form}"
                    add(key, s)
                    plain.setdefault(lang, []).append((key, C.nfc(" ".join(s.split()))))
    # directionals (English only here): one prefix and one suffix directional per
    # (stem, type, form), chosen by position, first two types, first and last form
    for lang in sorted(langs):
        L = langs[lang]
        dirs = L.get("directionals")
        if not dirs:
            continue
        for si, stem in enumerate(L["stems"].get("names", [])):
            for ti, t in enumerate(L["types"][:2]):
                for fi, form in enumerate((t["forms"][0], t["forms"][-1])):
                    pre = dirs[(si + ti + fi) % len(dirs)]
                    post = dirs[(si * 3 + ti + 2 * fi + 1) % len(dirs)]
                    add(f"{lang}|dir-pre|{stem}|{form}|{pre}", f"{pre} {stem} {form}")
                    add(f"{lang}|dir-post|{stem}|{form}|{post}", f"{stem} {form} {post}")
    # numbered roads
    sfx = lex["number_suffixes"]
    for lang in sorted(langs):
        for road in langs[lang].get("numbered_roads", []):
            for n in lex["numbers"]:
                for sfi, suffix in enumerate(sfx):
                    if suffix and lang in ("en", "fr", "pt"):
                        continue
                    add(f"{lang}|num|{road}|{n}|{suffix}", f"{road} {n}{suffix}")
    # fixed phrases
    for lang in sorted(langs):
        for phrase in langs[lang].get("fixed", []):
            add(f"{lang}|fixed|{phrase}", phrase)
    # units: every k-th plain street (in key order) gets a unit designator of its own language
    units, joiners, k = lex["units"], lex["unit_joiners"], lex["unit_every"]
    for lang in sorted(plain):
        base = sorted(plain[lang])
        lang_units = units.get(lang, units["en"])
        for i in range(0, len(base), k):
            u = lang_units[(i // k) % len(lang_units)]
            j = joiners[(i // k) % len(joiners)]
            add(f"{lang}|unit|{base[i][0]}|{u}", f"{base[i][1]}{j}{u}")
    # cross streets
    cross = lex["cross_streets"]
    for lang in sorted(cross["joiners"]):
        base = sorted(plain.get(lang, []))
        n = len(base)
        for i in range(0, n, cross["every"]):
            a, b = base[i], base[(i * 7 + 3) % n]
            if a[1] == b[1]:
                continue
            js = cross["joiners"][lang]
            add(f"{lang}|cross|{a[0]}|{b[0]}|{js[(i // cross['every']) % len(js)]}",
                f"{a[1]} {js[(i // cross['every']) % len(js)]} {b[1]}")
    return sorted(out.items())


def street_reason(value):
    if not value:
        return "empty"
    if has_control(value):
        return "control_char"
    return None


def build_streets_pool(oracle_keys):
    lex = load_json(STREETS_LEXICON)
    items = expand_streets(lex)
    if len(items) < lex["min_pool_size"]:
        raise SystemExit(f"streets lexicon expands to {len(items)} < min_pool_size {lex['min_pool_size']}")
    cands = [("streets", s, "streets_v1", key, lex["license"], None) for key, s in items]
    acc, exc = run_pipeline(cands, street_reason, oracle_keys)
    return acc, exc, {"rows_read": len(items), "other_language_rows": 0}


def symbol_reason(value):
    if not value:
        return "empty"
    if has_control(value):
        return "control_char"
    if "@" in value or URL_RE.search(value):
        return "at_or_url"
    return None


def build_symbols_pool(oracle_keys):
    lex = load_json(SYMBOLS_LEXICON)
    cands = []
    for g in lex["groups"]:
        for i, v in enumerate(lex["groups"][g]):
            cands.append(("symbols", v, "benign_symbols_v1", f"{g}#{i:03d}", lex["license"], None))
    if len(cands) < lex["min_entries"]:
        raise SystemExit(f"benign symbols lexicon has {len(cands)} < min_entries {lex['min_entries']}")
    acc, exc = run_pipeline(cands, symbol_reason, oracle_keys)
    return acc, exc, {"rows_read": len(cands), "other_language_rows": 0}


# ───────────────────────────────── oracle (exact part only) ─────────────────────────────────
def load_attack_keys(path):
    C.assert_not_protected(path)
    if not os.path.isfile(path):
        raise SystemExit(f"REFUSED: attack pool {path} not found")
    keys, records = set(), 0
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            records += 1
            try:
                k = json.loads(line).get("canonical_key")
            except (ValueError, AttributeError):
                k = None
            if isinstance(k, str):
                keys.add(k)
    if not keys:
        raise SystemExit(f"REFUSED: attack pool {path} yields no canonical_key")
    return keys, {"file": os.path.basename(path), "sha256": C.sha256_file(path), "records": records,
                  "canonical_keys": len(keys)}


# ───────────────────────────────── build command ─────────────────────────────────
MANAGED_FILES = ["names_given.jsonl", "names_family.jsonl", "prose_en.jsonl", "streets.jsonl",
                 "symbols.jsonl", "benign_excluded.jsonl", "manifest.json"]


def count_flags(records):
    c = collections.Counter()
    for r in records:
        c.update(r["flags"])
    return dict(sorted(c.items()))


def cmd_build(args):
    python_info = C.check_python()
    out_root = C.assert_not_protected(args.out_dir)
    raw_dir = C.assert_not_protected(args.raw_dir or os.path.join(out_root, "raw"))
    out_dir = os.path.join(out_root, BENIGN_SUBDIR)
    os.makedirs(out_dir, exist_ok=True)
    for name in MANAGED_FILES:                      # never leave a stale artifact behind
        p = os.path.join(out_dir, name)
        if os.path.isfile(p):
            os.remove(p)

    oracle_keys, attack_pin = None, None
    if args.attack_pool:
        oracle_keys, attack_pin = load_attack_keys(args.attack_pool)
    prose_lang = args.prose_lang
    prose_pool = "prose_en" if prose_lang == "eng" else f"prose_{prose_lang}"
    plan = [("names_given", lambda ld: build_name_pool("names_given", "given", "wikidata_given_names", ld, oracle_keys)),
            ("names_family", lambda ld: build_name_pool("names_family", "family", "wikidata_family_names", ld, oracle_keys)),
            (prose_pool, lambda ld: build_prose_pool(prose_pool, prose_lang, ld, oracle_keys,
                                                     args.prose_min_len, args.prose_max_len))]
    source_of = {"names_given": "wikidata_given_names", "names_family": "wikidata_family_names",
                 prose_pool: "tatoeba_cc0"}

    pools, artifacts, all_excluded, blocked, sources = {}, [], [], [], {}
    results = {}
    for pool_id, fn in plan:
        sid = source_of[pool_id]
        loaded = load_pinned(raw_dir, sid)
        if loaded is None:
            pools[pool_id] = {"status": BLOCKED, "source_id": sid, "accepted": 0, "min_pool_size": MIN_POOL_SIZE,
                              "meets_min_pool_size": False}
            blocked.append(pool_id)
            continue
        sources[sid] = source_pin(loaded[1], sid)
        acc, exc, info = fn(loaded)
        results[pool_id] = (acc, exc, info, sid)
    for pool_id, fn, sid in (("streets", build_streets_pool, "streets_v1"), ("symbols", build_symbols_pool, "benign_symbols_v1")):
        acc, exc, info = fn(oracle_keys)
        results[pool_id] = (acc, exc, info, sid)

    for pool_id in sorted(results):
        acc, exc, info, sid = results[pool_id]
        art = C.write_jsonl(os.path.join(out_dir, f"{pool_id}.jsonl"), acc, sort_key)
        art["path"] = f"{pool_id}.jsonl"
        artifacts.append(art)
        all_excluded += exc
        reasons = collections.Counter(r["exclusion_reason"] for r in exc)
        if info["other_language_rows"]:
            reasons["not_selected_language(counted_only)"] = info["other_language_rows"]
        pools[pool_id] = {
            "status": BUILT, "source_id": sid, "rows_read": info["rows_read"],
            "extracted": len(acc) + len(exc), "accepted": len(acc), "excluded": len(exc),
            "exclusion_reasons": dict(sorted(reasons.items())),
            "flags_extracted": count_flags([r for r in acc + exc if r["value"] is not None]),
            "flags_accepted": count_flags(acc),
            "min_pool_size": MIN_POOL_SIZE, "meets_min_pool_size": len(acc) >= MIN_POOL_SIZE,
            "artifact": art["path"]}
    for r in all_excluded:   # D59 mapping added beside the original reason, which is never changed
        r["d59_exclusion_reason"] = C.d59_exclusion_reason(r["exclusion_reason"])
    art = C.write_jsonl(os.path.join(out_dir, "benign_excluded.jsonl"), all_excluded, sort_key)
    art["path"] = "benign_excluded.jsonl"
    artifacts.append(art)

    symbols_ok = {r["value"] for r in results["symbols"][0]}
    survival = {v: (v in symbols_ok) for v in SURVIVAL_FIXTURE}

    lexicons = {}
    for p in (STREETS_LEXICON, SYMBOLS_LEXICON):
        lex = load_json(p)
        lexicons[lex["id"]] = {"file": os.path.relpath(p, C.REPO_ROOT), "sha256": C.sha256_file(p),
                               "license": lex["license"], "schema": lex["schema"]}
    code_files = [os.path.abspath(__file__), os.path.join(HERE, "v5_pools_common.py")]
    if oracle_keys is not None:
        code_files.append(os.path.join(HERE, "parse_dataset_v4.py"))
    manifest = {
        "schema": BUILDER_SCHEMA, "pool_schema": C.SCHEMA, "kind": "benign_source_pools",
        "spec": "reports/v5/v5-data-spec-draft/README.md (r3) sections 2.1, 3, 4.4, 4.6; D58",
        "pools": dict(sorted(pools.items())), "blocked_pools": sorted(blocked),
        "sources": dict(sorted(sources.items())), "lexicons": lexicons,
        "config": {"prose_lang": prose_lang, "prose_min_len": args.prose_min_len,
                   "prose_max_len": args.prose_max_len, "name_max_len": NAME_MAX_LEN,
                   "family_max_tokens": FAMILY_MAX_TOKENS, "min_pool_size_report_only": MIN_POOL_SIZE},
        "oracle": {
            "exact_canonical_key": ("APPLIED" if oracle_keys is not None
                                    else "NOT_APPLIED: no --attack-pool given"),
            "attack_pool": attack_pin,
            "containment_ge_L": "PENDING: L not calibrated (spec 4.4)",
            "breakout_signatures": "PENDING: signature list not frozen (spec 4.4)"},
        "survival_fixture": {"values": survival, "all_survive": all(survival.values())},
        "pending": (["Wikidata family-name source: BLOCKED until a complete pinned WDQS response exists"]
                    if "names_family" in blocked else [])
                   + ["oracle containment length L and breakout signatures (spec 4.4)"],
        "privacy": ("Names: Wikidata name items only (Q202444, Q101352), recombined later, never a person record. "
                    "Prose: Tatoeba CC0 export with digit-run/phone/e-mail/URL/date/possible-full-name filters. "
                    "Streets: synthetic, no house number or city. Pools are local and gitignored."),
        "code_fingerprint": C.code_fingerprint(code_files), "environment": C.environment(),
        "python": python_info,
        "provenance": C.provenance(code_files + [STREETS_LEXICON, SYMBOLS_LEXICON]),
        "d59_mapping": C.d59_mapping_table(),
        "d59_exclusion_counts": dict(sorted(collections.Counter(
            str(r["d59_exclusion_reason"]) for r in all_excluded).items())),
        "artifacts": sorted(artifacts, key=lambda a: a["path"]),
    }
    C.write_json(os.path.join(out_dir, "manifest.json"), manifest)
    print(json.dumps({"out_dir": out_dir, "blocked": sorted(blocked),
                      "accepted": {k: v["accepted"] for k, v in sorted(pools.items())},
                      "survival_ok": manifest["survival_fixture"]["all_survive"]}, sort_keys=True))
    if not manifest["survival_fixture"]["all_survive"]:
        print("FAIL: survival fixture value(s) not ACCEPTED", file=sys.stderr)
        return 3
    return 0


# ───────────────────────────────── acquire command ─────────────────────────────────
def acquire_plan(only=None, raw_dir=DEFAULT_RAW_DIR, endpoint=WDQS_ENDPOINT):
    if endpoint not in WDQS_ENDPOINTS:
        raise SystemExit(f"REFUSED: {endpoint!r} is not a first-party Wikimedia WDQS endpoint {WDQS_ENDPOINTS}")
    items = []
    for sid, s in SOURCES.items():
        if only and sid not in only:
            continue
        item = {"source_id": sid, "url": s["url"], "out_file": os.path.join(raw_dir, s["file"]),
                "licence": s["licence"], "expected_bytes": s["expected_bytes"],
                "max_bytes": s["max_bytes"], "timeout_s": s["timeout_s"]}
        if s["kind"] == "wdqs":
            item["url"] = endpoint
            item["method"] = "GET " + endpoint + "?format=json&query=<query>"
            item["query"] = s["query"]
        else:
            item["method"] = "GET archive, extract one member safely"
            item["archive_file"] = os.path.join(raw_dir, s["archive"])
            item["extracted_bytes_expected"] = s["expected_extracted_bytes"]
        items.append(item)
    return items


def http_get(url, accept, timeout, max_bytes):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        length = resp.headers.get("Content-Length")
        if length and int(length) > max_bytes:
            raise SystemExit(f"REFUSED: {url} announces {length} bytes > limit {max_bytes}")
        buf = bytearray()
        while True:
            chunk = resp.read(1 << 20)
            if not chunk:
                break
            buf += chunk
            if len(buf) > max_bytes:
                raise SystemExit(f"REFUSED: {url} exceeds the {max_bytes}-byte limit")
        return bytes(buf)


def safe_extract_member(archive_path, member_name, dest_path, max_bytes):
    """Extract exactly one regular file from a tar.bz2.  The whole archive is rejected if ANY member
    has an absolute path, a `..` component, a backslash, or is a link / device / fifo."""
    with tarfile.open(archive_path, "r:*") as tf:
        wanted = None
        for m in tf.getmembers():
            name = m.name
            parts = name.replace("\\", "/").split("/")
            if name.startswith("/") or "\\" in name or ".." in parts or re.match(r"^[A-Za-z]:", name):
                raise SystemExit(f"REFUSED: unsafe path in archive: {name!r}")
            if m.issym() or m.islnk() or m.isdev() or m.isfifo():
                raise SystemExit(f"REFUSED: link or special file in archive: {name!r}")
            if m.isfile() and posixpath.normpath(name) == member_name:
                wanted = m
        if wanted is None:
            raise SystemExit(f"REFUSED: {member_name} not found in {os.path.basename(archive_path)}")
        if wanted.size > max_bytes:
            raise SystemExit(f"REFUSED: {member_name} is {wanted.size} bytes > limit {max_bytes}")
        src = tf.extractfile(wanted)
        tmp = dest_path + ".part"
        written = 0
        with open(tmp, "wb") as out:
            while True:
                chunk = src.read(1 << 20)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    out.close()
                    os.remove(tmp)
                    raise SystemExit("REFUSED: extraction exceeded the size limit")
                out.write(chunk)
        os.replace(tmp, dest_path)


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write_sidecar(path, side):
    C.write_json(path + ".source.json", side)


def _acquire_one(sid, raw_dir, endpoint=WDQS_ENDPOINT):
    if endpoint not in WDQS_ENDPOINTS:
        raise SystemExit(f"REFUSED: {endpoint!r} is not a first-party Wikimedia WDQS endpoint {WDQS_ENDPOINTS}")
    s = SOURCES[sid]
    os.makedirs(raw_dir, exist_ok=True)
    dest = os.path.join(raw_dir, s["file"])
    if os.path.exists(dest) or os.path.exists(dest + ".source.json"):
        raise SystemExit(f"REFUSED: {dest} (or its sidecar) already exists; pinned raw files are never overwritten")
    retrieved_at = _utc_now()                      # recorded once, at download
    if s["kind"] == "wdqs":
        url = endpoint + "?" + urllib.parse.urlencode({"query": s["query"], "format": "json"})
        data = http_get(url, "application/sparql-results+json", s["timeout_s"], s["max_bytes"])
        parse_wdqs(data)                           # must be valid SPARQL JSON results
        with open(dest, "wb") as fh:
            fh.write(data)
        _write_sidecar(dest, {"url": url, "endpoint": endpoint, "query": s["query"],
                              "retrieved_at": retrieved_at, "sha256": C.sha256_bytes(data), "bytes": len(data),
                              "licence": s["licence"], "licence_evidence_url": s["licence_evidence_url"],
                              "user_agent": USER_AGENT})
    else:
        arch = os.path.join(raw_dir, s["archive"])
        if os.path.exists(arch):
            raise SystemExit(f"REFUSED: {arch} already exists")
        data = http_get(s["url"], "application/x-bzip2", s["timeout_s"], s["max_bytes"])
        with open(arch, "wb") as fh:
            fh.write(data)
        _write_sidecar(arch, {"url": s["url"], "retrieved_at": retrieved_at, "sha256": C.sha256_bytes(data),
                              "bytes": len(data), "licence": s["licence"],
                              "licence_evidence_url": s["licence_evidence_url"], "user_agent": USER_AGENT})
        safe_extract_member(arch, s["file"], dest, s["max_extracted_bytes"])
        _write_sidecar(dest, {"url": s["url"], "archive": s["archive"], "archive_sha256": C.sha256_bytes(data),
                              "retrieved_at": retrieved_at, "sha256": C.sha256_file(dest),
                              "bytes": os.path.getsize(dest), "licence": s["licence"],
                              "licence_evidence_url": s["licence_evidence_url"], "user_agent": USER_AGENT})
    return dest


def cmd_acquire(args):
    raw_dir = C.assert_not_protected(args.raw_dir)
    plan = acquire_plan(args.only, raw_dir, args.endpoint)
    if args.dry_run:
        print(json.dumps({"dry_run": True, "network": "none", "items": plan}, indent=2, ensure_ascii=False))
        return 0
    if not args.yes_download:
        print("REFUSED: acquire downloads from the network (query.wikidata.org, downloads.tatoeba.org). "
              "Re-run with --dry-run to inspect, or with --yes-download once downloads are authorized.",
              file=sys.stderr)
        return 2
    for item in plan:
        print("downloading", item["source_id"], "->", _acquire_one(item["source_id"], raw_dir, args.endpoint))
    return 0


def build_parser():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("acquire", help="download and pin the raw sources (needs --yes-download)")
    a.add_argument("--raw-dir", default=DEFAULT_RAW_DIR)
    a.add_argument("--only", action="append", choices=sorted(SOURCES))
    a.add_argument("--dry-run", action="store_true", help="print the plan, no network")
    a.add_argument("--yes-download", action="store_true", help="explicit authorization to use the network")
    a.add_argument("--endpoint", default=WDQS_ENDPOINT, choices=WDQS_ENDPOINTS,
                   help="first-party Wikimedia WDQS endpoint (recorded in the sidecar)")
    b = sub.add_parser("build", help="build the pools from pinned raw files and the lexicons")
    b.add_argument("--raw-dir", default=None, help="default: <out-dir>/raw")
    b.add_argument("--out-dir", default=C.DEFAULT_OUT_DIR)
    b.add_argument("--attack-pool", default=None, help="attack_pool.jsonl with canonical_key (oracle exact rule)")
    b.add_argument("--prose-lang", default="eng")
    b.add_argument("--prose-min-len", type=int, default=PROSE_MIN_LEN)
    b.add_argument("--prose-max-len", type=int, default=PROSE_MAX_LEN)
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    return cmd_acquire(args) if args.cmd == "acquire" else cmd_build(args)


if __name__ == "__main__":
    sys.exit(main())
