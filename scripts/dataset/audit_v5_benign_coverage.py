"""
firewall-IA — V5 benign coverage audit of V4-clean TRAIN (audit v1).

DATA AUDIT + DIAGNOSTIC CONTRAST. It measures, on V4-clean TRAIN only, how the benign (ALLOW)
and attack (BLOCK) classes are represented along character, encoding, lexical, structural,
JSON, form/field and envelope dimensions. Every marker is counted four ways per class: rows,
unique texts, V4 generator groups (D16 / D54 provenance) and D54 components. A marker's benign
support follows D18: ABSENT (0 benign generator groups), SCARCE (1-29), SUPPORTED (>= 30).

It then computes the same markers on two CONSUMED development diagnostics (#57, #60) and
crosses them with the V4 decisions recorded there. The output states facts and correlations;
it never states a cause and never a rate (D42). It trains, fits or thresholds nothing.

Reads:
  datasets/v4_clean/train.jsonl            V4 TRAIN, SHA-256 checked against the manifest
  datasets/hybrid_analyzer_v2/hybrid_analyzer_v2.jsonl
                                           group ids only; a raw line is parsed ONLY if it
                                           carries "meta_v4_split": "train" (V4 eval =
                                           Analyzer INTERNAL TEST rows are skipped unparsed)
  reports/hybrid/v4-analyzer-disagreement-v1/records.jsonl   development data (#57)
  reports/hybrid/v4-analyzer-paired-dev-v1/records.jsonl     development data (#60)
Never opens datasets/v4_clean/eval.jsonl, External Test v1, docker/.lab-logs or any model.

    python3 scripts/dataset/audit_v5_benign_coverage.py \
        --out reports/v5/benign-coverage-audit-v1/results.json
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import unquote, unquote_plus

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO_ROOT, "data_plane"))

import request_features as rf  # noqa: E402  (stdlib only)

ANALYSIS_VERSION = "v5-benign-coverage-audit/v1"

V4_TRAIN = "datasets/v4_clean/train.jsonl"
V4_TRAIN_SHA256 = "4459f6861629279395acc57f99173d82bbda4dc8205a5f3bd08750dd528d262b"
HYBRID_V2 = "datasets/hybrid_analyzer_v2/hybrid_analyzer_v2.jsonl"
HYBRID_V2_SHA256 = "e8da8674435ed65057161bb4c74b41dc4aa1d8bf876b0327c53ecba7c0d99b75"
HYBRID_TRAIN_MARK = '"meta_v4_split": "train"'
DEV_SOURCES = {
    "dev57": "reports/hybrid/v4-analyzer-disagreement-v1/records.jsonl",
    "dev60": "reports/hybrid/v4-analyzer-paired-dev-v1/records.jsonl",
}

MIN_GROUPS = 30  # D18 support rule, applied to benign V4 generator groups

# Paths this audit must never open (External Test v1, its captures, and V4 eval, which is the
# Analyzer's INTERNAL TEST, closed after its second look, D54).
_FORBIDDEN = ("datasets/external_v1", "reports/external", "docker/.lab-logs",
              "datasets/v4_clean/eval.jsonl")


def guarded_path(rel_or_abs: str) -> str:
    """Absolute path of an input, refusing every forbidden location."""
    path = os.path.realpath(rel_or_abs if os.path.isabs(rel_or_abs)
                            else os.path.join(REPO_ROOT, rel_or_abs))
    for forbidden in _FORBIDDEN:
        f = os.path.realpath(os.path.join(REPO_ROOT, forbidden))
        if path == f or path.startswith(f + os.sep):
            raise PermissionError(f"refusing to open a forbidden input: {forbidden}")
    return path


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(guarded_path(path), "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ── request parsing (same partition rules as request_features.extract_features) ────────────
@dataclass(frozen=True)
class Request:
    method: str
    path: str
    query: str
    headers: tuple          # ((lowercase name, value), ...)
    body: str
    content_type: str       # media type of the first Content-Type header, lowercase


def split_request(text: str) -> Request:
    head, _, body = text.partition("\n\n")
    request_line, *header_lines = head.split("\n")
    method, _, rest = request_line.partition(" ")
    target = rest.rpartition(" ")[0] if " " in rest else rest
    path, _, query = target.partition("?")
    headers = []
    for line in header_lines:
        name, _, value = line.partition(":")
        if name.strip():
            headers.append((name.strip().lower(), value.strip()))
    content_type = ""
    for name, value in headers:
        if name == "content-type":
            content_type = value.split(";")[0].strip().lower()
            break
    return Request(method, path, query, tuple(headers), body, content_type)


_PCT = re.compile(r"%[0-9A-Fa-f]{2}")


def decode_layers(s: str, form: bool = False, max_layers: int = 3) -> tuple[str, int]:
    """Iteratively percent-decode `s`. Returns (decoded, percent_layers), where
    percent_layers counts the passes that decoded at least one %XX triplet (>= 2 means
    double encoding). With form=True the first pass also maps '+' to a space
    (application/x-www-form-urlencoded); later passes never do. Invalid UTF-8 becomes U+FFFD."""
    cur, layers = s, 0
    for i in range(max_layers):
        had_pct = bool(_PCT.search(cur))
        if i == 0 and form:
            nxt = unquote_plus(cur, errors="replace")
        elif had_pct:
            nxt = unquote(cur, errors="replace")
        else:
            break
        if had_pct:
            layers += 1
        if nxt == cur:
            break
        cur = nxt
    return cur, layers


def parse_pairs(s: str) -> list[tuple[str, str]]:
    """Raw (name, value) pairs of an `a=1&b=2` string. Empty segments are not parameters;
    `flag` without '=' is a parameter with an empty value (as request_features counts it)."""
    out = []
    for segment in s.split("&"):
        if segment:
            name, _, value = segment.partition("=")
            out.append((name, value))
    return out


_FORM_SEGMENT = re.compile(r"[^=&\s]+=[^&]*")


def body_syntax(body: str) -> tuple[str, object]:
    """Classify a body by its syntax, independently of the declared Content-Type (V4-clean
    randomizes Content-Type, D1). Returns (kind, parsed): kind is none | json_object |
    json_array | json_scalar | form_pairs | xml | other; parsed is the JSON value (with
    duplicate-key detection) or the raw pairs, else None."""
    stripped = body.strip()
    if not stripped:
        return "none", None
    if stripped[0] in "{[":
        try:
            value = json.loads(stripped, object_pairs_hook=_JsonObject)
        except ValueError:
            return "other", None
        return ("json_object" if isinstance(value, dict)
                else "json_array" if isinstance(value, list) else "json_scalar"), value
    if stripped.startswith("<"):
        return "xml", None
    segments = [seg for seg in body.split("&") if seg]
    if segments and all(_FORM_SEGMENT.fullmatch(seg) for seg in segments):
        return "form_pairs", parse_pairs(body)
    return "other", None


class _JsonObject(dict):
    """dict that remembers whether the source object repeated a key."""
    duplicate_keys = False

    def __init__(self, pairs):
        super().__init__()
        for k, v in pairs:
            if k in self:
                self.duplicate_keys = True
            self[k] = v


def json_profile(value) -> dict:
    """Structural description of a parsed JSON value (top level + all leaves)."""
    prof = {"top_keys": len(value) if isinstance(value, dict) else None,
            "nested_object": False, "array_inside": False, "number": False, "bool": False,
            "null": False, "string": False, "duplicate_keys": False, "depth": 0,
            "strings": []}

    def walk(v, depth, top):
        prof["depth"] = max(prof["depth"], depth)
        if isinstance(v, dict):
            if not top:
                prof["nested_object"] = True
            if getattr(v, "duplicate_keys", False):
                prof["duplicate_keys"] = True
            for item in v.values():
                walk(item, depth + 1, False)
        elif isinstance(v, list):
            if not top:
                prof["array_inside"] = True
            for item in v:
                walk(item, depth + 1, False)
        elif isinstance(v, bool):
            prof["bool"] = True
        elif isinstance(v, (int, float)):
            prof["number"] = True
        elif v is None:
            prof["null"] = True
        else:
            prof["string"] = True
            prof["strings"].append(str(v))

    walk(value, 1 if isinstance(value, (dict, list)) else 0, True)
    prof["depth"] = max(prof["depth"] - 1, 0) if isinstance(value, (dict, list)) else 0
    return prof


# ── lexical matching ──────────────────────────────────────────────────────────────────────
LEXICAL_TERMS = (
    # requested by the audit brief
    "select", "union", "and", "or", "from", "drop", "insert", "update", "delete", "admin",
    "root", "script", "localhost", "file", "url", "callback", "redirect",
    # added because they are frequent in V4-clean attack payloads and ordinary in English /
    # web vocabulary (justified by the data, not by assumption of attack meaning)
    "where", "table", "null", "sleep", "exec", "alert", "include", "http", "https", "etc",
    "passwd", "javascript", "cat", "echo", "ping", "eval", "onerror", "order", "the", "please",
    "call", "match",
)


def term_regex(term: str) -> re.Pattern:
    """Case-insensitive whole-token match: the term may not touch a letter or digit."""
    return re.compile(r"(?<![a-z0-9])" + re.escape(term) + r"(?![a-z0-9])", re.IGNORECASE)


_TERM_RES = {t: term_regex(t) for t in LEXICAL_TERMS}
_WORD = re.compile(r"[^\W\d_]{2,}")


def is_free_text(value: str) -> bool:
    """A value that reads as human text: at least three alphabetic words of length >= 2
    separated by whitespace."""
    return len(value.split()) >= 3 and len(_WORD.findall(value)) >= 3


# ── field-name classes (names are lowercased; substring match on purpose) ─────────────────
FIELD_CLASSES = {
    "username": ("user", "login", "uname", "nick", "account"),
    "password": ("pass", "pwd", "contrase", "clave"),
    "email": ("mail",),
    "address": ("addr", "direcc", "street", "calle", "city", "ciudad", "zip", "postal",
                "provinc", "country", "pais"),
    "free_text_name": ("comment", "message", "msg", "note", "body", "text", "title", "subject",
                       "descr", "content", "feedback", "review", "bio"),
    "payment": ("card", "tarjeta", "ntc", "cvv", "iban"),
    "security_sensitive_name": ("cmd", "exec", "file", "path", "url", "uri", "redirect",
                                "callback", "return", "next", "dest", "target", "template",
                                "tpl", "include", "host", "domain", "src"),
}


def field_classes(name: str) -> set[str]:
    n = name.lower()
    return {cls for cls, keys in FIELD_CLASSES.items() if any(k in n for k in keys)}


# ── marker extraction ─────────────────────────────────────────────────────────────────────
CONTENT_CHARS = ("'", '"', "#", "!", ";", "|", "\\", "`", "<", ">", "{", "}", "(", ")",
                 "..", "$", "*", "~", "[", "]")
VALUE_CHARS = ("/", "&", "=", "%", ":", "@", ",", "+", "?")
RAW_TRIPLETS = ("%27", "%22", "%23", "%21", "%2F", "%2E", "%3C", "%3B", "%7C", "%00", "%0A",
                "%0D", "%20", "%25")
_URL_VALUE = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE)
_PATH_VALUE = re.compile(r"^(\.{0,2}/|[\w.\-]+/[\w.\-/]+)")
_LOOPBACK = re.compile(r"^(localhost|127(\.\d{1,3}){3}|\[?::1\]?)$", re.IGNORECASE)
_IP_LITERAL = re.compile(r"^(\d{1,3}(\.\d{1,3}){3}|\[[0-9a-f:]+\])$", re.IGNORECASE)
_PUNCT = re.compile(r"[^\w\s\-.@]")
_INTERNAL_ADDR = re.compile(r"(?<![\d.])(127(\.\d{1,3}){3}|0\.0\.0\.0|169\.254(\.\d{1,3}){2})"
                            r"(?![\d])|\[::1\]")
ENVELOPE_HEADERS = ("cookie", "authorization", "origin", "referer", "proxy-connection",
                    "connection", "accept", "accept-language", "accept-encoding",
                    "content-length", "x-forwarded-for", "x-requested-with",
                    "transfer-encoding")


def bucket(n: int, edges=(0, 1, 2, 3, 4, 5), top: str = "6+") -> str:
    return str(n) if n in edges else top


def host_parts(host: str) -> tuple[str, str]:
    if host.startswith("["):
        name, _, rest = host[1:].partition("]")
        return name, rest[1:] if rest.startswith(":") else ""
    name, _, port = host.rpartition(":") if host.count(":") == 1 else (host, "", "")
    return (name, port) if name else (host, "")


def ua_family(ua: str | None) -> str:
    if ua is None:
        return "absent"
    u = ua.lower()
    for fam, keys in (("curl", ("curl/",)), ("wget", ("wget",)),
                      ("python", ("python", "httpx", "aiohttp", "urllib")),
                      ("mobile_app", ("mobileapp",)), ("browser", ("mozilla",))):
        if any(k in u for k in keys):
            return fam
    return "other"


def extract_markers(text: str) -> dict:
    """All audit markers of one D1 request text. Returns {"markers": set[str], "values":
    [...decoded values...]}. Marker names are '<dimension>:<name>'. Content and value markers
    never read headers; envelope markers read only headers."""
    req = split_request(text)
    markers: set[str] = set()

    # values: query pairs, then the body by its syntax
    query_pairs = parse_pairs(req.query)
    kind, parsed = body_syntax(req.body)
    body_pairs = parsed if kind == "form_pairs" else []
    names, values = [], []
    pct_layers = 0
    for name, value in query_pairs + body_pairs:
        dn, ln = decode_layers(name, form=True)
        dv, lv = decode_layers(value, form=True)
        names.append(dn)
        values.append(dv)
        pct_layers = max(pct_layers, ln, lv)
    jp = None
    if kind.startswith("json"):
        jp = json_profile(parsed)
        values.extend(jp["strings"])
    elif kind in ("xml", "other"):
        dv, lv = decode_layers(req.body)
        values.append(dv)
        pct_layers = max(pct_layers, lv)
    dpath, lp = decode_layers(req.path)
    pct_layers = max(pct_layers, lp)
    content = "\n".join([dpath, *values])
    joined_values = "\n".join(values)

    # characters (decoded content = path + values; values only for separators)
    for ch in CONTENT_CHARS:
        if ch in content:
            markers.add(f"char:{ch}")
    for ch in VALUE_CHARS:
        if ch in joined_values:
            markers.add(f"value_char:{ch}")
    if any(ord(c) > 127 for c in content):
        markers.add("char:non_ascii_decoded")

    # encoding (raw, undecoded surface)
    raw = req.path + "?" + req.query + "\n" + req.body
    if _PCT.search(raw):
        markers.add("encoding:any_pct_triplet")
    if _PCT.search(req.path):
        markers.add("encoding:pct_in_path")
    if _PCT.search(req.query):
        markers.add("encoding:pct_in_query")
    if _PCT.search(req.body):
        markers.add("encoding:pct_in_body")
    if pct_layers >= 2:
        markers.add("encoding:double_or_more")
    if "+" in req.query or (kind == "form_pairs" and "+" in req.body):
        markers.add("encoding:plus_in_query_or_form")
    upper_raw = raw.upper()
    for trip in RAW_TRIPLETS:
        if trip in upper_raw:
            markers.add(f"encoding:{trip}")
    if any(ord(c) > 127 for c in raw):
        markers.add("encoding:raw_non_ascii")

    # lexical (decoded content; whole-token, case-insensitive)
    for term, rx in _TERM_RES.items():
        if rx.search(content):
            markers.add(f"lexical:{term}")
    if any(is_free_text(v) for v in values):
        markers.add("lexical:free_text_value")
    # internal / loopback address literals anywhere in the decoded content
    if _INTERNAL_ADDR.search(content):
        markers.add("lexical:internal_address_literal")
    # the same literal anywhere in the whole text, headers included (position-agnostic)
    if _INTERNAL_ADDR.search(text):
        markers.add("anywhere:internal_address_literal")

    # structure
    f = rf.extract_features(text)
    markers.add(f"structure:method={req.method}")
    markers.add(f"structure:declared_ct={req.content_type or 'none'}")
    markers.add(f"structure:body_syntax={kind}")
    declared_json = req.content_type == "application/json" or req.content_type.endswith("+json")
    if (req.body.strip() and
            ((declared_json and not kind.startswith("json"))
             or (req.content_type == rf.FORM_MEDIA_TYPE and kind != "form_pairs")
             or ("xml" in req.content_type and kind != "xml"))):
        markers.add("structure:declared_ct_body_mismatch")
    n_body = len(body_pairs) if kind == "form_pairs" else (
        len(parsed) if isinstance(parsed, dict) else 0)
    markers.add(f"structure:query_params={bucket(len(query_pairs))}")
    markers.add(f"structure:body_params={bucket(n_body)}")
    markers.add(f"structure:total_params={bucket(len(query_pairs) + n_body)}")
    markers.add(f"structure:rf_total_param_count={bucket(f.total_param_count)}")
    if f.repeated_param_name_count:
        markers.add("structure:repeated_param_names")
    if req.query and req.body.strip():
        markers.add("structure:query_and_body")
    markers.add(f"structure:path_depth={bucket(f.path_depth)}")
    if re.search(r"\.[A-Za-z0-9]{1,5}$", req.path):
        markers.add("structure:path_has_extension")
    if any(_URL_VALUE.match(v.strip()) for v in values):
        markers.add("structure:url_valued_param")
    if any(_PATH_VALUE.match(v.strip()) and not _URL_VALUE.match(v.strip()) for v in values):
        markers.add("structure:path_valued_param")
    if any(v.isdigit() for v in values):
        markers.add("structure:numeric_value")
    if any(re.search(r"[A-Za-z]", v) and re.search(r"\d", v) for v in values):
        markers.add("structure:alnum_mixed_value")
    if any(" " in v for v in values):
        markers.add("structure:value_with_space")
    if any(len(v) > 64 for v in values):
        markers.add("structure:long_value_gt64")

    # JSON
    if jp is not None:
        if jp["top_keys"] is not None:
            markers.add(f"json:top_keys={bucket(jp['top_keys'], (0, 1, 2, 3, 4), '5+')}")
        markers.add(f"json:depth={bucket(jp['depth'], (0, 1, 2), '3+')}")
        for key in ("nested_object", "array_inside", "number", "bool", "null", "string",
                    "duplicate_keys"):
            if jp[key]:
                markers.add(f"json:{key}")
        if kind == "json_array":
            markers.add("json:top_level_array")
        if any(_URL_VALUE.match(s.strip()) for s in jp["strings"]):
            markers.add("json:url_string")
        if any(is_free_text(s) for s in jp["strings"]):
            markers.add("json:free_text_string")

    # forms and field semantics (query + form body + JSON top-level keys)
    if kind == "form_pairs":
        markers.add(f"form:body_fields={bucket(len(body_pairs))}")
        if any(_PUNCT.search(v) for v in values[len(query_pairs):]):
            markers.add("form:punctuation_in_body_value")
    n_pairs = len(query_pairs) + len(body_pairs)
    pairs = list(zip(names[:n_pairs], values[:n_pairs]))
    if kind == "json_object":
        pairs += [(str(k), v if isinstance(v, str) else json.dumps(v))
                  for k, v in parsed.items()]
    for name, value in pairs:
        for cls in field_classes(name):
            markers.add(f"field:{cls}")
            if cls == "password" and value:
                if re.search(r"[^A-Za-z0-9]", value):
                    markers.add("field:password_value_has_symbol")
                if re.search(r"[A-Za-z]", value) and re.search(r"\d", value):
                    markers.add("field:password_value_alnum_mixed")
            if cls == "address" and value and re.search(r"\d", value) and " " in value:
                markers.add("field:address_value_number_and_words")
            if cls == "free_text_name" and value and is_free_text(value):
                markers.add("field:free_text_field_with_free_text")
            if cls == "free_text_name" and value and _PUNCT.search(value):
                markers.add("field:free_text_field_with_punctuation")

    # envelope (audit only; D44: never an ML feature)
    hdr = dict(req.headers)
    host = hdr.get("host")
    if host is None:
        markers.add("envelope:host_absent")
    else:
        hname, port = host_parts(host)
        if _LOOPBACK.match(hname) or hname in ("::1",):
            markers.add("envelope:host_loopback")
            markers.add("envelope:host_loopback_" + ("name" if hname.lower() == "localhost"
                                                     else "ip"))
        if _IP_LITERAL.match(hname) or hname == "::1":
            markers.add("envelope:host_ip_literal")
        if not port:
            port_label = "none"
        elif port in ("80", "443", "8000", "8080"):
            port_label = port
        else:
            port_label = "other"
        markers.add(f"envelope:host_port={port_label}")
    markers.add(f"envelope:ua_family={ua_family(hdr.get('user-agent'))}")
    for name in ENVELOPE_HEADERS:
        if name in hdr:
            markers.add(f"envelope:has_{name}")
    markers.add(f"envelope:header_count={bucket(len(req.headers), (0, 1, 2, 3, 4, 5), '6+')}")

    return {"markers": markers, "values": values}


def dimension(marker: str) -> str:
    return marker.split(":", 1)[0]


# ── aggregation over TRAIN ────────────────────────────────────────────────────────────────
def support_status(benign_groups: int, min_groups: int = MIN_GROUPS) -> str:
    if benign_groups == 0:
        return "ABSENT"
    return "SCARCE" if benign_groups < min_groups else "SUPPORTED"


def aggregate(rows) -> dict:
    """rows: iterable of dicts with keys text, label (ALLOW|BLOCK), gen_group, d54_group,
    source. Returns per-marker counts by class and the totals. Order-independent."""
    acc = defaultdict(lambda: {"ALLOW": [0, set(), set(), set()], "BLOCK": [0, set(), set(), set()]})
    benign_src = defaultdict(lambda: defaultdict(set))
    totals = {"ALLOW": [0, set(), set(), set()], "BLOCK": [0, set(), set(), set()]}
    for row in rows:
        th = text_sha256(row["text"])
        label = row["label"]
        t = totals[label]
        t[0] += 1
        t[1].add(th)
        t[2].add(row["gen_group"])
        t[3].add(row["d54_group"])
        for m in extract_markers(row["text"])["markers"]:
            a = acc[m][label]
            a[0] += 1
            a[1].add(th)
            a[2].add(row["gen_group"])
            a[3].add(row["d54_group"])
            if label == "ALLOW":
                benign_src[m][row["source"]].add(row["gen_group"])
    markers = {}
    for m in sorted(acc):
        entry = {}
        for label in ("ALLOW", "BLOCK"):
            rows_n, texts, gens, d54s = acc[m][label]
            entry[label] = {"rows": rows_n, "unique_texts": len(texts),
                            "generator_groups": len(gens), "d54_groups": len(d54s)}
        bg, ag = entry["ALLOW"]["generator_groups"], entry["BLOCK"]["generator_groups"]
        entry["benign_generator_groups_by_source"] = {
            s: len(g) for s, g in sorted(benign_src[m].items())}
        entry["benign_support"] = support_status(bg)
        entry["attack_support"] = support_status(ag)
        entry["benign_group_share"] = round(bg / (bg + ag), 4) if bg + ag else None
        markers[m] = entry
    total = {label: {"rows": v[0], "unique_texts": len(v[1]), "generator_groups": len(v[2]),
                     "d54_groups": len(v[3])} for label, v in totals.items()}
    return {"totals": total, "markers": markers}


def load_train_rows():
    """V4 TRAIN rows joined with their group ids. Hybrid rows of V4 eval are skipped by a
    substring test on the raw line, before any parsing."""
    with open(guarded_path(V4_TRAIN), encoding="utf-8") as f:
        v4 = [json.loads(line) for line in f if line.strip()]
    groups = {}
    with open(guarded_path(HYBRID_V2), encoding="utf-8") as f:
        for raw in f:
            if HYBRID_TRAIN_MARK not in raw:
                continue
            r = json.loads(raw)
            if r["meta_v4_split"] != "train":
                continue
            groups[r["meta_v4_line"]] = r
    if sorted(groups) != list(range(len(v4))):
        raise ValueError("hybrid_analyzer_v2 does not cover every V4 train line exactly once")
    rows = []
    for i, row in enumerate(v4):
        label = row["output"].split(" |")[0].strip()
        g = groups[i]
        if g["meta_v4_decision"] != label:
            raise ValueError(f"label mismatch at V4 train line {i}")
        rows.append({"text": row["input"], "label": label,
                     "gen_group": g["meta_generator_group_id"], "d54_group": g["meta_group_id"],
                     "source": g["meta_generator_source"]})
    return rows


# ── development contrast (#57, #60: consumed diagnostic data) ─────────────────────────────
def load_dev_units(path: str, source: str) -> list[dict]:
    """Unique benign and attack texts of one development set, with V4's decision per text.
    A text recorded with two different V4 decisions is kept and flagged."""
    by_text = {}
    with open(guarded_path(path), encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            r = json.loads(line)
            th = text_sha256(r["text"])
            u = by_text.setdefault(th, {"source": source, "text_sha256": th, "text": r["text"],
                                        "label": r["label"], "v4_decisions": set(),
                                        "v4_reasons": set(),
                                        "subset": r.get("source") or r.get("placement")})
            u["v4_decisions"].add(r["v4_decision"])
            u["v4_reasons"].add(r.get("v4_reason") or "")
    out = []
    for u in by_text.values():
        u["v4_consistent"] = len(u["v4_decisions"]) == 1
        u["v4_decision"] = sorted(u["v4_decisions"])[0] if u["v4_consistent"] else "MIXED"
        out.append(u)
    return sorted(out, key=lambda u: u["text_sha256"])


def contrast(dev_units: list[dict], train_markers: dict) -> dict:
    """Cross each development benign text's markers with TRAIN benign support."""
    def uncovered(ms, dims):
        return sorted(m for m in ms if dimension(m) in dims
                      and train_markers.get(m, {}).get("benign_support", "ABSENT") != "SUPPORTED")

    content_dims = {"char", "value_char", "encoding", "lexical", "structure", "json", "form",
                    "field"}
    envelope_dims = {"envelope", "anywhere"}
    per_marker = defaultdict(Counter)
    by_bucket = defaultdict(Counter)
    by_env_bucket = defaultdict(Counter)
    marker_sets = defaultdict(Counter)
    set_examples = defaultdict(list)
    counter_examples_block, counter_examples_allow = [], []
    benign = [u for u in dev_units if u["label"] == "ALLOW"]
    for u in benign:
        ms = extract_markers(u["text"])["markers"]
        unc_c, unc_e = uncovered(ms, content_dims), uncovered(ms, envelope_dims)
        dec = u["v4_decision"]
        for m in unc_c + unc_e:
            per_marker[m][dec] += 1
        by_bucket[bucket(len(unc_c), (0, 1, 2), "3+")][dec] += 1
        by_env_bucket[bucket(len(unc_e), (0, 1), "2+")][dec] += 1
        content_set = tuple(sorted(m for m in ms if dimension(m) in content_dims))
        marker_sets[content_set][dec] += 1
        set_examples[content_set].append({"v4": dec, "request_line": u["text"].split("\n", 1)[0],
                                          "body": u["text"].partition("\n\n")[2][:120]})
        first_line = u["text"].split("\n", 1)[0][:100]
        if dec == "BLOCK" and not unc_c:
            counter_examples_block.append({"source": u["source"], "text_sha256": u["text_sha256"],
                                           "first_line": first_line,
                                           "uncovered_envelope": unc_e,
                                           "v4_reasons": sorted(u["v4_reasons"])})
        if dec == "ALLOW" and len(unc_c) >= 3:
            counter_examples_allow.append({"source": u["source"], "text_sha256": u["text_sha256"],
                                           "first_line": first_line,
                                           "uncovered_content": unc_c})
    mixed_sets = [dict(c) for c in marker_sets.values() if len(c) > 1]
    mixed_detail = sorted(
        ({"v4": dict(c), "examples": sorted(set_examples[k], key=lambda e: (e["v4"],
                                                                           e["request_line"],
                                                                           e["body"]))[:8]}
         for k, c in marker_sets.items() if len(c) > 1),
        key=lambda d: (-sum(d["v4"].values()), d["examples"][0]["request_line"]))
    return {
        "benign_unique_texts": len(benign),
        "benign_v4": dict(Counter(u["v4_decision"] for u in benign)),
        "inconsistent_v4_texts": sum(1 for u in dev_units if not u["v4_consistent"]),
        "by_uncovered_content_markers": {k: dict(v) for k, v in sorted(by_bucket.items())},
        "by_uncovered_envelope_markers": {k: dict(v) for k, v in sorted(by_env_bucket.items())},
        "per_uncovered_marker": {m: {"ALLOW": c["ALLOW"], "BLOCK": c["BLOCK"],
                                     "train_benign_support":
                                         train_markers.get(m, {}).get("benign_support", "ABSENT"),
                                     "train_benign_generator_groups":
                                         train_markers.get(m, {}).get("ALLOW", {}).get(
                                             "generator_groups", 0),
                                     "train_attack_generator_groups":
                                         train_markers.get(m, {}).get("BLOCK", {}).get(
                                             "generator_groups", 0)}
                                 for m, c in sorted(per_marker.items())},
        "content_marker_sets": len(marker_sets),
        "content_marker_sets_with_mixed_v4_decisions": len(mixed_sets),
        "texts_in_mixed_sets": sum(sum(c.values()) for c in mixed_sets),
        "mixed_sets_detail": mixed_detail,
        "block_with_zero_uncovered_content_markers": counter_examples_block,
        "allow_with_three_or_more_uncovered_content_markers": len(counter_examples_allow),
        "allow_with_three_or_more_uncovered_examples": counter_examples_allow[:15],
    }


def git_state() -> dict:
    try:
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True,
                              text=True, check=True).stdout.strip()
        branch = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=REPO_ROOT,
                                capture_output=True, text=True, check=True).stdout.strip()
        return {"base_commit": head, "branch": branch}
    except (OSError, subprocess.CalledProcessError):
        return {"base_commit": None, "branch": None}


def run(out_path: str) -> dict:
    for path, expected in ((V4_TRAIN, V4_TRAIN_SHA256), (HYBRID_V2, HYBRID_V2_SHA256)):
        actual = sha256_file(path)
        if actual != expected:
            raise ValueError(f"{path}: SHA-256 {actual} != expected {expected}")
    rows = load_train_rows()
    agg = aggregate(rows)
    dev = {}
    for name, path in DEV_SOURCES.items():
        units = load_dev_units(path, name)
        dev[name] = {"input": path, "sha256": sha256_file(path), "unique_texts": len(units),
                     **contrast(units, agg["markers"])}
    status_counts = defaultdict(Counter)
    for m, e in agg["markers"].items():
        status_counts[dimension(m)][e["benign_support"]] += 1
    result = {
        "analysis_version": ANALYSIS_VERSION,
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        **git_state(),
        "inputs": {
            "v4_train": {"path": V4_TRAIN, "sha256": V4_TRAIN_SHA256, "rows": len(rows)},
            "hybrid_analyzer_v2": {"path": HYBRID_V2, "sha256": HYBRID_V2_SHA256,
                                   "used": "group ids of V4-train rows only"},
            "not_opened": list(_FORBIDDEN),
        },
        "support_rule": {"unit": "benign V4 generator groups (D16/D54 provenance)",
                         "ABSENT": "0", "SCARCE": f"1-{MIN_GROUPS - 1}",
                         "SUPPORTED": f">= {MIN_GROUPS} (D18)"},
        "totals": agg["totals"],
        "benign_rows_by_source": dict(Counter(r["source"] for r in rows if r["label"] == "ALLOW")),
        "benign_support_status_by_dimension": {d: dict(c) for d, c in sorted(status_counts.items())},
        "markers": agg["markers"],
        "dev_contrast": dev,
        "non_claims": [
            "Counts on V4-clean TRAIN describe the training distribution; they are not rates.",
            "Development counts (#57, #60) are diagnostic counts on author-chosen compositions, "
            "never FPR / recall / prevalence (D42).",
            "A marker co-occurring with V4 BLOCK decisions is a correlation, not a cause.",
            "Envelope markers are audited only; D44 forbids them as model features.",
        ],
    }
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=1, sort_keys=True, ensure_ascii=False)
        f.write("\n")
    return result


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--out", default="reports/v5/benign-coverage-audit-v1/results.json")
    args = p.parse_args(argv)
    out = args.out if os.path.isabs(args.out) else os.path.join(REPO_ROOT, args.out)
    res = run(out)
    t = res["totals"]
    print(f"V4 TRAIN: ALLOW {t['ALLOW']} | BLOCK {t['BLOCK']}")
    print("benign support by dimension:", json.dumps(res["benign_support_status_by_dimension"]))
    print("wrote", out)


if __name__ == "__main__":
    main()
