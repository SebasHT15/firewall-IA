#!/usr/bin/env python3
"""V5 stage 4 — HTTP template catalogue, typed slots and the template audit (issue #74).

Implements, on top of the stage-3 identities (`v5_identities`, D64), the catalogue side of
V5-DATA-SPEC-r3 (FROZEN, D62):

  §4.1  carrier symmetry: one carrier per template; benign rows and twins share the template
  §4.2  typed slots and the slot -> category compatibility table (BINDING, D58)
  §4.6  template_id (I-4 skeleton: method, carrier, media type, path skeleton, ordered positional
        slots; field names are never part of it) and declared struct_cluster_id; the template
        audit (Jaccard >= 0.60 over `template_tokens`); undeclared same-stratum near-duplicates and
        any cross-carrier near-duplicate (I-16, D-2) stop the build — never resolved by relaxing
        the audit, never by merging across carriers

Carriers (= carrier strata of the split config): path, query, form, json, text (§2.2 media types:
no body, application/x-www-form-urlencoded, application/json, text/plain).

Stdlib only, plus the stage-3 identity module. Nothing here renders, labels or assigns a split.

CLI
  python3 scripts/dataset/v5_catalog.py audit [--catalog P] [--lexicon P] [--out JSON] [--summary MD]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import v5_identities as I  # noqa: E402

CATALOG_SCHEMA = "v5-template-catalog/v1"
LEXICON_SCHEMA = "v5-field-names/v1"
AUDIT_SCHEMA = "v5-template-audit/v1"
DEFAULT_CATALOG = os.path.join(HERE, "v5_templates", "catalog_v1.json")
DEFAULT_LEXICON = os.path.join(HERE, "v5_templates", "field_names_v1.json")

CARRIERS = ("path", "query", "form", "json", "text")
CARRIER_MEDIA = {"path": None, "query": None, "form": "application/x-www-form-urlencoded",
                 "json": "application/json", "text": "text/plain"}
CARRIER_METHODS = {"path": ("GET", "DELETE"), "query": ("GET", "DELETE"),
                   "form": ("POST", "PUT", "PATCH"), "json": ("POST", "PUT", "PATCH"), "text": ("POST", "PUT")}

# Stage-2 category vocabulary (`dedup_scope`; traversal + file inclusion merged by D49).
SQLI, XSS, CMDI, SSTI = "SQL Injection", "XSS Injection", "Command Injection", "Server Side Template Injection"
NOSQL, XPATH, CRLF = "NoSQL Injection", "XPath Injection", "CRLF Injection"
SSRF, REDIRECT, PATH_FILE = "Server Side Request Forgery", "Open Redirect", "path_file_access"
INJECTION_CATEGORIES = (SQLI, XSS, CMDI, SSTI, NOSQL, XPATH, CRLF, PATH_FILE)
POLICY_CATEGORIES = (SSRF, REDIRECT)            # BLOCK only through a POL-* class (§4.3)

# §4.2 slot compatibility (APPROVED D58; the table itself is binding, placement shares are PROPOSED).
ATTACK_SLOT_TYPES = ("free_string", "json_leaf", "url", "path_file")
SCALAR_SLOT_TYPES = ("int", "number", "bool", "enum", "token")
SLOT_TYPES = ATTACK_SLOT_TYPES + SCALAR_SLOT_TYPES
SLOT_COMPATIBILITY = {
    "free_string": frozenset({SQLI, XSS, CMDI, SSTI, NOSQL, XPATH, CRLF}),
    "url": frozenset({SSRF, REDIRECT}),
    "path_file": frozenset({PATH_FILE}),
    "json_leaf": frozenset({NOSQL, SQLI, XSS, SSTI}),
}
# Benign value pools each attackable slot type may draw from. `names_family` is BLOCKED (#75) and is
# never listed: a pool that does not exist is never silently substituted.
SLOT_POOLS = {
    "free_string": ("names_given", "streets", "prose_en", "symbols", "passwords", "addr_data"),
    "json_leaf": ("names_given", "streets", "prose_en", "symbols", "passwords", "addr_data"),
    "url": ("urls_public", "urls_relative"),
    "path_file": ("rel_paths",),
}
# Which slot types may sit where. Attackable slots live only in the template's carrier; the path may
# hold typed scalars in any carrier, and attackable segments only in the `path` carrier.
LOCATION_TYPES = {"path": {"free_string", "path_file", "int", "token"},
                  "query": {"free_string", "url", "path_file", "int", "number", "bool", "enum", "token"},
                  "form": {"free_string", "url", "path_file", "int", "number", "bool", "enum", "token"},
                  "json": {"json_leaf", "url", "path_file", "int", "number", "bool", "enum", "token"},
                  "text": {"free_string"}}
NAMES_FOR_TYPE = {"free_string": "text", "json_leaf": "text", "url": "url", "path_file": "path", "int": "int",
                  "number": "number", "bool": "bool", "enum": "enum", "token": "token"}
_ID = re.compile(r"[a-z0-9][a-z0-9-]*\Z")
_SEGMENT = re.compile(r"[a-z0-9][a-z0-9._-]*\Z")
_CHOICE = re.compile(r"[A-Za-z0-9_-]+\Z")
_ARRAY = "[]"


class CatalogError(ValueError):
    """The catalogue or the lexicon is malformed (refused before anything is audited)."""


class CatalogStop(RuntimeError):
    """The template audit found a blocking problem (D60: the build reports it and stops)."""

    def __init__(self, findings):
        self.findings = sorted(findings, key=lambda f: json.dumps(f, sort_keys=True))
        super().__init__("; ".join(f"{f['code']}: {f['detail']}" for f in self.findings))


# ───────────────────────────── model ─────────────────────────────
@dataclass(frozen=True)
class Slot:
    slot_id: str                 # template-local: p0.. (path), s0.. (carrier, document order)
    location: str                # path | query | form | json | text
    key_path: tuple              # positional (ints / "[]"), never names; path slots: (segment index,)
    value_type: str
    names: str | None = None     # field-name list id, None for path / text / array elements
    pools: tuple = ()
    choices: tuple = ()

    @property
    def attackable(self) -> bool:
        return self.value_type in ATTACK_SLOT_TYPES

    @property
    def compatible_categories(self) -> frozenset:
        return SLOT_COMPATIBILITY.get(self.value_type, frozenset())


@dataclass(frozen=True)
class Node:
    """JSON body tree. kind: object | array | leaf. Object children carry a name site."""
    kind: str
    key_path: tuple
    children: tuple = ()
    slot: Slot | None = None
    names: str | None = None     # this node's own key name list when its parent is an object


@dataclass(frozen=True)
class Template:
    name: str
    struct_cluster_id: str
    carrier: str
    method: str
    media_type: str | None
    path: tuple                  # literal str segments and path Slots
    slots: tuple                 # every Slot, path slots first, then carrier slots in document order
    body: Node | None = None     # json only
    fields: tuple = ()           # query / form: carrier slots in order; text: the one body slot

    def skeleton(self) -> I.TemplateSkeleton:
        path = tuple(s if isinstance(s, str) else "{" + s.value_type + "}" for s in self.path)
        carrier_slots = tuple((s.key_path, s.value_type) for s in self.slots if s.location != "path")
        return I.TemplateSkeleton(self.method, self.carrier, self.media_type, path, carrier_slots)

    @property
    def template_id(self) -> str:
        return I.template_id(self.skeleton())

    @property
    def tokens(self) -> frozenset:
        return I.template_tokens(self.skeleton())

    @property
    def attack_slots(self) -> tuple:
        return tuple(s for s in self.slots if s.attackable)

    def name_sites(self) -> list:
        """(site key, names list id, parent key) for every keyed position, in document order.
        Names are unique per parent object; the generator draws them per pair."""
        out = []
        if self.carrier in ("query", "form"):
            out = [(s.key_path, s.names, ()) for s in self.fields]
        elif self.carrier == "json":
            def walk(n: Node):
                for c in n.children:
                    if n.kind == "object":
                        out.append((c.key_path, c.names, n.key_path))
                    walk(c)
            walk(self.body)
        return out


@dataclass(frozen=True)
class Catalog:
    templates: tuple
    lexicon: dict                # list id -> tuple of names
    sha256: str                  # catalogue file bytes
    lexicon_sha256: str
    path: str = ""
    lexicon_path: str = ""
    by_id: dict = field(default_factory=dict)

    def template(self, template_id: str) -> Template:
        return self.by_id[template_id]


# ───────────────────────────── parsing and validation ─────────────────────────────
def _sha(path: str) -> tuple:
    with open(path, "rb") as fh:
        data = fh.read()
    return data, hashlib.sha256(data).hexdigest()


def load_lexicon(path: str = DEFAULT_LEXICON) -> tuple:
    data, sha = _sha(path)
    obj = json.loads(data)
    return parse_lexicon(obj), sha


def parse_lexicon(obj) -> dict:
    if not isinstance(obj, dict) or obj.get("schema") != LEXICON_SCHEMA:
        raise CatalogError(f"lexicon schema must be {LEXICON_SCHEMA!r}")
    lists = obj.get("lists")
    if not isinstance(lists, dict) or not lists:
        raise CatalogError("lexicon needs non-empty `lists`")
    out = {}
    for k, names in lists.items():
        if not isinstance(names, list) or not names:
            raise CatalogError(f"lexicon list {k!r} is empty")
        for n in names:
            if not isinstance(n, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", n):
                raise CatalogError(f"lexicon list {k!r}: field name {n!r} must match [a-z][a-z0-9_]*")
        if len(set(names)) != len(names):
            raise CatalogError(f"lexicon list {k!r} has duplicates")
        out[k] = tuple(names)
    missing = sorted((set(NAMES_FOR_TYPE.values()) | {"object"}) - set(out))
    if missing:
        raise CatalogError(f"lexicon lacks lists {missing}")
    return out


def _slot(spec, sid, location, key_path, lexicon, named):
    if not isinstance(spec, dict) or "type" not in spec:
        raise CatalogError(f"slot {sid}: spec must be an object with `type`")
    extra = set(spec) - {"type", "names", "pools", "choices"}
    if extra:
        raise CatalogError(f"slot {sid}: unknown keys {sorted(extra)}")
    vt = spec["type"]
    if vt not in SLOT_TYPES:
        raise CatalogError(f"slot {sid}: unknown type {vt!r}")
    if vt not in LOCATION_TYPES[location]:
        raise CatalogError(f"slot {sid}: type {vt!r} is not allowed in the {location}")
    names = spec.get("names")
    if named:
        if names is None:
            raise CatalogError(f"slot {sid}: a keyed slot needs `names`")
        if names not in lexicon:
            raise CatalogError(f"slot {sid}: unknown field-name list {names!r}")
    elif names is not None:
        raise CatalogError(f"slot {sid}: an unkeyed slot (path, text, array element) takes no `names`")
    pools = tuple(spec.get("pools", SLOT_POOLS.get(vt, ())))
    if vt in ATTACK_SLOT_TYPES:
        if not pools or len(set(pools)) != len(pools) or not set(pools) <= set(SLOT_POOLS[vt]):
            raise CatalogError(f"slot {sid}: pools {list(pools)} must be a non-empty subset of {list(SLOT_POOLS[vt])}")
    elif "pools" in spec:
        raise CatalogError(f"slot {sid}: scalar type {vt!r} takes no pools")
    choices = tuple(spec.get("choices", ()))
    if vt == "enum":
        if len(choices) < 2 or len(set(choices)) != len(choices) or not all(
                isinstance(c, str) and _CHOICE.match(c) for c in choices):
            raise CatalogError(f"slot {sid}: enum needs >= 2 distinct [A-Za-z0-9_-] choices")
    elif choices:
        raise CatalogError(f"slot {sid}: only enum slots take choices")
    return Slot(sid, location, tuple(key_path), vt, names, pools, choices)


def _parse_json(spec, lexicon, counter):
    def node(s, kp, named, names=None):
        if not isinstance(s, dict):
            raise CatalogError("json node must be an object")
        kinds = [k for k in ("object", "array") if k in s]
        if len(kinds) > 1:
            raise CatalogError("json node has both object and array")
        if kinds:
            k = kinds[0]
            extra = set(s) - {k, "names"}
            if extra:
                raise CatalogError(f"json container: unknown keys {sorted(extra)}")
            own = s.get("names")
            if named and own not in lexicon:
                raise CatalogError(f"json container under an object needs a known `names`, got {own!r}")
            if not named and own is not None:
                raise CatalogError("json container in an array or at the root takes no `names`")
            items = s[k]
            if not isinstance(items, list) or not items:
                raise CatalogError(f"json {k} must have at least one child (no empty containers)")
            if k == "object":
                kids = tuple(node(c, kp + (i,), True) for i, c in enumerate(items))
            else:
                kids = tuple(node(c, kp + (_ARRAY, i), False) for i, c in enumerate(items))
            return Node(k, kp, kids, None, own)
        sid = f"s{counter[0]}"
        counter[0] += 1
        sl = _slot(s, sid, "json", kp, lexicon, named)
        return Node("leaf", kp, (), sl, sl.names)
    if not isinstance(spec, dict) or not ({"object", "array"} & set(spec)):
        raise CatalogError("json body root must be an object or an array")
    if "names" in spec:
        raise CatalogError("json root takes no `names`")
    return node(spec, (), False)


def _leaves(n: Node) -> list:
    if n.kind == "leaf":
        return [n.slot]
    return [s for c in n.children for s in _leaves(c)]


def parse_template(t, lexicon) -> Template:
    if not isinstance(t, dict):
        raise CatalogError("template must be an object")
    name = t.get("name")
    if not isinstance(name, str) or not _ID.match(name):
        raise CatalogError(f"template name {name!r} must match [a-z0-9][a-z0-9-]*")
    allowed = {"name", "cluster", "carrier", "method", "path", "fields", "json", "text"}
    extra = set(t) - allowed
    if extra:
        raise CatalogError(f"{name}: unknown keys {sorted(extra)}")
    cluster = t.get("cluster")
    if not isinstance(cluster, str) or not _ID.match(cluster):       # no '|' or NUL: row-RNG coordinate
        raise CatalogError(f"{name}: cluster {cluster!r} must match [a-z0-9][a-z0-9-]*")
    carrier = t.get("carrier")
    if carrier not in CARRIERS:
        raise CatalogError(f"{name}: carrier {carrier!r} not in {CARRIERS}")
    method = t.get("method")
    if method not in CARRIER_METHODS[carrier]:
        raise CatalogError(f"{name}: method {method!r} not allowed for carrier {carrier} {CARRIER_METHODS[carrier]}")
    body_keys = {"fields": ("query", "form"), "json": ("json",), "text": ("text",)}
    for k, carriers in body_keys.items():
        if (k in t) != (carrier in carriers):
            raise CatalogError(f"{name}: carrier {carrier} {'needs' if carrier in carriers else 'takes no'} `{k}`")
    raw_path = t.get("path")
    if not isinstance(raw_path, list) or not raw_path:
        raise CatalogError(f"{name}: path must be a non-empty list")
    path, slots, p = [], [], 0
    for i, seg in enumerate(raw_path):
        if isinstance(seg, str):
            if not _SEGMENT.match(seg):
                raise CatalogError(f"{name}: path segment {seg!r} must match [a-z0-9][a-z0-9._-]*")
            path.append(seg)
        else:
            sl = _slot(seg, f"p{p}", "path", (i,), lexicon, False)
            if sl.attackable and carrier != "path":
                raise CatalogError(f"{name}: attackable path slot outside the path carrier")
            p += 1
            path.append(sl)
            slots.append(sl)
    body, fields = None, ()
    if carrier in ("query", "form"):
        raw = t["fields"]
        if not isinstance(raw, list) or not raw:
            raise CatalogError(f"{name}: fields must be a non-empty list")
        fields = tuple(_slot(f, f"s{i}", carrier, (i,), lexicon, True) for i, f in enumerate(raw))
        slots += fields
    elif carrier == "json":
        body = _parse_json(t["json"], lexicon, [0])
        slots += _leaves(body)
    elif carrier == "text":
        fields = (_slot(t["text"], "s0", "text", (0,), lexicon, False),)
        slots += fields
    tpl = Template(name, cluster, carrier, method, CARRIER_MEDIA[carrier], tuple(path), tuple(slots), body, fields)
    if not tpl.attack_slots:
        raise CatalogError(f"{name}: no attackable slot (a template must host a twin)")
    if carrier == "path" and not any(s.attackable for s in tpl.path if not isinstance(s, str)):
        raise CatalogError(f"{name}: the path carrier needs an attackable path slot")
    per_parent = Counter((parent, names) for _, names, parent in tpl.name_sites())
    for (parent, names), n in per_parent.items():
        if n > len(lexicon[names]):
            raise CatalogError(f"{name}: {n} keys under {parent} draw from {names!r} with only {len(lexicon[names])} names")
    keyed = Counter(parent for _, _, parent in tpl.name_sites())
    for parent, n in keyed.items():
        pool = set().union(*(lexicon[nm] for _, nm, pr in tpl.name_sites() if pr == parent))
        if n > len(pool):
            raise CatalogError(f"{name}: object {parent} has {n} keys but only {len(pool)} distinct names")
    tpl.skeleton().as_obj()                  # positional key paths only (refuses names, I-4)
    return tpl


def parse_catalog(obj, lexicon) -> list:
    if not isinstance(obj, dict) or obj.get("schema") != CATALOG_SCHEMA:
        raise CatalogError(f"catalogue schema must be {CATALOG_SCHEMA!r}")
    raw = obj.get("templates")
    if not isinstance(raw, list) or not raw:
        raise CatalogError("catalogue needs a non-empty `templates` list")
    tpls, names, ids = [], set(), {}
    for t in raw:
        tpl = parse_template(t, lexicon)
        if tpl.name in names:
            raise CatalogError(f"template name {tpl.name!r} declared twice")
        names.add(tpl.name)
        tid = tpl.template_id
        if tid in ids:   # field names are excluded from the id: two templates differing only there are one structure
            raise CatalogError(f"templates {ids[tid]!r} and {tpl.name!r} have the same structural skeleton "
                               f"(template_id {tid[:16]}); field names never distinguish templates")
        ids[tid] = tpl.name
        tpls.append(tpl)
    return tpls


def load_catalog(path: str = DEFAULT_CATALOG, lexicon_path: str = DEFAULT_LEXICON) -> Catalog:
    lexicon, lsha = load_lexicon(lexicon_path)
    data, sha = _sha(path)
    tpls = parse_catalog(json.loads(data), lexicon)
    return Catalog(tuple(tpls), lexicon, sha, lsha, path, lexicon_path, {t.template_id: t for t in tpls})


def catalog_from_objects(obj, lexicon_obj) -> Catalog:
    """In-memory catalogue (tests and fixtures); hashes are over canonical JSON."""
    lexicon = parse_lexicon(lexicon_obj)
    tpls = parse_catalog(obj, lexicon)
    sha = hashlib.sha256(I.canonical_json(obj).encode()).hexdigest()
    lsha = hashlib.sha256(I.canonical_json(lexicon_obj).encode()).hexdigest()
    return Catalog(tuple(tpls), lexicon, sha, lsha, "", "", {t.template_id: t for t in tpls})


# ───────────────────────────── declarations and the template audit ─────────────────────────────
def template_decls(catalog: Catalog) -> list:
    """Stage-3 `TemplateDecl`s: carrier stratum = carrier; audit tokens = `template_tokens`."""
    return [I.TemplateDecl(t.template_id, t.struct_cluster_id, t.carrier, t.tokens) for t in catalog.templates]


def audit(catalog: Catalog, cluster_merges=()) -> dict:
    """The template audit (§4.6). Blocking findings:
      UNDECLARED_NEAR_DUPLICATE  Jaccard >= 0.60 between templates of different clusters of ONE carrier:
                                 the fix is a declared cluster merge (never split; the proposal is listed)
      I16_CROSS_CARRIER          Jaccard >= 0.60 between templates of different carriers: a merge would make
                                 a cluster span two strata, which D-2 refuses; no relaxation exists (D64 §5)
      CLUSTER_SPANS_STRATA       a declared merge joins clusters of two carriers (D-2)
    Non-blocking: NOT_EVALUABLE_STRUCTURE (a carrier with < 3 clusters, §4.6 step 1)."""
    by_id = {t.template_id: t for t in catalog.templates}
    findings, info = [], []
    tokens = {t.template_id: t.tokens for t in catalog.templates}
    pairs = I.near_duplicate_pairs(tokens)
    try:
        table = I.resolve_clusters(template_decls(catalog), cluster_merges)
        resolved = table.template_cluster
    except I.IdentityError as e:
        findings.append({"code": "CLUSTER_SPANS_STRATA" if "spans strata" in str(e) else "CLUSTER_DECLARATION",
                         "detail": str(e)})
        table, resolved = None, {t.template_id: t.struct_cluster_id for t in catalog.templates}
    same, cross, intra = [], [], []
    for a, b, inter, union in pairs:
        ta, tb = by_id[a], by_id[b]
        rec = {"a": ta.name, "b": tb.name, "intersection": inter, "union": union,
               "jaccard": f"{inter / union:.4f}", "clusters": [resolved[a], resolved[b]],
               "carriers": [ta.carrier, tb.carrier]}
        if resolved[a] == resolved[b]:
            intra.append(rec)
        elif ta.carrier != tb.carrier:
            cross.append(rec)
        else:
            same.append(rec)
    for r in same:
        findings.append({"code": "UNDECLARED_NEAR_DUPLICATE",
                         "detail": f"{r['a']} ~ {r['b']} (J={r['jaccard']}) in clusters {r['clusters']}: declare a merge"})
    for r in cross:
        findings.append({"code": "I16_CROSS_CARRIER",
                         "detail": f"{r['a']} ({r['carriers'][0]}) ~ {r['b']} ({r['carriers'][1]}) J={r['jaccard']}: "
                                   "clusters of two carriers cannot be merged (D-2) and the audit is not relaxed; "
                                   "change the catalogue"})
    clusters_per = defaultdict(set)
    for t in catalog.templates:
        clusters_per[t.carrier].add(resolved[t.template_id])
    strata = {}
    for c in CARRIERS:
        n = len(clusters_per.get(c, ()))
        strata[c] = {"clusters": n, "templates": sum(1 for t in catalog.templates if t.carrier == c),
                     "flag": "NOT_EVALUABLE_STRUCTURE" if n < 3 else "OK"}
        if n < 3:
            info.append({"code": "NOT_EVALUABLE_STRUCTURE", "detail": f"carrier {c}: {n} cluster(s) < 3"})
    proposal = I.propose_merges([tuple(r["clusters"]) for r in same])
    return {"schema": AUDIT_SCHEMA, "ok": not findings, "catalog_sha256": catalog.sha256,
            "lexicon_sha256": catalog.lexicon_sha256, "templates": len(catalog.templates),
            "near_duplicate_threshold": "Jaccard >= 0.60 (5*inter >= 3*union)",
            "pairs_at_threshold": len(pairs), "intra_cluster_pairs": intra, "same_carrier_cross_cluster": same,
            "cross_carrier": cross, "proposed_cluster_merges": proposal, "strata": strata,
            "findings": findings, "info": info, "cluster_table_resolved": table is not None}


def require_clean(report: dict) -> None:
    if report["findings"]:
        raise CatalogStop(report["findings"])


def cluster_table(catalog: Catalog, cluster_merges=()):
    """Audit, stop on any blocking finding, then return the stage-3 ClusterTable."""
    require_clean(audit(catalog, cluster_merges))
    return I.resolve_clusters(template_decls(catalog), cluster_merges)


# ───────────────────────────── coverage report ─────────────────────────────
def _json_depth(n: Node) -> int:
    return 0 if n.kind == "leaf" else 1 + max(_json_depth(c) for c in n.children)


def coverage(catalog: Catalog) -> dict:
    per = {}
    for c in CARRIERS:
        ts = [t for t in catalog.templates if t.carrier == c]
        cats = Counter(cat for t in ts for s in t.attack_slots for cat in s.compatible_categories)
        per[c] = {
            "templates": len(ts), "clusters": len({t.struct_cluster_id for t in ts}),
            "methods": dict(sorted(Counter(t.method for t in ts).items())),
            "media_type": CARRIER_MEDIA[c],
            "slot_types": dict(sorted(Counter(s.value_type for t in ts for s in t.slots).items())),
            "attack_slots_per_template": sorted({len(t.attack_slots) for t in ts}),
            "keyed_fields_per_template": sorted({len(t.name_sites()) for t in ts}),
            "json_depth": sorted({_json_depth(t.body) for t in ts}) if c == "json" else None,
            "json_root": sorted({t.body.kind for t in ts}) if c == "json" else None,
            "compatible_categories_slot_count": dict(sorted(cats.items())),
            "pools": sorted({p for t in ts for s in t.attack_slots for p in s.pools}),
        }
    all_cats = set().union(*SLOT_COMPATIBILITY.values())
    reached = {cat: sorted(c for c in CARRIERS if per[c]["compatible_categories_slot_count"].get(cat))
               for cat in sorted(all_cats)}
    return {"per_carrier": per, "category_carriers": reached,
            "categories_without_slot": sorted(c for c, v in reached.items() if not v)}


def summary_md(report: dict, cov: dict) -> str:
    lines = ["# V5 template catalogue audit (stage 4, issue #74)", "",
             f"- catalogue sha256 `{report['catalog_sha256']}`; lexicon sha256 `{report['lexicon_sha256']}`",
             f"- templates: {report['templates']}; audit {'PASS' if report['ok'] else 'FAIL'}; "
             f"pairs at Jaccard >= 0.60: {report['pairs_at_threshold']} (intra-cluster {len(report['intra_cluster_pairs'])}, "
             f"same-carrier cross-cluster {len(report['same_carrier_cross_cluster'])}, cross-carrier {len(report['cross_carrier'])})",
             "", "| carrier | clusters | templates | flag | methods | slot types |", "|---|---|---|---|---|---|"]
    for c in CARRIERS:
        s, p = report["strata"][c], cov["per_carrier"][c]
        lines.append(f"| {c} | {s['clusters']} | {s['templates']} | {s['flag']} | "
                     f"{', '.join(f'{k} {v}' for k, v in p['methods'].items())} | "
                     f"{', '.join(f'{k} {v}' for k, v in p['slot_types'].items())} |")
    lines += ["", "| category | carriers with a compatible slot |", "|---|---|"]
    for cat, cs in cov["category_carriers"].items():
        lines.append(f"| {cat} | {', '.join(cs) or '—'} |")
    if report["findings"]:
        lines += ["", "## Blocking findings", ""] + [f"- `{f['code']}` {f['detail']}" for f in report["findings"]]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("audit")
    a.add_argument("--catalog", default=DEFAULT_CATALOG)
    a.add_argument("--lexicon", default=DEFAULT_LEXICON)
    a.add_argument("--out")
    a.add_argument("--summary")
    args = ap.parse_args(argv)
    cat = load_catalog(args.catalog, args.lexicon)
    rep, cov = audit(cat), coverage(cat)
    out = {"audit": rep, "coverage": cov}
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    if args.summary:
        with open(args.summary, "w", encoding="utf-8") as fh:
            fh.write(summary_md(rep, cov))
    print(json.dumps({"ok": rep["ok"], "templates": rep["templates"], "findings": len(rep["findings"]),
                      "strata": {c: s["clusters"] for c, s in rep["strata"].items()}}, sort_keys=True))
    return 0 if rep["ok"] else 2


if __name__ == "__main__":
    sys.exit(main())
