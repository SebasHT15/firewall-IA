"""
firewall-IA — case generator for the V4 minimal-pair probe (`v5-minimal-pairs-v1`).

DEVELOPMENT DIAGNOSTIC DATA. These cases are never V5 training, validation or
checkpoint-selection data. V5 may learn the *concepts* derived from the probe's results,
never these texts, templates or value pools (whose SHA-256 the manifest records so a V5
builder can assert disjointness).

Every case is a BENIGN request of a fictitious municipal library and events portal. A
*base* is one value tuple drawn once from this file's pools. Each factor renders every base
at several *levels*; a *comparison* pairs a reference level with one other level of the same
base, and the two texts differ in exactly one declared dimension. Nothing is copied from
`fwlab.test`, the lab application, issues #57/#60 or External Test v1.

Rendering follows D1 and `parse_dataset_v4.render_request`: LF line endings, origin-form
target, one `Name: value` line per header, a blank line and the body only when there is a
body, no trailing newline. Query and form values are percent-encoded with
`quote(v, safe="")` unless the factor is the encoding itself. JSON bodies use
`json.dumps` with its default separators. `Content-Type` is the last header of a body
request; a `Content-Length` level is inserted immediately before it.

Standard library only. Deterministic: the same seed yields byte-identical files.

    python3 scripts/evaluation/minimal_pair_probe_cases.py --out-dir reports/v5/minimal-pair-probe-v1
"""

import argparse
import hashlib
import json
import os
import random
import sys
from dataclasses import dataclass, field, replace
from urllib.parse import quote

GENERATOR_VERSION = "v5-minimal-pairs-v1/generator-2"
SEED = 20261006
DATA_ROLE = ("DEVELOPMENT DIAGNOSTIC (minimal-pair probe). Never V5 training, validation or "
             "checkpoint-selection data; never copied into a V5 generator.")
REPEAT_FRACTION = 0.10          # CONTROL-REP: share of unique texts scored 3 times
REPEAT_RUNS = 3

# ── Pools (probe-only; hashed into the manifest) ──────────────────────────────────────────
POOLS = {
    # Envelope. Host values are reserved example domains (RFC 2606/6761) not used by the V4
    # generator; user agents and accept values are ordinary client strings.
    "hosts": ["library.example.net", "events.example.net", "portal.example.net",
              "catalog.example.org", "branches.example.org", "reading.example.net"],
    "user_agents": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
        "curl/8.7.1", "python-requests/2.32.3", "okhttp/4.12.0"],
    "accepts": ["*/*", "text/html,application/xhtml+xml", "application/json"],
    # Content.
    "first_names": ["amara", "bruno", "celia", "dmitri", "elif", "farid", "greta", "hiro",
                    "ingrid", "jonas", "kaia", "leon", "mirela", "nikhil", "olga", "petra",
                    "quentin", "rosa", "soren", "talia"],
    "surnames_plain": ["berg", "castillo", "dahl", "esposito", "fischer", "grant", "holm",
                       "ivanova", "jensen", "keller", "lund", "marsh"],
    # (reference without apostrophe, level with apostrophe): same letters, one character added.
    "surnames_apostrophe": [("oneil", "o'neil"), ("obrien", "o'brien"), ("dangelo", "d'angelo"),
                            ("oconnor", "o'connor"), ("dsouza", "d'souza"), ("ohara", "o'hara"),
                            ("darcy", "d'arcy"), ("oreilly", "o'reilly"), ("ndiaye", "n'diaye"),
                            ("damico", "d'amico"), ("omalley", "o'malley"), ("dalessio", "d'alessio"),
                            ("osullivan", "o'sullivan"), ("odonnell", "o'donnell"), ("okeefe", "o'keefe"),
                            ("oleary", "o'leary"), ("oneal", "o'neal"), ("oshea", "o'shea"),
                            ("otoole", "o'toole"), ("orourke", "o'rourke"), ("odowd", "o'dowd"),
                            ("ogrady", "o'grady"), ("omara", "o'mara"), ("donofrio", "d'onofrio"),
                            ("dagostino", "d'agostino"), ("dcosta", "d'costa"), ("lheureux", "l'heureux"),
                            ("daubigne", "d'aubigne"), ("oflynn", "o'flynn"), ("ogorman", "o'gorman"),
                            ("durso", "d'urso"), ("ohare", "o'hare")],
    "streets": ["Linden Road", "Harbour View", "Maple Avenue", "Quarry Lane", "Orchard Way",
                "Birch Close", "Mill Street", "Station Parade"],
    "branches": ["central", "riverside", "northgate", "eastfield", "hillcrest", "old-town"],
    "topics": ["gardening", "astronomy", "watercolour", "chess", "pottery", "birdwatching",
               "knitting", "photography", "beekeeping", "cycling", "origami", "baking",
               "calligraphy", "woodworking", "embroidery", "sailing", "hiking", "geology",
               "ceramics", "botany", "puppetry", "juggling", "genealogy", "composting",
               "printmaking", "rowing", "stargazing", "quilting", "mosaics", "foraging"],
    "titles": ["the quiet harbour", "a field guide to mosses", "northern lights", "city of maps",
               "the clockmaker", "river songs", "salt marsh tales", "paper boats",
               "winter kitchen", "the long walk"],
    "collections": ["maps", "posters", "photos", "scores", "letters", "plans"],
    "files": ["city-plan.png", "harbour-1910.jpg", "concert-poster.pdf", "reading-list.pdf",
              "branch-map.svg", "festival-programme.pdf"],
    "external_hosts": ["maps.example.org", "calendar.example.com", "media.example.org",
                       "tickets.example.com"],
    "url_paths": ["/account/loans", "/events/calendar", "/members/home", "/catalog/saved"],
    "extra_query": [("page", "2"), ("view", "grid"), ("lang", "en"), ("limit", "20"),
                    ("format", "list"), ("year", "2025")],
    "extra_fields": [("branch", "central"), ("language", "en"), ("format", "print"),
                     ("newsletter", "weekly"), ("pickup", "front-desk"), ("reminder", "email")],
    # Free-text sentences: (clause_a, clause_b) joined by ", " and ended by "." at the reference.
    # Covered characters only (letters, digits, space, ',', '.'); no SQL-homonym word.
    "clauses": [("The reading room is quiet today", "thanks for the new chairs"),
                ("My card expires next month", "please send a reminder"),
                ("The story hour was lovely", "my daughter wants to come back"),
                ("Parking is full on Saturdays", "maybe add bike racks"),
                ("The audio guide works well", "the volume is a bit low"),
                ("I returned two books yesterday", "they still show as borrowed"),
                ("The study pods are popular", "booking them early helps"),
                ("Opening hours changed this week", "the website shows the old times"),
                ("The poetry night was great", "looking forward to the next one"),
                ("Wifi is slow upstairs", "downstairs it is fine"),
                ("The new catalog is easy to use", "the search is fast"),
                ("My hold arrived quickly", "thank you very much"),
                ("The lift is out of service", "the stairs are open"),
                ("The art class was full", "please run another session"),
                ("My son lost his library card", "can we get a new one"),
                ("The printer on level two jams", "it needs paper too"),
                ("The garden tour starts at nine", "bring a hat"),
                ("Thanks for the quick reply", "the issue is fixed now"),
                ("The cafe opens late on Mondays", "coffee would help"),
                ("The film night was well run", "the sound was clear"),
                ("Our book club meets on Tuesdays", "we need a bigger room"),
                ("The kids corner is bright", "the toys are clean"),
                ("My renewal went through", "the due date is next week"),
                ("The map collection is wonderful", "the staff were helpful"),
                ("The heating is too high", "the reading room is warm"),
                ("I found a lost umbrella", "it is at the front desk"),
                ("The language cafe was fun", "I made new friends"),
                ("Your newsletter arrived today", "the photos look great"),
                ("The return slot was jammed", "I used the desk instead"),
                ("The music room piano is out of tune", "it still sounds nice")],
    # SQL/shell homonyms in ordinary prose: (neutral word, homonym, frames). Each frame has one
    # '{w}' slot and one '{t}' topic slot; the two sentences of a base differ only in {w}.
    "homonyms": [
        ("choose", "select", ["Please help me {w} a {t} book for beginners",
                              "Can I {w} a seat for the {t} talk",
                              "How do I {w} a pickup branch for my {t} hold",
                              "I want to {w} two {t} titles for my club",
                              "When can I {w} the {t} workshop date"]),
        ("association", "union", ["The staff {w} meets after the {t} fair",
                                  "Our student {w} runs a {t} evening",
                                  "Is the {w} hall open for the {t} club",
                                  "The local {w} sponsors the {t} contest",
                                  "Ask the {w} desk about the {t} grant"]),
        ("by", "from", ["A talk {w} the author of the {t} series",
                        "Letters {w} readers about the {t} exhibit",
                        "Photos {w} the {t} weekend are online",
                        "A donation {w} the {t} society arrived",
                        "Notes {w} the last {t} meetup"]),
        ("when", "where", ["Tell me {w} the {t} club meets",
                           "I forgot {w} the {t} class is held",
                           "Please confirm {w} the {t} books go back",
                           "Can you say {w} the {t} kits are kept",
                           "I asked {w} the {t} group gathers"]),
        ("desk", "table", ["Reserve a {w} in the {t} room",
                           "The {w} near the {t} shelf is broken",
                           "Is there a free {w} for {t} study",
                           "We need one more {w} for the {t} fair",
                           "My laptop is at the {t} {w}"]),
        ("phone", "call", ["Please {w} me about my {t} hold",
                           "I will {w} the branch about the {t} event",
                           "Can staff {w} me when the {t} book is ready",
                           "{w} the desk to join the {t} circle",
                           "I missed the {w} about the {t} workshop"]),
        ("game", "match", ["The {t} {w} starts at noon",
                           "Our team won the {t} {w}",
                           "Is the {t} {w} open to visitors",
                           "The final {t} {w} is on Friday",
                           "Bring a friend to the {t} {w}"]),
        ("add", "include", ["Please {w} my {t} notes in the file",
                            "Can you {w} the {t} handout",
                            "I would like to {w} a {t} title on my list",
                            "Does the pass {w} the {t} session",
                            "We will {w} a short {t} quiz"]),
        ("request", "order", ["My book {w} for {t} is late",
                              "I placed a {t} {w} last week",
                              "Can I change my {t} {w}",
                              "The {t} {w} shows as pending",
                              "Cancel the {t} {w} please"]),
        ("leave", "drop", ["I will {w} the {t} books at the front desk",
                           "Can I {w} my {t} kit at any branch",
                           "Please {w} the {t} flyers by the door",
                           "We {w} the {t} returns in the box",
                           "You can {w} the {t} forms at reception"]),
        ("plus", "and", ["Maps {w} atlases for the {t} project",
                         "Bring a pen {w} a notebook to {t} class",
                         "Kids {w} parents can join the {t} hour",
                         "Tea {w} biscuits after the {t} talk",
                         "Books {w} games for the {t} night"]),
        ("vs", "or", ["Morning {w} evening {t} sessions",
                      "Is the {t} kit for kids {w} adults",
                      "Paperback {w} hardcover for the {t} guide",
                      "Online {w} in person {t} classes",
                      "Large print {w} audio for the {t} novel"]),
    ],
}


def pools_sha256() -> dict:
    return {name: hashlib.sha256(json.dumps(v, ensure_ascii=False, sort_keys=True)
                                 .encode("utf-8")).hexdigest() for name, v in sorted(POOLS.items())}


def enc(v: str) -> str:
    """Percent-encode a value exactly as the V4 generator does for targets and forms."""
    return quote(v, safe="")


# ── Request model and D1 rendering ────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Req:
    method: str
    path: str
    query: tuple = ()               # ((name, already-encoded value), ...)
    headers: tuple = ()             # ((name, value), ...) envelope, before Content-Type
    content_type: str | None = None
    body: str | None = None
    content_length: bool = False    # True inserts a correct Content-Length before Content-Type
    chunked: bool = False           # True inserts "Transfer-Encoding: chunked" before Content-Type;
                                    # the body stays de-chunked, as mitmproxy renders it (note F)

    def render(self) -> str:
        target = self.path
        if self.query:
            target += "?" + "&".join(f"{k}={v}" for k, v in self.query)
        lines = [f"{self.method} {target} HTTP/1.1"]
        lines += [f"{k}: {v}" for k, v in self.headers]
        if self.body is not None:
            if self.content_length:
                lines.append(f"Content-Length: {len(self.body.encode('utf-8'))}")
            if self.chunked:
                lines.append("Transfer-Encoding: chunked")
            if self.content_type:
                lines.append(f"Content-Type: {self.content_type}")
        text = "\n".join(lines)
        if self.body is not None:
            text += "\n\n" + self.body
        return text


def form_body(fields) -> str:
    return "&".join(f"{k}={enc(v)}" for k, v in fields)


def envelope(rng, host=None, accept_language=False, proxy_connection=False):
    h = [("Host", host or rng.choice(POOLS["hosts"])),
         ("User-Agent", rng.choice(POOLS["user_agents"])),
         ("Accept", rng.choice(POOLS["accepts"]))]
    if accept_language:
        h.append(("Accept-Language", "en-US,en;q=0.9"))
    if proxy_connection:
        h.append(("Proxy-Connection", "keep-alive"))
    return tuple(h)


def set_host(headers, value):
    return tuple(("Host", value) if k == "Host" else (k, v) for k, v in headers)


def body_req(rng, path, fields, method=None, headers=None, ctype="application/x-www-form-urlencoded"):
    return Req(method or rng.choice(["POST", "POST", "PUT", "PATCH"]), path,
               headers=headers if headers is not None else envelope(rng),
               content_type=ctype, body=form_body(fields))


def get_req(rng, path, query, headers=None):
    return Req("GET", path, query=tuple((k, enc(v)) for k, v in query),
               headers=headers if headers is not None else envelope(rng))


def value_carrier(rng, i, name, value_by_level, paths):
    """One value in either a GET query or a one-field form body; carrier alternates by base."""
    path = rng.choice(paths)
    headers = envelope(rng)
    method = rng.choice(["POST", "POST", "PUT", "PATCH"])
    if i % 2 == 0:
        return {lv: Req("GET", path, query=((name, enc(v)),), headers=headers)
                for lv, v in value_by_level.items()}
    return {lv: Req(method, path, headers=headers, content_type="application/x-www-form-urlencoded",
                    body=form_body([(name, v)])) for lv, v in value_by_level.items()}


def username(rng):
    return rng.choice(POOLS["first_names"]) + rng.choice(
        ["", ".", "-"]) + rng.choice(POOLS["surnames_plain"] + [str(rng.randint(2, 98))])


def plain_body_base(rng, kind, path):
    """Body bases of F-CL: form with 1 or 2 fields, JSON with 1 or 3 string keys."""
    name, title, branch = username(rng), rng.choice(POOLS["titles"]), rng.choice(POOLS["branches"])
    headers, method = envelope(rng), rng.choice(["POST", "POST", "PUT", "PATCH"])
    if kind == "form1":
        return Req(method, path, headers=headers, content_type="application/x-www-form-urlencoded",
                   body=form_body([("title", title)]))
    if kind == "form2":
        return Req(method, path, headers=headers, content_type="application/x-www-form-urlencoded",
                   body=form_body([("member", name), ("title", title)]))
    if kind == "json1":
        return Req(method, path, headers=headers, content_type="application/json",
                   body=json.dumps({"title": title}))
    return Req(method, path, headers=headers, content_type="application/json",
               body=json.dumps({"member": name, "title": title, "branch": branch}))


# ── Factors ───────────────────────────────────────────────────────────────────────────────
# Each builder returns {level: Req} for base i. COMPARISONS lists (reference, level) pairs.
BODY_PATHS = ["/api/v2/reservations", "/events/signup", "/members/settings", "/catalog/holds",
              "/rooms/booking", "/feedback/new"]
GET_PATHS = ["/catalog/find", "/events/upcoming", "/rooms/availability", "/members/history",
             "/branches/hours", "/media/browse"]


def f_cl(rng, i):
    kind = ["form1", "form2", "json1", "json3"][i % 4]
    r = plain_body_base(rng, kind, rng.choice(BODY_PATHS))
    return {"absent": r, "present": replace(r, content_length=True),
            "te_chunked": replace(r, chunked=True)}


def _host_base(rng, i):
    if i % 2 == 0:
        return get_req(rng, rng.choice(GET_PATHS), [("topic", rng.choice(POOLS["topics"]))])
    return plain_body_base(rng, "form1", rng.choice(BODY_PATHS))


def f_port(rng, i):
    r = _host_base(rng, i)
    host = dict(r.headers)["Host"]
    out = {"none": r}
    for p in (8080, 8443, 30000):
        out[f"port_{p}"] = replace(r, headers=set_host(r.headers, f"{host}:{p}"))
    return out


def f_hostip(rng, i):
    r = _host_base(rng, i)
    return {"dns": r,
            "ip_127.0.0.1": replace(r, headers=set_host(r.headers, "127.0.0.1")),
            "ip_10.0.0.5": replace(r, headers=set_host(r.headers, "10.0.0.5")),
            # RFC 5737 documentation address: a portless, non-loopback, non-private IP Host.
            "ip_203.0.113.10": replace(r, headers=set_host(r.headers, "203.0.113.10"))}


def f_pxy(rng, i):
    r = _host_base(rng, i)
    return {"absent": r, "present": replace(r, headers=r.headers + (("Proxy-Connection", "keep-alive"),))}


def control_env(rng, i):
    r = _host_base(rng, i)
    return {"absent": r,
            "present": replace(r, headers=r.headers + (("Accept-Language", "en-US,en;q=0.9"),))}


def f_nquery(rng, i):
    extras = rng.sample(POOLS["extra_query"], 3)
    base = [("topic", rng.choice(POOLS["topics"]))]
    path, headers = rng.choice(GET_PATHS), envelope(rng)
    return {"n1": get_req(rng, path, base, headers),
            "n2": get_req(rng, path, base + extras[:1], headers),
            "n4": get_req(rng, path, base + extras[:3], headers)}


def f_nfields(rng, i):
    extras = rng.sample(POOLS["extra_fields"], 4)
    base = [("title", rng.choice(POOLS["titles"]))]
    path, headers = rng.choice(BODY_PATHS), envelope(rng)
    method = rng.choice(["POST", "POST", "PUT", "PATCH"])
    out = {f"n{k}": body_req(rng, path, base + extras[:k - 1], method, headers)
           for k in (1, 2, 3, 5)}
    # Serve-like twins (correct Content-Length): content effect under the gateway envelope.
    out["n1_cl"], out["n2_cl"] = replace(out["n1"], content_length=True), replace(out["n2"], content_length=True)
    return out


def f_pwd(rng, i):
    al = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    pw = "".join(rng.choice(al) for _ in range(12))
    pos = rng.randint(4, 8)
    name = ["new_password", "password"][i % 2]
    path, headers = rng.choice(["/members/settings", "/members/password", "/account/security"]), envelope(rng)
    method = rng.choice(["POST", "POST", "PUT", "PATCH"])
    levels = {"alnum": pw}
    # '-' (literal) and '@' (encoded %40) are covered characters: within-factor controls.
    for label, ch in (("bang", "!"), ("hash", "#"), ("dash", "-"), ("at", "@")):
        levels[label] = pw[:pos] + ch + pw[pos + 1:]
    return {lv: body_req(rng, path, [(name, v)], method, headers) for lv, v in levels.items()}


def f_apos(rng, i):
    ref, apos = POOLS["surnames_apostrophe"][i]      # one distinct surname per base
    return value_carrier(rng, i, "surname", {"plain": ref, "apostrophe": apos},
                         ["/members/lookup", "/members/settings", "/events/signup"])


def f_addr(rng, i):
    n, street, unit = rng.randint(2, 180), rng.choice(POOLS["streets"]), rng.randint(1, 30)
    return value_carrier(rng, i, "address", {
        "plain": f"{n} {street} Apt {unit}",
        "comma": f"{n} {street}, Apt {unit}",
        "hash": f"{n} {street} Apt #{unit}"}, ["/members/settings", "/catalog/delivery", "/events/signup"])


def f_punct(rng, i):
    a, b = POOLS["clauses"][i]                       # one distinct clause pair per base
    return value_carrier(rng, i, "note", {
        "comma_period": f"{a}, {b}.",
        "semicolon": f"{a}; {b}.",
        "ampersand": f"{a} & {b}.",
        "exclamation": f"{a}, {b}!",
        "question": f"{a}, {b}?"}, ["/feedback/new", "/members/notes", "/events/comments"])


def f_word(rng, i):
    neutral, hom, frames = POOLS["homonyms"][i % len(POOLS["homonyms"])]
    frame = frames[(i // len(POOLS["homonyms"])) % len(frames)]
    t = rng.choice(POOLS["topics"])
    make = lambda w: frame.format(w=w, t=t)     # noqa: E731
    # Carrier alternates by frame index, so every homonym appears in both carriers.
    carrier = (i // len(POOLS["homonyms"])) % 2
    return value_carrier(rng, carrier, ["q", "message"][carrier],
                         {"neutral": make(neutral), "homonym": make(hom)},
                         ["/catalog/find", "/feedback/new", "/events/ask"])


def f_freetext(rng, i):
    t = POOLS["topics"][i]                           # one distinct keyword per base
    sentence = ["beginner guides to {t} for small spaces",
                "books about {t} for a weekend course",
                "is there a {t} club for teenagers",
                "looking for a gentle {t} guide with pictures",
                "recommend a {t} book for my father"][i % 5].format(t=t)
    return value_carrier(rng, i, ["q", "interest"][i % 2], {"keyword": t, "sentence": sentence},
                         ["/catalog/find", "/members/interests", "/events/suggest"])


def f_json(rng, i):
    title, branch = rng.choice(POOLS["titles"]), rng.choice(POOLS["branches"])
    copies = str(rng.randint(1, 4))
    path, headers = rng.choice(["/api/v2/reservations", "/api/v2/holds", "/api/v2/requests"]), envelope(rng)
    method = rng.choice(["POST", "POST", "PUT", "PATCH"])
    mk = lambda obj: Req(method, path, headers=headers, content_type="application/json",  # noqa: E731
                         body=json.dumps(obj))
    s4 = {"title": title, "branch": branch, "copies": copies, "notify": "true"}
    k1 = mk({"title": title})
    return {"k1_string": k1,
            "k1_cl": replace(k1, content_length=True),
            "k4_cl": replace(mk(s4), content_length=True),
            "k4_strings": mk(s4),
            "k4_number": mk({**s4, "copies": int(copies)}),
            "k4_boolean": mk({**s4, "notify": True}),
            "k4_nested": mk({**s4, "branch": {"name": branch}}),
            "k4_array": mk({**s4, "branch": [branch]})}


def f_ctb(rng, i):
    r = body_req(rng, rng.choice(BODY_PATHS), [("title", rng.choice(POOLS["titles"]))])
    return {"form_type": r, "json_type": replace(r, content_type="application/json")}


def f_enc(rng, i):
    words = rng.sample(POOLS["topics"], 2)
    v = f"{words[0]} {words[1]} kits"
    path, headers = rng.choice(GET_PATHS), envelope(rng)
    return {"pct20": Req("GET", path, query=(("topic", enc(v)),), headers=headers),
            "plus": Req("GET", path, query=(("topic", v.replace(" ", "+")),), headers=headers)}


def f_path(rng, i):
    coll, fname, year = rng.choice(POOLS["collections"]), rng.choice(POOLS["files"]), rng.randint(1990, 2025)
    headers = envelope(rng)
    mk = lambda p: Req("GET", p, headers=headers)   # noqa: E731
    return {"depth3": mk(f"/media/{coll}/{fname}"),
            "depth5": mk(f"/media/archive/{year}/{coll}/{fname}"),
            "encoded_slash": mk(f"/media/{coll}%2F{fname}")}


def f_url(rng, i):
    host = rng.choice(POOLS["hosts"])
    ext, upath = rng.choice(POOLS["external_hosts"]), rng.choice(POOLS["url_paths"])
    # Neutral parameter names: a member's website / a shared link. 'next'/'return_url' would make
    # an external URL the open-redirect shape, where BLOCK is arguably correct (review IMPORTANT).
    name = ["website", "link"][i % 2]
    headers = envelope(rng, host=host)
    path = rng.choice(["/members/details", "/events/share", "/groups/info"])
    vals = {"https_same_host": f"https://{host}{upath}",
            "https_external": f"https://{ext}{upath}",
            "http_external": f"http://{ext}{upath}"}
    return {lv: Req("GET", path, query=((name, enc(v)),), headers=headers) for lv, v in vals.items()}


def f_name(rng, i):
    v = f"{rng.choice(POOLS['topics'])}-list-{rng.randint(2024, 2026)}"
    path, headers = rng.choice(GET_PATHS + BODY_PATHS), envelope(rng)
    method = rng.choice(["POST", "POST", "PUT", "PATCH"])
    out = {}
    for name in ("note", "template", "callback", "file"):
        if i % 2 == 0:
            out[name] = Req("GET", path, query=((name, enc(v)),), headers=headers)
        else:
            out[name] = body_req(rng, path, [(name, v)], method, headers)
    return out


def control_cov(rng, i):
    a = username(rng)
    b = username(rng)
    while b == a:
        b = username(rng)
    return value_carrier(rng, i, "username", {"user_a": a, "user_b": b},
                         ["/members/lookup", "/members/settings", "/events/signup"])


# factor id -> (block, n_bases, builder, [(reference, level), ...], tests)
FACTORS = {
    "F-CL":       ("ENVELOPE", 40, f_cl, [("absent", "present"), ("absent", "te_chunked")], "M-envelope"),
    "F-PORT":     ("ENVELOPE", 30, f_port, [("none", "port_8080"), ("none", "port_8443"),
                                            ("none", "port_30000")], "M-envelope"),
    "F-HOSTIP":   ("ENVELOPE", 30, f_hostip, [("dns", "ip_127.0.0.1"), ("dns", "ip_10.0.0.5"),
                                              ("dns", "ip_203.0.113.10"),
                                              ("ip_203.0.113.10", "ip_127.0.0.1"),
                                              ("ip_203.0.113.10", "ip_10.0.0.5")],
                   "M-token / M-envelope (portless IP Host)"),
    "F-PXY":      ("ENVELOPE", 30, f_pxy, [("absent", "present")], "M-envelope"),
    "F-NQUERY":   ("CONTENT", 30, f_nquery, [("n1", "n2"), ("n1", "n4")], "M-content"),
    "F-NFIELDS":  ("CONTENT", 30, f_nfields, [("n1", "n2"), ("n1", "n3"), ("n1", "n5"),
                                              ("n1_cl", "n2_cl")], "M-content"),
    "F-PWD":      ("CONTENT", 30, f_pwd, [("alnum", "bang"), ("alnum", "hash"), ("alnum", "dash"),
                                          ("alnum", "at")], "M-content"),
    "F-APOS":     ("CONTENT", 30, f_apos, [("plain", "apostrophe")], "M-content"),
    "F-ADDR":     ("CONTENT", 30, f_addr, [("plain", "comma"), ("plain", "hash"), ("comma", "hash")],
                   "M-content"),
    "F-PUNCT":    ("CONTENT", 30, f_punct, [("comma_period", "semicolon"), ("comma_period", "ampersand"),
                                            ("comma_period", "exclamation"),
                                            ("comma_period", "question")], "M-content"),
    "F-WORD":     ("CONTENT", 60, f_word, [("neutral", "homonym")], "M-content"),
    "F-FREETEXT": ("CONTENT", 30, f_freetext, [("keyword", "sentence")], "M-content"),
    "F-JSON":     ("CONTENT", 30, f_json, [("k1_string", "k4_strings"), ("k4_strings", "k4_number"),
                                           ("k4_strings", "k4_boolean"), ("k4_strings", "k4_nested"),
                                           ("k4_strings", "k4_array"), ("k1_cl", "k4_cl")], "M-content"),
    "F-CTB":      ("CONTENT", 30, f_ctb, [("form_type", "json_type")], "M-content (reverse shortcut)"),
    "F-ENC":      ("CONTENT", 30, f_enc, [("pct20", "plus")], "M-content"),
    "F-PATH":     ("CONTENT", 30, f_path, [("depth3", "depth5"), ("depth3", "encoded_slash")], "M-content"),
    "F-URL":      ("CONTENT", 30, f_url, [("https_same_host", "https_external"),
                                          ("https_external", "http_external")], "M-content"),
    "F-NAME":     ("CONTENT", 30, f_name, [("note", "template"), ("note", "callback"), ("note", "file")],
                   "M-content (name semantics)"),
    "CONTROL-COV": ("CONTROL", 40, control_cov, [("user_a", "user_b")], "M-instability (content)"),
    "CONTROL-ENV": ("CONTROL", 30, control_env, [("absent", "present")], "M-instability (envelope)"),
}


def text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def generate(seed: int = SEED):
    """Return (cases, comparisons, repeat_ids). Deterministic in `seed`."""
    cases, comparisons, seen_text = [], [], {}
    used_texts = set()          # across ALL factors: bases are never shared between factors
    for fid, (block, n_bases, builder, comps, tests) in FACTORS.items():
        for i in range(n_bases):
            # A base must not repeat any text of an earlier base (of any factor): bases are the
            # independent units. A collision redraws deterministically (attempt counter).
            for attempt in range(1000):
                rng = random.Random(f"{seed}|{fid}|{i}|{attempt}")
                levels = builder(rng, i)
                texts = {req.render() for req in levels.values()}
                if len(texts) == len(levels) and not texts & used_texts:
                    break
            else:
                raise RuntimeError(f"{fid}: cannot draw a distinct base {i}")
            used_texts |= texts
            for lv, req in levels.items():
                text = req.render()
                cid = f"{fid}|b{i:02d}|{lv}"
                cases.append({"case_id": cid, "factor": fid, "block": block, "base": i,
                              "level": lv, "text": text, "text_sha256": text_sha256(text)})
                seen_text.setdefault(text, []).append(cid)
        for ref, lv in comps:
            comparisons.append({"comparison_id": f"{fid}:{ref}->{lv}", "factor": fid, "block": block,
                                "reference": ref, "level": lv, "n_bases": n_bases, "tests": tests})
    unique = sorted({c["text_sha256"] for c in cases})
    rng = random.Random(f"{seed}|repeat")
    repeat = sorted(rng.sample(unique, max(1, round(REPEAT_FRACTION * len(unique)))))
    return cases, comparisons, repeat


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.strip().split("\n")[0])
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args(argv)
    cases, comparisons, repeat = generate()
    os.makedirs(args.out_dir, exist_ok=True)
    cases_path = os.path.join(args.out_dir, "cases.jsonl")
    manifest_path = os.path.join(args.out_dir, "manifest.json")
    for p in (cases_path, manifest_path):
        if os.path.exists(p):
            raise SystemExit(f"REFUSING to overwrite {p}")
    with open(cases_path, "x", encoding="utf-8") as f:
        for c in cases:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")
    with open(cases_path, "rb") as f:
        cases_sha = hashlib.sha256(f.read()).hexdigest()
    manifest = {
        "probe": "v5-minimal-pairs-v1", "generator_version": GENERATOR_VERSION, "seed": SEED,
        "data_role": DATA_ROLE, "label_of_every_case": "benign (by construction)",
        "cases_file": "cases.jsonl", "cases_sha256": cases_sha,
        "n_cases": len(cases), "n_unique_texts": len({c["text_sha256"] for c in cases}),
        "factors": {fid: {"block": b, "n_bases": n, "tests": t}
                    for fid, (b, n, _, _, t) in FACTORS.items()},
        "comparisons": comparisons,
        "repeat_control": {"fraction": REPEAT_FRACTION, "runs": REPEAT_RUNS,
                           "text_sha256": repeat},
        "pools_sha256": pools_sha256(),
    }
    with open(manifest_path, "x", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"{len(cases)} cases, {manifest['n_unique_texts']} unique texts, "
          f"{len(comparisons)} comparisons, {len(repeat)} repeated texts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
