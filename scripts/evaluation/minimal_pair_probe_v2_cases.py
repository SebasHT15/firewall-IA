"""
firewall-IA — case generator for the V4 minimal-pair probe v2 (`v5-minimal-pairs-v2`).

DEVELOPMENT DIAGNOSTIC DATA. Never V5 training, validation or checkpoint-selection data; V5 may
learn the *concepts* the results demonstrate, never these texts, templates or pools (whose SHA-256
the manifest records so a V5 builder can assert disjointness).

Every case is a BENIGN request of a fictitious community recreation centre. A *base* is one value
tuple drawn once from this file's pools; each base is rendered at several *levels*; a *comparison*
pairs a reference level with one other level of the same base, differing in exactly one declared
dimension (PROTOCOL.md §3). Nothing is copied from minimal-pair v1, `fwlab`, issues #57/#60,
External Test v1 or the V4 eval / INTERNAL TEST sets. The field token `address` is reused on purpose
— it is the independent variable under test in question A — but all values, templates and hosts are
new, and the case texts are disjoint from v1 (asserted in tests).

Rendering follows D1 / `render_request`: LF line endings, origin-form target, one `Name: value`
header line, a blank line and the body only when there is a body, no trailing newline. Query and form
values are percent-encoded with `quote(v, safe="")` (so a literal `#`->`%23`, `'`->`%27`, `!`->`%21`);
JSON string bodies keep the literal character. `Content-Type` is the last header of a body request.

Standard library only. Deterministic: the same seed yields byte-identical files.

    python3 scripts/evaluation/minimal_pair_probe_v2_cases.py --out-dir reports/v5/minimal-pair-probe-v2
"""

import argparse
import hashlib
import json
import os
import random
import sys
from dataclasses import dataclass
from urllib.parse import quote

GENERATOR_VERSION = "v5-minimal-pairs-v2/generator-2"
SEED = 20261007
DATA_ROLE = ("DEVELOPMENT DIAGNOSTIC (minimal-pair probe v2). Never V5 training, validation or "
             "checkpoint-selection data; never copied into a V5 generator.")
REPEAT_FRACTION = 0.10
REPEAT_RUNS = 3

# ── Pools (probe-only; hashed into the manifest; no v1 value reuse) ─────────────────────────
POOLS = {
    "hosts": ["members.example.com", "centre.example.org", "signup.example.net",
              "desk.example.org", "hub.example.com", "classes.example.net"],
    "user_agents": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
        "curl/8.9.1", "python-httpx/0.27.0", "Go-http-client/2.0"],
    "accepts": ["*/*", "text/html,application/xhtml+xml", "application/json"],
    # ADDRESS. Neutral prose: benign free text, NO digits, NO location / delivery / street words
    # (30 distinct; opinions and thanks, so the `address`-name test is not blunted by location text).
    "addr_prose": [
        "the session was really enjoyable", "thank you for the warm welcome",
        "everyone was very friendly today", "the staff went above and beyond",
        "i had a wonderful afternoon here", "the atmosphere felt calm and open",
        "the talk was genuinely inspiring", "my family enjoyed every minute",
        "the volunteers were so patient", "it was a lovely relaxed morning",
        "the music made the day special", "i left feeling really refreshed",
        "the group was warm and welcoming", "such a thoughtful little event",
        "the energy in the room was great", "i learned so much and had fun",
        "the organisers did a superb job", "a cheerful and friendly crowd",
        "the mood was upbeat throughout", "a gentle and pleasant experience",
        "the hosts were kind and funny", "everything felt unhurried and easy",
        "a genuinely heartwarming visit", "the company was delightful today",
        "i felt welcome from the start", "a bright and happy gathering",
        "the whole thing was a joy", "people were generous with time",
        "a calm and contented afternoon", "the warmth here is wonderful"],
    "streets": ["Cedar Grove", "Willow Bend", "Granite Court", "Meadow Rise", "Tanner Lane",
                "Bevel Street", "Kestrel Walk", "Dunmore Road", "Sorrel Close", "Hartley Row"],
    "numfmt_labels": ["Bay", "Shelf", "Rack", "Unit", "Berth", "Stall", "Booth", "Crate"],
    "pass_alphabet": "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789",
    "slot_nouns": ["aisle", "bay", "locker", "rack", "stall", "berth", "booth", "kiosk",
                   "cubby", "niche", "pod", "crate", "ledge", "alcove", "cabinet"],
    # APOSTROPHE pools: (plain, apostrophe) — exactly one "'" added, same letters.
    "apos_contraction": [
        ("its open late", "it's open late"), ("were nearly full", "we're nearly full"),
        ("youre welcome here", "you're welcome here"), ("dont miss friday", "don't miss friday"),
        ("cant wait for it", "can't wait for it"), ("well see you then", "we'll see you then"),
        ("its a great turnout", "it's a great turnout"), ("theyre all booked", "they're all booked"),
        ("shes leading today", "she's leading today"), ("hes on the desk", "he's on the desk"),
        ("lets meet at noon", "let's meet at noon"), ("youll enjoy this", "you'll enjoy this"),
        ("wont take long", "won't take long"), ("isnt it lovely", "isn't it lovely"),
        ("weve added seats", "we've added seats")],
    "apos_possessive": [
        ("the clubs schedule", "the club's schedule"), ("a members pass", "a member's pass"),
        ("the teams list", "the team's list"), ("the owners note", "the owner's note"),
        ("the childs seat", "the child's seat"), ("the drivers entrance", "the driver's entrance"),
        ("the writers group", "the writer's group"), ("the singers night", "the singer's night"),
        ("the readers corner", "the reader's corner"), ("the bakers table", "the baker's table"),
        ("the painters studio", "the painter's studio"), ("the dancers warmup", "the dancer's warmup"),
        ("the gardeners shed", "the gardener's shed"), ("the makers fair", "the maker's fair"),
        ("the sailors knot", "the sailor's knot")],
    "apos_title": [
        ("childrens hour", "children's hour"), ("winters tale", "winter's tale"),
        ("travellers guide", "traveller's guide"), ("beginners circle", "beginner's circle"),
        ("painters palette", "painter's palette"), ("sailors log", "sailor's log"),
        ("farmers market", "farmer's market"), ("new years social", "new year's social"),
        ("mothers day tea", "mother's day tea"), ("workers forum", "worker's forum"),
        ("teachers lounge", "teacher's lounge"), ("veterans meetup", "veteran's meetup"),
        ("founders week", "founder's week"), ("elders circle", "elder's circle"),
        ("artists alley", "artist's alley")],
    "apos_place": [
        ("kings lynn", "king's lynn"), ("queens ferry", "queen's ferry"),
        ("bishops waltham", "bishop's waltham"), ("marthas vineyard", "martha's vineyard"),
        ("shepherds bush", "shepherd's bush"), ("st johns wood", "st john's wood"),
        ("earls court", "earl's court"), ("barons court", "baron's court"),
        ("friars walk", "friar's walk"), ("coopers hill", "cooper's hill"),
        ("potters bar", "potter's bar"), ("hunters gate", "hunter's gate"),
        ("abbots way", "abbot's way"), ("priests lane", "priest's lane"),
        ("masons yard", "mason's yard")],
    # In-run surname positive control (fresh surnames; none overlap v1's apostrophe-surname pool).
    "apos_surname": [
        ("ocallaghan", "o'callaghan"), ("odriscoll", "o'driscoll"), ("oloughlin", "o'loughlin"),
        ("omahony", "o'mahony"), ("oquinn", "o'quinn"), ("oreardon", "o'reardon"),
        ("ohalloran", "o'halloran"), ("odea", "o'dea"), ("ofarrell", "o'farrell"),
        ("okane", "o'kane"), ("okelly", "o'kelly"), ("odwyer", "o'dwyer"),
        ("ohagan", "o'hagan"), ("onolan", "o'nolan"), ("omeara", "o'meara")],
    "cov_firsts": ["aria", "bodhi", "cleo", "dario", "esme", "finn", "gaia", "hugo", "iris",
                   "juno", "kian", "lola", "milo", "nadia", "otto", "pia", "rafa", "suki",
                   "theo", "uma", "vera", "wren", "yara", "zane"],
    "cov_lasts": ["abernathy", "bellweather", "crumb", "dunwoody", "everhart", "fennimore",
                  "gillespie", "harlow", "ingersoll", "janowski", "kettleby", "larkspur"],
    "paths_query": ["/centre/find", "/classes/browse", "/rooms/when", "/members/history",
                    "/desk/lookup", "/events/next"],
    "paths_body": ["/members/profile", "/classes/enrol", "/rooms/reserve", "/desk/request",
                   "/events/rsvp", "/feedback/add"],
}


def pools_sha256() -> dict:
    return {name: hashlib.sha256(json.dumps(v, ensure_ascii=False, sort_keys=True)
                                 .encode("utf-8")).hexdigest() for name, v in sorted(POOLS.items())}


def enc(v: str) -> str:
    return quote(v, safe="")


@dataclass(frozen=True)
class Req:
    method: str
    path: str
    query: tuple = ()
    headers: tuple = ()
    content_type: str | None = None
    body: str | None = None

    def render(self) -> str:
        target = self.path
        if self.query:
            target += "?" + "&".join(f"{k}={v}" for k, v in self.query)
        lines = [f"{self.method} {target} HTTP/1.1"]
        lines += [f"{k}: {v}" for k, v in self.headers]
        if self.body is not None and self.content_type:
            lines.append(f"Content-Type: {self.content_type}")
        text = "\n".join(lines)
        if self.body is not None:
            text += "\n\n" + self.body
        return text


def form_body(fields) -> str:
    return "&".join(f"{k}={enc(v)}" for k, v in fields)


def envelope(rng, host=None):
    return (("Host", host or rng.choice(POOLS["hosts"])),
            ("User-Agent", rng.choice(POOLS["user_agents"])),
            ("Accept", rng.choice(POOLS["accepts"])))


def carrier_render(carrier, rng, field_value_by_level, method=None, headers=None):
    """Render each level in a fixed carrier; only the (field, value) differs between levels."""
    method = method or rng.choice(["POST", "POST", "PUT", "PATCH"])
    headers = headers if headers is not None else envelope(rng)
    if carrier == "query":
        path = rng.choice(POOLS["paths_query"])
        return {lv: Req("GET", path, query=((f, enc(v)),), headers=headers)
                for lv, (f, v) in field_value_by_level.items()}
    path = rng.choice(POOLS["paths_body"])
    if carrier == "json":
        return {lv: Req(method, path, headers=headers, content_type="application/json",
                        body=json.dumps({f: v})) for lv, (f, v) in field_value_by_level.items()}
    return {lv: Req(method, path, headers=headers, content_type="application/x-www-form-urlencoded",
                    body=form_body([(f, v)])) for lv, (f, v) in field_value_by_level.items()}


def _insert(s, ch, pos):
    return s[:pos] + ch + s[pos:]


def _token(rng, n=10):
    return "".join(rng.choice(POOLS["pass_alphabet"]) for _ in range(n))


# ── Factors. Each builder returns (levels: {level: Req}, stratum: str) for base i. ──────────
def f2_addr(rng, i):
    carrier = "query" if i % 2 == 0 else "body"
    prose = POOLS["addr_prose"][i]
    n, street, unit = rng.randint(2, 180), rng.choice(POOLS["streets"]), rng.randint(1, 60)
    street_val = f"{n} {street} Apt {unit}"                 # two numbers, capitalised
    la, lb = rng.sample(POOLS["numfmt_labels"], 2)
    numfmt = f"{la} {rng.randint(2, 90)} {lb} {rng.randint(2, 90)}"   # capitalised, two numbers, not an address
    levels = carrier_render(carrier, rng, {
        "n_prose":  ("detail", prose),
        "n2_prose": ("remark", prose),                      # neutral->neutral rename control
        "n_street": ("detail", street_val),
        "n_numfmt": ("detail", numfmt),
        "a_prose":  ("address", prose),
        "a_street": ("address", street_val),
    })
    return levels, carrier


HASH_CONTEXTS = ["passlike", "identifier", "generic", "json_text"]


def f2_hash(rng, i):
    ctx = HASH_CONTEXTS[i % len(HASH_CONTEXTS)]
    if ctx == "passlike":
        base = _token(rng, 10)
        pos = rng.randint(3, 7)
        field, carrier = "passcode", "body"
    elif ctx == "identifier":
        noun, num = rng.choice(POOLS["slot_nouns"]), rng.randint(2, 40)
        base, pos = f"{noun} {num}", len(noun) + 1
        field, carrier = "ref_code", "query"
    else:  # generic (form) and json_text (JSON) share field and template: only carrier+encoding differ
        noun, num, m = rng.choice(POOLS["slot_nouns"]), rng.randint(2, 9), rng.randint(10, 40)
        base, pos = f"{noun} {num} of {m}", len(noun) + 1
        field = "caption"
        carrier = "body" if ctx == "generic" else "json"
    levels = carrier_render(carrier, rng, {
        "base": (field, base),
        "hash": (field, _insert(base, "#", pos)),
        "punct": (field, _insert(base, "!", pos)),   # covered punctuation that also %-encodes (%21)
    })
    return levels, ctx


# class -> (pool name, field, carrier)
APOS_CLASSES = [("contraction", "apos_contraction", "caption", "body"),
                ("possessive", "apos_possessive", "caption", "query"),
                ("title", "apos_title", "display_label", "body"),
                ("place_json", "apos_place", "place_label", "json"),
                ("surname", "apos_surname", "full_name", "body")]


def f2_apos(rng, i):
    cls, pool, field, carrier = APOS_CLASSES[i % len(APOS_CLASSES)]
    plain, apos = POOLS[pool][i // len(APOS_CLASSES)]
    levels = carrier_render(carrier, rng, {"plain": (field, plain), "apostrophe": (field, apos)})
    return levels, cls


COV_STRATA = ["handle", "prose", "token", "json"]


def control_cov2(rng, i):
    """Instability control, stratified to match the three questions' domains (10 bases each)."""
    stratum = COV_STRATA[i % len(COV_STRATA)]
    if stratum == "handle":
        a = (rng.choice(POOLS["cov_firsts"]) + rng.choice(["", "_", "."])
             + rng.choice(POOLS["cov_lasts"] + [str(rng.randint(2, 98))]))
        b = a
        while b == a:
            b = (rng.choice(POOLS["cov_firsts"]) + rng.choice(["", "_", "."])
                 + rng.choice(POOLS["cov_lasts"] + [str(rng.randint(2, 98))]))
        field, carrier = "display_name", ("query" if (i // len(COV_STRATA)) % 2 == 0 else "body")
    elif stratum == "prose":
        a, b = rng.sample(POOLS["addr_prose"], 2)
        field, carrier = "detail", "body"
    elif stratum == "token":
        a, b = _token(rng, 10), _token(rng, 10)
        field, carrier = "passcode", "body"
    else:  # json string value, same carrier as the json test strata
        n1, n2 = rng.sample(POOLS["slot_nouns"], 2)
        a = f"{n1} {rng.randint(2, 9)} of {rng.randint(10, 40)}"
        b = f"{n2} {rng.randint(2, 9)} of {rng.randint(10, 40)}"
        field, carrier = "comment_text", "json"
    levels = carrier_render(carrier, rng, {"val_a": (field, a), "val_b": (field, b)})
    return levels, stratum


# factor id -> (block, n_bases, builder, [(reference, level), ...], tests)
FACTORS = {
    "F2-ADDR": ("CONTENT", 30, f2_addr,
                [("n_prose", "n_street"), ("n_prose", "n_numfmt"), ("n_numfmt", "n_street"),
                 ("n_prose", "a_prose"), ("n_street", "a_street"), ("n_prose", "n2_prose")],
                "M-content (address name/value/format isolation; n2_prose = rename control)"),
    "F2-HASH": ("CONTENT", 60, f2_hash,
                [("base", "hash"), ("base", "punct"), ("punct", "hash")],
                "M-content (# across contexts; punct = covered-char control; punct->hash = #-specificity)"),
    "F2-APOS": ("CONTENT", 75, f2_apos,
                [("plain", "apostrophe")],
                "M-content (apostrophe across classes; surname stratum = in-run positive control)"),
    "CONTROL-COV2": ("CONTROL", 40, control_cov2,
                     [("val_a", "val_b")], "M-instability (content), stratified over test domains"),
}


def text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def generate(seed: int = SEED):
    cases, comparisons = [], []
    used_texts = set()
    for fid, (block, n_bases, builder, comps, tests) in FACTORS.items():
        for i in range(n_bases):
            for attempt in range(1000):
                rng = random.Random(f"{seed}|{fid}|{i}|{attempt}")
                levels, stratum = builder(rng, i)
                texts = {req.render() for req in levels.values()}
                if len(texts) == len(levels) and not texts & used_texts:
                    break
            else:
                raise RuntimeError(f"{fid}: cannot draw a distinct base {i}")
            used_texts |= texts
            for lv, req in levels.items():
                text = req.render()
                cases.append({"case_id": f"{fid}|b{i:02d}|{lv}", "factor": fid, "block": block,
                              "base": i, "level": lv, "stratum": stratum,
                              "text": text, "text_sha256": text_sha256(text)})
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
        "probe": "v5-minimal-pairs-v2", "generator_version": GENERATOR_VERSION, "seed": SEED,
        "data_role": DATA_ROLE, "label_of_every_case": "benign (by construction)",
        "cases_file": "cases.jsonl", "cases_sha256": cases_sha,
        "n_cases": len(cases), "n_unique_texts": len({c["text_sha256"] for c in cases}),
        "factors": {fid: {"block": b, "n_bases": n, "tests": t}
                    for fid, (b, n, _, _, t) in FACTORS.items()},
        "strata": {fid: sorted({c["stratum"] for c in cases if c["factor"] == fid})
                   for fid in FACTORS},
        "comparisons": comparisons,
        "repeat_control": {"fraction": REPEAT_FRACTION, "runs": REPEAT_RUNS, "text_sha256": repeat},
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
