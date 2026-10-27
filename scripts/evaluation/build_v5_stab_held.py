#!/usr/bin/env python3
"""Build an independent, sealed V5 stability set without model predictions.

The set is created once in a new directory. Its rows must remain unread by the
training path and are evaluated only through the post-freeze single-run guard.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "v5-stab-held/v1"
SALT = "v5-stab-held-independent-2026-10-25-v1"
ROOT_WORDS = ("arven", "bellora", "cressin", "dalmere", "elvora", "farsen",
              "gilmore", "hevrin", "isola", "jandor", "kelven", "lorien")
CARRIERS = ("query", "form", "json")
HIGH_FAMILIES = ("percent_punctuation", "apostrophe_name", "apostrophe_prose",
                 "street_address", "typed_multikey_json", "password_punctuation",
                 "external_http_url", "chunked_envelope")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def token(*parts: object) -> str:
    return digest("|".join([SALT, *map(str, parts)]).encode())[:12]


def neutral(carrier: str, i: int, side: int) -> str:
    return f"{ROOT_WORDS[(i + side * 5) % len(ROOT_WORDS)]}-{token(carrier, i, side)[:7]}"


def render(carrier: str, value: str | dict, pair_key: str) -> str:
    path = f"/research-stability/{pair_key}"
    if carrier == "query":
        return f"GET {path}?ledger_note={quote(str(value), safe='')}&ledger_mode=summary HTTP/1.1\n"
    if carrier == "form":
        body = f"ledger_note={quote(str(value), safe='')}&ledger_mode=summary"
        return (f"POST {path} HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\n{body}")
    if carrier == "json":
        payload = value if isinstance(value, dict) else {"ledger_note": value, "ledger_mode": "summary"}
        return (f"POST {path} HTTP/1.1\nContent-Type: application/json\n\n"
                + json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    raise ValueError(carrier)


def chunked_source_wire(canonical_text: str) -> bytes:
    """Construct a valid raw chunked envelope for an already-rendered form body."""
    head, body = canonical_text.split("\n\n", 1)
    if not head.startswith("POST ") or "Content-Type: application/x-www-form-urlencoded" not in head:
        raise ValueError("chunked contrast requires form POST")
    payload = body.encode("utf-8")
    header = head.replace("\n", "\r\n").encode("ascii")
    return (header + b"\r\nTransfer-Encoding: chunked\r\n\r\n"
            + f"{len(payload):X}".encode("ascii") + b"\r\n" + payload + b"\r\n0\r\n\r\n")


def contrast(family: str, i: int) -> tuple[str, str | dict, str | dict]:
    marker = token(family, i)[:6]
    if family == "percent_punctuation":
        return "query", f"catalog-{marker}", f"catalog%2F{marker}"
    if family == "apostrophe_name":
        return "form", f"Daven{marker}", f"D'aven{marker}"
    if family == "apostrophe_prose":
        return "json", f"the maker note {marker}", f"the maker's note {marker}"
    if family == "street_address":
        return "form", f"{i+21} Kestrel Mews {marker}", f"Suite {i+21}, Kestrel Mews {marker}"
    if family == "typed_multikey_json":
        return "json", {"ledger_note": f"item-{marker}", "count": i+1, "flag": True}, {
            "ledger_note": f"item-{marker}", "count": str(i+1), "flag": True}
    if family == "password_punctuation":
        return "form", f"Lumen{marker}8", f"Lumen!{marker}8"
    if family == "external_http_url":
        return "query", f"https://catalogue-stability.invalid/item/{marker}", f"http://catalogue-stability.invalid/item/{marker}"
    if family == "chunked_envelope":
        # `canonical_request` consumes transfer framing before model text. The
        # source framing contrast is kept in metadata, while a benign value
        # swap keeps the two canonical model inputs distinct.
        return "form", f"ledger-{marker}-a", f"ledger-{marker}-b"
    raise ValueError(family)


def build() -> list[dict]:
    rows = []

    def add(kind: str, family: str, carrier: str, i: int, side: str,
            label: str, value: str | dict, pair_key: str) -> None:
        element = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                   if isinstance(value, dict) else value)
        text = render(carrier, value, pair_key)
        chunked = family == "chunked_envelope" and side == "B"
        rows.append({"schema": SCHEMA, "role": "STAB-HELD", "kind": kind,
                     "family": family, "carrier": carrier, "pair_id": pair_key,
                     "side": side, "label": label,
                     "case_id": token(kind, family, carrier, i, side),
                     "value_element": element,
                     "text": text,
                     "source_framing": "chunked" if chunked else "identity",
                     "source_wire_sha256": digest(chunked_source_wire(text)) if chunked else None})

    for carrier in CARRIERS:
        for i in range(100):
            pair_key = token("control", carrier, i)
            add("control", "same_class_swap", carrier, i, "A", "ALLOW", neutral(carrier, i, 0), pair_key)
            add("control", "same_class_swap", carrier, i, "B", "ALLOW", neutral(carrier, i, 1), pair_key)

    for family in HIGH_FAMILIES:
        for i in range(30):
            carrier, a, b = contrast(family, i)
            pair_key = token("contrast", family, i)
            add("contrast", family, carrier, i, "A", "ALLOW", a, pair_key)
            add("contrast", family, carrier, i, "B", "ALLOW", b, pair_key)

    # Fresh project-authored attack twins; exact strings differ from the V5
    # source pool by the independent, deterministic per-pair marker.
    for carrier in CARRIERS:
        for i in range(30):
            marker = token("attack", carrier, i)[:8]
            payload = (f"' OR '{marker}'='{marker}'--" if carrier == "query" else
                       f";printf STAB{marker}" if carrier == "form" else
                       f"<svg onload=alert(0x{marker[:4]})>")
            pair_key = token("attack-twin", carrier, i)
            add("attack_twin", "attack_control", carrier, i, "A", "ALLOW",
                neutral(carrier, i, 2), pair_key)
            add("attack_twin", "attack_control", carrier, i, "B", "BLOCK",
                payload, pair_key)
    return rows


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    if a.out.exists():
        raise SystemExit("output directory exists: sealed set is never overwritten")
    rows = build()
    a.out.mkdir(parents=True)
    data = b"".join((json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n").encode() for r in rows)
    (a.out / "cases.jsonl").write_bytes(data)
    counts = Counter((r["kind"], r["family"], r["carrier"], r["label"]) for r in rows)
    manifest = {"schema": "v5-stab-held-manifest/v1", "status": "CANDIDATE_NOT_SEALED",
                "role": "STAB-HELD", "salt_sha256": digest(SALT.encode()),
                "generator_sha256": digest(Path(__file__).read_bytes()),
                "cases_sha256": digest(data), "cases": len(rows),
                "counts": [{"kind": k[0], "family": k[1], "carrier": k[2],
                            "label": k[3], "rows": v} for k, v in sorted(counts.items())],
                "control_base_pairs_per_carrier": 100,
                "high_contrast_base_pairs_per_family": 30,
                "attack_twin_base_pairs_per_carrier": 30,
                "evaluation_read_once": True, "training_authorized": False}
    (a.out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"cases": len(rows), "status": manifest["status"],
                      "cases_sha256": manifest["cases_sha256"]}, sort_keys=True))


if __name__ == "__main__":
    main()
