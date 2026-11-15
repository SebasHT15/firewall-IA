#!/usr/bin/env python3
"""Issue #64, section S4: header and category counts over V4-clean TRAIN (aggregates only).

Usage: python3 reports/v5/freeze-prep/s4_v4_train_header_counts.py datasets/v4_clean/train.jsonl
"""
import json, re, sys
from collections import Counter
c = Counter()
for line in open(sys.argv[1], encoding="utf-8"):
    r = json.loads(line); t = r["input"]; lab = r["output"].split(" |")[0]
    head = t.split("\n\n", 1)[0]
    has = lambda name: re.search(rf"(?im)^{name}\s*:", head)
    if has("Content-Length"): c[f"content_length_{lab}"] += 1
    if has("Transfer-Encoding"): c[f"transfer_encoding_{lab}"] += 1
    if has("Cookie"): c[f"cookie_{lab}"] += 1
    o, rf = has("Origin"), has("Referer")
    if o or rf: c[f"origin={bool(o)}_referer={bool(rf)}_{lab}"] += 1
    m = re.search(r"(?im)^Authorization:\s*(.*)$", head)
    if m:
        v = m.group(1)
        c[f"authorization_{lab}"] += 1
        if "JWT" in r["output"]:
            c["jwt_category_rows"] += 1
            c["jwt_category_value_starts_Bearer_eyJ"] += v.startswith("Bearer eyJ")
        if lab == "ALLOW":
            c["benign_auth_header_segment:" + v.split(".")[0]] += 1
    if "CSRF" in r["output"]:
        ov = re.search(r"(?im)^Origin:\s*(.*)$", head)
        ov = ov.group(1).strip() if ov else ""
        c["csrf_rows"] += 1
        c["csrf_origin_evil_or_attacker"] += bool(re.search(r"evil|attacker", ov, re.I))
        c["csrf_origin_null"] += ov == "null"
for k, v in sorted(c.items()): print(k, v)
