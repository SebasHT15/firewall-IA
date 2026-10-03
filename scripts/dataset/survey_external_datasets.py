"""
firewall-IA — verification measurements for the External Dataset Survey
(Hybrid Architecture Phase 2A, Issue #51).

Reads public datasets from LOCAL copies (or stdin) and prints the few statistics the
survey relies on: label co-occurrence (is a request ever labelled with more than one
attack type?), which headers are present, request bodies, duplicates. It integrates
nothing, trains nothing, and nothing it reads belongs in the repository. Sources and
download commands: reports/hybrid/phase2a-analyzer-design/README.md, "External
Dataset Survey".

    srbh       SR-BH 2020 CSV (Harvard Dataverse doi:10.7910/DVN/OGOIXX), path or "-"
    modsec30   "Thirty-Day ... ModSecurity" owasp.zip (Zenodo 10.5281/zenodo.17178461)
    modsecwp   ModSec-WP .xlsx (Zenodo 10.5281/zenodo.21872151)
    crs        coreruleset tests/regression/tests directory
    gotestwaf  gotestwaf testcases directory

    python3.12 scripts/dataset/survey_external_datasets.py srbh - < data_capec_multilabel.csv
"""

import argparse
import csv
import glob
import hashlib
import io
import json
import re
import sys
import zipfile
import xml.etree.ElementTree as ET
from collections import Counter


def srbh(path):
    stream = sys.stdin.buffer if path == "-" else open(path, "rb")
    rows = csv.reader(io.TextIOWrapper(stream, encoding="utf-8", errors="replace", newline=""))
    hdr = next(rows)
    labels = hdr[24:]
    n = 0
    lab, per_row, combos, dup, present = Counter(), Counter(), Counter(), Counter(), Counter()
    for row in rows:
        if len(row) != len(hdr):
            continue
        n += 1
        d = dict(zip(hdr, row))
        on = [l for l, v in zip(labels, row[24:]) if v.strip() == "1"]
        attacks = [l for l in on if not l.startswith("000")]
        lab.update(on)
        per_row[len(attacks)] += 1
        if len(attacks) > 1:
            combos[" + ".join(sorted(a.split(" - ")[0] for a in attacks))] += 1
        dup[hashlib.sha256("\0".join((d["request_http_method"], d["request_http_request"],
                                      d["request_body"])).encode()).hexdigest()] += 1
        for f in ("request_cookie", "request_body", "request_referer", "request_origin"):
            present[f] += bool(d[f])
    return {"columns": hdr, "rows": n, "label_counts": dict(lab),
            "attack_labels_per_row": dict(sorted(per_row.items())),
            "top_label_combinations": dict(combos.most_common(12)),
            "distinct_method_target_body": len(dup), "non_empty_fields": dict(present)}


def modsec30(path):
    z = zipfile.ZipFile(path)
    tx = body = 0
    headers, fam, per_tx, combos = Counter(), Counter(), Counter(), Counter()
    for name in z.namelist():
        if not name.endswith(".log"):
            continue
        text = z.read(name).decode("utf-8", "replace")
        for block in re.split(r"\n--[0-9a-f]{8}-A--\n", "\n" + text)[1:]:
            tx += 1
            sec = dict(re.findall(r"--[0-9a-f]{8}-([A-Z])--\n(.*?)(?=\n--[0-9a-f]{8}-[A-Z]--|\Z)",
                                  "--00000000-A--\n" + block, re.S))
            for line in sec.get("B", "").splitlines()[1:]:
                if ":" in line:
                    headers[line.split(":", 1)[0].strip().lower()] += 1
            body += bool(sec.get("C", "").strip())
            tags = set(re.findall(r'\[tag "attack-([a-z-]+)"\]', sec.get("H", "")))
            per_tx[len(tags)] += 1
            fam.update(tags)
            if len(tags) > 1:
                combos[" + ".join(sorted(tags))] += 1
    return {"transactions": tx, "with_request_body": body,
            "header_presence": {h: headers[h] for h in ("authorization", "cookie", "content-length",
                                                        "transfer-encoding", "referer", "origin")},
            "attack_family_tags_per_transaction": dict(sorted(per_tx.items())),
            "attack_family_counts": dict(fam.most_common()),
            "top_family_combinations": dict(combos.most_common(10))}


def modsecwp(path):
    z = zipfile.ZipFile(path)
    ns = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    names = z.namelist()
    shared = ([("".join(t.itertext())) for t in ET.fromstring(z.read("xl/sharedStrings.xml")).findall("m:si", ns)]
              if "xl/sharedStrings.xml" in names else [])

    def value(c):
        if c.get("t") == "s":
            return shared[int(c.find("m:v", ns).text)]
        t = c.find(".//m:t", ns)
        if t is not None:
            return t.text or ""
        v = c.find("m:v", ns)
        return v.text if v is not None else ""

    col = lambda ref: re.match(r"[A-Z]+", ref).group(0)
    rows = ET.fromstring(z.read("xl/worksheets/sheet1.xml")).findall(".//m:sheetData/m:row", ns)
    hdr = {col(c.get("r")): value(c) for c in rows[0]}
    label = next(k for k, v in hdr.items() if v == "label")
    return {"rows": len(rows) - 1, "columns": list(hdr.values()),
            "labels": dict(Counter(value(c) for r in rows[1:] for c in r
                                   if col(c.get("r")) == label).most_common())}


def crs(directory):
    import yaml
    tests = multi = benign = raw = 0
    families = Counter()
    for f in glob.glob(f"{directory}/**/*.yaml", recursive=True):
        doc = yaml.safe_load(open(f, encoding="utf-8")) or {}
        for t in doc.get("tests") or []:
            tests += 1
            families[f.split("/")[-2]] += 1
            for st in t.get("stages") or []:
                inp, log = st.get("input") or {}, ((st.get("output") or {}).get("log") or {})
                multi += len(log.get("expect_ids") or []) > 1
                benign += bool(log.get("no_expect_ids")) and not log.get("expect_ids")
                raw += bool(inp.get("encoded_request") or inp.get("raw_request"))
    return {"tests": tests, "stages_expecting_more_than_one_rule": multi,
            "benign_style_stages": benign, "raw_or_encoded_request_stages": raw,
            "tests_per_rule_family": dict(sorted(families.items()))}


def gotestwaf(directory):
    import yaml
    payloads, placeholders, unparseable = Counter(), Counter(), []
    for f in sorted(glob.glob(f"{directory}/**/*.y*ml", recursive=True)):
        try:
            doc = yaml.safe_load(open(f, encoding="utf-8")) or {}
        except yaml.YAMLError:
            unparseable.append(f.split(directory)[-1])
            continue
        payloads[f.split("/")[-2]] += len(doc.get("payload") or [])
        for p in doc.get("placeholder") or []:
            placeholders[p if isinstance(p, str) else next(iter(p))] += 1
    return {"payloads_per_set": dict(payloads), "placeholders": dict(placeholders.most_common()),
            "unparseable_files": unparseable}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("dataset", choices=["srbh", "modsec30", "modsecwp", "crs", "gotestwaf"])
    ap.add_argument("path")
    args = ap.parse_args()
    print(json.dumps(globals()[args.dataset](args.path), indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
