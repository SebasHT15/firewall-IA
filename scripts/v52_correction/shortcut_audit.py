"""Check obvious lexical shortcuts in a proposed, unprotected V5.2 delta.

This is a diagnostic classifier, not a Firewall-IA candidate or a quality
estimate. It uses only delta TRAIN and VALIDATION and never opens protected
roles, the V5.1 parent, or model weights.
"""
import argparse
from collections import Counter
import hashlib
import ipaddress
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load_rows(desc):
    path = Path(desc["path"])
    raw = path.read_bytes()
    if sha(raw) != desc["sha256"] or len(raw) != desc["bytes"]:
        raise ValueError("delta artifact changed")
    rows = [json.loads(line) for line in raw.splitlines()]
    if len(rows) != desc["rows"]:
        raise ValueError("delta row count changed")
    return rows


def confusion(rows, prediction):
    counts = Counter((row["label"], bool(pred)) for row, pred in zip(rows, prediction))
    return {"TP": counts[("BLOCK", True)], "TN": counts[("ALLOW", False)],
            "FP": counts[("ALLOW", True)], "FN": counts[("BLOCK", False)]}


def fetch_host(row):
    target = row["text"].split(" ", 2)[1]
    url = parse_qs(urlsplit(target).query)["url"][0]
    return urlsplit(url).hostname


def run(manifest_path, output):
    manifest_raw = manifest_path.read_bytes()
    manifest = json.loads(manifest_raw)
    if manifest.get("schema") != "v52-correction-delta-candidate/v1":
        raise ValueError("wrong delta manifest")
    train = load_rows(manifest["delta_artifacts"]["TRAIN"])
    validation = load_rows(manifest["delta_artifacts"]["VALIDATION"])
    vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(3, 5), min_df=2)
    train_x = vectorizer.fit_transform([row["text"] for row in train])
    validation_x = vectorizer.transform([row["text"] for row in validation])
    clf = LogisticRegression(max_iter=1000, random_state=0)
    clf.fit(train_x, [row["label"] == "BLOCK" for row in train])
    predictions = [bool(x) for x in clf.predict(validation_x)]
    family = {}
    for name in sorted({row["family"] for row in validation}):
        idx = [i for i, row in enumerate(validation) if row["family"] == name]
        family[name] = confusion([validation[i] for i in idx], [predictions[i] for i in idx])
    host_rule = {}
    for split, rows in (("TRAIN", train), ("VALIDATION", validation)):
        ssrf = [row for row in rows if row["family"] == "ssrf"]
        guesses = [ipaddress.ip_address(fetch_host(row)).is_private
                   if fetch_host(row).replace(".", "").isdigit() else False for row in ssrf]
        host_rule[split] = confusion(ssrf, guesses)
    result = {
        "schema": "v52-correction-shortcut-audit/v1",
        "scope": "DIAGNOSTIC_ONLY_NOT_MODEL_QUALITY",
        "manifest_sha256": sha(manifest_raw),
        "script_sha256": sha(Path(__file__).read_bytes()),
        "lexical_probe": {"method": "TF-IDF character 3-5 grams; logistic regression C=1; TRAIN delta only",
                          "validation": confusion(validation, predictions), "families": family},
        "ssrf_private_ip_only_rule": host_rule,
        "interpretation": [
            "A private-IP-only SSRF rule no longer separates labels; both callback names occur in both classes.",
            "The lexical probe still separates all delta validation rows. Shared route and path cues make this split easy for a shallow model.",
            "This does not estimate performance on a new application, new attack syntax, or the protected test.",
        ],
        "protected_opened": False,
        "candidate_selected": None,
    }
    with output.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.manifest, args.output), sort_keys=True))
