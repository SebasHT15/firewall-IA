"""Build a reviewable V5.2 correction delta from explicit application policies.

No training, model predictions, protected data or backend effect claims. The
private delta lives outside the repository; this script writes hashes and a
public protocol for review before any owner admission.
"""
import argparse
from collections import Counter
import hashlib
import ipaddress
import json
from pathlib import Path
import posixpath
import re
from urllib.parse import parse_qs, urlencode, urlsplit


REPO = Path(__file__).resolve().parents[2]
RETENTION = REPO / "reports/v5/successor-training-2026-10-31-reviewed/DATA_RETENTION.json"
DOCKER_CASES = REPO / "reports/v5/docker-application-2026-11-02/run-1/cases.jsonl"
DOCKER_PRIVATE = Path("/home/sebas/Documents/Codex/2026-10-26/ta/work/docker-application-20261102-run1/cases.private.jsonl")
OLD_DEV = Path("/home/sebas/Documents/Codex/2026-10-26/ta/work/metrics-2026-10-30/inputs.private.jsonl")
RECIPE = REPO / "reports/v5/successor-training-2026-10-31-reviewed/recipe.EXPERIMENTAL.json"
TARGET = REPO / "scripts/v5_successor/docker_eval/target.py"
ALLOW = "ALLOW | Normal HTTP request with no attack patterns detected."
REASONS = {
    "ssrf": "Server-side request forgery attack detected.",
    "open_redirect": "Open redirect payload detected.",
    "path_traversal": "Path traversal attack detected.",
}
SCHEMA = "v52-correction-delta-candidate/v1"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def rows(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def canonical(target):
    return "GET " + target + " HTTP/1.1\n"


def make_row(split, family, template, pair, label, target, *, policy):
    text = canonical(target)
    reason = REASONS.get(family) if label == "BLOCK" else None
    return {
        "schema": "v52-correction-example/v1", "split": split,
        "id": f"v52-{split.lower()}-{family}-{template}-{pair:03d}-{label.lower()}",
        "component_id": f"v52-{family}-template-{template}",
        "pair_id": f"v52-{split.lower()}-{family}-{template}-{pair:03d}",
        "family": family, "label": label, "label_status": "POLICY_DEFINED",
        "policy_id": policy, "text": text, "text_sha256": sha(text.encode()),
        "output": ALLOW if label == "ALLOW" else "BLOCK | " + reason,
        "reason": reason,
        "effect_evidence": "NOT_RUN; policy reference only",
    }


def callback_ip():
    hosts = set()
    for case in rows(DOCKER_PRIVATE):
        if case["family"] == "ssrf" and case["label"] == "BLOCK":
            url = parse_qs(urlsplit(case["target"]).query)["url"][0]
            hosts.add(urlsplit(url).hostname)
    if len(hosts) != 1:
        raise ValueError("callback host not unique")
    host = hosts.pop()
    if not ipaddress.ip_address(host).is_private:
        raise ValueError("callback is not a private lab address")
    return host


def fetch_pair(t, i, callback):
    n = 1000 + i
    # The callback container has both an assets alias and a private-IP name.
    # It returns a synthetic secret for /internal/ on EITHER host. Cross the
    # names so the model cannot use the host alone as a label shortcut.
    allow_host, block_host = [
        ("assets.fwlab.test", callback),
        (callback, "assets.fwlab.test"),
        ("assets.fwlab.test", "assets.fwlab.test"),
        (callback, callback),
        ("assets.fwlab.test", callback),
        (callback, "assets.fwlab.test"),
    ][t]
    public_path = ["info", "manual", "catalog", "thumb", "guide", "release"][t]
    private_path = ["token", "session", "status", "account", "key", "profile"][t]
    benign = f"http://{allow_host}:9200/public/{public_path}?doc={n}"
    private = f"http://{block_host}:9200/internal/{private_path}?doc={n}"
    return ("/fetch?" + urlencode({"url": benign, "view": n}),
            "/fetch?" + urlencode({"url": private, "view": n}))


def redirect_pair(t, i):
    n = 1000 + i
    local = [
        f"/products/{n % 23 + 1}",
        f"http://shop.fwlab.test/products/{n % 23 + 1}",
        f"https://shop.fwlab.test/catalog?item={n}",
        f"//shop.fwlab.test/products/{n % 23 + 1}",
        f"http://shop.fwlab.test/catalog?item={n}",
        f"https://shop.fwlab.test/profile?item={n}",
    ][t]
    external = [
        f"http://collector{n % 17}.example.test/cb?item={n}",
        f"http://collector{n % 19}.example.test/cb?item={n}",
        f"https://collector{n % 13}.example.test/cb?item={n}",
        f"//collector{n % 11}.example.test/cb?item={n}",
        f"http://collector{n % 7}.example.test:9200/cb?item={n}",
        f"https://collector{n % 5}.example.test/out/receipt?order={n}",
    ][t]
    return ("/go?" + urlencode({"next": local, "view": n}),
            "/go?" + urlencode({"next": external, "view": n}))


def traversal_pair(t, i):
    n = 1000 + i
    benign = [
        "docs/../readme.txt", "./guide.txt", "public/../readme.txt",
        "public/../guide.txt", "docs//../guide.txt", "./readme.txt",
    ][t]
    private = [
        "docs/../../private/canary.txt", "../private/canary.txt",
        "x/../../private/canary.txt", "./../private/canary.txt",
        "docs//../../private/canary.txt", "../private//canary.txt",
    ][t]
    return ("/download?" + urlencode({"file": benign, "view": n}),
            "/download?" + urlencode({"file": private, "view": n}))


EDGE_TERMS = [
    "select a product manual", "curl quickstart guide", "shell necklace handbook",
    "script writing class", "union workers journal", "SQL learning notes",
    "redirect instruction booklet", "C++ primer", "2 < 5 classroom example",
    "{{name}} template tutorial", "café guide", "東京の商品案内",
    "naïve résumé collection", "safe & sound catalog", "../ paths explained",
    "http://example.test/reference", "<b>markup guide</b>", "127.0.0.1 networking book",
]


def generate(callback):
    result = []
    builders = {"ssrf": lambda t, i: fetch_pair(t, i, callback), "open_redirect": redirect_pair,
                "path_traversal": traversal_pair}
    policies = {"ssrf": "v52-app-fetch-private-target/v1",
                "open_redirect": "v52-app-redirect-external-location/v1",
                "path_traversal": "v52-app-download-private-file/v1"}
    for family, build in builders.items():
        for template in range(6):
            split = "TRAIN" if template < 4 else "VALIDATION"
            for pair in range(30 if split == "TRAIN" else 15):
                target_allow, target_block = build(template, pair + template * 100)
                for label, target in (("ALLOW", target_allow), ("BLOCK", target_block)):
                    result.append(make_row(split, family, template, pair, label, target,
                                           policy=policies[family]))
    for index, term in enumerate(EDGE_TERMS):
        split = "TRAIN" if index < 12 else "VALIDATION"
        for replica in range(5):
            n = 1000 + index * 10 + replica
            target = "/search?" + urlencode({"q": term + f" volume {n}", "view": n})
            row = make_row(split, "benign_edge", index, replica, "ALLOW", target,
                           policy="v52-app-search-literal-text/v1")
            result.append(row)
    return result


def check_policy(row, callback):
    target = row["text"].split(" ", 2)[1]
    parsed = urlsplit(target)
    params = parse_qs(parsed.query)
    label = row["label"]
    if row["family"] == "ssrf":
        url = urlsplit(params["url"][0])
        same_callback = (url.scheme == "http" and url.hostname in ("assets.fwlab.test", callback)
                         and url.port == 9200)
        benign = same_callback and url.path.startswith("/public/")
        private = same_callback and url.path.startswith("/internal/")
        if not (benign if label == "ALLOW" else private):
            raise ValueError("fetch policy mismatch")
    elif row["family"] == "open_redirect":
        url = urlsplit(params["next"][0])
        local = ((not url.scheme and not url.netloc)
                 or (url.scheme in ("", "http", "https") and url.hostname == "shop.fwlab.test"
                     and url.port is None))
        external = (url.scheme in ("", "http", "https") and url.hostname is not None
                    and url.hostname.startswith("collector") and url.hostname.endswith(".example.test"))
        if not (local if label == "ALLOW" else external):
            raise ValueError("redirect policy mismatch")
    elif row["family"] == "path_traversal":
        resolved = posixpath.normpath("/public/" + params["file"][0])
        # The disposable target has only these three synthetic files. A benign
        # path that stays under /public/ but returns 404 is a weak control.
        benign = resolved in ("/public/readme.txt", "/public/guide.txt")
        private = resolved == "/private/canary.txt"
        if not (benign if label == "ALLOW" else private):
            raise ValueError("download policy mismatch")
    elif row["family"] == "benign_edge":
        if parsed.path != "/search" or label != "ALLOW" or not params.get("q"):
            raise ValueError("search policy mismatch")
    else:
        raise ValueError("unknown family")


def verify_parent():
    retention = json.loads(RETENTION.read_text())
    parent = {}
    for split in ("TRAIN", "VALIDATION"):
        name = f"rows.{split}.jsonl"
        matches = [d for path, d in retention["files"].items()
                   if path.endswith("/v51-training-candidate-20261031-reviewed/" + name)]
        if len(matches) != 1:
            raise ValueError("parent rows missing: " + name)
        d = matches[0]
        path = Path(d["path"])
        raw = path.read_bytes()
        if sha(raw) != d["sha256"] or len(raw) != d["bytes"]:
            raise ValueError("parent rows changed: " + name)
        parent[split] = {"path": str(path), "sha256": d["sha256"],
                         "rows": len(raw.splitlines()), "bytes": len(raw)}
    return parent


def audit(data, parent, callback):
    by_split = {split: [r for r in data if r["split"] == split]
                for split in ("TRAIN", "VALIDATION")}
    if len({r["id"] for r in data}) != len(data):
        raise ValueError("duplicate IDs")
    hashes = {split: {r["text_sha256"] for r in by_split[split]}
              for split in by_split}
    if len(hashes["TRAIN"]) != len(by_split["TRAIN"]) or len(hashes["VALIDATION"]) != len(by_split["VALIDATION"]):
        raise ValueError("duplicate delta text")
    if hashes["TRAIN"] & hashes["VALIDATION"]:
        raise ValueError("TRAIN/VALIDATION delta text overlap")
    signatures = {split: {re.sub(r"\d+", "#", r["text"]) for r in by_split[split]}
                  for split in by_split}
    if signatures["TRAIN"] & signatures["VALIDATION"]:
        raise ValueError("TRAIN/VALIDATION template signature overlap")
    components = {split: {r["component_id"] for r in by_split[split]}
                  for split in by_split}
    if components["TRAIN"] & components["VALIDATION"]:
        raise ValueError("TRAIN/VALIDATION component overlap")
    old_hashes = set()
    for desc in parent.values():
        old_hashes |= {sha(r["text"].encode()) for r in rows(Path(desc["path"]))}
    if old_hashes & (hashes["TRAIN"] | hashes["VALIDATION"]):
        raise ValueError("delta overlaps V5.1 TRAIN/VALIDATION")
    docker_hashes = {r["canonical_sha256"] for r in rows(DOCKER_CASES)}
    old_dev_hashes = {r["canonical_sha256"] for r in rows(OLD_DEV)
                      if r.get("canonical_sha256")}
    if (docker_hashes | old_dev_hashes) & (hashes["TRAIN"] | hashes["VALIDATION"]):
        raise ValueError("delta overlaps known DEV")
    for split, members in by_split.items():
        pairs = {}
        for r in members:
            check_policy(r, callback)
            if r["text_sha256"] != sha(r["text"].encode()):
                raise ValueError("text integrity failure")
            if r["output"] != (ALLOW if r["label"] == "ALLOW" else "BLOCK | " + REASONS[r["family"]]):
                raise ValueError("label/reason mismatch")
            if r["family"] != "benign_edge":
                pairs.setdefault(r["pair_id"], []).append(r["label"])
        if any(sorted(labels) != ["ALLOW", "BLOCK"] for labels in pairs.values()):
            raise ValueError("incomplete pair")
    return {split: {"rows": len(members), "labels": dict(Counter(r["label"] for r in members)),
                    "families": dict(Counter(r["family"] for r in members)),
                    "components": len(components[split]), "paired_groups": len({r["pair_id"] for r in members
                                                                              if r["family"] != "benign_edge"})}
            for split, members in by_split.items()}


def run(private_dir, public_dir):
    if private_dir.exists() or public_dir.exists():
        raise FileExistsError("output directory exists")
    parent = verify_parent()
    callback = callback_ip()
    data = generate(callback)
    summary = audit(data, parent, callback)
    private_dir.mkdir(parents=True)
    public_dir.mkdir(parents=True)
    artifacts = {}
    for split in ("TRAIN", "VALIDATION"):
        path = private_dir / f"delta.{split}.jsonl"
        raw = "".join(json.dumps(r, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
                      for r in data if r["split"] == split).encode()
        with path.open("xb") as handle:
            handle.write(raw)
        path.chmod(0o600)
        artifacts[split] = {"path": str(path.resolve()), "sha256": sha(raw),
                            "bytes": len(raw), "rows": len(raw.splitlines())}
    manifest = {
        "schema": SCHEMA, "status": "PROPOSED_NO_TRAINING_AUTHORIZATION",
        "parent": parent, "delta_artifacts": artifacts, "summary": summary,
        "source_sha256": {str(Path(__file__).relative_to(REPO)): sha(Path(__file__).read_bytes()),
                          str(TARGET.relative_to(REPO)): sha(TARGET.read_bytes()),
                          str(RECIPE.relative_to(REPO)): sha(RECIPE.read_bytes()),
                          "private_docker_cases": sha(DOCKER_PRIVATE.read_bytes())},
        "label_basis": "POLICY_DEFINED for the disposable app; no new effect controls run",
        "static_application_policy_check": "PASS for fetch host/route, redirect destination, traversal resolution and search text",
        "known_dev_overlap": 0, "parent_overlap": 0, "train_validation_text_overlap": 0,
        "train_validation_component_overlap": 0, "train_validation_digit_normalized_signature_overlap": 0,
        "protected_opened": False,
        "training_authorized": False, "candidate_selected": None,
        "limits": ["Application-specific URL and route policy",
                   "Backend effects of delta examples have not been measured",
                   "Benign edge search examples are unpaired and need shortcut review",
                   "No independent test or deployment claim"],
    }
    path = public_dir / "MANIFEST.PROPOSED.json"
    with path.open("x", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, ensure_ascii=False, sort_keys=True)
        handle.write("\n")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-dir", type=Path, required=True)
    parser.add_argument("--public-dir", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.private_dir.resolve(), args.public_dir.resolve())
    print(json.dumps({"summary": result["summary"], "artifacts": result["delta_artifacts"]},
                     ensure_ascii=False, sort_keys=True))
