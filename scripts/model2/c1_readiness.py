"""Synthetic-only D1/canonical feature audit. No dataset inputs or model fitting.

Uses the actual gateway renderer, adapter and feature extractor. Reports fixture
IDs and changed field names, not request text or feature values. Run with:
  .venv-dataplane/bin/python -B -m scripts.model2.c1_readiness
"""
import dataclasses
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "data_plane"))
import canonical_adapter as adapter
import canonical_request as cr
import request_features as rf


def deny_dataset_reads(event, args):
    """Extra execution guard, not a general filesystem security boundary."""
    if event == "open" and isinstance(args[0], (str, bytes, os.PathLike)):
        if "datasets" in Path(os.fsdecode(args[0])).resolve().parts:
            raise PermissionError("dataset access forbidden in synthetic C1 audit")


@dataclasses.dataclass(frozen=True)
class Case:
    id: str
    method: bytes = b"GET"
    target: bytes = b"/synthetic"
    headers: tuple = ((b"Host", b"synthetic.invalid"),)
    body: bytes = b""
    version: bytes = b"HTTP/1.1"


def fixtures():
    form = ((b"Content-Type", b"application/x-www-form-urlencoded"),)
    js = ((b"Content-Type", b"application/json"),)
    gz = form + ((b"Content-Encoding", b"gzip"),)
    return (
        Case("empty_get"),
        Case("encoded_query", target=b"/search?q=O%27Brien&next=https%3A%2F%2Fexample.invalid"),
        Case("form", b"POST", b"/submit", form, b"name=O%27Brien&note=hello+world"),
        Case("json", b"POST", b"/api", js, b'{"n":2,"ok":true,"items":[1,2]}'),
        Case("utf8_body", b"POST", b"/submit", form, "name=José".encode()),
        Case("invalid_utf8", b"POST", b"/submit", form, b"name=\xff"),
        Case("literal_escape", b"POST", b"/submit", form, b"name=\\xff"),
        Case("gzip_one", b"POST", b"/submit", gz, gzip.compress(b"a=1", mtime=0)),
        Case("gzip_two", b"POST", b"/submit", gz,
             gzip.compress(b"a=1", mtime=0) + gzip.compress(b"&b=2", mtime=0)),
        Case("gzip_invalid", b"POST", b"/submit", gz, b"not-gzip"),
        Case("json_wrong_shape", b"POST", b"/api", js, b"{broken"),
        Case("duplicate_content_type", b"POST", b"/submit", form + form, b"x=1"),
        Case("double_encoding", target=b"/search?q=%2527"),
        Case("invalid_target_utf8", target=b"/search?q=\xff"),
        Case("asterisk", b"OPTIONS", b"*"),
        Case("http10", version=b"HTTP/1.0"),
        Case("host_ua_a", headers=((b"Host", b"first.invalid"), (b"User-Agent", b"fixture-a"))),
        Case("host_ua_b", headers=((b"Host", b"second.invalid"), (b"User-Agent", b"fixture-b"))),
    )


def compare(case):
    import data_plane as gateway
    from mitmproxy import http
    from mitmproxy.test import tutils
    request = tutils.treq(method=case.method, path=case.target, authority=b"",
                         http_version=case.version, headers=http.Headers(case.headers), content=case.body)
    snapshot = adapter.build_snapshot(request, 1)
    canonical = cr.canonicalize(adapter.snapshot_to_parts(snapshot), cr.Limits(1_048_576))
    row = {"fixture": case.id, "canonical_outcome": canonical.outcome,
           "canonical_reject": canonical.reject, "canonical_signals": list(canonical.signals),
           "canonical_size": canonical.size, "d1_error": None,
           "compared": False, "equal": None, "changed_fields": []}
    try:
        before = rf.extract_features(gateway.render_request(request))
    except (UnicodeError, ValueError, TypeError) as exc:
        row["d1_error"] = type(exc).__name__
        return row
    if canonical.outcome != cr.ACCEPT:
        return row
    after = rf.extract_features(canonical.text)
    row["compared"] = True
    row["changed_fields"] = [f.name for f in dataclasses.fields(rf.RequestFeatures)
                              if getattr(before, f.name) != getattr(after, f.name)]
    row["equal"] = not row["changed_fields"]
    return row


def source_hashes():
    paths = ("data_plane/request_features.py", "data_plane/canonical_adapter.py",
             "data_plane/canonical_request.py", "data_plane/data_plane.py",
             "scripts/model2/c1_readiness.py", "scripts/model2/contracts.py",
             "scripts/model2/evaluation.py")
    return {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in paths}


def report():
    before = source_hashes()
    rows = [compare(case) for case in fixtures()]
    if before != source_hashes():
        raise RuntimeError("audited source changed during execution; rerun")
    from importlib.metadata import version
    return {"schema": "model2-c1-readiness/v1", "scope": "synthetic-only, no fitting",
            "python": sys.version.split()[0], "mitmproxy": version("mitmproxy"),
            "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                                text=True).strip(),
            "source_sha256": before, "feature_schema": rf.FEATURE_SCHEMA_VERSION,
            "feature_count": len(dataclasses.fields(rf.RequestFeatures)) - 1,
            "cases": rows,
            "summary": {"total": len(rows), "compared": sum(r["compared"] for r in rows),
                        "different": sum(r["equal"] is False for r in rows),
                        "d1_errors": sum(r["d1_error"] is not None for r in rows),
                        "canonical_rejected": sum(r["canonical_outcome"] == cr.REJECT for r in rows)},
            "limitations": ["No training data, labels, weights or protected evaluation read.",
                            "Parity does not establish C1 completeness or model quality.",
                            "No framing verification, deployment or training approval.",
                            "Lab decode cap; token budget unset, size UNCHECKED.",
                            "Dataset guard is not a sandbox against aliases or copied files."]}


def main():
    if len(sys.argv) != 1:
        raise SystemExit("This synthetic audit accepts no input or dataset arguments")
    sys.addaudithook(deny_dataset_reads)
    print(json.dumps(report(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
