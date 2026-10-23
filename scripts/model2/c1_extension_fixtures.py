"""Reproducible built-in C1 evidence fixtures; no external input path."""
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sys

from . import c1_extensions as c1

ROOT = Path(__file__).resolve().parents[2]


def fixtures():
    return (
        ("query_url_and_tokens", b"/fixture?u=https%3A%2F%2Fa.invalid&word=select", b"", None),
        ("form_url_and_plus", b"/fixture", b"u=http%3A%2F%2Fa.invalid&phrase=a+b", b"application/x-www-form-urlencoded"),
        ("json_native_types", b"/fixture", b'["true",true,"42",42,1e400,null,""]', b"application/json"),
        ("plain_body_unparsed", b"/fixture", b"ordinary text", b"text/plain"),
        ("invalid_percent_view", b"/fixture?x=%ZZ", b"", None),
        ("value_bound", b"/fixture?x=" + b"a" * 2049, b"", None),
        ("ascii_lexemes", b"/fixture", '["ſcript","SCRIPT"]'.encode(), b"application/json"),
        ("invalid_url_ports", b"/fixture", b'["http://a.invalid:99999","https://a.invalid:bad"]', b"application/json"),
    )


def source_hashes():
    paths = ("scripts/model2/c1_extensions.py", "scripts/model2/c1_extension_fixtures.py",
             "scripts/model2/contracts.py", "data_plane/request_features.py", "data_plane/canonical_request.py")
    return {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in paths}


def run():
    before, cases = source_hashes(), {}
    for name, target, body, ct in fixtures():
        headers = () if ct is None else ((b"Content-Type", ct),)
        canonical = c1.cr.canonicalize(c1.cr.RequestParts(b"POST" if body else b"GET", target,
                                                         headers=headers, body=body), c1.cr.Limits(70000))
        evidence = asdict(c1.extract_extension(canonical))
        del evidence["baseline"]  # No per-request baseline values in this fixture report.
        cases[name] = evidence
    if before != source_hashes():
        raise RuntimeError("source changed during execution; rerun")
    return {"schema": "c1-extension-fixture-evidence/v2", "scope": "FIXTURE_ONLY",
            "source_sha256": before, "cases": cases, "operational_policy_approved": False,
            "limitations": ["C1 remains incomplete; COMPLETE refers only to this bounded extraction scope.",
                            "raw is literal query/form values but parsed JSON scalars; not original wire bytes.",
                            "URL shape and lexical tokens never mean maliciousness or safety.",
                            "New facts are metadata only; no dataset or model is trained here."]}


def main():
    if len(sys.argv) != 1:
        raise SystemExit("C1 fixture reporter accepts no input arguments")
    print(json.dumps(run(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
