#!/usr/bin/env python3
"""firewall-IA — batching and verbatim collection of the LLM annotations of a post-filter audit round (D58, §7).
Stdlib only.

The annotators are read-only Claude Code subagents, one fresh agent per batch. Each one may read only its own batch
file and its annotator instructions, and returns its labels through its final hand-back message. This tool:

    batches   split annotation_<who>/packet.jsonl into consecutive, hashed batch files (deterministic; never rewritten)
    collect   for one batch, read the subagent transcript (Claude Code JSONL) and check that:
                - every assistant turn was served by the expected model id (the API `model` field);
                - the only tool calls are Read on the allowed files, plus the final hand-back;
              then store the hand-back text VERBATIM (raw/), parse its JSON lines and refuse any missing, extra,
              duplicate or invalid item. A refused batch is re-run with a fresh agent (new attempt), never edited.
    assemble  merge the accepted batches into annotations_<who>.jsonl (sorted by sample_id). Labels, failure modes,
              categories and notes are copied unchanged; `batch` and `attempt` are added.

The coordinator never writes or changes a label.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import audit_v5_attack_pool as PRE  # noqa: E402
import v5_pools_common as C  # noqa: E402

FIELDS = ("sample_id", "label_class", "failure_mode", "better_category", "note")
HANDBACK = "SubagentHandback"


def _who_dir(round_dir: str, who: str) -> str:
    if who not in ("a1", "a2"):
        raise SystemExit("annotator must be a1 or a2")
    return os.path.join(round_dir, f"annotation_{who}")


def make_batches(round_dir: str, who: str, size: int) -> dict:
    d = _who_dir(round_dir, who)
    bdir = os.path.join(d, "batches")
    os.makedirs(bdir)                                     # fails if it exists: batches are never rewritten
    lines = open(os.path.join(d, "packet.jsonl"), encoding="utf-8").read().splitlines()
    out = []
    for i in range(0, len(lines), size):
        chunk = lines[i:i + size]
        name = f"batch_{len(out) + 1:02d}.jsonl"
        data = ("\n".join(chunk) + "\n").encode("utf-8")
        with open(os.path.join(bdir, name), "wb") as fh:
            fh.write(data)
        out.append({"batch": len(out) + 1, "file": f"batches/{name}", "rows": len(chunk), "sha256": C.sha256_bytes(data),
                    "sample_ids": [json.loads(x)["sample_id"] for x in chunk]})
    man = {"annotator": who, "packet_sha256": C.sha256_file(os.path.join(d, "packet.jsonl")), "batch_size": size,
           "rule": "consecutive slices of packet.jsonl in its stored order", "batches": out}
    C.write_json(os.path.join(d, "batches.json"), man)
    return man


def read_transcript(path: str) -> list:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def audit_transcript(events: list, expected_model: str, allowed_paths: set) -> dict:
    """-> {models, turns, tool_calls, handback, violations}. A wrong or mixed model (e.g. a harness fallback to
    another model after a safety-classifier stop) or a forbidden tool call is a violation: the attempt is recorded
    REFUSED with this evidence, never accepted."""
    models, turns, calls, handback, violations = set(), [], [], None, []
    for ev in events:
        msg = ev.get("message") or {}
        if ev.get("type") != "assistant":
            continue
        models.add(msg.get("model"))
        turns.append({"model": msg.get("model"), "stop_reason": msg.get("stop_reason")})
        for part in msg.get("content") or []:
            if not isinstance(part, dict) or part.get("type") != "tool_use":
                continue
            name, inp = part.get("name"), part.get("input") or {}
            calls.append({"tool": name, "file_path": inp.get("file_path")})
            if name == HANDBACK:
                handback = inp.get("message")
            elif name != "Read" or os.path.realpath(inp.get("file_path") or "") not in allowed_paths:
                violations.append(f"forbidden tool call {name} {inp.get('file_path')!r}")
    if models != {expected_model}:
        violations.append(f"models served {sorted(map(str, models))} != expected {expected_model}")
    if not isinstance(handback, str) or not handback.strip():
        violations.append("no hand-back message in the transcript")
    return {"models": sorted(map(str, models)), "turns": turns, "tool_calls": calls, "handback": handback or "",
            "violations": violations}


def parse_handback(text: str, expected_ids: list) -> list:
    """JSON-object lines of the hand-back, validated against the batch. Non-JSON lines (fences, prose) are ignored;
    every expected id must appear exactly once, with a valid label; nothing else may appear."""
    rows = []
    for line in text.splitlines():
        s = line.strip()
        if not (s.startswith("{") and s.endswith("}")):
            continue
        try:
            obj = json.loads(s)
        except ValueError:
            raise SystemExit(f"REFUSED: unparseable JSON line: {s[:80]!r}")
        rows.append(obj)
    ids = [r.get("sample_id") for r in rows]
    errs = []
    if sorted(ids) != sorted(expected_ids):
        missing = sorted(set(expected_ids) - set(ids))
        extra = sorted(set(ids) - set(expected_ids))
        dups = sorted({i for i in ids if ids.count(i) > 1})
        errs.append(f"coverage: missing {missing[:10]} extra {extra[:10]} duplicates {dups[:10]}")
    for r in rows:
        lc, fm = r.get("label_class"), r.get("failure_mode")
        if lc not in PRE.LABEL_CLASSES:
            errs.append(f"{r.get('sample_id')}: bad label_class {lc!r}")
        if lc == "INCORRECT" and fm not in PRE.FAILURE_MODES:
            errs.append(f"{r.get('sample_id')}: INCORRECT needs a failure_mode in the vocabulary")
        if fm not in (None, "none", "") and fm not in PRE.FAILURE_MODES:
            errs.append(f"{r.get('sample_id')}: bad failure_mode {fm!r}")
        if set(r) - set(FIELDS):
            errs.append(f"{r.get('sample_id')}: unexpected fields {sorted(set(r) - set(FIELDS))}")
    if errs:
        raise SystemExit("REFUSED: hand-back invalid:\n  " + "\n  ".join(errs[:20]))
    return rows


def collect(round_dir: str, who: str, batch: int, transcript: str, expected_model: str, attempt: int,
            agent_id: str) -> dict:
    d = _who_dir(round_dir, who)
    man = json.load(open(os.path.join(d, "batches.json"), encoding="utf-8"))
    b = man["batches"][batch - 1]
    bpath = os.path.join(d, b["file"])
    if C.sha256_file(bpath) != b["sha256"]:
        raise SystemExit("REFUSED: batch file changed after batching")
    allowed = {os.path.realpath(bpath), os.path.realpath(os.path.join(d, "README.md"))}
    events = read_transcript(transcript)
    aud = audit_transcript(events, expected_model, allowed)
    raw_dir = os.path.join(d, "raw")
    os.makedirs(raw_dir, exist_ok=True)
    stem = f"batch_{batch:02d}.attempt_{attempt}"
    raw_path = os.path.join(raw_dir, stem + ".handback.txt")
    if os.path.exists(raw_path):
        raise SystemExit(f"REFUSED: {raw_path} exists; raw outputs are never overwritten")
    with open(raw_path, "w", encoding="utf-8") as fh:
        fh.write(aud["handback"])
    rec = {"annotator": who, "batch": batch, "attempt": attempt, "agent_id": agent_id,
           "models_served": aud["models"], "turns": aud["turns"], "tool_calls": aud["tool_calls"],
           "transcript_sha256": C.sha256_file(transcript), "handback_sha256": C.sha256_file(raw_path),
           "batch_sha256": b["sha256"]}
    if aud["violations"]:
        rec["status"] = "REFUSED"
        rec["refusal"] = "REFUSED: " + "; ".join(aud["violations"])
    else:
        try:
            rows = parse_handback(aud["handback"], b["sample_ids"])
            rec["status"] = "ACCEPTED"
            rec["rows"] = len(rows)
        except SystemExit as exc:
            rec["status"] = "REFUSED"
            rec["refusal"] = str(exc)
    C.write_json(os.path.join(raw_dir, stem + ".provenance.json"), rec)
    return rec


def assemble(round_dir: str, who: str, partial: bool = False) -> dict:
    """Complete: annotations_<who>.jsonl (refused unless every batch has exactly one ACCEPTED attempt).
    partial=True: annotations_<who>.partial.jsonl with the accepted batches only, plus the list of missing batches;
    the official file is never written from a partial set."""
    d = _who_dir(round_dir, who)
    man = json.load(open(os.path.join(d, "batches.json"), encoding="utf-8"))
    raw_dir = os.path.join(d, "raw")
    out, used, missing = [], [], []
    for b in man["batches"]:
        acc = []
        for name in sorted(os.listdir(raw_dir)):
            if name.startswith(f"batch_{b['batch']:02d}.attempt_") and name.endswith(".provenance.json"):
                p = json.load(open(os.path.join(raw_dir, name), encoding="utf-8"))
                if p["status"] == "ACCEPTED":
                    acc.append(p)
        if len(acc) > 1 or (len(acc) == 0 and not partial):
            raise SystemExit(f"REFUSED: batch {b['batch']} has {len(acc)} accepted attempts (need exactly 1)")
        if not acc:
            missing.append({"batch": b["batch"], "sample_ids": b["sample_ids"]})
            continue
        p = acc[0]
        text = open(os.path.join(raw_dir, f"batch_{b['batch']:02d}.attempt_{p['attempt']}.handback.txt"),
                    encoding="utf-8").read()
        for r in parse_handback(text, b["sample_ids"]):
            out.append({**{f: r.get(f) for f in FIELDS}, "batch": b["batch"], "attempt": p["attempt"]})
        used.append({"batch": b["batch"], "attempt": p["attempt"], "handback_sha256": p["handback_sha256"]})
    name = f"annotations_{who}.partial.jsonl" if partial else f"annotations_{who}.jsonl"
    info = C.write_jsonl(os.path.join(round_dir, name), out, key=lambda r: r["sample_id"])
    res = {"annotator": who, "file": name, "rows": info["records"], "sha256": info["sha256"], "batches": used,
           "missing_batches": [m["batch"] for m in missing], "missing_rows": sum(len(m["sample_ids"]) for m in missing)}
    if partial:
        C.write_json(os.path.join(round_dir, f"annotations_{who}.partial.status.json"), {**res, "missing": missing})
    return res


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("batches", "collect", "assemble"):
        sp = sub.add_parser(name)
        sp.add_argument("--round-dir", required=True)
        sp.add_argument("--annotator", required=True, choices=("a1", "a2"))
        if name == "batches":
            sp.add_argument("--size", type=int, required=True)
        if name == "assemble":
            sp.add_argument("--partial", action="store_true", help="write annotations_<who>.partial.jsonl only")
        if name == "collect":
            sp.add_argument("--batch", type=int, required=True)
            sp.add_argument("--transcript", required=True)
            sp.add_argument("--model", required=True, help="expected API model id, e.g. claude-sonnet-5-5")
            sp.add_argument("--attempt", type=int, default=1)
            sp.add_argument("--agent-id", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "batches":
        res = make_batches(a.round_dir, a.annotator, a.size)
        print(json.dumps({"batches": len(res["batches"]), "rows": [b["rows"] for b in res["batches"]]}))
    elif a.cmd == "collect":
        res = collect(a.round_dir, a.annotator, a.batch, a.transcript, a.model, a.attempt, a.agent_id)
        print(json.dumps({k: res[k] for k in ("batch", "attempt", "status", "models_served") if k in res}
                         | ({"refusal": res["refusal"]} if "refusal" in res else {}), indent=1))
    else:
        print(json.dumps(assemble(a.round_dir, a.annotator, a.partial), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
