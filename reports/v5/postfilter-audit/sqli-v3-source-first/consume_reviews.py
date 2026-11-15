#!/usr/bin/env python3
"""Capture the three blind Codex handbacks and apply frozen r4 adjudication."""
import glob
import hashlib
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[3]
OUT = HERE / "validation-codex-v3"
ROLES = {"a1": "gpt-6.1-sol", "a2": "gpt-6-astra", "r3": "gpt-6-sol"}
FIELDS = {"sample_id", "label_class", "failure_mode", "better_category", "note"}
LABELS = {"VERIFIABLE", "PROBABLY_CORRECT", "UNCERTAIN", "INCORRECT"}
FAILURES = {"prose", "tool_output", "placeholder", "markdown_residue", "setup_command",
            "reference_url", "wrong_category", "truncated", "encoding_garbage", "other"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load_role(role, model, ids, artifacts):
    agent = f"/root/sqli_v3_{role}"
    candidates = []
    for filename in glob.glob("/home/sebas/.codex/sessions/2026/10/25/*.jsonl"):
        path = pathlib.Path(filename)
        with path.open() as stream:
            first = json.loads(stream.readline())
        if first.get("type") == "session_meta" and first.get("payload", {}).get("agent_path") == agent:
            candidates.append(path)
    assert len(candidates) == 1, (agent, candidates)
    session = candidates[0]
    log = session.read_bytes()
    events = [json.loads(line) for line in log.splitlines()]
    models = [event["payload"]["model"] for event in events
              if event["type"] == "turn_context" and "model" in event["payload"]]
    assert models and set(models) == {model}, (role, models)
    texts = []
    for event in events:
        payload = event.get("payload", {})
        if event["type"] == "response_item" and payload.get("type") == "message" and payload.get("role") == "assistant":
            texts.extend(c["text"] for c in payload.get("content", [])
                         if c.get("type") == "output_text" and c.get("text", "").lstrip().startswith('{"sample_id"'))
    assert len(texts) == 1, (role, len(texts))
    raw = (texts[0].rstrip("\n") + "\n").encode()
    rows = [json.loads(line) for line in raw.splitlines() if line]
    assert len(rows) == len(ids) == 50 and [row["sample_id"] for row in rows] == ids
    for row in rows:
        assert set(row) == FIELDS and row["label_class"] in LABELS
        assert isinstance(row["note"], str) and row["note"].strip() and "\n" not in row["note"]
        if row["label_class"] == "INCORRECT":
            assert row["failure_mode"] in FAILURES
            assert (row["better_category"] is not None) == (row["failure_mode"] == "wrong_category")
        else:
            assert row["failure_mode"] is None and row["better_category"] is None
    artifacts[f"{role}.handback.jsonl"] = raw
    evidence = {"schema": "codex-review-session-evidence/v1", "agent_path": agent,
                "session_log": str(session), "session_log_sha256": sha(log),
                "session_thread_id": events[0]["payload"]["id"],
                "parent_thread_id": events[0]["payload"]["parent_thread_id"],
                "model_in_turn_context": models, "valid_final_answers": 1,
                "selected_final_answer_sha256_terminal_lf": sha(raw),
                "trailing_newline_canonicalized": True,
                "sample_sha256": sha((HERE / "sample_n50.jsonl").read_bytes()),
                "preregistration_sha256": sha((HERE / "preregistration.json").read_bytes())}
    evidence_raw = (json.dumps(evidence, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
    artifacts[f"{role}.session-evidence.json"] = evidence_raw
    provenance = {"role": role, "model_requested": model, "agent_id": agent,
                  "fresh_session": True, "inherited_history": False,
                  "handback_sha256": sha(raw), "session_evidence_sha256": sha(evidence_raw),
                  "session_log_sha256": sha(log)}
    return {row["sample_id"]: row for row in rows}, provenance


def main():
    pre = (HERE / "preregistration.json").read_bytes()
    pool = (HERE / "pool.jsonl").read_bytes()
    sample = (HERE / "sample_n50.jsonl").read_bytes()
    auth = (HERE / "execution-authorization.CITED.json").read_bytes()
    authorization = json.loads(auth)
    assert authorization["owner_approved"] is True and authorization["training_authorized"] is False
    assert authorization["preregistration_sha256"] == sha(pre)
    assert authorization["population_sha256"] == sha(pool)
    assert authorization["sample_sha256"] == sha(sample)
    ids = [json.loads(line)["record_id"] for line in sample.splitlines() if line]
    assert len(ids) == len(set(ids)) == 50
    artifacts = {}
    answers, provenance = {}, []
    for role, model in ROLES.items():
        answers[role], p = load_role(role, model, ids, artifacts)
        provenance.append(p)
    sys.path.insert(0, str(REPO / "scripts/dataset"))
    import adjudicate_v5_r4_continuation as rules
    traces = []
    for rid in ids:
        votes = {role: answers[role][rid]["label_class"] for role in ROLES}
        label, rule = rules.adjudicate(votes["a1"], votes["a2"], votes["r3"])
        traces.append({"sample_id": rid, "category": "SQL Injection", **votes,
                       "adjudicated_label": label, "rule": rule})
    criteria = {"acceptance_criteria": {"C1": {"limit": 0.20}, "C2": {"limit": 0.35}},
                "wilson": {"z": 1.96}}
    summary = rules.summarize(traces, criteria)["SQL Injection"]
    result = {"schema": "sqli-v3-prospective-result/v1", "preregistration_sha256": sha(pre),
              "population_sha256": sha(pool), "sample_sha256": sha(sample),
              "authorization_sha256": sha(auth), "category_outcomes": {"SQL Injection": summary},
              "provenance": provenance, "traces": traces,
              "training_authorized": False, "automatic_admission": False, "human_validation": False}
    artifacts["result.json"] = (json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
    assert not OUT.exists(), OUT
    OUT.mkdir()
    for name, data in artifacts.items():
        (OUT / name).write_bytes(data)
    (OUT / "SHA256SUMS").write_text("".join(f"{sha(artifacts[name])}  {name}\n" for name in sorted(artifacts)))
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
