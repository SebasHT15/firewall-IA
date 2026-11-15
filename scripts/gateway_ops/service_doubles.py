"""
TEST DOUBLE of the V4 or V5 control-plane service. NOT A MODEL. Every answer is a fixed rule, so a
result obtained through it says nothing about detection quality.

    python scripts/gateway_ops/service_doubles.py --role v5 --port 18001 --manifest <manifest.json>

Rule: BLOCK when the input contains the word `evil`, ALLOW otherwise. `POST /__control` with
{"behavior": ...} changes the behavior at runtime, to exercise failure modes:

    normal | slow | serial | block_all | invalid | error500 | saturated503 | hang | bad_json |
    contract_mismatch | adapter_mismatch | recipe_mismatch | vocabulary_mismatch | budget_mismatch |
    token_contract_mismatch | profile_mismatch | profile_of_other_adapter | no_profile

`serial` behaves like one GPU: one inference at a time for `inference_ms`, at most `max_inflight` calls
inside, 503 beyond that, reporting queue and service time as the real API does. It is how queueing can be
exercised on a CPU. Its times are the ones it was told to use.

`GET /__stats` returns the call count. The V5 double serves the identity of the manifest (v1 or v2), so
it passes readiness exactly when a real service with that identity would.
"""
import argparse
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TOKEN_FIELDS = ("max_length", "margin", "overhead", "label_budget", "max_new_tokens")


class State:
    behavior = "normal"
    calls = 0
    lock = threading.Lock()
    gpu = threading.Lock()
    inference_ms = 100.0
    max_inflight = 8
    inside = 0
    decoder = "native"


def classify(role, text):
    decision = "BLOCK" if "evil" in text else "ALLOW"
    body = {"status": "ok", "decision": decision, "invalid_reason": None}
    if role == "v5":
        body["generate_ms"] = 0.1
    return body


def served_profile(v5):
    """What /health reports for the runtime of a manifest: the summary of its profile file."""
    runtime = v5.get("runtime")
    if runtime:
        path = runtime["profile_path"]
        with open(path if os.path.isabs(path) else os.path.join(REPO, path), encoding="utf-8") as fh:
            profile = json.load(fh)
        summary = {k: profile.get(k) for k in ("schema", "profile_id", "status", "precision",
                                               "double_quant", "recipe_sha256", "adapter_sha256")}
        if "decoder" in profile:
            summary.update(decoder=profile["decoder"], decoder_sha256=profile["decoder_sha256"])
        return {**summary, "sha256": runtime["profile_sha256"]}
    return {"sha256": v5["runtime_profile_sha256"]} if v5.get("runtime_profile_sha256") else None


def serial_inference(role, text):
    """One at a time, bounded, as the real service. Returns (status, body)."""
    with State.lock:
        if State.inside >= State.max_inflight:
            return 503, {"detail": "Saturated"}
        State.inside += 1
    entered = time.perf_counter()
    try:
        with State.gpu:
            started = time.perf_counter()
            time.sleep(State.inference_ms / 1000)
            pipeline = (time.perf_counter() - started) * 1000
    finally:
        with State.lock:
            State.inside -= 1
    verified = State.decoder != "native"
    return 200, {**classify(role, text), "queue_wait_ms": (started - entered) * 1000,
                 "pipeline_ms": pipeline, "service_ms": (time.perf_counter() - entered) * 1000,
                 "generated_tokens": 9, "decoder_verified": True if verified else None,
                 "decoder_fallback": False if verified else None}


def build_handler(role, manifest):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def reply(self, status, payload):
            data = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/__stats":
                self.reply(200, {"calls": State.calls, "behavior": State.behavior})
            elif self.path == "/health":
                body = {"status": "ok", "model_loaded": True}
                if role == "v5":
                    v5 = manifest["v5"]
                    body.update(adapter_sha256=("0" * 64 if State.behavior == "adapter_mismatch"
                                                else v5["adapter_sha256"]),
                                template_fingerprint=v5["template_fingerprint"])
                    profile = served_profile(v5)
                    if State.behavior == "profile_mismatch":
                        profile = {**(profile or {}), "sha256": "e" * 64}
                    elif State.behavior == "profile_of_other_adapter":
                        profile = {**(profile or {}), "adapter_sha256": "0" * 64}
                    elif State.behavior == "no_profile":
                        profile = None
                    if profile:
                        body["runtime_profile"] = profile
                self.reply(200, body)
            elif self.path == "/contract" and role == "v5":
                v5 = manifest["v5"]
                contract = {"template_fingerprint": v5["template_fingerprint"],
                            "recipe_sha256": ("0" * 64 if State.behavior in ("contract_mismatch",
                                                                             "recipe_mismatch")
                                              else v5["recipe_sha256"]),
                            "vocabulary": (v5["vocabulary"][:-1]
                                           if State.behavior == "vocabulary_mismatch"
                                           else v5["vocabulary"]),
                            "token_budget_B": (v5["token_budget_B"] + 1
                                               if State.behavior == "budget_mismatch"
                                               else v5["token_budget_B"])}
                contract.update({k: v5[k] for k in TOKEN_FIELDS + ("base_model", "base_revision")
                                 if k in v5})
                if State.behavior == "token_contract_mismatch":
                    contract["label_budget"] = -1
                self.reply(200, contract)
            else:
                self.reply(404, {"detail": "not found"})

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            if self.path == "/__control":
                command = json.loads(raw)
                State.behavior = command["behavior"]
                State.inference_ms = command.get("inference_ms", State.inference_ms)
                State.max_inflight = command.get("max_inflight", State.max_inflight)
                self.reply(200, {"behavior": State.behavior})
                return
            if self.path != "/classify":
                self.reply(404, {"detail": "not found"})
                return
            with State.lock:
                State.calls += 1
            behavior = State.behavior
            if behavior == "hang":
                time.sleep(60)
            if behavior == "slow":
                time.sleep(0.2)
            if behavior == "serial":
                body = json.loads(raw)
                self.reply(*serial_inference(role, body.get("canonical_request") or body.get("request")))
            elif behavior == "block_all":
                self.reply(200, {"status": "ok", "decision": "BLOCK", "invalid_reason": None})
            elif behavior == "error500":
                self.reply(500, {"detail": "injected"})
            elif behavior == "saturated503":
                self.reply(503, {"detail": "injected"})
            elif behavior == "bad_json":
                self.reply(200, b"{not json")
            elif behavior == "invalid":
                self.reply(200, {"status": "invalid", "decision": None,
                                 "invalid_reason": "not_in_vocabulary"})
            else:
                body = json.loads(raw)
                self.reply(200, classify(role, body.get("canonical_request") or body.get("request")))

    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=("v4", "v5"), required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--manifest")
    args = parser.parse_args()
    manifest = None
    if args.role == "v5":
        with open(args.manifest, encoding="utf-8") as fh:
            manifest = json.load(fh)
        State.decoder = (served_profile(manifest["v5"]) or {}).get("decoder", "native")
    server = ThreadingHTTPServer(("127.0.0.1", args.port), build_handler(args.role, manifest))
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":
    main()
