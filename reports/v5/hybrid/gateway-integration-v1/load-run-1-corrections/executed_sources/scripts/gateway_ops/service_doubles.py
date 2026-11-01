"""
TEST DOUBLE of the V4 or V5 control-plane service. NOT A MODEL. Every answer is a fixed rule, so a
result obtained through it says nothing about detection quality.

    python scripts/gateway_ops/service_doubles.py --role v5 --port 18001 --manifest <manifest.json>

Rule: BLOCK when the input contains the word `evil`, ALLOW otherwise. `POST /__control` with
{"behavior": ...} changes the behavior at runtime, to exercise failure modes:

    normal | slow | block_all | invalid | error500 | saturated503 | hang | bad_json | contract_mismatch

`GET /__stats` returns the call count. The V5 double serves the identity of the manifest, so it
passes readiness exactly when a real service with that identity would.
"""
import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class State:
    behavior = "normal"
    calls = 0
    lock = threading.Lock()


def classify(role, text):
    decision = "BLOCK" if "evil" in text else "ALLOW"
    body = {"status": "ok", "decision": decision, "invalid_reason": None}
    if role == "v5":
        body["generate_ms"] = 0.1
    return body


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
            mismatch = State.behavior == "contract_mismatch"
            if self.path == "/__stats":
                self.reply(200, {"calls": State.calls, "behavior": State.behavior})
            elif self.path == "/health":
                body = {"status": "ok", "model_loaded": True}
                if role == "v5":
                    v5 = manifest["v5"]
                    body.update(adapter_sha256=v5["adapter_sha256"],
                                template_fingerprint=v5["template_fingerprint"])
                    if v5.get("runtime_profile_sha256"):
                        body["runtime_profile"] = {"sha256": v5["runtime_profile_sha256"]}
                self.reply(200, body)
            elif self.path == "/contract" and role == "v5":
                v5 = manifest["v5"]
                self.reply(200, {"template_fingerprint": v5["template_fingerprint"],
                                 "recipe_sha256": "0" * 64 if mismatch else v5["recipe_sha256"],
                                 "vocabulary": v5["vocabulary"],
                                 "token_budget_B": v5["token_budget_B"]})
            else:
                self.reply(404, {"detail": "not found"})

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            if self.path == "/__control":
                State.behavior = json.loads(raw)["behavior"]
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
            if behavior == "block_all":
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
    server = ThreadingHTTPServer(("127.0.0.1", args.port), build_handler(args.role, manifest))
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":
    main()
