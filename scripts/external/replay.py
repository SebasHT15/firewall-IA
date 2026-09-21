"""External Test v1 — byte-exact replay of frozen cases through an explicit HTTP proxy.

Reads records carrying a `request_text` (the classifier representation) and re-emits each
one so that the proxy, after parsing, renders back EXACTLY the same text. That equality is
what makes the frozen case and the classified input the same object.

    frozen text --wire.to_wire()--> proxy --mitmproxy parse--> render_request() --> text

Uses a raw socket on purpose. Every HTTP client library rewrites something — adds
Accept-Encoding, reorders headers, normalises capitalisation, manages Connection. Any of
those would change what V4 sees, and every header is model input.

MODES
    --target gateway   replay through the firewall data plane; records decision evidence
                       (HTTP status) for L2. This is the External v1 execution channel.
    --target capture   replay through the CAPTURE proxy; used only to verify capture
                       fidelity before freeze, with no model in the path.

Output: one JSONL record per replayed request.
"""

import argparse
import datetime
import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wire  # noqa: E402


def replay_one(proxy_host: str, proxy_port: int, text: str, timeout: float):
    """Send one frozen request through the proxy. Returns a result dict."""
    # A non-canonical case can never round-trip; fail before it reaches the model.
    wire.assert_canonical(text)
    payload = wire.to_wire(text, strict=True)
    started = time.perf_counter()
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall(payload)
        status, headers, body = wire.read_response(sock)
    finally:
        sock.close()
    elapsed_ms = (time.perf_counter() - started) * 1000
    return {
        "http_status": status,
        "response_headers": headers,
        "response_body_prefix": body[:200].decode("utf-8", errors="replace"),
        "response_bytes": len(body),
        "wire_bytes": len(payload),
        "elapsed_ms": round(elapsed_ms, 2),
    }


def load_cases(path: str, limit: int | None, only_host: str | None = None):
    """Cases in file order, optionally narrowed to one destination host.

    A browser capture can contain requests the browser made on its own initiative to
    hosts outside the lab. Those are not lab traffic and must not be replayed: they would
    leave the authorized environment. `--only-host` keeps the selection to the lab
    application, and the count of what was skipped is reported rather than hidden.
    """
    out, skipped = [], 0
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if "request_text" not in rec:
                raise SystemExit(f"record without request_text in {path}")
            if only_host and rec.get("host") != only_host:
                skipped += 1
                continue
            out.append(rec)
            if limit and len(out) >= limit:
                break
    if only_host:
        print(f"host filter {only_host!r}: {len(out)} selected, {skipped} skipped",
              flush=True)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cases", required=True, help="JSONL with request_text per line")
    ap.add_argument("--out", required=True, help="JSONL results path")
    ap.add_argument("--target", choices=("gateway", "capture"), required=True)
    ap.add_argument("--proxy-host", default=None)
    ap.add_argument("--proxy-port", type=int, default=None)
    ap.add_argument("--repetitions", type=int, default=1)
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--only-host", default=None,
                    help="replay only requests whose captured host matches, e.g. "
                         "shop.fwlab.test. Keeps browser background traffic out.")
    ap.add_argument("--delay-ms", type=float, default=0.0,
                    help="pause between requests; the control plane serialises inference")
    args = ap.parse_args(argv)

    defaults = {"gateway": ("data-plane", 8080), "capture": ("capture-proxy", 8081)}
    host = args.proxy_host or defaults[args.target][0]
    port = args.proxy_port or defaults[args.target][1]

    cases = load_cases(args.cases, args.limit, args.only_host)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    if os.path.exists(args.out):
        raise SystemExit(f"refusing to overwrite existing results: {args.out}")

    print(f"replay: {len(cases)} case(s) x {args.repetitions} rep(s) -> {args.target} "
          f"{host}:{port}", flush=True)

    failures = 0
    with open(args.out, "w", encoding="utf-8") as out:
        for rep in range(1, args.repetitions + 1):
            for i, case in enumerate(cases, 1):
                text = case["request_text"]
                rec = {
                    "case_id": case.get("case_id", case.get("seq")),
                    "repetition": rep,
                    "target": args.target,
                    "registered_sha256": case.get("request_sha256") or wire.sha256_text(text),
                    "sent_sha256": wire.sha256_text(text),
                    "sent_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                }
                try:
                    rec.update(replay_one(host, port, text, args.timeout))
                    rec["error"] = None
                except Exception as exc:
                    failures += 1
                    rec["error"] = f"{type(exc).__name__}: {exc}"
                out.write(json.dumps(rec, ensure_ascii=False) + "\n")
                out.flush()
                if args.delay_ms:
                    time.sleep(args.delay_ms / 1000.0)
                if i % 50 == 0:
                    print(f"  rep {rep}: {i}/{len(cases)}", flush=True)

    print(f"replay done: {len(cases) * args.repetitions} request(s), {failures} error(s)",
          flush=True)
    print(f"results: {args.out}", flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
