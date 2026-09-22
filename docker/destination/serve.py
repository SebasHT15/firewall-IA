"""firewall-IA Docker Lab — destination application.

The protected origin server. Its only job is to make ONE question answerable
without ambiguity:

    did this request actually reach the destination, or did the gateway stop it?

Proving a request DID arrive is easy. Proving one did NOT arrive is the whole
point of the BLOCK and fail-closed smoke tests, so receipt is recorded as
structured, append-only JSONL that a test can read and count, not as prose in a
console that a test would have to scrape.

Standard library only. No framework, no dependencies, no state beyond the log.
It is a test fixture, not a component of the firewall.

    ACCESS_LOG  path of the JSONL receipt log (default /logs/destination-access.jsonl)
    PORT        listen port (default 9000)
    WWW_ROOT    directory served (default /srv/www)
"""

import datetime
import json
import os
import sys
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

ACCESS_LOG = os.environ.get("ACCESS_LOG", "/logs/destination-access.jsonl")
PORT = int(os.environ.get("PORT", "9000"))
WWW_ROOT = os.environ.get("WWW_ROOT", "/srv/www")

_log_lock = threading.Lock()


class ReceiptLoggingHandler(SimpleHTTPRequestHandler):
    """Serves WWW_ROOT and records every request that reaches this process.

    The record is written BEFORE the response is produced, so a request is
    logged even if serving it fails. Nothing here inspects or rejects requests:
    the destination is deliberately permissive, otherwise a BLOCK observed by a
    smoke test could be the destination's doing rather than the gateway's.
    """

    server_version = "firewall-ia-lab-destination/1.0"
    protocol_version = "HTTP/1.1"

    def _record(self) -> None:
        entry = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "method": self.command,
            "path": self.path,
            "host_header": self.headers.get("Host"),
            "user_agent": self.headers.get("User-Agent"),
            "client_ip": self.client_address[0],
        }
        line = json.dumps(entry, ensure_ascii=False)
        with _log_lock:
            with open(ACCESS_LOG, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
        # Also to stdout, so `docker compose logs destination` shows the same
        # receipts a human is looking for.
        print("RECEIVED " + line, flush=True)

    def do_GET(self) -> None:
        self._record()
        super().do_GET()

    def do_HEAD(self) -> None:
        self._record()
        super().do_HEAD()

    def do_POST(self) -> None:
        # SimpleHTTPRequestHandler has no POST. The lab only needs receipt
        # evidence, so the body is drained and a fixed 200 is returned.
        self._record()
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        body = b"destination received POST\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:
        # Replaced by _record(); keeps the default stderr line out of the way.
        pass


def main() -> int:
    os.makedirs(os.path.dirname(ACCESS_LOG) or ".", exist_ok=True)
    # Touch the log so a reader never has to special-case "file does not exist"
    # versus "no requests received".
    with open(ACCESS_LOG, "a", encoding="utf-8"):
        pass
    handler = partial(ReceiptLoggingHandler, directory=WWW_ROOT)
    server = ThreadingHTTPServer(("0.0.0.0", PORT), handler)
    print(f"destination ready: port={PORT} root={WWW_ROOT} access_log={ACCESS_LOG}",
          flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
