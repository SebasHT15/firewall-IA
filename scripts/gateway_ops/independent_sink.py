"""
Independent reception point for L2/L3 checks: an inert HTTP/1.1 destination in its own process.

    python scripts/gateway_ops/independent_sink.py --port 18002 --out sink.jsonl

It imports nothing from this repository on purpose: reception must not depend on the parser under
test. For each request it records the SHA-256 and length of the EXACT bytes received, and answers
200. It executes nothing, so a delivered request proves delivery and never proves that an attack
would have succeeded.

Framing here is deliberately simple: Content-Length, or chunked read to the terminating chunk. It
keeps the connection open, like a real upstream, so reused connections are exercised.
"""
import argparse
import hashlib
import json
import re
import socketserver
import threading
import time

RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok"


class Records:
    lock = threading.Lock()
    path = None
    count = 0


def read_more(sock, buf):
    data = sock.recv(65536)
    if not data:
        raise EOFError
    buf += data


def read_message(sock, buf):
    while b"\r\n\r\n" not in buf:
        read_more(sock, buf)
    end = buf.index(b"\r\n\r\n") + 4
    head = bytes(buf[:end]).lower()
    length = re.search(rb"\r\ncontent-length:[ \t]*([0-9]+)", head)
    if b"\r\ntransfer-encoding:" in head:
        position = end
        while True:
            while b"\r\n" not in buf[position:]:
                read_more(sock, buf)
            line_end = buf.index(b"\r\n", position)
            size = int(bytes(buf[position:line_end]).split(b";")[0], 16)
            position = line_end + 2 + size + 2
            while len(buf) < position:
                read_more(sock, buf)
            if size == 0:
                end = position
                break
    elif length:
        end += int(length.group(1))
        while len(buf) < end:
            read_more(sock, buf)
    message = bytes(buf[:end])
    del buf[:end]
    return message


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        buf = bytearray()
        try:
            while True:
                message = read_message(self.request, buf)
                first_line = message.split(b"\r\n", 1)[0]
                record = {"utc": time.time(), "wire_sha256": hashlib.sha256(message).hexdigest(),
                          "wire_bytes": len(message),
                          "first_line_sha256": hashlib.sha256(first_line).hexdigest()}
                with Records.lock:
                    Records.count += 1
                    with open(Records.path, "a", encoding="utf-8") as fh:
                        fh.write(json.dumps(record) + "\n")
                self.request.sendall(RESPONSE)
        except (EOFError, ConnectionError, ValueError):
            return


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    Records.path = args.out
    with Server(("127.0.0.1", args.port), Handler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
