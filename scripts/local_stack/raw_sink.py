"""
Raw reception point for the transport checks: an inert HTTP/1.1 destination that keeps the EXACT bytes
of every message it receives. Standard library only and nothing from this repository, so what it
records does not depend on any parser under test.

    python -I scripts/local_stack/raw_sink.py --port 9300 --out <private dir>/raw-sink.jsonl

One JSON line per message: arrival time, SHA-256, length and the bytes in base64. The file belongs in a
PRIVATE directory. Framing here is deliberately simple (Content-Length, or chunked to the last chunk)
and the connection stays open, like a real upstream. It answers 200 and executes nothing.
"""
import argparse
import base64
import hashlib
import json
import re
import socketserver
import threading
import time

RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 9\r\n\r\nreceived\n"
HEAD_RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 9\r\n\r\n"


class Records:
    lock = threading.Lock()
    path = None


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
    if re.search(rb"\r\ntransfer-encoding:[^\r\n]*chunked", head):
        position = end
        while True:
            while b"\r\n" not in buf[position:]:
                read_more(sock, buf)
            line_end = buf.index(b"\r\n", position)
            size = int(bytes(buf[position:line_end]).split(b";")[0], 16)
            if size == 0:            # last chunk, optional trailers, empty line
                while bytes(buf).find(b"\r\n\r\n", line_end) < 0:
                    read_more(sock, buf)
                end = bytes(buf).index(b"\r\n\r\n", line_end) + 4
                break
            position = line_end + 2 + size + 2
            while len(buf) < position:
                read_more(sock, buf)
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
                record = {"utc": time.time(), "sha256": hashlib.sha256(message).hexdigest(),
                          "bytes": len(message), "b64": base64.b64encode(message).decode("ascii"),
                          "peer_port": self.client_address[1]}
                with Records.lock, open(Records.path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(record) + "\n")
                self.request.sendall(HEAD_RESPONSE if message[:5] == b"HEAD " else RESPONSE)
        except (EOFError, ConnectionError, ValueError):
            return


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    Records.path = args.out
    with Server((args.host, args.port), Handler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
