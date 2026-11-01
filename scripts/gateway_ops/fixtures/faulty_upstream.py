"""
Upstream that fails inside its response, to see what reaches the client through the real gateway.

    python scripts/gateway_ops/fixtures/faulty_upstream.py --port 18002 --behavior cut

Reads one request head and answers `Content-Length: 10` with only 3 bytes of body, then:

    cut     closes the connection
    reset   aborts it with a TCP reset
    stall   keeps it open and sends nothing more

A test fixture. It records nothing and imports nothing from this repository.
"""
import argparse
import socket
import socketserver
import struct
import time

PARTIAL = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 10\r\n\r\nabc"


class Handler(socketserver.BaseRequestHandler):
    behavior = "cut"

    def handle(self):
        data = b""
        while b"\r\n\r\n" not in data:
            more = self.request.recv(65536)
            if not more:
                return
            data += more
        self.request.sendall(PARTIAL)
        if self.behavior == "stall":
            time.sleep(120)
        elif self.behavior == "reset":
            self.request.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--behavior", choices=("cut", "reset", "stall"), required=True)
    args = parser.parse_args()
    Handler.behavior = args.behavior
    with Server(("127.0.0.1", args.port), Handler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
