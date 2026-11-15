"""Synthetic assets and private canary on the experiment's internal Docker net."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import time

CANARY = b'FWLAB_SYNTHETIC_SECRET_92f730b1'


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        private = self.path.startswith('/internal/')
        body = CANARY if private else b'Public laboratory asset'
        with Path('/evidence/callback.jsonl').open('a') as fh:
            fh.write(json.dumps(dict(path=self.path, private=private, time=time.time())) + '\n')
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == '__main__':
    ThreadingHTTPServer(('0.0.0.0', 9200), Handler).serve_forever()
