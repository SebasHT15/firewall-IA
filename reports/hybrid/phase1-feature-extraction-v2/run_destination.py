"""Run the Docker Lab destination (docker/destination/serve.py) on the host, on
LOOPBACK only, for the Hybrid Architecture Phase 1 live shadow-mode run.

serve.py binds 0.0.0.0 because it is written for a container. On the host that
would expose it to the local network, so its server class is wrapped to bind
127.0.0.1. Nothing else changes: same handler, same JSONL receipt log.

    ACCESS_LOG=<path> PORT=9000 WWW_ROOT=docker/destination/www \
        python3.12 reports/hybrid/phase1-feature-extraction-v2/run_destination.py
"""

import os
import sys
from http.server import ThreadingHTTPServer

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(REPO_ROOT, "docker", "destination"))

import serve  # noqa: E402


def loopback_server(address, handler):
    return ThreadingHTTPServer(("127.0.0.1", address[1]), handler)


serve.ThreadingHTTPServer = loopback_server
sys.exit(serve.main())
