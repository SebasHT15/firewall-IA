#!/usr/bin/env bash
# Hybrid Architecture Phase 1 live shadow-mode run — the client side.
#
# Sends a FIXED, pre-declared list of requests through the gateway, 3 times each,
# and prints the HTTP status the client got. Hand-written requests only: no
# External Test v1 case, no dataset row, and no marker header (every header is
# model input). The same list is sent with shadow feature extraction off and on.
#
# Usage, from the repository root, with the gateway on 127.0.0.1:8080 and the
# destination on localhost:9000:
#     reports/hybrid/phase1-feature-extraction-v2/send_requests.sh
set -u

PROXY=http://127.0.0.1:8080
DEST=http://localhost:9000
REPS=3

send() {  # <name> <curl arguments...>
  local name=$1; shift
  for rep in $(seq 1 "$REPS"); do
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -x "$PROXY" "$@")
    echo "$name rep=$rep status=$code"
  done
}

send get-simple        "$DEST/index.html"
send get-query         "$DEST/products.html?category=books&page=2"
send post-form         -d "name=ana&qty=2" "$DEST/products.html"
send post-json         -H "Content-Type: application/json" -d '{"sku": "A-1", "qty": 2, "opts": {"gift": true}}' "$DEST/products.html"
send get-unicode-pct   "$DEST/products.html?q=caf%C3%A9%20con%20leche"
send get-repeated      "$DEST/products.html?tag=a&tag=b&tag=c"
send get-long-path     "$DEST/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/index.html"
send get-sqli          "$DEST/products.html?id=1%27%20OR%20%271%27%3D%271"
send get-xss           "$DEST/products.html?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
send get-traversal     "$DEST/products.html?file=..%2F..%2F..%2Fetc%2Fpasswd"
send post-form-cmdi    -d "host=127.0.0.1;cat /etc/passwd" "$DEST/products.html"
