#!/bin/sh
# Real verification with V4 and V5 already up, in visible terminals. Usage:
#   scripts/gateway_ops/run_real.sh <label> <v5 service log> <v4 service log> <manifest> [real_check options]
# Service logs and gateway logs stay in WORK, outside the repository: they can carry request paths.
W=${WORK:-/home/sebas/Documents/Codex/2026-10-26/ta/work/gateway-real-2026-10-30}
E=${EVIDENCE:-reports/v5/hybrid/gateway-integration-v1/real-run-1}
label=$1; v5_log=$2; v4_log=$3; manifest=$4; shift 4
exec .venv-dataplane/bin/python -u scripts/gateway_ops/real_check.py --out "$E" --work "$W/runs" \
    --manifest "$manifest" \
    --inputs /home/sebas/Documents/Codex/2026-10-26/ta/work/metrics-2026-10-30/inputs.private.jsonl \
    --v4-url http://127.0.0.1:8000 --v5-url http://127.0.0.1:8001 \
    --v4-log "$W/$v4_log" --v5-log "$W/$v5_log" --label "$label" "$@"
