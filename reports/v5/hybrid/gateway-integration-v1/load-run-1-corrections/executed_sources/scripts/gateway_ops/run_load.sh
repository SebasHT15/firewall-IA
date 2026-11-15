#!/bin/sh
# Load phases with real services. Reserve the GPU in GPU_STATUS.json first. Usage:
#   scripts/gateway_ops/run_load.sh --phase ladder [--phase soak --soak-rates reference=R,verified=R] ...
# Finished runs are skipped, so it can be restarted. See docs/cascade_gateway.md.
W=${WORK:-/home/sebas/Documents/Codex/2026-10-26/ta/work/gateway-real-2026-10-30/load-run-1}
E=${EVIDENCE:-reports/v5/hybrid/gateway-integration-v1/load-run-1}
V=reports/v5/successor-2026-10-30/verified-suffix/service-final
exec .venv-dataplane/bin/python -u scripts/gateway_ops/load_check.py --out "$E" --work "$W" \
    --manifest reports/v5/hybrid/gateway-integration-v1/manifests/dev_fixture_baseline34.json \
    --verified-manifest "$V/cascade-manifest.EXPERIMENTAL.json" \
    --verified-profile "$V/verified-suffix.EXPERIMENTAL.json" \
    --inputs /home/sebas/Documents/Codex/2026-10-26/ta/work/metrics-2026-10-30/inputs.private.jsonl "$@"
