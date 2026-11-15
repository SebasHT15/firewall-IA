#!/bin/sh
# Traffic and operation trials of a delivered candidate, after training. Needs the GPU hand-off in
# GPU_STATUS.json; `load_check.py` refuses to load a model without it. Usage:
#   EVIDENCE=<new dir> WORK=<private dir> MANIFEST=<v2 manifest> \
#     scripts/gateway_ops/run_candidate_load.sh --phase ladder
# Finished runs are skipped. Rates come from the ladder of THIS candidate. See
# docs/cascade_candidate_handoff.md.
: "${EVIDENCE:?a new evidence directory}"
: "${WORK:?a private directory outside the repository}"
: "${MANIFEST:?the candidate v2 manifest}"
I=${INPUTS:-/home/sebas/Documents/Codex/2026-10-26/ta/work/metrics-2026-10-30/inputs.private.jsonl}
exec .venv-dataplane/bin/python -u scripts/gateway_ops/load_check.py --out "$EVIDENCE" --work "$WORK" \
    --candidate-manifest "$MANIFEST" --inputs "$I" "$@"
