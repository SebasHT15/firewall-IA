#!/usr/bin/env bash
# firewall-IA Docker Lab — live demo, host side.
#
# A short, deterministic walk-through of the gateway's outcomes for an audience:
#
#   [1/5] startup      clean the lab, start it, wait until V4 is loaded on the GPU
#   [2/5] ALLOW        benign request              -> 200, destination receives it
#   [3/5] BLOCK        BLOCK-labelled test request -> 403, destination receives nothing
#   [4/5] fail-closed  classifier stopped          -> 503, destination receives nothing
#   [5/5] recovery     classifier restarted        -> the benign request works again
#
# NO TEST LOGIC OF ITS OWN. Every request, fixture, expected status and destination
# receipt check is the smoke client's (docker/client/smoke_test.py), exactly as validated
# in reports/lab/docker-lab-v1/. This file only sequences the stages, keeps the
# fail-closed guards of docker/smoke_test.sh, and prints the evidence in between: the
# control plane's /health, and the data plane's own decision line for each request.
# docker/smoke_test.sh remains the canonical infrastructure check.
#
# INFRASTRUCTURE DEMO ONLY, in the authorized local lab. It uses the smoke fixtures, NOT
# External Test v1 cases, and it is not an evaluation or a benchmark: no accuracy, FPR,
# FNR or latency claim may be derived from its output.
#
#   docker compose build     # once, beforehand
#   ./docker/demo.sh         # add --step to pause for Enter between stages
#
# Non-destructive: the clean step removes the lab's CONTAINERS and network only — never
# volumes, images, the adapter, receipt logs or anything under datasets/ or reports/.
# Exits non-zero, prints DEMO FAIL and names the stage on the first unexpected result.
# If it stopped the control plane, it restarts it before exiting.

set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

COMPOSE="${COMPOSE:-docker compose}"
LOG_DIR="${LAB_LOG_DIR:-./docker/.lab-logs}"
ADAPTER_DIR="${LAB_ADAPTER_DIR:-./model-output-v4-clean}"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_LOG="$LOG_DIR/demo-$RUN_ID.log"
STEP=0
STOPPED_CONTROL_PLANE=0

for arg in "$@"; do
  case "$arg" in
    --step) STEP=1 ;;
    -h|--help) sed -n '2,/^$/{s/^# \{0,1\}//;p}' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg (usage: ./docker/demo.sh [--step])"; exit 2 ;;
  esac
done

mkdir -p "$LOG_DIR"
# Same rule as smoke_test.sh: what the audience saw is kept on disk, not only in a
# terminal (docs/ml_evaluation_methodology.md section 13). Gitignored working output.
exec > >(tee -a "$RUN_LOG") 2>&1

bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
stage() { printf '\n\033[1;36m[%s] %s\033[0m\n' "$1" "$2"; }
ok()    { printf '\033[32m  ok\033[0m  %s\n' "$*"; }
die() {
  printf '\n\033[1;31mDEMO FAIL\033[0m  %s\n' "$*"
  echo "log: $RUN_LOG"
  exit 1
}
pause() {
  [ "$STEP" = 1 ] || return 0
  printf '\n  (press Enter to continue) '
  read -r _ </dev/tty || true
}

# Container state of a service, or "absent" when it has none. Same parsing as
# docker/smoke_test.sh.
service_state() {
  $COMPOSE ps -a --format json "$1" 2>/dev/null \
    | grep -o '"State":"[a-z]*"' | head -1 | cut -d'"' -f4 \
    | grep . || echo absent
}

# `grep >/dev/null`, not `grep -q`, throughout: under pipefail an early-exiting grep -q
# can SIGPIPE the writer and turn a match into a failure.
wait_control_plane_healthy() {
  for _ in $(seq 1 90); do
    $COMPOSE ps --format json control-plane 2>/dev/null \
      | grep '"Health":"healthy"' >/dev/null && return 0
    printf '.'; sleep 2
  done
  return 1
}

# The control plane is not published to the host, so /health is read from inside its
# own container. Read-only.
show_health() {   # <stage label>
  local health
  health=$($COMPOSE exec -T control-plane python3 -c \
    "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=5).read().decode())" \
    2>/dev/null) || die "$1: could not read /health from the control plane"
  echo "  GET /health -> $health"
  [[ $health =~ \"model_loaded\":[[:space:]]*true ]] \
    || die "$1: /health does not report model_loaded: true"
  $COMPOSE logs --no-color control-plane 2>/dev/null \
    | grep -o 'startup: model ready on .*' | tail -1 | sed 's/^/  control-plane: /'
  ok "control plane healthy, V4 loaded"
}

# The data plane's decision lines (ALLOW / BLOCK / BLOCK (fail-closed)), shown after each
# request so the audience sees what the gateway decided and why. The pass/fail verdict
# is the smoke client's, not this.
decisions() {
  $COMPOSE logs --no-color data-plane 2>/dev/null \
    | grep -E '\] (ALLOW|BLOCK) ' | sed -E 's/^[^|]*\| //'
}

# Runs one smoke-client phase, shows its result lines and the gateway's decision, and
# stops the demo if the client did not observe the expected status and receipt.
client_phase() {   # <stage label> <phase> [extra `compose run` flags...]
  local label=$1 phase=$2 before out rc
  shift 2
  before=$(decisions | wc -l)
  out=$($COMPOSE run --rm "$@" client "$phase" 2>&1); rc=$?
  printf '%s\n' "$out" | grep -E '^\[(ALLOW|BLOCK|FAILCLOSED)\]' | sed 's/^/  /'
  decisions | tail -n +"$(( before + 1 ))" | sed 's/^/  data-plane: /'
  if [ "$rc" != 0 ]; then
    echo "  full smoke-client output:"
    printf '%s\n' "$out" | sed 's/^/  | /'
    die "$label: smoke client phase '$phase' did not observe the expected result"
  fi
}

restore_control_plane() {
  [ "$STOPPED_CONTROL_PLANE" = 1 ] || return 0
  [ "$(service_state control-plane)" = running ] && return 0
  echo
  bold "restoring the control plane"
  $COMPOSE start control-plane >/dev/null 2>&1
  if wait_control_plane_healthy; then echo; ok "control plane healthy again"
  else echo; echo "  WARNING: control plane not healthy; check: docker compose ps"; fi
}
trap restore_control_plane EXIT

# ── Banner ────────────────────────────────────────────────────────────────
bold "firewall-IA — Docker Lab demo   run $RUN_ID"
echo "client -> data-plane (mitmproxy) -> control-plane (FastAPI /classify) -> TinyLlama V4"
echo "       ALLOW -> forward | BLOCK -> 403 | no valid decision -> 503 (fail-closed)"
echo "Authorized local lab. Smoke fixtures only, not External Test v1. Not an evaluation."
echo "log: $RUN_LOG"

# ── Preconditions: checked before anything is touched ────────────────────
[ -f "$ADAPTER_DIR/adapter_model.safetensors" ] \
  || die "preconditions: V4 adapter not found in $ADAPTER_DIR (see docker/README.md)"
for img in control-plane data-plane destination client; do
  docker image inspect "firewall-ia/$img:lab" >/dev/null 2>&1 \
    || die "preconditions: image firewall-ia/$img:lab missing — run: docker compose build"
done

# ── [1/5] startup ─────────────────────────────────────────────────────────
stage 1/5 "startup — clean lab, start services, wait for the model"
# Both profiles, or containers started under them (lab-app, capture-proxy, generator)
# survive a plain `down` and keep the network in use. Containers and network only.
$COMPOSE --profile smoke --profile extv1 down --remove-orphans >/dev/null 2>&1 \
  || die "1/5: docker compose down failed"
ok "previous lab containers removed (volumes, images and logs kept)"
# data-plane depends on control-plane `service_healthy`, so this returns only once V4 is
# loaded; --wait also covers the destination's healthcheck.
printf '  starting control-plane, data-plane, destination (model load) ... '
$COMPOSE up -d --wait --wait-timeout 300 control-plane data-plane destination >/dev/null 2>&1 \
  || { echo; $COMPOSE logs --tail 30 control-plane; die "1/5: lab did not start healthy"; }
echo done
show_health 1/5
for _ in $(seq 1 30); do
  $COMPOSE logs --no-color data-plane 2>/dev/null | grep 'data plane ready' >/dev/null && break
  sleep 1
done
$COMPOSE logs --no-color data-plane 2>/dev/null | grep -o 'data plane ready.*' | tail -1 \
  | sed 's/^/  data-plane: /' | grep . || die "1/5: data plane never logged 'data plane ready'"
ok "gateway listening, policy fail-closed"
pause

# ── [2/5] ALLOW ───────────────────────────────────────────────────────────
stage 2/5 "ALLOW — benign request: expect 200 and delivery to the destination"
client_phase 2/5 allow
ok "ALLOW: forwarded, the destination received it"
pause

# ── [3/5] BLOCK ───────────────────────────────────────────────────────────
stage 3/5 "BLOCK — BLOCK-labelled test request (SQL injection): expect 403, nothing delivered"
client_phase 3/5 block
ok "BLOCK: 403 from the gateway, the destination received nothing"
pause

# ── [4/5] fail-closed ─────────────────────────────────────────────────────
stage 4/5 "fail-closed — classifier stopped: expect 503, nothing delivered"
STOPPED_CONTROL_PLANE=1
$COMPOSE stop control-plane >/dev/null 2>&1 || die "4/5: could not stop the control plane"
state=$(service_state control-plane)
[ "$state" != running ] || die "4/5: control plane still '$state' — the fail-closed case would test nothing"
ok "control plane is '$state' before the request"
# --no-deps is REQUIRED: without it Compose resolves client -> data-plane -> control-plane
# (service_healthy) and restarts the classifier just stopped (docker/README.md).
client_phase 4/5 failclosed --no-deps
state=$(service_state control-plane)
[ "$state" != running ] || die "4/5: control plane came back during the request — result not trustworthy"
ok "fail-closed: 503, the destination received nothing (control plane '$state' throughout)"
pause

# ── [5/5] recovery ────────────────────────────────────────────────────────
stage 5/5 "recovery — restart the classifier, the benign request works again"
$COMPOSE start control-plane >/dev/null 2>&1 || die "5/5: could not start the control plane"
printf '  waiting for model_loaded '
wait_control_plane_healthy || { echo; die "5/5: control plane did not become healthy again"; }
echo
STOPPED_CONTROL_PLANE=0
show_health 5/5
client_phase 5/5 allow
ok "recovery: normal operation resumed"

trap - EXIT
printf '\n\033[1;32mDEMO PASS\033[0m  ALLOW 200 delivered · BLOCK 403 not delivered · fail-closed 503 not delivered · recovery OK\n'
echo "Infrastructure demo on smoke fixtures; not External Test v1 and implies no model metric."
echo "destination receipts: $LOG_DIR/destination-access.jsonl"
echo "log:                  $RUN_LOG"
exit 0
