#!/usr/bin/env bash
# Every validation pass in one unattended go: scripted suite, live suite,
# co-located identity, and sensor cost. Safe to run in the background.
#
#   sudo nohup ./validate.sh > /dev/null 2>&1 &
#   tail -f validation-*.log
#
# No `set -e`: a failing pass must not stop the later ones. Each pass records
# its own exit code and the digest reports all three.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
# endpoints and the API key for compose; .env is gitignored
[ -f "$HERE/.env" ] && { set -a; . "$HERE/.env"; set +a; }
LOG="$HERE/validation-$(date -u +%Y%m%dT%H%M%SZ).log"
exec > >(tee -a "$LOG") 2>&1

echo "=== validation $(date -u +%FT%TZ) ==="
echo

echo "== 0. containers =="
if docker compose up -d; then
  sleep 6
  docker ps --format '  {{.Names}} {{.Status}}' | grep swarm || true
else
  echo "  compose up failed; the bench needs swarm-agent-alpha/beta/gamma"
fi
echo

echo "== 1. scripted (4 repeats per scenario) + live (3 per mode) =="
BENCH_START=$SECONDS
./bench.sh --repeats 4 --live-repeats 3
RC_BENCH=$?
echo "  bench exited $RC_BENCH after $((SECONDS-BENCH_START))s"
echo

echo "== 2. co-located identity =="
./colocated_test.sh
RC_COLO=$?
echo

echo "== 3. sensor cost =="
./overhead_test.sh
RC_OH=$?
echo

DIGEST="$HERE/validation-digest.txt"
{
  echo "=== digest $(date -u +%FT%TZ) ==="
  echo "bench=$RC_BENCH colocated=$RC_COLO overhead=$RC_OH"
  echo
  echo "-- scripted totals --"
  grep -E "^  (ALL|[a-z].*[0-9]{2,}) " "$LOG" | tail -8
  echo
  echo "-- live --"
  grep -E "transcript-detected|^  (covert|coop|benign|launder)" "$LOG" | tail -8
  echo
  echo "-- colocated --"
  grep -E "^  edges:|^VERDICT" "$LOG" | tail -2
  echo
  echo "-- overhead --"
  grep -E "workload median|sensor CPU|events captured" "$LOG" | tail -3
  echo
  echo "full log: $LOG"
} | tee "$DIGEST"

echo
echo "digest written to $DIGEST"
