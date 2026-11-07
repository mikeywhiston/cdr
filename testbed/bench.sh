#!/usr/bin/env bash
# Scripted scenario suite: every channel class, repeated, scored against declared
# ground truth. Deterministic (no model in the loop), so a re-run reproduces the
# corpus byte-for-byte apart from timestamps.
#
#   sudo ./bench.sh [--repeats 3] [--only pattern]
#
# Results append to testbed/results/<run>/results.jsonl.
set -euo pipefail

[ "$(id -u)" = "0" ] || { echo "$(basename "$0") must run as root (needs cgroup and eBPF access)" >&2; exit 2; }

HERE="$(cd "$(dirname "$0")" && pwd)"
BINDIR="$(cd "$HERE/../ebpf-agent" && pwd)/target"
if [ -x "$BINDIR/release/ebpf-agent" ]; then
  BIN="$BINDIR/release/ebpf-agent"
else
  BIN="$BINDIR/debug/ebpf-agent"
  echo "note: release binary missing, using debug (run cargo build --release)" >&2
fi
# Local endpoints and secrets live in .env (gitignored); see .env.example.
[ -f "$HERE/.env" ] && { set -a; . "$HERE/.env"; set +a; }
[ -n "${ES:-}" ] || { echo "ES is not set: copy .env.example to .env and fill it in" >&2; exit 2; }
REPEATS=3
LIVE_REPEATS=0
ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --repeats) REPEATS="$2"; shift 2 ;;
    --only) ONLY="$2"; shift 2 ;;
    --live-repeats) LIVE_REPEATS="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    *) echo "unknown arg $1" >&2; exit 2 ;;
  esac
done

DRY_RUN="${DRY_RUN:-0}"
RUN="$(date -u +%Y%m%dT%H%M%SZ)"
[ "$DRY_RUN" = "1" ] && RUN=dryrun
OUT="$HERE/results/$RUN"
if [ "$DRY_RUN" = "1" ]; then
  echo "dry run: scenarios/bench -> $(ls -d scenarios/bench/*/ | wc -l) scenarios x $REPEATS"
else
  mkdir -p "$OUT"
  : > "$OUT/results.jsonl"
  {
    echo "run=$RUN"
    echo "started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "repeats=$REPEATS"
    sha256sum "$HERE"/../ebpf-agent/ebpf-agent/src/*.rs \
              "$HERE"/../ebpf-agent/ebpf-agent-ebpf/src/main.rs \
              "$HERE"/../ebpf-agent/ebpf-agent-common/src/lib.rs 2>/dev/null | sed 's|.*/ebpf-agent/||'
    sha256sum "$HERE"/scenarios/bench/*/* 2>/dev/null | sed "s|$HERE/||"
  } > "$OUT/provenance.txt"
fi

declare -A C=([a]=alpha [b]=beta [c]=gamma)

run_once() {  # $1=scenario dir  $2=episode id
  local dir="$1"
  local ep="$2"
  local w="$OUT/$ep"
  if [ "${DRY_RUN:-0}" = "1" ]; then
    echo "  would run $(basename "$dir") -> $ep"
    return 0
  fi
  mkdir -p "$w"
  for c in alpha beta gamma; do
    docker exec "swarm-agent-$c" sh -c 'rm -rf /shared/* /shared/.[!.]* /tmp/payload /tmp/rnd-* /shared/.[!.]*' >/dev/null 2>&1 || true
  done
  if [ -f "$dir/setup.sh" ]; then
    docker exec -i swarm-agent-alpha sh < "$dir/setup.sh" >/dev/null 2>&1 || true
    echo "  setup applied"
  fi
  "$BIN" run --spool "$w/events.jsonl" --edges "$w/edges.jsonl" 2> "$w/stats.log" &
  local sensor=$!
  sleep 2.5
  for py in "$dir"/*.py; do
    local letter; letter=$(basename "$py" .py)
    local ctr="${C[$letter]:-alpha}"
    docker exec "swarm-agent-$ctr" rm -rf /tmp/payload >/dev/null 2>&1 || true
    docker exec "swarm-agent-$ctr" mkdir -p /tmp/payload
    docker cp "$py" "swarm-agent-$ctr:/tmp/payload/run.py"
    docker exec -d "swarm-agent-$ctr" python3 /tmp/payload/run.py
  done
  sleep 4.5
  kill -INT "$sensor" 2>/dev/null || true
  wait "$sensor" 2>/dev/null || true

  local policy="$HERE/policies/$(python3 -c "import json;print(json.load(open('$dir/truth.json'))['policy'])").json"
  "$BIN" replay "$w/events.jsonl" --edges "$w/edges.jsonl" >/dev/null 2>&1
  "$BIN" score --edges "$w/edges.jsonl" --truth "$dir/truth.json" --policy "$policy" \
    >> "$OUT/results.jsonl"
}

for dir in "$HERE"/scenarios/bench/*/; do
  name=$(basename "$dir")
  [ -n "$ONLY" ] && case "$name" in *"$ONLY"*) ;; *) continue ;; esac
  for r in $(seq 1 "$REPEATS"); do
    echo "== $name #$r =="
    run_once "$dir" "$name-$r"
  done
done

if [ "$LIVE_REPEATS" -gt 0 ] 2>/dev/null; then
  [ "$DRY_RUN" = "1" ] || : > "$OUT/live.jsonl"
  for mode in covert coop benign launder launder-npm launder-cargo; do
    for r in $(seq 1 "$LIVE_REPEATS"); do
      ep="live-$mode-$r"
      echo "== live $mode #$r =="
      if [ "$DRY_RUN" = "1" ]; then
        echo "  would run run-episode.sh $ep $mode"
        continue
      fi
      "$HERE/run-episode.sh" "$ep" "$mode" > "$OUT/$ep.log" 2>&1 || true
      [ -f "$HERE/episodes/$ep/summary.json" ] && cp "$HERE/episodes/$ep/summary.json" "$OUT/$ep.json" \
        && cat "$OUT/$ep.json" >> "$OUT/live.jsonl"
    done
  done
fi

[ "$DRY_RUN" = "1" ] && exit 0
python3 "$HERE/bench_summary.py" "$OUT/results.jsonl" "$OUT/live.jsonl"

echo "results: $OUT/results.jsonl"
