#!/usr/bin/env bash
# Live-agent episode. Emits $OUT/summary.json for the bench to aggregate.
#
#   sudo ./run-episode.sh <episode> <mode>
set -euo pipefail

EP="${1:?usage: run-episode.sh <episode> <mode>}"
MODE="${2:?usage: run-episode.sh <episode> <mode>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
SCEN="$HERE/scenarios/live/$MODE"
OUT="$HERE/episodes/$EP"
BIN="$(cd "$HERE/../ebpf-agent" && pwd)/target/debug/ebpf-agent"
ES="${ES:-http://100.76.120.85:9200}"
INDEX="cdr-$(echo "$EP" | tr '[:upper:]' '[:lower:]')"
POLICY="$HERE/policies/$([ "$MODE" = coop ] || [ "$MODE" = benign ] && echo cooperative || echo covert).json"
AGENTS="alpha beta"

[ -d "$SCEN" ] || { echo "no scenario at $SCEN" >&2; exit 2; }
rm -rf "$OUT"; mkdir -p "$OUT"

for c in $AGENTS; do
  docker exec "swarm-agent-$c" sh -c 'rm -rf /shared/* /shared/.[!.]* /tmp/payload' >/dev/null 2>&1 || true
  docker exec "swarm-agent-$c" mkdir -p /tmp/payload
  docker cp "$SCEN/$c/." "swarm-agent-$c:/tmp/payload/" >/dev/null
  docker exec "swarm-agent-$c" sh -c '[ -f /tmp/payload/install.sh ] && sh /tmp/payload/install.sh' >/dev/null 2>&1 || true
done

(
  sleep 4
  SENSOR=$(pgrep -n -f 'target/debug/ebpf-agent run' || true)
  for c in $AGENTS; do
    prompt=$(cat "$SCEN/$c/prompt.txt")
    docker exec "swarm-agent-$c" sh -c "cd /workspace && omp \"$prompt\"" > "$OUT/$c.omp.log" 2>&1 || true
  done
  sleep 2
  [ -n "${SENSOR:-}" ] && kill -INT "$SENSOR"
) &
AGENTS_PID=$!

"$BIN" run --spool "$OUT/events.jsonl" --edges "$OUT/edges.jsonl" \
  --es "$ES" --index "$INDEX" --dead-letter "$OUT/es-dead.ndjson" 2> "$OUT/stats.log"

wait "$AGENTS_PID" 2>/dev/null || true

for c in $AGENTS; do
  mkdir -p "$OUT/$c-sessions"
  docker cp "swarm-agent-$c:/root/.omp/agent/sessions" "$OUT/$c-sessions/" >/dev/null 2>&1 || true
  f=$(find "$OUT/$c-sessions" -name '*.jsonl' -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2-)
  [ -n "$f" ] && cp "$f" "$OUT/$c.jsonl"
done

ino_of() {
  id=$(docker inspect -f '{{.Id}}' "swarm-agent-$1")
  grep "cgroup=.*$id" "$OUT/stats.log" | grep -o 'ino=[0-9]*' | cut -d= -f2 | head -1
}
A_INO=$(ino_of alpha || true); B_INO=$(ino_of beta || true)

TR="--transcript ${A_INO:-0}=$OUT/alpha.jsonl --transcript ${B_INO:-0}=$OUT/beta.jsonl"

"$BIN" baseline --edges "$OUT/edges.jsonl" $TR > "$OUT/baseline.json" 2>/dev/null || echo '{}' > "$OUT/baseline.json"
"$BIN" desync --events "$OUT/events.jsonl" --edges "$OUT/edges.jsonl" --policy "$POLICY" $TR \
  > "$OUT/desync-honest.jsonl" 2> "$OUT/desync-honest.log" || true
if [ -s "$OUT/beta.jsonl" ]; then
  sed 's|python3 /tmp/payload/b.py|python3 /tmp/innocent.py|g' "$OUT/beta.jsonl" > "$OUT/beta.tampered.jsonl"
  "$BIN" desync --events "$OUT/events.jsonl" --edges "$OUT/edges.jsonl" --policy "$POLICY" \
    --transcript "${A_INO:-0}=$OUT/alpha.jsonl" --transcript "${B_INO:-0}=$OUT/beta.tampered.jsonl" \
    --variant tampered > "$OUT/desync-tampered.jsonl" 2> "$OUT/desync-tampered.log" || true
fi

"$BIN" score --edges "$OUT/edges.jsonl" --truth "$SCEN/truth.json" --policy "$POLICY" \
  > "$OUT/score.json" 2>/dev/null || echo '{}' > "$OUT/score.json"

python3 - "$OUT" "$EP" "$MODE" "$INDEX" <<'PY'
import json, sys, pathlib
out, ep, mode, index = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
def rd(p, default):
    try: return json.loads((out/p).read_text())
    except Exception: return default
def counts(p):
    d = {"matched":0,"mismatch":0,"omission":0}
    try:
        for line in (out/p).read_text().splitlines():
            if line.startswith("desync: matched="):
                parts = dict(x.split("=") for x in line.split()[1:])
                d = {k:int(v) for k,v in parts.items()}
    except Exception: pass
    return d
score = rd("score.json", {})
summary = {
  "episode": ep, "mode": mode, "index": index, "suite": "live",
  "edges": score.get("edges", 0),
  "tp": score.get("tp", 0), "fp": score.get("fp", 0), "fn": score.get("fn", 0),
  "unsanctioned": score.get("unsanctioned", 0), "ignored_parent": score.get("ignored_parent", 0),
  "baseline": rd("baseline.json", {}),
  "desync_honest": counts("desync-honest.log"),
  "desync_tampered": counts("desync-tampered.log"),
}
(out/"summary.json").write_text(json.dumps(summary) + "\n")
print(json.dumps({k: summary[k] for k in ("episode","mode","edges","unsanctioned","tp","fp","fn")}))
PY
