#!/usr/bin/env bash
# One-shot viability test for co-located agents.
#
# Two processes inside ONE container are moved into separate child cgroups, one
# writes a file the other reads. If an edge appears whose endpoints are those two
# cgroups, co-location works. Needs root.
#
#   sudo ./colocated_test.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$(cd "$HERE/../ebpf-agent" && pwd)/target/debug/ebpf-agent"
CTR=swarm-agent-alpha

CID=$(docker inspect -f '{{.Id}}' "$CTR")
CG="/sys/fs/cgroup/swarm_adr.slice/docker-$CID.scope"
A="$CG/agent-a"
B="$CG/agent-b"

echo "== 1. create child cgroups =="
mkdir -p "$A" "$B" && echo "  created $A" && echo "  created $B"
printf '%s\n%s\n' "$A" "$B" > /tmp/agents.txt

echo "== 2. payloads =="
docker exec -i "$CTR" sh -c 'mkdir -p /tmp/payload; cat > /tmp/payload/w.py' <<'PYW'
import time
time.sleep(1.2)
open("/shared/colocated", "w").write("payload")
PYW
docker exec -i "$CTR" sh -c 'cat > /tmp/payload/r.py' <<'PYR'
import time
time.sleep(1.6)
open("/shared/colocated").read()
PYR
docker exec "$CTR" rm -f /shared/colocated

echo "== 3. sensor with declared agents =="
"$BIN" run --spool /tmp/co-events.jsonl --edges /tmp/co-edges.jsonl \
  --agent-cgroups /tmp/agents.txt 2> /tmp/co-stats.log &
SENSOR=$!
sleep 2.5

echo "== 4. launch both processes, then move each into its cgroup =="
docker exec -d "$CTR" sh -c 'sleep 0.8; exec python3 /tmp/payload/w.py'
docker exec -d "$CTR" sh -c 'sleep 0.8; exec python3 /tmp/payload/r.py'
sleep 0.4
PW=$(pgrep -f 'payload/w\.py' | head -1 || true)
PR=$(pgrep -f 'payload/r\.py' | head -1 || true)
echo "  host pids: writer=${PW:-?} reader=${PR:-?}"
if [ -n "${PW:-}" ]; then echo "$PW" > "$A/cgroup.procs" && echo "  moved writer -> agent-a"; fi
if [ -n "${PR:-}" ]; then echo "$PR" > "$B/cgroup.procs" && echo "  moved reader -> agent-b"; fi
echo "  agent-a procs: $(cat "$A/cgroup.procs" 2>/dev/null | tr '\n' ' ')"
echo "  agent-b procs: $(cat "$B/cgroup.procs" 2>/dev/null | tr '\n' ' ')"

sleep 3.5
kill -INT "$SENSOR" 2>/dev/null || true
wait "$SENSOR" 2>/dev/null || true

echo "== 5. identities the sensor registered =="
grep "agent ino=" /tmp/co-stats.log | sed 's/^/  /' || echo "  none"

echo "== 6. replay and show edges =="
"$BIN" replay /tmp/co-events.jsonl --edges /tmp/co-edges.jsonl >/dev/null 2>&1 || true
EDGES=$(grep -c '"kind":"edge"' /tmp/co-edges.jsonl 2>/dev/null || true); EDGES=${EDGES:-0}
echo "  edges: $EDGES"
grep '"kind":"edge"' /tmp/co-edges.jsonl 2>/dev/null | sed 's/^/  /' || true

echo
if [ "$EDGES" -gt 0 ]; then
  echo "VERDICT: co-location detected — the two child cgroups formed an edge."
else
  echo "VERDICT: no edge. Check that both pids moved (step 4) and that the sensor"
  echo "         registered four or more agent inodes (step 5)."
fi
