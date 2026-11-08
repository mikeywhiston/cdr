#!/usr/bin/env bash
# Measures sensor cost: the same fixed workload run with the sensor off, then on.
#
# Reports workload CPU time (user + system) rather than wall time, because CPU
# time is immune to whatever else the host happens to be doing. Wall time is
# reported alongside it for context only.
#
#   sudo ./overhead_test.sh          # 7 runs each side
#   sudo N=11 ./overhead_test.sh     # tighter medians
set -euo pipefail

[ "$(id -u)" = "0" ] || { echo "$(basename "$0") must run as root (needs cgroup and eBPF access)" >&2; exit 2; }

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$(cd "$HERE/../ebpf-agent" && pwd)/target/release/ebpf-agent"
# CPU cost is only meaningful for an optimised build.
[ -x "$BIN" ] || { echo "build first: (cd ebpf-agent && cargo build --release)"; exit 1; }

CTR="${CTR:-swarm-agent-alpha}"
N="${N:-7}"

# The workload prints "cpu_seconds wall_seconds" using process_time, which
# counts user + system time for the process itself.
WORK='
import hashlib, time
d = b"x" * 1000000
c0, w0 = time.process_time(), time.time()
for _ in range(1500):
    hashlib.sha256(d).digest()
print("%.3f %.3f" % (time.process_time() - c0, time.time() - w0))
'

med_col() { # $1 = column, rest = samples
  local col=$1; shift
  printf "%s\n" "$@" | awk -v c="$col" '{print $c}' | sort -n |
    awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}'
}

echo "== workload, sensor off ($N runs) =="
OFF=()
for i in $(seq "$N"); do
  v=$(docker exec "$CTR" python3 -c "$WORK")
  OFF+=("$v")
  printf "   cpu=%ss wall=%ss\n" "$(echo "$v" | cut -d' ' -f1)" "$(echo "$v" | cut -d' ' -f2)"
done

echo "== sensor on =="
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
START=$(date +%s%N)
"$BIN" run --spool "$TMP/events.jsonl" --edges "$TMP/edges.jsonl" > "$TMP/sensor.log" 2>&1 &
SENSOR=$!
sleep 3
if ! kill -0 "$SENSOR" 2>/dev/null; then
  echo "sensor failed to start:"; tail -3 "$TMP/sensor.log"; exit 1
fi
cpu_s() { awk '{print $14+$15}' "/proc/$1/stat" 2>/dev/null || echo 0; }
C0=$(cpu_s "$SENSOR")
ON=()
for i in $(seq "$N"); do
  v=$(docker exec "$CTR" python3 -c "$WORK")
  ON+=("$v")
  printf "   cpu=%ss wall=%ss\n" "$(echo "$v" | cut -d' ' -f1)" "$(echo "$v" | cut -d' ' -f2)"
done
C1=$(cpu_s "$SENSOR")
END=$(date +%s%N)
kill -INT "$SENSOR" 2>/dev/null || true; wait "$SENSOR" 2>/dev/null || true

MOFF_C=$(med_col 1 "${OFF[@]}"); MON_C=$(med_col 1 "${ON[@]}")
MOFF_W=$(med_col 2 "${OFF[@]}"); MON_W=$(med_col 2 "${ON[@]}")
EVENTS=$(wc -l < "$TMP/events.jsonl" 2>/dev/null || echo 0)
SENS_CPU=$(awk -v a="$C0" -v b="$C1" 'BEGIN{printf "%.2f", (b-a)/100}')
ELAPSED=$(awk -v a="$START" -v b="$END" 'BEGIN{printf "%.2f", (b-a)/1e9}')
SCPU=$(awk -v s="$SENS_CPU" -v e="$ELAPSED" 'BEGIN{if(e>0) printf "%.2f", s/e*100; else print 0}')
DCPU=$(awk -v a="$MOFF_C" -v b="$MON_C" 'BEGIN{if(a>0) printf "%+.2f", (b-a)/a*100; else print "n/a"}')
DWALL=$(awk -v a="$MOFF_W" -v b="$MON_W" 'BEGIN{if(a>0) printf "%+.2f", (b-a)/a*100; else print "n/a"}')

echo
echo "workload CPU      off=${MOFF_C}s  on=${MON_C}s  delta=${DCPU}%   <- the claim"
echo "workload wall     off=${MOFF_W}s  on=${MON_W}s  delta=${DWALL}%   (load-sensitive, context only)"
echo "sensor CPU        ${SENS_CPU}s over ${ELAPSED}s wall = ${SCPU}% of one core"
echo "events captured   ${EVENTS}"
