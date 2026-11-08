#!/usr/bin/env bash
# Measures sensor cost: the same fixed workload, sensor off then sensor on.
# Reports both the workload slowdown and the CPU the sensor itself burns.
#   sudo ./overhead_test.sh
set -euo pipefail

[ "$(id -u)" = "0" ] || { echo "$(basename "$0") must run as root (needs cgroup and eBPF access)" >&2; exit 2; }

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$(cd "$HERE/../ebpf-agent" && pwd)/target/release/ebpf-agent"
# CPU cost is only meaningful for an optimised build.
[ -x "$BIN" ] || { echo "build first: (cd ebpf-agent && cargo build --release)"; exit 1; }
CTR=swarm-agent-alpha
N=5

WORK='import hashlib,time
d=b"x"*1000000
t=time.time()
for _ in range(1500): hashlib.sha256(d).digest()
print("%.3f" % (time.time()-t))'

med() { printf "%s\n" "$@" | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}'; }

echo "== workload, sensor off =="
OFF=()
for i in $(seq $N); do v=$(docker exec "$CTR" python3 -c "$WORK"); OFF+=("$v"); echo "  $v"; done

echo "== sensor on =="
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
START=$(date +%s%N)
"$BIN" run --spool "$TMP/events.jsonl" --edges "$TMP/edges.jsonl" > "$TMP/sensor.log" 2>&1 &
SENSOR=$!
sleep 3
if ! kill -0 "$SENSOR" 2>/dev/null; then
  echo "sensor failed to start:"; tail -3 "$TMP/sensor.log"; exit 1
fi

cpu_s() { awk '{print $14+$15}' /proc/$1/stat 2>/dev/null || echo 0; }
C0=$(cpu_s $SENSOR)
ON=()
for i in $(seq $N); do v=$(docker exec "$CTR" python3 -c "$WORK"); ON+=("$v"); echo "  $v"; done
C1=$(cpu_s $SENSOR)
T0=$(date +%s%N)
kill -INT $SENSOR 2>/dev/null || true; wait $SENSOR 2>/dev/null || true
T1=$(date +%s%N)

END=$(date +%s%N)
MOFF=$(med "${OFF[@]}"); MON=$(med "${ON[@]}")
EVENTS=$(wc -l < "$TMP/events.jsonl" 2>/dev/null || echo 0)
SENS_CPU=$(awk -v a="$C0" -v b="$C1" 'BEGIN{d=(b-a)/100; printf "%.2f", d}')
ELAPSED=$(awk -v a="$START" -v b="$END" 'BEGIN{printf "%.2f", (b-a)/1e9}')
WORK=$(awk -v m="$MON" -v n="$N" 'BEGIN{printf "%.2f", m*n}')
PCT=$(awk -v a="$MOFF" -v b="$MON" 'BEGIN{printf "%.2f", (b-a)/a*100}')
SCPU=$(awk -v s="$SENS_CPU" -v e="$ELAPSED" 'BEGIN{if(e>0) printf "%.2f", s/e*100; else print 0}')
PER_EV=$(awk -v s="$SENS_CPU" -v n="${EVENTS:-0}" 'BEGIN{if(n>0) printf "%.0f", s/n*1e6; else print 0}')

echo
echo "workload median   off=${MOFF}s  on=${MON}s  slowdown=${PCT}%"
echo "sensor CPU        ${SENS_CPU}s over ${ELAPSED}s wall = ${SCPU}% of one core"
echo "events captured   ${EVENTS} (${PER_EV} us of sensor CPU per event)"
echo "workload total    ${WORK}s of container work inside a ${ELAPSED}s window"
