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

# Two workloads. The CPU-bound one barely touches the filesystem, so it measures
# the probe's per-syscall floor. The I/O-bound one exercises openat2 plus fstat on
# every iteration, which is where the resolution path actually spends its time.
MODE="${MODE:-cpu}"
case "$MODE" in
  cpu) WORK='
import hashlib, time
d = b"x" * 1000000
c0, w0 = time.process_time(), time.time()
for _ in range(1500):
    hashlib.sha256(d).digest()
print("%.3f %.3f" % (time.process_time() - c0, time.time() - w0))
' ;;
  io) WORK='
import os, time
p = "/tmp/io_probe.bin"
with open(p, "wb") as f:
    f.write(b"x" * 4096)
c0, w0 = time.process_time(), time.time()
for _ in range(1500):
    fd = os.open(p, os.O_RDONLY)
    os.read(fd, 4096)
    os.close(fd)
print("%.3f %.3f" % (time.process_time() - c0, time.time() - w0))
' ;;
  *) echo "MODE must be cpu or io" >&2; exit 2 ;;
esac

med_col() { # $1 = column, rest = samples
  local col=$1; shift
  printf "%s\n" "$@" | awk -v c="$col" '{print $c}' | sort -n |
    awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}'
}

echo "== workload ($MODE), sensor off ($N runs) =="
OFF=()
for i in $(seq "$N"); do
  v=$(docker exec "$CTR" python3 -c "$WORK")
  OFF+=("$v")
  printf "   cpu=%ss wall=%ss\n" "$(echo "$v" | cut -d' ' -f1)" "$(echo "$v" | cut -d' ' -f2)"
done

echo "== sensor on =="
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
START=$(date +%s%N)
PIN="${PIN:-0}"; CORE="${CORE:-0}"
LAUNCH=()
[ "$PIN" = "1" ] && LAUNCH=(taskset -c "$CORE")
"${LAUNCH[@]}" "$BIN" run --spool "$TMP/events.jsonl" --edges "$TMP/edges.jsonl" > "$TMP/sensor.log" 2>&1 &
SENSOR=$!
sleep 3
if ! kill -0 "$SENSOR" 2>/dev/null; then
  echo "sensor failed to start:"; tail -3 "$TMP/sensor.log"; exit 1
fi
cpu_s() { awk '{print $14+$15}' "/proc/$1/stat" 2>/dev/null || echo 0; }
C0=$(cpu_s "$SENSOR")
W0=$(date +%s%N)
ON=()
for i in $(seq "$N"); do
  v=$(docker exec "$CTR" python3 -c "$WORK")
  ON+=("$v")
  printf "   cpu=%ss wall=%ss\n" "$(echo "$v" | cut -d' ' -f1)" "$(echo "$v" | cut -d' ' -f2)"
done
C1=$(cpu_s "$SENSOR")
W1=$(date +%s%N)
END=$(date +%s%N)
kill -INT "$SENSOR" 2>/dev/null || true; wait "$SENSOR" 2>/dev/null || true

MOFF_C=$(med_col 1 "${OFF[@]}"); MON_C=$(med_col 1 "${ON[@]}")
MOFF_W=$(med_col 2 "${OFF[@]}"); MON_W=$(med_col 2 "${ON[@]}")
EVENTS=$(wc -l < "$TMP/events.jsonl" 2>/dev/null || echo 0)
SENS_CPU=$(awk -v a="$C0" -v b="$C1" 'BEGIN{printf "%.2f", (b-a)/100}')
ELAPSED=$(awk -v a="$W0" -v b="$W1" 'BEGIN{printf "%.2f", (b-a)/1e9}')
SCPU=$(awk -v s="$SENS_CPU" -v e="$ELAPSED" 'BEGIN{if(e>0) printf "%.2f", s/e*100; else print 0}')
DCPU=$(awk -v a="$MOFF_C" -v b="$MON_C" 'BEGIN{if(a>0) printf "%+.2f", (b-a)/a*100; else print "n/a"}')
DWALL=$(awk -v a="$MOFF_W" -v b="$MON_W" 'BEGIN{if(a>0) printf "%+.2f", (b-a)/a*100; else print "n/a"}')

echo
echo "mode              $MODE   pin=$PIN"
echo "workload CPU      off=${MOFF_C}s  on=${MON_C}s  delta=${DCPU}%   <- the claim"
echo "workload wall     off=${MOFF_W}s  on=${MON_W}s  delta=${DWALL}%   (load-sensitive, context only)"
echo "sensor CPU        ${SENS_CPU}s over the ${ELAPSED}s workload window = ${SCPU}% of one core"
echo "events captured   ${EVENTS}"
awk -v s="$SENS_CPU" -v n="$EVENTS" 'BEGIN{if(n>0) printf "sensor CPU/event  %.0f us\n", s/n*1e6}'
awk -v s="$SENS_CPU" -v m="$MON_C" -v n="$N" 'BEGIN{if(m>0) printf "sensor CPU / workload CPU  %.1f%%\n", s/(m*n)*100}' 
