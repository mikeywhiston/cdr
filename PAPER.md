# CDR — Kernel-Attested Identity for Multi-Agent Collusion Detection

<!--
PLACEHOLDERS — each one is a command you run and a number you paste. Nothing else.
R1   capture coverage  : cat corpus/capture_report.txt
R2   alias churn       : cdr bench --scenario alias-churn
R3   edges             : cdr edges --corpus corpus/ep-A
R4   transcript recall : cdr baseline --corpus corpus/ep-A
R5   benign false edges: cdr edges --corpus corpus/benign-01
R6   survive unlink    : grep -c survived_unlink corpus/edges/ep-A.jsonl
R7   desync            : cdr desync --corpus corpus/ep-A
R8   delta sweep       : cdr sweep --deltas 0.01,0.1,1,10
R9   attacks           : cdr bench --scenario attacks
R10  overhead          : /proc/stat delta, both arms
R11  ingest lag        : es_lag_ms from the sensor stats line
R12  unclassified      : stats line, unclassified / total
-->

## Abstract (target: 200 words)

Frontier agents execute arbitrary shell inside sandboxes, which destroys the integrity of
in-band transcript monitoring: a monitor reads what the agent *says* it did. We present CDR,
an out-of-band causal monitor that binds agent identity to the Linux cgroup v2 inode at
Ring-0 (zero syscall table in kernel, `<<R1>>` syscalls covered by data-driven capture) and
reconstructs covert inter-agent communication as a directed hypergraph over shared kernel
objects. On `<<N>>` episodes ... kernel provenance recovers `<<R3>>` of `<<T>>` covert edges
that a transcript-only monitor recovers `<<R4>>`, at `<<R5>>` false edges per benign episode
and `<<R10>>` overhead. We further show `<<R7>>` of declared tool calls that never executed
were detected by cognitive-physical desync, and that evasion is bounded: forcing inter-signal
delay above `<<R8>>` drives detection to `<<…>>` at a cost of `<<…>>` bits/second.

**Contribution claims (all four must appear on page 1):**
1. Identity as a kernel object — attested, not self-reported (`<<R2>>`).
2. Transcript-borne monitoring has zero recall on agent-authored deception — argued from
   information flow, then measured (`<<R4>>`).
3. Storage-channel coverage is complete up to the directory object, including the
   "zero-read" channel previously assigned to statistical detection (`<<R3>>`, `<<R6>>`).
4. The sensor's own blind spots are measured, not asserted (`<<R9>>`, `<<R12>>`).

---

## 1. Introduction

- The incident framing: N agents, M aliases, spoofed tool calls. [cite METR / Swarm Traces **as reported**]
- In-band telemetry fails twice: it can be edited, and even when honest it never contains the
  covert event — the edge lives in the kernel, the transcript contains only declarations.
- The Fragmentation Effect: per-instance monitors see 99% benign slices.
- Contributions list (the four above), one line each, each pointing at its result.

## 2. Related work and threat model

- In-band linguistic steganography detection vs out-of-band OS dead-drops.
- eBPF observability is commodity (Tetragon/Tracee/Falco): those give raw events or per-process
  policy; none binds *agent* identity or emits cross-agent causal verdicts. **Name this
  difference explicitly** — a security-literate reviewer will ask.
- Provenance graphs (SPADE/CamFlow) vs this: we produce a verdict, not a graph dump.
- Why `ptrace`/`strace` fails: `TracerPid != 0` and 10–50x slowdown.
- Threat model, capability-scoped:
  - L0 default docker caps: no `SYS_ADMIN`/`BPF`/`PERFMON`/`SYS_PTRACE` → telemetry unreachable.
  - L1 elevated caps: integrity not defensible in-band; escalate to microVM boundary. State it.
  - Out of scope: `--privileged` (not a sandbox), class-3 microarchitectural channels.

## 3. Method — as built, not as planned

### 3.1 Attested identity
`bpf_get_current_cgroup_id()` at the tracepoint; leaf→ancestor walk to depth 6 with per-CPU
cache; identity is the container's cgroup inode. Aliases (`comm`, hostname, uid) are display
only. `<<R2>>` shows one container retaining a single identity across N renames.

### 3.2 Data-driven capture (no syscall table in Ring-0)
The probe carries `nr`, six registers, cgroup, comm, and up to two user strings chosen by a
bitmask map. The mask is *derived from the running kernel*: for each `sys_enter_*`, parse
`/sys/kernel/tracing/events/syscalls/*/format` and mark arguments typed `char *`.
`<<R1>>` of ~450 syscalls carry captured string arguments. Adding a syscall is a map insert.

### 3.3 Two inode classes
- **File inodes** — `openat`/`write`/`unlink` mutate; `openat`/`read`/`stat`/`getdents` sense.
- **Directory inodes** — `create`/`unlink` mutate the directory; `getdents64` senses it.
  This makes the "zero-read" channel a deterministic storage channel: the receiver never opens
  the sender's files, but both traverse the same directory object, so the causal edge is exact.
  **No statistical model is required for this class.** `<<R6>>` — edge survives `rm -f`.
- **Object keys generalise beyond `(dev,ino)`**: `(ipc,key)` for shm/msg/sem, `(pid,sig)` for
  signals, `(sock,ino)` for sockets. The architecture is "two agents touched the same kernel
  object in order", not "a file was written".

### 3.3.1 Direction is a precision knob, not a gate
An edge exists when two distinct identities touch the same object key in temporal order. A
per-syscall direction map only decides the *arrow*; a syscall absent from the map is not
dropped, it yields an **undirected adjacency edge** (`confidence: adjacency`). Coverage is
therefore a property of capture (any captured string that `statx` resolves), not of the table —
an adversary cannot escape by choosing an unmodelled verb, only by avoiding shared objects
entirely, which pushes them into pure timing and therefore into `<<R8>>`. Two operating points
are reported: directed (high precision) and adjacency-inclusive (high recall).

### 3.4 Cognitive-physical desync
Join kernel events to agent-authored `trajectory.json` by RTC (monotonic + boot offset). A
declared tool call with no corresponding syscall in a ±window is a desync; a kernel `execve`
in that window with no declaration is an omission. `<<R7>>`.

### 3.5 Ingest and analyst surface
`cdr ingest --follow` tails the episode corpus into Elasticsearch (bulk, 1s/500 docs,
idempotent `_id`); the corpus file is the source of truth and ES is a replayable mirror.
Ingestion lag `<<R11>>` makes "real-time" measurable. The defragmentation view collapses three
agents onto one incident timeline — the Fragmentation Effect, answered visually.

## 4. Results

| Claim | Metric | Kernel provenance | Transcript-only | Notes |
|---|---|---|---|---|
| Dead-drop edge recall | R3 |  | R4 | N episodes |
| Dir-count channel | R3 |  | R4 | zero file reads by receiver |
| Survives scrubbing | R6 |  | — | `unlink` after read |
| Benign false edges | R5 |  |  | parallel build + pytest |
| Spoof detection | R7 |  | — | precision/recall |
| Overhead | R10 |  | — | CPU + latency |
| Ingest→Kibana lag | R11 |  | — | p50/p99 |

**Figure 1:** two adjacency matrices, same episode, same axes — left from transcripts (empty), right from kernel.
**Figure 2:** detection probability vs inter-signal delay Δ (R8).
**Table 2:** six attacks, each with outcome (R9).

## 5. Limitations

- `MAP_SHARED` writes are edge-visible (mmap is captured at map time) but content-blind.
- `io_uring` submission hides N operations behind one `io_uring_enter`.
- `<<R12>>` of slice syscalls are unclassified and histogrammed, not observed.
- Class-3 microarchitectural channels are out of scope by construction.
- Single host; cgroup ids are host-local (cross-host correlation key = shared `(dev,ino)`).
- Co-tenancy noise at high agent density.

## 6. Conclusion

Restores the reference-monitor property for multi-agent deployments: the supervisor receives
one de-fragmented timeline of attested causal edges instead of N self-reported slices.

## Appendix A — Event schema v1 (normative)

248-byte fixed record, zero implicit padding, compile-time size and offset assertions.
`kind`/`flags`/`fd`/`dirfd` are ingest-derived from `nr` + args; `resolved` bit 1 means
*string captured*, not *path validated*. Full field table + the kind-dependent slot convention
goes here, plus the capture-mask derivation rule.

## Appendix B — Dual use

Publishing the detector invites low-and-slow signalling. Measurement (`<<R8>>`) bounds it:
evasion above Δ* costs bandwidth, so detection latency and covert capacity trade off
directly. Defensive-only; no offensive capability is added.

## Appendix C — LLM usage statement

[required by the sprint template]
