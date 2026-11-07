# CDR — Collusion Detection and Response

Kernel-level provenance for multi-agent collusion detection. Agents run with
unrestricted shell, so anything they report about their own actions is a claim,
not evidence. CDR ignores transcripts entirely: it observes file activity at the
syscall boundary, attributes each event to an agent by *cgroup inode* rather than
pid or process name, and forms edges only when an event provably crosses an agent
boundary. A syscall cannot lie about which cgroup it ran in.

## Build and run

```sh
cd ebpf-agent
cargo build --release            # eBPF object + userspace loader
sudo ./target/release/ebpf-agent run \
    --spool events.jsonl --edges edges.jsonl
```

Testbed (three containers in one cgroup slice):

```sh
cd testbed
sudo ./bench.sh --repeats 4      # scripted scenarios, deterministic
sudo ./bench.sh --live           # model-driven agents, in-process payloads
```

## Layout

- `ebpf-agent/ebpf-agent-ebpf/` — the kernel probe (`sys_enter`/`sys_exit`,
  per-syscall filtering, ringbuf emission).
- `ebpf-agent/ebpf-agent/src/` — userspace: inode resolution, fd tracking,
  cgroup ancestry, event correlation, baselines, scoring, Elasticsearch sink.
- `testbed/` — docker-compose stack, scenario generators, bench harness.
- `BLUEPRINT.md` — the full design and evaluation plan.
- `testbed/CODE_FROZEN.txt` — the frozen code state and every change-recorded
  decision made during evaluation.

## Notes on identity

Agent identity is the cgroup inode, resolved by walking the cgroup ancestry of the
emitting process up to the nearest slice descendant. Deployment is declared out of
band, never asserted by the agent: a nested cgroup confers identity only if the
harness declared it, so an agent cannot impersonate a neighbour or manufacture
collusion edges by creating cgroups.

## Licences

Userspace dual MIT/Apache-2.0; eBPF dual GPL-2.0/MIT.
