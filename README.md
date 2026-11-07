# CDR: Collusion Detection and Response

Kernel-level provenance for multi-agent collusion detection. I built this because
agents that are trusted with a shell can say anything about what they did, and
every log-based oversight tool records those claims rather than the actions.

CDR ignores the transcript. It observes file activity at the syscall boundary,
attributes each event to an agent by *cgroup inode* rather than by pid or process
name, and forms an edge only when an event provably crosses an agent boundary. A
syscall cannot lie about which cgroup it ran in.

Mikey Whiston, Sentinel Logic Ltd. Design, code and evaluation are mine; the
disclosure at the end says which parts were drafted with an AI assistant.

## Build and run

```sh
cd ebpf-agent
cargo build --release            # eBPF object + userspace loader
sudo ./target/release/ebpf-agent run \
    --spool events.jsonl --edges edges.jsonl
```

I test against three containers in one cgroup slice:

```sh
cd testbed
sudo ./bench.sh --repeats 4      # scripted scenarios, deterministic
sudo ./bench.sh --live           # model-driven agents, in-process payloads
sudo ./colocated_test.sh         # two agents inside one container
sudo ./overhead_test.sh          # sensor cost against a fixed workload
```

## Layout

- `ebpf-agent/ebpf-agent-ebpf/`: the kernel probe (`sys_enter`/`sys_exit`,
  per-syscall filtering, ringbuf emission).
- `ebpf-agent/ebpf-agent/`: userspace. Inode resolution, fd tracking, cgroup
  ancestry, event correlation, baselines, scoring, Elasticsearch sink.
- `testbed/`: docker-compose stack, scenario generators, bench harness, and the
  recorded corpora under `testbed/episodes/`.
- `paper/`: the LaTeX source of the paper.
- `BLUEPRINT.md`: the design and evaluation plan I worked from.
- `testbed/CODE_FROZEN.txt`: the frozen code state, and every decision made during
  evaluation, including the ones I got wrong and reverted.

## How identity works, and why it is not a name

Agent identity is the cgroup inode, resolved by walking the cgroup ancestry of the
emitting process up to the nearest slice descendant. Deployment is declared out of
band, never asserted by the agent: a nested cgroup confers identity only if my
harness declared it, so an agent cannot impersonate a neighbour, and it cannot
manufacture collusion edges by splitting itself into several identities.

I first implemented the obvious alternative, where any child cgroup named
`agent-*` became an agent. A reviewer pointed out that an agent able to create
cgroups could then adopt a neighbour's name, or create several names to split its
own footprint and produce edges between two halves of one attacker. Both attacks
come from trusting a string the subject chooses, so I withdrew it. See
`CODE_FROZEN.txt` for the log of that reversal and the re-run that confirmed it
changed nothing else.

`testbed/colocated_test.sh` demonstrates the current design: two processes inside
one container, moved into child cgroups declared out of band, producing an edge
between them in three of three runs.

## Licences

Userspace dual MIT/Apache-2.0; eBPF dual GPL-2.0/MIT.

## AI Disclosure

Parts of this code were written with an AI coding assistant. The userspace loader,
the correlation and reconciliation modules, the scenario generators and the bench
harness were drafted by the assistant under my direction, and I reviewed every
change before it was built or run.

The design is mine: identity by cgroup inode rather than pid or name, the object
key as device and inode rather than inode, the choice to reconcile declarations
against execution rather than trust them, and the withdrawal of name-based identity
markers after the impersonation case was raised in review. Those decisions, and
the incidents behind them, are recorded in `testbed/CODE_FROZEN.txt`.

No evaluation result in this repository was produced by a model. Every number in
the paper comes from running the built binary against recorded corpora, and the
corpora and edge files are committed so the claims can be re-derived.
