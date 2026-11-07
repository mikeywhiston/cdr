# CDR: Collusion Detection and Response

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

- `ebpf-agent/ebpf-agent-ebpf/`: the kernel probe (`sys_enter`/`sys_exit`,
  per-syscall filtering, ringbuf emission).
- `ebpf-agent/ebpf-agent/src/`: userspace. Inode resolution, fd tracking,
  cgroup ancestry, event correlation, baselines, scoring, Elasticsearch sink.
- `testbed/`: docker-compose stack, scenario generators, bench harness.
- `BLUEPRINT.md`: the full design and evaluation plan.
- `testbed/CODE_FROZEN.txt`: the frozen code state and every decision made
  during evaluation, including the ones that were wrong and were reverted.

## Notes on identity

Agent identity is the cgroup inode, resolved by walking the cgroup ancestry of the
emitting process up to the nearest slice descendant. Deployment is declared out of
band, never asserted by the agent: a nested cgroup confers identity only if the
harness declared it, so an agent cannot impersonate a neighbour or manufacture
collusion edges by creating cgroups. See `testbed/colocated_test.sh` for the
demonstration and the reasoning in `CODE_FROZEN.txt` for why a naming convention
was rejected.

## Licences

Userspace dual MIT/Apache-2.0; eBPF dual GPL-2.0/MIT.

## AI Disclosure

Parts of this code were written with an AI coding assistant. In practice that
means the userspace loader, the correlation and reconciliation modules, the
scenario generators and the bench harness were drafted by the assistant under
the author's direction, and the author reviewed every change before it was built
or run.

The design is the author's: the identity model (cgroup inode rather than pid or
name), the object key (device and inode rather than inode), the decision that
declarations are reconciled against execution rather than trusted, and the
rejection of name-based identity markers after a reviewer pointed out that an
agent could impersonate a neighbour by creating a similarly named cgroup. Those
decisions, and the incidents behind them, are recorded in
`testbed/CODE_FROZEN.txt`.

No evaluation result in this repository was produced by a model. Every number in
the paper comes from running the built binary against recorded corpora, and the
corpora and edge files are committed so the claims can be re-derived.
