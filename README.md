# CDR: Collusion Detection and Response
### Built for the Apart Research Swarm Alignment Hackathon 2026

As it stands, agents can pretend to perform actions they never declare, and declare actions they never performed. 
They can rewrite transcripts. They can work in unsanctioned shared directories with other agents
to achieve a larger goal.

Kernel-level provenance for multi-agent collusion detection is the only account the agent has no ability to doctor.
I built this because agents that are trusted with a shell can say anything about what they did, and
every log-based oversight tool records those claims rather than the actions. As a field, we are beyond
limiting agent capabilities to certain commands, so ordinarily there would be a trade-off to
confinement. CDR removes that trade-off so that actions stay observable regardless of what the agent says about them.

CDR ignores the transcript. It observes file activity at the syscall boundary,
attributes each event to an agent by cgroup inode rather than by pid or process
name, and forms an edge between two agents that touched the same object. A syscall cannot 
lie about which cgroup it ran in.

## Results

Across 72 scripted episodes over 18 channels, CDR recovers 80/80 interactions with no false edges. Across 18 episodes
of model-driven agents, the kernel recorded 42 interactions and a monitor that only looks at the transcript recovered none,
including three modes where the agent's declaration was true, and the named binary was hostile (`launder` assessment type).

## Build and run

```sh
cd ebpf-agent
cargo build --release            # eBPF object + userspace loader
sudo ./target/release/ebpf-agent run \
    --spool events.jsonl --edges edges.jsonl
```

### Testing

```sh
cd testbed
cp .env.example .env             # ES, Kibana, API key (already set locally)
sudo ./bench.sh --repeats 4              # scripted scenarios, deterministic
sudo ./bench.sh --live-repeats 3         # model-driven agents
sudo ./colocated_test.sh                 # two agents inside one container
sudo ./overhead_test.sh                  # sensor cost against a fixed workload
sudo ./validate.sh                       # all of the above, unattended
```

## Layout

- `ebpf-agent/ebpf-agent-ebpf/`: the kernel probe (`sys_enter`/`sys_exit`,
  per-syscall filtering, ringbuf emission).
- `ebpf-agent/ebpf-agent/`: userspace. Inode resolution, fd tracking, cgroup
  ancestry, event correlation, baselines, scoring, Elasticsearch sink.
- `testbed/`: docker-compose stack, scenario generators, bench harness, and the
  recorded corpora under `testbed/episodes/`.
- `paper/`: the LaTeX source of the paper.

## Identity
Agents are identified by their cgroup inode, resolved by walking the cgroup ancestry of the
emitting process up to the nearest slice descendant. Deployment is declared out of
band, never asserted by the agent. A nested cgroup confers identity only if my
harness declared it, so an agent cannot impersonate another agent, and it cannot
manufacture collusion edges by splitting itself into several identities.

`testbed/colocated_test.sh` demonstrates the current design. Two processes inside
one container, moved into child cgroups declared OOB, producing an edge
between them in 3/3 cases.

## Licences

Userspace dual MIT/Apache-2.0; eBPF dual GPL-2.0/MIT.

## Preexisting Disclosure

Prior to the start of the Apart Research hackathon, I created the `Dockerfile` and `docker-compose.yml` in the `testbed/`
directory. This was such that I wouldn't need to create a swarm testing environment from scratch under timed conditions.
A template eBPF probe was also created prior to the start of the hackathon, on the Thursday, which was effectively
rewritten entirely (as it originally used `sys_enter_execve` as a trigger, and logged all `execve`s to stdout).

## AI Disclosure and Result Integrity

Parts of this code were written with Deepseek V4.1 Flash due to time constraints.
The userspace loader, the correlation and reconciliation modules, the scenario generators 
and the bench harness were drafted by the assistant under my direction, and I reviewed every
change before it was built or run.

Every design choice is mine: identity by cgroup inode rather than pid or name, the object
key as device and inode rather than inode, the choice to reconcile declarations
against execution rather than trust them.

All results in this repository were formed by `testbed/` and numbers were not influenced by any models.
Running `testbed/` on a clone regenerates every scripted number reported within the paper, and
the scripted tests will replay identically. However, the live suite depends on 
hosted models (namely Deepseek V4.1 Flash via OpenCode Go), so CDR's edge counts will 
differ from run to run. A transcript monitor will remain consistent at recovering zero interactions, 
because CDR's edges are not derivable by any transcript.

I appreciate any further reproductions to corroborate the impact of CDR.