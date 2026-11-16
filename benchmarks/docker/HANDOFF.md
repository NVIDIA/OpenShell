# Sandbox performance and filesystem research handoff

> **Checkpoint note.** This handoff preserves the original Cedar-based
> checkpoint `8dd0a0cae` and its historical measurements. The current
> performance PR #5687 is being ported onto `main` independently of Cedar, and
> the CA bundle PR #5686 remains stacked above it. The inherited-branch
> instructions below describe the original checkpoint, not the `main`-based
> port.

This document carries the conversation context to a different machine.
Everything below describes completed work unless marked as future work.
See the Git branch containing this file for the implementation; machine-local
credentials, binaries, Docker state and `.cache` contents are not required to
understand the results and are not included.

## Objective and user decisions

The original request was to benchmark regular Docker against the OpenShell
Docker driver, distinguish syscall interception from other runtime costs,
implement improvements, and report measurements. The investigation expanded
to the PR responsible for slow file opens and alternative sandbox filesystems.

The user's current priorities are:

- Broad deployment compatibility and capability-free workloads.
- Keep a kernel enforcement hook. The current implementation retains seccomp
  user notification and Landlock.
- Do not make direct per-config-file infrastructure volumes the solution.
- Do not make FUSE, `/dev/fuse`, privileged mounts, host agents, KVM, or custom
  kernels mandatory for the current runtime.
- Better filesystem support remains a future goal. A Landlock replacement is
  open for research, but was deferred from the performance iteration.
- Use **Claude Code CLI with model alias `fable`** for code changes. It worked
  here with CLI 2.1.323 and resolved to `claude-fable-5-2`. Verify the alias and
  authentication on the new machine; credentials/config were not transferred.
- The user explicitly authorized completing the latest benchmarks under
  shared-host build load. Do not describe those measurements as idle-host runs.

No PR or merge was requested. The earlier experimental work was preserved.

## Repository and implementation state

Repository: `https://github.com/NVIDIA/OpenShell`.

The working checkout started at detached commit
`e9f4a4269c8350f52ed827eb5d3588a20b25436d`. The continuation branch is
`drew/compatible-config-performance`; use its current tip for the final state.
The branch includes the earlier experiments as well as the latest iteration.

The runtime split matters: `openshell-sandbox` owns the workload, seccomp
broker, Landlock and process identity. A separate trusted supervisor owns
policy evaluation, credentials and upstream network activity. A storage
backend does not replace this trust boundary.

### Earlier performance changes retained

- Narrow scalar socket-option fast paths, including the `TCP_NODELAY`
  whitelist, with argument-width and denial behavior preserved.
- Avoid duplicate descriptor enumeration on the ordinary socket path, while
  retaining headroom checks and recounting after collection.
- Copy socket addresses once on the successful path; preserve the earlier
  error-path reads. Measurements showed `process_vm_readv` working on the
  tested host and Docker posture, so no backend-selection cache was introduced.
- Reuse bounded blocking-connect workers instead of spawning one thread per
  connect. Keep admission limits, cancellation and identity handling.
- Extend the benchmark harness with file-open attribution and concurrency.
- Preserve the Docker native provider-store experiment: one volume mounted
  writable for the runtime and read-only for the workload, validated mounts,
  atomic generation exchange and a real Landlock capability probe. It fails
  closed on invalid declared storage and only falls back when a validated
  store is proven empty and the kernel is unqualified.

The native store is now **disabled by default**. Opt-in is the Docker crate's
Cargo feature `experimental-native-provider-files`. Podman, Kubernetes and VM
drivers continue to declare no native provider store.

### Latest compatible iteration: enabled behavior

Primary implementation: `crates/openshell-sandbox/src/provider_files.rs`.

- `Revision<Backing>` holds immutable config bytes and their prepared backing;
  `Snapshot<Backing>` is a complete path-to-revision generation.
- Prepare one sealed memfd per changed file during publication. Reuse the
  revision when the same path's bytes are unchanged.
- Prepare the entire next generation before acquiring the publication write
  lock. Preparation failure leaves the old generation intact. Exchange the
  whole snapshot under the lock and release old backing outside it.
- Keep a read-only anchor and a verified descriptor for the runtime's own
  `/proc/self/fd`. Reopen the anchor for **every caller**, giving a fresh
  read-only open file description and independent offset. `dup`/`try_clone`
  would share offsets and is not a substitute.
- Preserve seals against writing, resizing and adding seals. Existing open
  descriptors keep old bytes after update or detach; future opens see the
  current revision or `ENOENT` after detach.
- Preserve limits: 64 files, 64 KiB per file, 256 KiB total. Cached anchors
  consume descriptors; preparation briefly retains old and new generations.
- Opens of one revision now share an inode, metadata and lock state. Because
  the workload owns that inode, it can change its mode; content remains
  sealed, and the runtime restores mode 0600 if a reopen fails with `EACCES`.

Open classification now reads exactly six bytes with the existing exact
task-memory reader:

1. Failed copy: continue to the kernel; a short valid ordinary pathname may
   end immediately before an unmapped page.
2. `/proc/`: consider the existing thread-name handler, still validating the
   complete path and caller/target identity.
3. `/run/o`: under virtual delivery, read the complete path and require the
   actual `/run/openshell/providers/` prefix before serving a config.
4. Other paths: continue; the kernel and Landlock authorize them.

This avoids decoding unrelated `openat2` pointer arguments. It does not cache
path classifications by pointer or authorize mutable paths using `CONTINUE`.
Ordinary `/run/o...` paths incur another full-path copy before continuation.

An intermediate partial-memory-copy helper was removed during review. The
final `linux/task_memory.rs` is byte-for-byte the preserved pre-iteration
version; do not resurrect `read_prefix` or its removed fork fixture.

No production receiver or wakeup tuning was added: blocking connects were
already offloaded. The immutable revision/backing separation is groundwork
for optional future filesystem delivery, not a general filesystem framework.

## Benchmark workloads and method

The shared C workload runs in ordinary Docker and through the Docker driver,
with the same image, UID/GID 1000, `/sandbox`, no external network, dropped
capabilities, no-new-privileges and Docker's default seccomp/AppArmor profiles.
OpenShell additionally applies its runtime enforcement. Nine paired trials
alternate mode order, shuffle cases and use full unrecorded warmups and fresh
containers. Images are cached; provisioning excludes build/pull time.

| Workload | Default operations | Meaning |
|---|---:|---|
| CPU | 100 million | Volatile integer recurrence; scheduling/CPU control |
| getpid | 1 million | Explicit kernel calls; syscall-filter control |
| file | 50,000 | Open `/etc/passwd`, read 64 bytes, close |
| spawn | 200 | Fork, exec `/bin/true`, wait |
| tcp-connect | 1,000 | Connect, 64-byte request/reply, close on loopback |
| tcp-stream | 20,000 | 64-byte request/reply on an established connection |
| provision | One/trial/mode | Creation through successful readiness exec |
| exec | One/trial/mode | Warm end-to-end `/bin/true` exec |
| file-open | 50,000 | Open/close without reading |
| file-read | 500,000 | Repeated reads on an FD opened before timing |
| file-t4 / file-t16 | 50,000 total | File loop split across 4 or 16 threads |
| file-latency | 50,000 | Per-operation p50/p99/max, including clock reads |

The Rust broker harness uses production launcher/broker code without the full
gateway/supervisor lifecycle. Its TCP-connect operation is connect/close,
without the C workload's echo. Do not subtract absolute timings between them.

Harness layers are `native`, `notify-only` (diagnostic continue-all responder),
`filtered` (virtual provider broker), and `native-opens` (native-store test
delivery). `--layer all` remains native+filtered; `--protocol all` remains the
two original TCP protocols; `--protocol file` selects the three file controls.

Latest additions:

- `--provider-file --provider-file-bytes N`: seed deterministic synthetic
  config bytes at `/run/openshell/providers/perf/config.toml`, use the real
  injection path and validate read content. Only `--layer filtered` supports
  this. Default size 4096, maximum 65536; incompatible combinations error.
- `--protocol mixed`: file-open/read plus TCP-connect or TCP-stream, with N
  workers **per class**, 2N total. Both classes continue until every worker
  reaches its quota. Report each class separately; do not pool percentiles.
  Mixed `iterations` records completed operations, so compare rates/latencies.
- Mixed failures, panics and content mismatches fail the run and stop peers.
- `--landlock`, `--concurrency 1|4|16`, `--sync-wakeup`, and
  `--notify-receivers` support attribution. The last two are experimental only.

## Results: keep the comparisons separate

### Original characterization

`RESULTS.md`, artifact `results/2026-11-12.json`:

- Ordinary file loop: Docker 89.719 ms, OpenShell 819.160 ms; paired +815.6%.
- New TCP connections: 36.447 vs 199.981 ms; paired +446.8%.
- Spawn: 107.498 vs 130.707 ms; paired +24.1%.
- CPU/getpid roughly unchanged; established TCP +4.7% in that full-driver run.
- Faster OpenShell warm exec is a client/control-plane comparison, not proof
  that child processes execute faster.

### Exact PR #3832 causality check

`RESULTS-PR3832.md`, artifact `results/2026-11-15-pr3832.json`:

- Exact parent: `5c0c9e446ed3b11e21198058873b0c6adfee6b4e`.
- Exact merge: `252882f37f2daa63ef4078b3bbb89adbcf43b409`.
- Clean historical checkouts, matching locked dependencies, nine paired
  trials each, 468 samples total.
- Open/read/close: 100.525 → 838.370 ms, **8.34×**.
- Open/close: 84.268 → 819.612 ms, **9.73×**.
- Existing-FD reads: 136.234 → 138.008 ms, +1.3%.
- File-loop overhead over Docker: +10.7% → +818.2%.

The PR added global notifications on `open/openat/openat2` for virtual provider
files. The regression is in opening, not established-FD read bandwidth.

### Earlier native-volume optimization

`RESULTS-AFTER.md`, artifact `results/2026-11-13-before-after.json`:

- File loop 791.401 → 107.091 ms, −86.5%.
- TCP-connect 195.008 → 110.234 ms, −43.5%.
- Spawn 125.095 → 107.832 ms, −13.8%.
- Provisioning 727.147 → 804.193 ms, +10.6%.

The file improvement depended on native volume delivery and removing read-open
notifications. **It is not the result of the current compatible default.**
The user rejected making that architecture mandatory; the code is retained
behind the build opt-in.

### Latest compatible cache iteration

`RESULTS-COMPATIBLE.md`, artifact `results/2026-11-16-compatible.json`:

| Config size | Threads | Before p50 µs | After p50 µs | Median paired change |
|---|---:|---:|---:|---:|
| 4 KiB | 1 | 23.208 | 16.149 | −31.8% |
| 4 KiB | 4 | 114.237 | 81.037 | −29.1% |
| 4 KiB | 16 | 493.951 | 332.185 | −32.3% |
| 64 KiB | 1 | 34.798 | 15.806 | −54.2% |
| 64 KiB | 4 | 158.465 | 79.422 | −52.7% |
| 64 KiB | 16 | 737.672 | 328.871 | −54.6% |

4 KiB improved in 9/9, 8/9 and 9/9 pairs respectively; 64 KiB improved in every
pair. One 4-thread trial had a severe outlier, retained in the ranges/raw data.
Each timed read requests 64 bytes; the file size controls preparation avoided.

Ordinary full-driver file loop: **821.889 → 824.404 ms (+0.3%)**. The ordinary
open notification tax remains. No whole-agent speedup was measured.

Latest collection included 31 harness cases × 9 pairs = 558 invocations/774
class reports, plus 468 full-driver samples. Both runtimes used identical new
measurement code; the full-driver runs shared the new virtual-default gateway
and unchanged supervisor. Both static sandbox builds enabled `perf-harness`,
including the same task-memory instrumentation; these are not exact shipping
build latencies.

An initial quiet-host attempt stopped after 20 accepted invocations when
other builds restarted; it is preserved but excluded. The user authorized a
fresh run under load. 475/558 final harness invocations observed Rust builds;
load/process counts and CPU utilization are recorded. Paired percentages are
medians of ratios and can differ from ratios of displayed medians.

Network caveats are material:

- Managed-file/TCP-connect mixed cases improved connection p50 in all pairs.
- At 16 threads, managed-file/TCP-stream had +4.8% paired stream p50 and −1.5%
  stream throughput.
- Standalone 16-thread connect p99 initially increased 21.0%.
- Five separate longer follow-up pairs did not reproduce it: p50 −0.3%,
  throughput +0.2%, p99 −6.5%. No Rust build processes were observed then.
- Different load conditions mean neither causality nor universal absence of
  network regressions is established. Keep both datasets; do not cherry-pick.

## Attribution and ideas already rejected

Measured single-thread file-open p50: native ~1.0 µs, notify-only ~14.9 µs,
full handler ~17.0 µs. A Landlock domain added ~0.15 µs in that experiment.
The notification round trip dominates; replacing Landlock alone cannot remove
it. Classic seccomp BPF cannot dereference a pathname pointer to select only
provider paths.

Synchronous wakeup improved a single-thread file case 16.3 → 4.1 µs, but
worsened multithread/network tails and some throughput. It remains off in
production. Two/four shared receivers also reduced throughput; not enabled.

Linux rejects a second `NEW_LISTENER` filter on the same task chain with
`EBUSY`. "Separate file and network listeners" cannot simply mean stacking
two notification listeners. The wakeup flag is per listener, not per syscall.

Do not cache path classification by pointer, trust mutable pointers for
authorization, cache task descriptors across PID/exec reuse without proof,
or skip mediation solely because no providers existed at launch: providers
can attach later.

## Filesystem research and longer-term options

`FILESYSTEM-RESEARCH.md` contains the full comparison and all **41 supplied
bookmark links**. The attachment was a curated summary from 1,796 exported
bookmark texts, not a freshly verified complete export. X posts were often
only partially readable; primary docs/repos were checked and uncertainties
are labeled. Do not turn vendor claims into measured OpenShell results.

Keep three responsibilities separate: config virtualization, durable workspace
storage, and filesystem confinement. FUSE/storage/snapshots do not themselves
replace Landlock; a VM boundary does not automatically protect runtime keys
or enforce per-path policy inside the guest.

Useful findings:

- **Sandlock** is the closest peer and retains Landlock with seccomp-notify.
  Its reversible-write staging/commit model is useful inspiration, not proof
  that it removes notification overhead or replaces Landlock.
- **AgentFS** uses a SQLite-backed inode/chunk store and FUSE; Linux `run`
  combines FUSE with a separate namespace sandbox. Cache invalidation and
  immutable revisions are useful patterns. Shared-mount SQLite WAL safety is
  not established by the SDK/storage abstraction.
- **Tines/Nest on gVisor** supplies local tmpfs FDs after opening files, keeps
  reads/writes/mmap local, pins step snapshots and commits by CAS on successful
  completion. In-step fsync is not durable publication; same-file conflicts
  are rejected. This is storage transaction design, not a drop-in broker.
- **gVisor** current checked source supports seccomp filter mode/TSYNC but
  rejects `NEW_LISTENER`; the existing broker cannot simply run inside runsc.
  Custom gofer extensions or Sentry synthetic files imply a custom backend/
  runsc redesign. Directfs vendor speedups compare gVisor variants, not native.
- **LayerFS** provides branches/FUSE workspaces over one local SQLite store.
  Docs require one Linux kernel and local ext4/xfs/btrfs; its WAL uses
  `synchronous=OFF` and claims no crash durability. It is not a cloud-shared
  durable disk merely because it has snapshots.
- **Tensorlake** separates content-addressed data from metadata and offers
  snapshots/forks. Mounted writes publish asynchronously; same-path writers
  can be last-writer-wins. SDK commit semantics differ from mounted autosave.
- **TiDB/Daytona** documents FUSE mounts, local write caching, explicit drain
  before handoff/deletion, and nontransactional overlapping writes. The match
  to `drive9` is uncertain, labeled accordingly.
- **Archil** documents FUSE/client privilege requirements and client-scoped
  locks; generic shared SQLite WAL safety does not follow. AgentRun's
  pi-durable-disk instead uses exclusive claims, fencing and release-before-
  migration. It explicitly does not sandbox the agent.
- **Box/Boat** was identified with medium confidence as ASCII Box, now Boat;
  do not substitute Box.com or unrelated similarly named projects. Its
  metadata-first FUSE restore mechanism remains bookmark-only, not verified
  in the product docs. Disk snapshot is not process/memory checkpoint.
- **virtiofs** transports filesystem access across a VM boundary and is
  already used for optional VM shares; it is not per-path confinement.
- Tool-shaped FS APIs, WASI and just-bash are not transparent enforcement for
  arbitrary native Python, Node or Claude Code binaries.

A small synthetic config filesystem would be one runtime-managed, read-only
mount at `/run/openshell/providers`, serving in-memory revisions. Kernel VFS
routing could keep unrelated opens native; per-revision inodes and cache
invalidation could preserve old-FD semantics. It still needs authorized mount
setup and `/dev/fuse`. The user prioritized compatibility, so this remains an
optional backend candidate, not the default or implemented next step.

FUSE is established on Linux hosts but not automatically available inside
restricted Docker/Kubernetes workloads. The old host had `/dev/fuse`; that
does not prove container mount permission. The exact meaning of "kernel hook"
for a future design remains open: kernel VFS/FUSE versus seccomp notification
on every open. If every open must still notify, that round-trip cost remains.

Landlock alternatives remain redesign candidates: private mount views with
RO/RW/noexec boundaries plus process/UID separation and sanitized FDs; host
AppArmor/SELinux/BPF LSM with privileged deployment support; a gVisor VFS;
or guest-internal policy in a VM. None was shown faster/safer for our policy.

Primary starting sources (full citations/identity qualifications in research):

- https://docs.kernel.org/userspace-api/seccomp_filter.html
- https://man7.org/linux/man-pages/man2/seccomp.2.html
- https://docs.kernel.org/filesystems/fuse/fuse.html
- https://docs.kernel.org/filesystems/fuse/fuse-passthrough.html
- https://docs.kernel.org/userspace-api/landlock.html
- https://docs.kernel.org/bpf/prog_lsm.html
- https://github.com/tursodatabase/agentfs
- https://github.com/multikernel/sandlock
- https://www.shayon.dev/post/2026/283/versioned-filesystem-for-disposable-sandboxes/
- https://github.com/google/gvisor/blob/master/pkg/sentry/syscalls/linux/sys_seccomp.go
- https://gvisor.dev/blog/2023/06/27/directfs/
- https://layerfs.ai/docs/platform/
- https://docs.tensorlake.ai/filesystems/architecture.md
- https://www.daytona.io/docs/en/mount-external-storage/
- https://docs.archil.com/details/consistency.md
- https://agentrun.ai/extensions/runs-anywhere
- https://github.com/containers/bubblewrap

## Validation completed

- Final sandbox library: 346 passed, two pre-existing native-mount tests
  ignored. Entrypoint: four passed; stdout-logging integration: one passed.
- Docker driver: 156 passed, two ignored, both feature off and feature on.
- Sandbox clippy with/without perf harness; Docker driver clippy with/without
  native-store feature; all targets with warnings denied. Formatting clean.
- Five final Docker E2E tests: `host_gateway_alias` (three),
  `policy_activation` (one), `provider_files` (one).
- Image binaries extracted and verified against archived sandbox hashes;
  staging binaries restored. Default workloads verified to have no provider
  volume/public provider mount. All benchmark-owned resources cleaned up.
- Cargo.lock, syscall filter and exact memory reader were unchanged by the
  latest compatible iteration. They do include earlier experiments versus
  the original repository base.
- Only this Linux x86_64 host was executed. No ARM64/old-kernel support claim.

## Rebuild and continue on another machine

Original environment: Ubuntu 26.04.1, kernel `7.0.0-1017-gcp`, Docker 29.1.3,
8-vCPU Xeon Platinum 8581C VM, ~31 GiB RAM, Rust 1.95.0. Static musl sandbox;
GNU supervisor used an Ubuntu 26.04 base/public CA bundle because the host GNU
build needed newer glibc than published distroless. Do not blindly reuse that
packaging workaround on another machine. Original Docker image IDs are
provenance, not downloadable portable assets.

Read root `AGENTS.md`, `CONTRIBUTING.md`, the crate READMEs and benchmark
runbook. Use `uv` for Python. Prefer mise Docker build tasks. A bare `mise
exec` attempted unrelated tool installation here; use installed tools or
`mise run --skip-tools` when prerequisites are already prepared. Docker access
on the old host required `sg docker -c`; do not assume it is needed elsewhere.

Core checks (use the repository toolchain on the new machine):

```shell
cargo test --locked -p openshell-sandbox --features perf-harness
cargo test --locked -p openshell-driver-docker --lib
cargo test --locked -p openshell-driver-docker --features experimental-native-provider-files --lib
cargo clippy --locked -p openshell-sandbox --all-targets --features perf-harness -- -D warnings
cargo clippy --locked -p openshell-driver-docker --all-targets -- -D warnings
cargo fmt --all -- --check
mise run perf:docker:test
```

Broker examples:

```shell
cargo build --release --locked -p openshell-sandbox --features perf-harness --bin openshell-seccomp-perf
target/release/openshell-seccomp-perf --layer filtered --protocol file --provider-file --landlock --concurrency 1 --iterations 10000 --warmup 1000
target/release/openshell-seccomp-perf --layer filtered --protocol mixed --provider-file --landlock --concurrency 4 --iterations 1000 --warmup 100
```

Use 1/4/16 threads and 4096/65536-byte configs. The final 31-case grid and
exact counts are in the raw artifact's `harness.cases`. Its single-thread
existing-FD controls use 100,000 reads; normal file loops use 10,000 operations
per worker; standalone TCP connect 1,000; stream 5,000; mixed connect 1,000;
mixed stream 2,000; warmups are 10%, at least 100. Keep mixed-connect counts
bounded to avoid exhausting loopback ephemeral ports.

For matched-container attribution build a static musl harness as well as the
sandbox, use UID/GID 1000, drop all capabilities, set no-new-privileges,
network none and default outer profiles, and mount only benchmark binaries
read-only for the measurement. This binary mount is test instrumentation,
not the rejected per-config delivery design.

For the full comparison, build matching runtime images through mise, create
a fresh dedicated Docker gateway and CLI registration, then use
`tasks/scripts/perf-docker.py` / `mise run perf:docker` per the runbook. Do not
copy old gateway JWT/TLS files or assume the old cache/state paths exist.
Use explicit `sandbox exec --name` syntax for compatibility with older CLIs.

For E2E, use `e2e/with-docker-gateway.sh` and the tests above, with new runtime
image overrides. It supports an existing plaintext
`OPENSHELL_GATEWAY_ENDPOINT`, or can start a temporary gateway. Inspect its
current help/source rather than reusing machine-local launch scripts.

The source before the latest iteration is reconstructible from
`baselines/pre-compatible.patch.gz`; see `baselines/README.md`. In particular,
reuse the **new virtual-default gateway** when comparing old/new sandbox
virtual delivery. Otherwise the older gateway can enable the native volume
and produce an invalid comparison.

## Suggested next work

1. Review this branch's full combined diff: it contains earlier experiments,
   not just the latest cache. Split it into reviewable changes before a PR.
2. Re-run on a controlled host before accepting network p99 conclusions;
   also test ARM64 and representative older supported kernels if available.
3. Add realistic import-heavy Python/Node startup, small build and actual
   agent workflows. Config-open microbenchmark wins are not whole-agent wins.
4. Measure publication/attach latency and descriptor-pressure behavior with
   many providers; cost moved from opens to revision preparation.
5. If filesystem work resumes, first define config delivery, workspace
   durability and confinement contracts separately. Treat FUSE as optional
   until per-driver bootstrap/mount feasibility is demonstrated.
6. Keep seccomp/Landlock and current safety checks while experimenting. Do not
   re-enable the wakeup hint, extra receivers or native-volume default based
   only on a single-thread gain or old headline benchmark.

Follow Conventional Commits and DCO signoff. Never put secrets into Git.
Read the appropriate contributor skill before creating a PR; no PR was
created as part of this handoff.
