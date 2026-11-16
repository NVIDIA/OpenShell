# Performance improvement candidates

Claude Code completed a read-only review using `--model fable`; its result
metadata reports `claude-fable-5-2`, 35 turns, and successful completion. This
shortlist combines that review with source checks. These are hypotheses to
test, not implemented optimizations or promised speedups.

The complete model response is saved locally in
`.cache/fable-performance-review.txt`, with execution metadata in
`.cache/fable-performance-review.json`. The input is
`.cache/fable-performance-review-prompt.txt`.

> **Current constraint (2026-11-16).** The user has since rejected the
> volume-backed native provider store described under "Provider files in
> Docker" below as a direction. That section and the measurements here remain
> as an unmodified record of what was implemented and measured. See the
> [filesystem research report](FILESYSTEM-RESEARCH.md) for the follow-up
> comparison and proposed experiments. It also notes that Linux allows only one
> seccomp notification listener per task, which rules out stacking a separate
> file-open listener.

> **Compatible follow-up (2026-11-16).** Revision caching and simpler open
> classification are implemented, with seccomp and Landlock retained. Docker
> now defaults to virtual delivery; the native-volume experiment requires an
> explicit build feature. The [new results](RESULTS-COMPATIBLE.md) distinguish
> managed config opens from ordinary files and document shared-host load and
> network-tail uncertainty. Earlier results below remain historical.

## Recommended sequence

| Order | Candidate | Why investigate it | Effort / confidence |
|---|---|---|---|
| 1 | Attribute the file-open cost | The largest measured difference is approximately 14.6 additional microseconds per open/read/close iteration. Separate wakeups, pathname copying, and Landlock before choosing a fix. | Small experiment; high value |
| 2 | Add a scalar `TCP_NODELAY` fast path | Client and server both set this option in the Docker workload; each currently notifies the broker even though its decision uses only scalar arguments. | Small change; strong candidate |
| 3 | Avoid duplicate descriptor enumeration | `prepare_registry_for_socket_with_count` counts `/proc/self/fd` twice on the ordinary path where no collection occurs. | Small change; validate concurrent headroom behavior |
| 4 | Optimize task-memory backend selection if profiling warrants it | `read_exact` first tries `process_vm_readv`, then opens and reads `/proc/<tid>/mem` on certain errors. Repeated fallback could amplify every open. Whether it occurred during collection is unknown. | Small to medium; conditional benefit |
| 5 | Reuse bounded blocking-connect workers | Each blocking local connect currently spawns an `openshell-local-connect` thread. The dispatcher must still remain responsive to unrelated notifications. | Medium; plausible benefit |
| 6 | Explore provider-file delivery that avoids read-open notifications | A protected filesystem representation could potentially let ordinary read opens remain native while supporting provider updates. This changes the delivery architecture across drivers. | Large; highest design uncertainty |
| 7 | Consider bounded parallel notification receivers | The current single receiver handles ordinary opens synchronously. Establish contention and tail latency before adding concurrency. | Medium to large; benefit unmeasured |

## First experiment: file-open attribution

Extend the opt-in performance harness with a file-open case. Compare native,
notification-and-continue only, notification plus pathname-prefix copying,
and the applicable Landlock configuration. Clearly label any diagnostic layers
as harness-only; do not add a production interception-disable switch.

Run both on the host and inside the matched Docker container posture. Count
which task-memory backend actually succeeds, and record broker service time
separately from the workload's round-trip time. Measure p50/p99 and throughput
with 1, 4, and 16 opener threads.

Add open/close-only and repeated reads from one already-open descriptor at
several sizes. Then cover provider paths, write opens, relative paths, and
`openat2`. A static executable spawn would help separate process supervision
from the ordinary file opens performed by a dynamic loader. Add an import-heavy
application startup or small build to assess whether microbenchmark savings
translate into useful application improvements.

Source anchors: `ProviderFiles::handle_open` in
`crates/openshell-sandbox/src/provider_files.rs`, `task_memory::read_exact` in
`crates/openshell-sandbox/src/linux/task_memory.rs`, and
`install_workload_listener` in
`crates/openshell-sandbox/src/linux/seccomp_notify.rs`.

## Constraints on the smaller changes

For the socket-option fast path, start with a narrow scalar whitelist. The
current handler uses `i32::try_from` on the 64-bit arguments and returns
`EINVAL` for values it cannot represent. Fable's broader proposal checked the
high words but also needs to reject low-word values above `INT32_MAX` to retain
that behavior. Preserve every denied option, argument-width handling, filter
precedence, and architecture checks. Test active behavior as well as the BPF
instruction representation.

For descriptor counting, recheck after collection and preserve the reserve for
control streams and exec pipes. A broker-only counter does not cover ambient
descriptor changes. Fable also proposed using the count exposed by `stat` on
`/proc/self/fd`; upstream Linux implements this in
[`proc_fd_getattr`](https://github.com/torvalds/linux/blob/master/fs/proc/fd.c).
That is a separate, feature-probed candidate with an enumeration fallback.
Validation must account for the enumeration's own open directory descriptor.

For memory reads, do not assume every permission error identifies a fixed
syscall-profile restriction. Establish backend behavior and qualification
scope before selecting a backend once. Preserve exact-copy requirements and
notification/task identity validation. Do not cache a task-memory descriptor
across exec or PID reuse without proving its lifecycle behavior.

For worker reuse, preserve the existing admission bound and failure handling.
Do not hold the registry lock during a blocking connect or mutate the
workload's shared blocking flags. Test full listener backlogs, worker
exhaustion, descriptor replacement, and unrelated mediation progressing.

## Benchmark distinctions and deferred ideas

The Docker workload uses blocking connects. The existing Rust harness calls
`TcpStream::connect_timeout`, whose Linux implementation temporarily sets
nonblocking mode; these exercise different broker branches. The host harness
also runs outside Docker's outer seccomp profile. Its timings cannot establish
the blocking worker cost or Docker-specific task-memory fallback cost.

Fable suggested a synchronous-wakeup listener hint as an experiment. The local
headers expose `SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP` and
`SECCOMP_IOCTL_NOTIF_SET_FLAGS`; header presence alone does not establish
runtime support or a benefit. Verify semantics and support before an A/B test,
keep unsupported-kernel behavior unchanged, and test both latency and
multithreaded throughput.

Do not cache pathname classification by pointer, continue mutable loopback
destination arguments unchecked, or remove notification identity checks.
Skipping interception because no providers exist at launch must account for
later provider attachment. Provider delivery changes must preserve immutable
workload identity, credential separation, update/detach semantics, and
fail-closed enforcement.

Any runtime implementation should pass focused sandbox tests, relevant active
qualification probes, and the sandbox E2E path required by `AGENTS.md`, followed
by the paired benchmark. No runtime implementation was made during this review.

## Implementation status

The candidates were implemented or evaluated after this review. This section
records what changed and what was measured while doing so. It reports no
Docker-benchmark result: the paired nine-trial comparison is run separately
against final release images.

The harness figures below are medians of five runs of 10,000 operations with
`openshell-seccomp-perf` built in release mode, on one eight-CPU host with
kernel 7.0. They attribute cost within the harness and are not the Docker
comparison.

| Order | Candidate | Outcome |
|---|---|---|
| 1 | Attribute the file-open cost | Implemented in the harness and the Docker workload; see below |
| 2 | Scalar `TCP_NODELAY` fast path | Implemented as a three-pair whitelist in the filter |
| 3 | Duplicate descriptor enumeration | Implemented: one count on the ordinary path, a recount only after a collection |
| 4 | Task-memory backend | Measured; no backend change. Socket addresses are now copied once |
| 5 | Reusable blocking-connect workers | Implemented with explicit live and parked thread caps |
| 6 | Provider files without read-open notifications | Implemented for the Docker driver; other drivers keep virtual delivery |
| 7 | Parallel receivers and synchronous wakeup | Measured; neither is enabled |

### File-open attribution

Single-threaded `file-open-close`, p50 per operation:

| Layer | p50 |
|---|---:|
| `native` | 1.0 µs |
| `notify-only` | 14.9 µs |
| `filtered` | 17.0 µs |
| `native-opens` | 1.1 µs |

The notification round trip accounts for nearly all of the cost of an
intercepted open. The broker's path-prefix copy adds about 2 µs in this run and
was within run-to-run variation in others. A Landlock domain added 0.15 µs to a
native open. Reads on an open descriptor cost the same in every layer
(0.26 to 0.30 µs). With 4 and 16 opener threads the single receiver held
throughput near 200,000 to 250,000 opens per second, against 0.9 to 1.0
million native.

### Task-memory backend

`process_vm_readv` served every broker copy and none fell back to
`/proc/<tid>/mem`, both on the host and in a container with Docker's default
seccomp and AppArmor profiles, all capabilities dropped, `no-new-privileges`,
and UID 1000. No backend selection or caching was added. `connect` and `bind`
now copy the socket address once instead of reading the family and the address
separately, with the previous two reads as the fallback for every error.

### Provider files in Docker

The Docker driver mounts a dedicated volume twice into the workload container:
writable beneath `/.openshell` for the sandbox runtime, and its `public`
subdirectory read-only at `/run/openshell` for the workload. The runtime
validates both mounts, publishes each generation by an atomic directory
exchange, and installs a filter that leaves read-only `open` and `openat` in
the kernel. Opens that request write access or carry `O_CREAT`, `O_TRUNC`, or
`O_TMPFILE`, and every `openat2`, still notify. Daemons older than
Engine API 1.45, sandboxes created earlier, and every other driver keep
virtual delivery. A store the driver declared must validate or the sandbox
does not start. A valid store on a kernel whose Landlock refuses an open in a
generation exchanged out mid-walk also keeps virtual delivery: the runtime
probes for that at startup, under the workload's own Landlock layers, and falls
back only once the store is proven empty. See the sandbox and Docker driver
READMEs.

### Synchronous wakeup

Not enabled. The hint improved single-threaded latency and regressed
concurrent TCP connects:

| Case | Default p50 / p99 | With hint p50 / p99 | Throughput change |
|---|---:|---:|---:|
| `file-open-close`, 1 thread, `filtered` | 16.3 / 22.8 µs | 4.1 / 9.0 µs | +271% |
| `file-open-close`, 4 threads, `filtered` | 19.9 / 28.8 µs | 16.8 / 33.4 µs | +15% |
| `file-open-close`, 16 threads, `filtered` | 72.0 / 89.8 µs | 68.6 / 124.7 µs | +3% |
| `tcp-connect`, 1 thread, `filtered` | 88.4 / 115.7 µs | 50.9 / 215.9 µs | +43% |
| `tcp-connect`, 4 threads, `filtered` | 214.1 / 265.4 µs | 250.5 / 511.5 µs | -19% |

Tail latency rose in every multi-threaded case and for single-threaded
connects. Native provider files remove the file-open notifications where the
hint helped most. The harness keeps `--sync-wakeup` so the question can be
reopened with workload data; a production change would also need a runtime
probe, since header presence does not establish kernel support.

### Parallel receivers

Not enabled. Answering the `notify-only` layer from 2 or 4 threads lowered
throughput at every opener count: by 4% and 11% with one opener, 15% and 40%
with four, and 28% and 38% with sixteen. The production broker keeps one
receiver, which also keeps its handler ordering.

### Remaining work

- Kubernetes, Podman, and VM sandboxes still intercept every open. Each needs
  its own way to mount one filesystem writable for the runtime and read-only
  for the workload.
- Under native delivery `openat2` and opens that can change the filesystem
  still notify. `openat2` carries its flags in workload memory, which the
  filter cannot read.
- An open caught mid-walk by a provider-file update relies on Landlock
  allowing a file whose directory left the public mount's tree. Kernels
  without the upstream disconnected-directory change (CVE-2025-68736) refuse
  it. The runtime probes the running kernel at startup and such a kernel keeps
  virtual delivery, so it gets none of this optimization. Linux 7.0 passes,
  measured under the Docker mounts. No kernel that fails was available; that
  path is tested with an injected outcome. See the sandbox README.
- Landlock does not mediate `chmod`, so a workload can change the mode of
  provider-file store entries through the private path. It cannot read or
  change their content there, and the read-only public mount refuses the same
  change. See the sandbox README.
- A replaced provider-file generation is removed one second after its
  replacement. A workload that holds a directory descriptor, rather than a
  file descriptor, across an update can find the directory emptied after that.
- A filesystem without `RENAME_EXCHANGE` under Docker's volume root fails
  store validation, and the sandbox does not start. The driver cannot detect
  this before provisioning.
