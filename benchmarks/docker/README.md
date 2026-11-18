# Docker driver performance benchmark

This benchmark compares the same compiled workload in ordinary Docker and in
the OpenShell Docker compute driver. It also measures provisioning and exec
latency separately. It does not change production isolation code.

The checked-in reports and raw data under `results/` measure the checkpoint
commits they record. Unstacking the implementation onto `main` is not a new
performance measurement; rerun the benchmark to measure the ported code.

See the [compatible virtual-delivery results](RESULTS-COMPATIBLE.md) for the
latest config-revision caching iteration and paired measurements on a shared
host. The earlier [before/after results](RESULTS-AFTER.md) cover the volume-backed
experiment. The [original results](RESULTS.md) preserve the first run. The
[performance candidates](PERFORMANCE-IDEAS.md) record the review, attribution
experiments, and implementation outcomes.

The [ARM64 paired rerun](RESULTS-ARM64.md) repeats the compatible comparison
on a shared aarch64 host with a reconstructed baseline. Its outcome is mixed:
1- and 4-thread config opens improve, 16-thread opens regress, and the report
records the code review findings and validation from that run.

The [historical PR #3832 comparison](RESULTS-PR3832.md) benchmarks its exact
parent and merged commit to identify when file-open overhead appeared.

The [filesystem research report](FILESYSTEM-RESEARCH.md) compares ways to
deliver virtual config files, store durable workspaces, and enforce filesystem
access control, using primary sources for a set of bookmarked projects. It is
research only: it ran no benchmarks, proposes experiments rather than a design,
and does not endorse the uncommitted volume-backed provider store.

## Plan and interpretation

1. Build the workload once and pin its local image ID for both modes. Use its
   non-root UID/GID, working directory, and identical iteration counts. Both
   workload containers have no external network, no capabilities, and
   `no-new-privileges`. Keep Docker's default seccomp profile enabled.
2. Run nine paired trials, alternating which mode goes first. Create a fresh
   container for each mode in each trial, then remove it before the other mode
   starts. This avoids a concurrently idle OpenShell supervisor in Docker trials.
3. Shuffle workload order reproducibly by trial. Warm up each workload once,
   then measure using `CLOCK_MONOTONIC` inside the workload. Warmups are full
   unrecorded executions. The runner retains end-to-end exec time separately.
4. Report median, min–max range, and median paired percentage overhead. Preserve
   every raw measurement, the policy hash, image IDs, execution settings,
   source commit, dirty status, kernel, Docker version, and CPU information.
   An incomplete run is marked `complete: false` in the JSON.
5. Run the existing production seccomp broker microbenchmark for attribution.
   The Docker comparison measures the combined sandbox/runtime cost, including
   Landlock, seccomp filters and notifications, process observation, and the
   supervisor. It cannot attribute the whole difference to syscall interception.

| Workload | Default operations | What it measures |
|---|---:|---|
| `cpu` | 100,000,000 | Volatile integer recurrence; control for CPU/scheduling noise |
| `getpid` | 1,000,000 | Explicit kernel calls, avoiding libc caching; filter traversal control |
| `file` | 50,000 | Open, read 64 bytes from `/etc/passwd`, close; warm filesystem metadata/data |
| `spawn` | 200 | Fork, exec `/bin/true`, wait for successful exit |
| `tcp-connect` | 1,000 | Socket, connect, 64-byte request/reply, close against a local fixture |
| `tcp-stream` | 20,000 | 64-byte request/reply on one established local TCP connection |
| `provision` | One per trial/mode | Client creation through successful `/bin/true` exec; excludes image building/pulling |
| `exec` | One per trial/mode | Warm end-to-end `/bin/true` exec, including client and control plane |

The runner then measures five file-open attribution cases. They run after the
six workloads above, in their own shuffled order, so they change neither the
order nor the definition of those six. Pass `--no-attribution` to skip them.

| Workload | Default operations | What it isolates |
|---|---:|---|
| `file-open` | 50,000 | Open and close without a read |
| `file-read` | 500,000 | 64-byte reads on one descriptor opened before the timer; no open is measured |
| `file-t4`, `file-t16` | 50,000 | The `file` operation split across 4 and 16 threads that start together |
| `file-latency` | 50,000 | The `file` operation with each iteration timed; reports p50, p99, and maximum latency |

Compare each with `file`. `file-latency` includes two clock reads in every
timed interval, so compare its percentiles between modes rather than with the
other cases.

TCP fixtures run in a thread inside the workload's own network namespace. All
connected and accepted sockets disable Nagle's algorithm. The connection case
includes client socket setup; the stream case excludes connection setup and
teardown. These are single-client, loopback tests; they do not measure external
network policy evaluation, DNS, HTTP inspection, TLS, or credential injection.
The file workload does not measure durable writes or storage throughput.

## Run

Use a Linux host with Docker, working Landlock/seccomp notification support,
`mise`, and the OpenShell development prerequisites from `CONTRIBUTING.md`.
Use a local Docker daemon and a dedicated local Docker gateway. Stop unrelated
builds and heavy workloads before measurement. Do not use a production gateway.

```shell
mise run perf:docker:build

# Build and start the source-checkout Docker gateway in a separate terminal.
# This also builds matching sandbox and supervisor images.
mise run gateway:docker

# Build the client with optimizations and use it explicitly.
mise exec -- cargo build --release -p openshell-cli
mise run perf:docker -- --openshell ./target/release/openshell --gateway docker-dev
```

The runner creates and deletes only its own randomly named `perf-*` resources.
The gateway must point to the same Docker daemon as the runner. It verifies that
the running workload has the pinned image ID and that the OpenShell workload
uses the sandbox binary. It does not provision or reconfigure the gateway.
Docker credentials and container environment variables are not included in the
report. Review host paths and image metadata before sharing the raw JSON.

Output defaults to `.cache/perf-docker/results.json` and `report.md`. For a quick
integration check, reduce counts and trial count:

```shell
mise run perf:docker -- --openshell ./target/release/openshell --trials 1 --scale 0.01 --output .cache/perf-docker-smoke
```

`mise run perf:docker:test` checks the runner's case order, output validation,
and report without Docker or a gateway.

The workload image uses mutable base-image tags for convenient local builds;
both modes use the same resolved image ID, recorded in the report. Pin base
digests and runtime image digests when comparing across dates or machines.
Record the gateway build profile and runtime images with any published results.
Provisioning measures warm images, not first-pull deployment. Nine trials are an
initial characterization, not a confidence bound or a regression threshold.
Repeat longer runs on an otherwise idle host before interpreting small deltas.

## Isolate seccomp network broker cost

The existing harness uses the production workload launcher and network broker
without the full gateway/supervisor lifecycle:

```shell
mise run perf:seccomp -- --layer all --protocol all --iterations 10000 --warmup 1000
```

Repeat that command and retain its JSONL. Its fixture and operation definitions
differ from this Docker workload, so compare native/filtered ratios within that
harness rather than subtracting its numbers from the Docker comparison. No
unsafe interception-disable switch is added to the production runtime.

## Attribute the file-open cost

The same harness separates the parts of a workload file open. `--layer all`
and `--protocol all` keep their original meaning (native and filtered; the two
TCP protocols), so earlier invocations measure what they measured.

```shell
mise run perf:seccomp -- --layer attribution --protocol file --iterations 10000 --warmup 1000
```

| Layer | What answers a file open |
|---|---|
| `native` | The kernel; no seccomp filter |
| `notify-only` | Harness only: the production filter, answered by a loop that continues every notification and reads no workload memory |
| `filtered` | The production broker with virtual provider files: one notification and one path-prefix copy per open |
| `native-opens` | The production broker with native provider files: read-only opens stay in the kernel |

`notify-only` against `native` is the notification round trip; `filtered`
against `notify-only` is the broker's work on top of it. Protocols
`file-open-close`, `file-open-read`, and `file-read` separate the open from the
read. Add `--concurrency 4` or `16` for opener threads, and `--landlock` to
confine the worker with a Landlock domain that handles every ABI v3 filesystem
right. `--file-path` selects the file. Reports include p50, p95, p99, and
maximum latency, and for broker layers `task_memory_reads`: how many
task-memory copies `process_vm_readv` served and how many fell back to
`/proc/<tid>/mem`.

### Managed provider files

The file protocols above open an ordinary file, which every layer continues
to the kernel. To measure an open the broker serves itself, add
`--provider-file`:

```shell
mise run perf:seccomp -- --layer filtered --protocol file --provider-file --iterations 10000 --warmup 1000
```

The harness publishes one synthetic provider file,
`/run/openshell/providers/perf/config.toml`, and the file protocols open that
path. `--provider-file-bytes` sets its size (default 4096, at most 65536). The
content depends only on the size, and the worker checks every byte it reads
against it. Reports carry `provider_file_bytes` and `file_path`, so a run on a
managed file cannot be mistaken for one on an ordinary file.

Only the `filtered` layer has virtual provider files. The harness refuses
`--provider-file` with any other layer, with `--file-path`, and with the TCP
protocols, instead of measuring `/etc/passwd` under another name. Compare a
managed open with an ordinary open in the same layer, or with the same harness
built against another revision of the broker.

### Mixed file and TCP workloads

`--protocol mixed` runs two workloads in which file opens and TCP operations
compete for the broker:

| Protocol | Classes, each on `--concurrency` threads |
|---|---|
| `mixed-file-tcp-connect` | `file-open-read` and `tcp-connect` |
| `mixed-file-tcp-stream` | `file-open-read` and `tcp-stream` |

```shell
mise run perf:seccomp -- --layer all --protocol mixed --concurrency 4 --iterations 10000 --warmup 1000
```

Each run prints one report per class, with `class` and `class_workers`, and
the throughput and latency percentiles of that class alone. Every thread keeps
operating until the last one has completed `--iterations` operations, so both
classes are measured over one window in which the other is running.
`iterations` in a mixed report is what the class completed in that window, so
compare throughput and percentiles, not counts. A thread keeps at most one
million latency samples. A mixed run checks what it reads: the file against
its content at the start, and each TCP echo against its request. A failed
operation, a mismatch, or a panic in one thread ends the run with an error.
Add `--provider-file` to make the file class open the managed provider file.

`--protocol all` and `--protocol file` do not include the mixed protocols.

`--sync-wakeup` and `--notify-receivers N` are experiments. The first requests
the kernel's synchronous-wakeup hint on the listener and fails on kernels
without it; the second answers the `notify-only` layer from several threads.
The production runtime uses neither.

To check the task-memory backend under Docker's default seccomp profile, run
the harness binary in a container as a non-root user with all capabilities
dropped. The harness has no supervisor or gateway, so it needs no network.
