# Historical benchmark: before and after PR #3832

[PR #3832](https://github.com/NVIDIA/OpenShell/pull/3832) was compared at its
exact parent (`5c0c9e446ed3b11e21198058873b0c6adfee6b4e`) and merged commit
(`252882f37f2daa63ef4078b3bbb89adbcf43b409`). Both historical source checkouts were clean and
unmodified. The [artifact](results/2026-11-15-pr3832.json) contains all 468 measurements,
image and binary identities, settings, and source hashes.

## Results

Open/read/close rose from **100.5 ms to 838.4 ms (8.34×)** across 50,000
iterations. Open/close alone became **9.73×** slower, while reads on an
already-open descriptor changed by **1.3%**. CPU and raw `getpid` were stable.
The adjacent-commit comparison confirms that this PR introduced the large
file-open regression on this host.

Each version completed nine paired Docker/OpenShell trials with the same
workload image, counts, policy, and benchmark source. Times below are medians.
Positive change means the OpenShell workload became slower after the PR.
Workload timers exclude exec transport; provisioning and exec include it.

| Case | Docker before ms | OpenShell before ms | Docker after ms | OpenShell after ms | OpenShell change |
|---|---:|---:|---:|---:|---:|
| `provision` | 202.979 | 651.105 | 214.433 | 639.703 | -1.8% |
| `exec` | 45.004 | 16.263 | 45.610 | 16.765 | +3.1% |
| `cpu` | 92.115 | 92.186 | 92.044 | 92.196 | +0.0% |
| `getpid` | 119.765 | 120.304 | 120.128 | 120.590 | +0.2% |
| `file` | 90.126 | 100.525 | 91.161 | 838.370 | +734.0% |
| `spawn` | 116.776 | 119.870 | 117.550 | 142.940 | +19.2% |
| `tcp-connect` | 37.434 | 205.590 | 37.652 | 207.558 | +1.0% |
| `tcp-stream` | 384.881 | 405.751 | 384.915 | 413.845 | +2.0% |
| `file-open` | 74.531 | 84.268 | 74.771 | 819.612 | +872.6% |
| `file-read` | 134.939 | 136.234 | 135.063 | 138.008 | +1.3% |
| `file-t4` | 75.462 | 90.679 | 76.095 | 277.890 | +206.5% |
| `file-t16` | 57.291 | 69.410 | 58.983 | 233.054 | +235.8% |
| `file-latency` | 94.344 | 103.940 | 94.206 | 848.394 | +716.2% |

Median paired OpenShell/Docker overhead for open/read/close:
**+10.7% before**, **+818.2% after**.
For open/close without the read: **+12.5% before**,
**+1009.6% after**.

Per-operation open/read/close latency, medians across trials:

| Runtime | Mode | p50 µs | p99 µs | Median trial maximum µs |
|---|---|---:|---:|---:|
| before | docker | 1.792 | 2.655 | 67.940 |
| before | openshell | 1.971 | 2.933 | 53.599 |
| after | docker | 1.795 | 2.601 | 56.480 |
| after | openshell | 16.300 | 25.755 | 382.397 |

The latency case includes two clock reads per iteration. Its trial maxima are
scheduling-sensitive and do not establish a tail-latency bound.

## Interpretation

The exact source delta is PR #3832. Its filter adds unconditional notification
of `open`, `openat`, and `openat2`; the broker checks the managed-file pathname
prefix before continuing ordinary opens. Therefore `/etc/passwd` opens incur
mediation even with no providers attached. The pre-PR runtime does not have
this file-open interception. Reads and closes were not newly intercepted.

These results compare the historical PR itself, rather than comparing the
later November baseline with the uncommitted performance fixes. The five file
controls isolate open/close, reads on an existing descriptor, concurrency, and
per-operation latency. The [runbook](README.md) defines all operation counts and
workloads. No historical runtime source was patched to build or run it.

## Method and environment

- Rust 1.95.0, release builds, locked dependencies. `Cargo.lock` is identical
  between these two commits. The gateway links only the Docker compute driver;
  telemetry is disabled. CLI, gateway, supervisor, and sandbox match each
  historical commit. The sandbox is static musl and passed static-link checks.
- Both supervisor images use the same Ubuntu 26.04 base and public CA bundle
  used for the earlier benchmarks. Historical default images use distroless
  Debian 13, whose glibc is older than this host's GNU build. Packaging uses the
  same current Docker recipe with the corresponding historical prebuilt binary;
  the historical runtime source remains unchanged.
- Same eight-vCPU Intel Xeon Platinum 8581C VM; kernel
  `7.0.0-1017-gcp`, Docker `29.1.3`.
  Both workload modes use UID/GID 1000, `/sandbox`, no external network,
  dropped capabilities, no-new-privileges, Docker's default seccomp profile,
  and `docker-default` AppArmor. OpenShell additionally applies its sandbox.
- Shared workload image: `sha256:f26afa7f641a412595b3643e9e030918413c2bb10baad87fff6781c0797c6723`.
  The previously built benchmark image was reused without modification.
- One full warmup per workload; trial order alternates Docker/OpenShell and
  shuffles workload order reproducibly. Fresh containers are removed before
  the next mode. Baseline and post-PR batches are sequential, with paired
  Docker controls in each batch. Small differences remain subject to host drift.
- The first smoke attempt exposed the older CLI syntax: `sandbox exec` needs
  `--name`, rather than a positional sandbox name. The harness now uses the
  explicit flag for both versions; workload code, counts, and timers are
  unchanged. The initial smoke attempt is excluded.
- Both versions passed a one-trial, scale-0.01 integration smoke run first.
  Compiler processes were idle before full measurement. Each accepted workload
  sample validated operation count, UID/GID, working directory, image identity,
  and successful execution. No new production code or policy was introduced.

Collection started at `2026-11-16T05:41:22.674170+00:00` (before) and
`2026-11-16T05:42:38.848324+00:00` (after). Local full runner output is in
`.cache/perf-pr3832-{before,after}/`; build/orchestration logs and scripts are
under `.cache/perf-pr3832-*` and `.cache/perf-run-pr3832.py`. Runtime images are
`openshell/{sandbox,supervisor}:perf-pr3832-{before,after}`.

The collection uses the same command against each version's matching gateway:

```shell
uv run --no-project tasks/scripts/perf-docker.py \
  --openshell /path/to/historical/openshell --gateway perf-docker \
  --trials 9 --output .cache/perf-pr3832-VARIANT
```

This is a warm-cache microbenchmark on one VM. It does not quantify complete
application startup, external networking, or a production regression threshold.
No separate host seccomp TCP microbenchmark was repeated for this historical run.
