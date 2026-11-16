# Compatible virtual config delivery: implementation and measurements

Measured November 16, 2026. This iteration retains seccomp notification and
Landlock, makes virtual delivery the Docker default, and adds no dependencies,
mounts, capabilities, or host agents to that path. The earlier native-volume
experiment remains available through the explicit
`experimental-native-provider-files` build feature.

The user chose to finish the paired measurements while other builds were
running on the shared host. Host load and observed Rust processes are recorded
with the samples. Treat small differences and tail-latency changes as
inconclusive; these runs cannot establish the absence of network regressions.

The [raw artifact](results/2026-11-16-compatible.json) contains all accepted
measurements, source/binary/image hashes, host and container settings, and any
discarded measurements. This compares the preserved virtual implementation
immediately before this iteration with the new virtual implementation. It
does not compare the new default with the earlier volume-backed optimization.

## Measured outcome

Median config-open latency fell at every tested thread count. These are
synthetic managed files, with a 64-byte read per open; they do not
establish a whole-agent speedup. Ranges below span the nine trial p50s.

| Config size | Threads | Before p50 µs [min–max] | After p50 µs [min–max] | Paired p50 change | Pairs with lower p50 |
|---|---:|---:|---:|---:|---:|
| 4 KiB | 1 | 23.208 [22.875–28.056] | 16.149 [14.974–20.030] | -31.8% | 9/9 |
| 4 KiB | 4 | 114.237 [63.025–125.608] | 81.037 [70.043–602.560] | -29.1% | 8/9 |
| 4 KiB | 16 | 493.951 [289.018–546.750] | 332.185 [167.521–348.033] | -32.3% | 9/9 |
| 64 KiB | 1 | 34.798 [29.003–41.814] | 15.806 [8.829–19.262] | -54.2% | 9/9 |
| 64 KiB | 4 | 158.465 [129.012–191.516] | 79.422 [41.241–85.716] | -52.7% | 9/9 |
| 64 KiB | 16 | 737.672 [694.523–790.884] | 328.871 [298.360–348.404] | -54.6% | 9/9 |

The full driver ordinary-file loop remained essentially unchanged:
821.889 → 824.404 ms for 50,000 open/read/close operations.
Caching configs does not remove the notification tax on unrelated opens.

Network results are mixed. With managed-file contention, TCP-connect p50
fell in all nine pairs at each thread count. However, the 16-thread
managed-file/TCP-stream case had +4.8% paired stream p50 and −1.5%
stream throughput. No receiver or wakeup tuning was enabled.

Standalone 16-thread TCP-connect p99 increased 21.0% in the initial matrix.
A separate follow-up ran five longer pairs (2,000 connects per worker,
rather than 1,000), preserving both sets of results. The follow-up saw
−0.3% paired p50, +0.2% throughput, and −6.5% p99; the increase was not
reproduced. No Rust build processes were observed during that later batch.
Different load conditions prevent attributing the first increase or
asserting that network tails cannot regress. Validate on a controlled
host before making a tail-latency guarantee.

## What changed

- Prepare and seal one memfd for each config revision at publication time.
  Reuse unchanged revisions. Each open gets a freshly reopened read-only
  file description, so callers have independent offsets. Failed publication
  leaves the prior snapshot intact; existing descriptors retain old content.
- Classify candidate paths with one exact six-byte memory read. Ordinary
  `openat2` calls outside those prefixes avoid reading `open_how`. Complete
  paths and identities are still checked for injected files and thread names;
  the kernel and Landlock authorize every continued open.
- Keep production receiver dispatch and synchronous-wakeup settings unchanged.
  Blocking local connects already use bounded asynchronous workers. The earlier
  hint experiment regressed concurrent/network cases; it remains harness-only.
- Separate immutable revisions from their delivery backing, giving a future
  filesystem backend a content/revision model without making FUSE a dependency.

## Measurement method

The broker harness uses identical new measurement code linked against the
preserved old and new runtime implementations. It runs 31 cases in nine paired
trials: 558 container invocations and 774 individual class reports. Cases are
shuffled deterministically per trial and variant order alternates. Both use
the same pinned workload image, UID/GID 1000, no network outside the container,
all capabilities dropped, no-new-privileges, Docker's default seccomp/AppArmor
settings, and a Landlock domain. Config bytes are deterministic and verified.
The synthetic managed paths are served by the production broker, never by
ordinary files or infrastructure volumes.

Mixed cases use N file and N TCP workers simultaneously, continuing both
classes until every worker reaches its quota. Percentiles and throughput are
reported separately per class. TCP connect in this harness measures connection
setup and close; stream measures a 64-byte echo on an established connection.
Config file size is 4 KiB or 64 KiB; each timed read requests 64 bytes.

The original Docker-driver benchmark also ran nine trials for each runtime,
with a fresh paired plain-Docker control: 468 samples in total. Its counts,
policy, workload image, and definitions are unchanged. Both runtime variants
use the same new virtual-default gateway and unchanged supervisor image. Its
TCP-connect workload includes a 64-byte echo, unlike the broker harness.
The static release sandbox images both enable `perf-harness`, including its
task-memory read counters. This compares equally instrumented builds of the
production code paths, rather than claiming exact shipping-build latency.

An initial attempt waited for Rust builds and discarded an overlapping pair,
then paused when more builds started. Its 20 accepted invocations are retained
as an excluded, incomplete pilot. The final comparison restarted from trial 1
with concurrent builds allowed, at the user's request. Each harness invocation
records load averages, Rust-process counts, and aggregate CPU utilization;
the full driver runs record load and build activity once per second. Smokes,
debug runs, and the interrupted pilot are excluded from the reported medians.
Alternating paired order helps control drift but cannot remove contention.
Nine trials do not establish a confidence bound or cross-platform support.

## Broker harness results

Values are medians of nine trial percentiles, not percentiles pooled across
trials. Changes are medians of paired trial ratios. Negative latency change is
faster; positive throughput change is faster. Existing-FD reads exclude opening.

| Case | Threads per class | Operation class | Before p50 µs | After p50 µs | Paired p50 change | Before p99 µs | After p99 µs | Paired throughput change |
|---|---:|---|---:|---:|---:|---:|---:|---:|
| `ordinary-existing-fd-read` | 1 | single | 0.314 | 0.313 | -0.6% | 0.484 | 0.473 | -0.5% |
| `ordinary-mixed-file-tcp-connect` | 1 | file-open-read | 21.033 | 21.302 | +3.9% | 59.026 | 50.581 | +2.9% |
| `ordinary-mixed-file-tcp-connect` | 1 | tcp-connect | 102.112 | 104.723 | -1.1% | 171.849 | 151.382 | +2.6% |
| `ordinary-mixed-file-tcp-connect` | 4 | file-open-read | 74.657 | 78.236 | -0.0% | 164.821 | 169.190 | -1.0% |
| `ordinary-mixed-file-tcp-connect` | 4 | tcp-connect | 319.221 | 331.190 | +1.3% | 410.939 | 431.887 | -1.3% |
| `ordinary-mixed-file-tcp-connect` | 16 | file-open-read | 363.942 | 337.743 | -4.4% | 922.106 | 677.385 | +9.2% |
| `ordinary-mixed-file-tcp-connect` | 16 | tcp-connect | 1491.632 | 1372.865 | -4.2% | 2885.440 | 2403.348 | +8.8% |
| `ordinary-mixed-file-tcp-stream` | 1 | file-open-read | 18.516 | 18.443 | +2.3% | 28.466 | 26.848 | +0.7% |
| `ordinary-mixed-file-tcp-stream` | 1 | tcp-stream | 20.391 | 15.952 | +1.4% | 28.969 | 30.199 | +0.1% |
| `ordinary-mixed-file-tcp-stream` | 4 | file-open-read | 33.038 | 34.777 | +0.5% | 64.856 | 59.893 | -3.6% |
| `ordinary-mixed-file-tcp-stream` | 4 | tcp-stream | 8.642 | 8.727 | +1.8% | 37.084 | 32.277 | +11.7% |
| `ordinary-mixed-file-tcp-stream` | 16 | file-open-read | 238.335 | 227.065 | +2.3% | 1340.390 | 2200.941 | -6.0% |
| `ordinary-mixed-file-tcp-stream` | 16 | tcp-stream | 23.281 | 23.716 | -5.7% | 92.716 | 97.288 | -1.8% |
| `ordinary-open-close` | 1 | single | 16.770 | 16.467 | -1.0% | 23.899 | 27.261 | +1.0% |
| `ordinary-open-read` | 1 | single | 16.874 | 16.525 | -4.9% | 25.010 | 26.224 | +4.9% |
| `ordinary-open-read` | 4 | single | 23.200 | 22.533 | -0.4% | 38.430 | 36.371 | +2.2% |
| `ordinary-open-read` | 16 | single | 73.149 | 74.990 | +2.3% | 90.930 | 116.954 | -2.4% |
| `provider-existing-fd-read` | 1 | single | 0.312 | 0.311 | -0.3% | 0.429 | 0.438 | -0.7% |
| `provider-mixed-file-tcp-connect` | 1 | file-open-read | 41.170 | 22.454 | -47.1% | 119.738 | 87.624 | +43.3% |
| `provider-mixed-file-tcp-connect` | 1 | tcp-connect | 195.076 | 158.144 | -14.7% | 383.580 | 278.919 | +20.0% |
| `provider-mixed-file-tcp-connect` | 4 | file-open-read | 180.844 | 149.214 | -19.1% | 343.167 | 277.333 | +21.4% |
| `provider-mixed-file-tcp-connect` | 4 | tcp-connect | 751.205 | 625.206 | -16.1% | 1150.059 | 997.970 | +19.0% |
| `provider-mixed-file-tcp-connect` | 16 | file-open-read | 856.473 | 682.767 | -23.3% | 2508.882 | 1608.239 | +29.1% |
| `provider-mixed-file-tcp-connect` | 16 | tcp-connect | 3489.562 | 2760.094 | -23.2% | 7501.378 | 5149.034 | +28.3% |
| `provider-mixed-file-tcp-stream` | 1 | file-open-read | 22.966 | 16.067 | -29.1% | 47.316 | 25.199 | +52.7% |
| `provider-mixed-file-tcp-stream` | 1 | tcp-stream | 15.951 | 16.208 | +0.1% | 26.664 | 32.567 | +2.4% |
| `provider-mixed-file-tcp-stream` | 4 | file-open-read | 130.422 | 86.970 | -30.9% | 243.165 | 173.385 | +45.6% |
| `provider-mixed-file-tcp-stream` | 4 | tcp-stream | 8.692 | 8.503 | -1.8% | 30.247 | 34.929 | +7.3% |
| `provider-mixed-file-tcp-stream` | 16 | file-open-read | 1094.762 | 806.044 | -26.7% | 3633.460 | 3830.251 | +18.4% |
| `provider-mixed-file-tcp-stream` | 16 | tcp-stream | 21.643 | 24.332 | +4.8% | 78.174 | 83.870 | -1.5% |
| `provider-open-close` | 1 | single | 22.676 | 15.966 | -28.9% | 46.271 | 26.410 | +40.5% |
| `provider-open-read-4096` | 1 | single | 23.208 | 16.149 | -31.8% | 41.349 | 27.283 | +51.0% |
| `provider-open-read-4096` | 4 | single | 114.237 | 81.037 | -29.1% | 230.812 | 128.943 | +42.3% |
| `provider-open-read-4096` | 16 | single | 493.951 | 332.185 | -32.3% | 789.818 | 541.010 | +48.2% |
| `provider-open-read-65536` | 1 | single | 34.798 | 15.806 | -54.2% | 89.754 | 27.730 | +126.8% |
| `provider-open-read-65536` | 4 | single | 158.465 | 79.422 | -52.7% | 324.421 | 115.371 | +117.6% |
| `provider-open-read-65536` | 16 | single | 737.672 | 328.871 | -54.6% | 1206.306 | 539.108 | +127.0% |
| `tcp-connect` | 1 | single | 92.960 | 95.623 | -0.5% | 151.312 | 155.274 | -0.5% |
| `tcp-connect` | 4 | single | 248.833 | 245.734 | -1.2% | 407.857 | 407.729 | +0.9% |
| `tcp-connect` | 16 | single | 1053.191 | 1055.419 | +1.5% | 1418.595 | 1688.513 | -1.7% |
| `tcp-stream` | 1 | single | 19.748 | 18.698 | -5.5% | 28.873 | 29.085 | +6.3% |
| `tcp-stream` | 4 | single | 22.902 | 23.114 | +1.1% | 38.042 | 39.777 | -5.3% |
| `tcp-stream` | 16 | single | 17.117 | 16.992 | +3.0% | 69.857 | 73.477 | +2.6% |

## Full Docker-driver comparison

Times are medians of nine trials. The two runtime columns have their own
paired Docker controls. These workloads open ordinary files, so they do not
directly measure config-revision caching. Provisioning and exec include client
transport; workload timers do not.

| Workload | Docker before ms | OpenShell before ms | Docker after ms | OpenShell after ms | OpenShell median time change |
|---|---:|---:|---:|---:|---:|
| `provision` | 210.178 | 732.966 | 207.417 | 739.247 | +0.9% |
| `exec` | 47.025 | 18.048 | 46.048 | 19.044 | +5.5% |
| `cpu` | 92.543 | 91.944 | 92.301 | 91.420 | -0.6% |
| `getpid` | 120.721 | 119.604 | 120.072 | 119.859 | +0.2% |
| `file` | 91.385 | 821.889 | 90.147 | 824.404 | +0.3% |
| `spawn` | 117.615 | 143.436 | 117.605 | 144.793 | +0.9% |
| `tcp-connect` | 37.512 | 115.559 | 37.251 | 118.336 | +2.4% |
| `tcp-stream` | 395.253 | 406.207 | 393.338 | 397.078 | -2.2% |
| `file-open` | 74.795 | 786.488 | 74.319 | 805.696 | +2.4% |
| `file-read` | 136.292 | 135.242 | 135.567 | 135.956 | +0.5% |
| `file-t4` | 73.073 | 281.934 | 73.917 | 284.909 | +1.1% |
| `file-t16` | 61.568 | 230.884 | 60.427 | 230.655 | -0.1% |
| `file-latency` | 93.739 | 826.340 | 93.683 | 817.809 | -1.0% |

## Validation and limits

- Sandbox unit tests: 346 passed, two pre-existing mount tests ignored;
  entrypoint and stdout-logging integration checks also passed.
- Docker-driver unit tests: 156 passed, two ignored, with the experimental
  feature both disabled and enabled.
- Sandbox lint checks pass with and without the perf harness; Docker-driver
  lint and repository formatting checks pass.
- All five final Docker E2E checks pass: provider open/update/detach, policy
  activation, and host-gateway alias behavior. Default workloads have no
  provider-file volume or `/run/openshell` provider mount.
- Config publication now bears memfd preparation cost and retains up to 64
  anchors, with transient additional descriptors during an update. Publication
  latency with attached providers was not benchmarked separately.
- Opens of one revision now share an inode, metadata and file-lock state,
  while retaining independent offsets and sealed contents. Updating identical
  bytes preserves that revision; detach and reattach creates a new revision.
- Ordinary paths starting `/run/o` require a full-path copy before continuing.
  Ordinary opens still pay the seccomp notification round trip. This iteration
  does not remove that architectural cost or replace Landlock.
- The ordinary `openat2` argument-copy reduction is checked functionally; the
  timed ordinary-file cases use normal library opens and do not isolate it.
- Executed on the recorded Linux x86_64 host. No old-kernel or ARM64 host was
  available. The implementation keeps the existing kernel APIs and bootstrap
  requirements; it does not establish untested platform support.

See the [runbook](README.md) for workload definitions and new harness flags,
and [filesystem research](FILESYSTEM-RESEARCH.md) for optional future backends.
