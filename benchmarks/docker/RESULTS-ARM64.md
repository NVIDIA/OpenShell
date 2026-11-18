# ARM64 paired rerun: compatible virtual config delivery

Measured November 16, 2026 on ARM64 Linux 6.17.0-1029-nvidia, Rust 1.95,
20-CPU shared host with unrelated k3d clusters left running. The outcome is
mixed: managed config opens get faster at 1 and 4 threads and slower at 16
threads, with large tail-latency and throughput regressions under contention.
Investigate and address the high-concurrency regression before proposing a
performance PR; reproducing it on an idle host is a diagnostic step, not a
sufficient outcome.

The [raw artifact](results/2026-11-16-arm64.json) holds every accepted sample,
binary and image hashes, host load, validation output, and the diagnostic
reproductions below. The earlier x86 reports
([compatible](RESULTS-COMPATIBLE.md), [before/after](RESULTS-AFTER.md),
[original](RESULTS.md), [PR #3832](RESULTS-PR3832.md)) are unchanged.

## Setup

- Checkpoint `8dd0a0c`. Baseline reconstructed from the preserved
  pre-compatible patch applied on `e9f4a42` plus the unchanged
  `provider_store.rs`, built with the same current harness.
- Both variants share the same `perf.rs`, `seccomp-perf.rs`,
  `task_memory.rs`, and `Cargo.lock` (hashes recorded). Static musl release
  builds with `perf-harness`; both sandbox images verified to contain the
  built binaries.
- Both Docker driver variants use the same current virtual-default gateway
  and supervisor. The native GNU supervisor needs `libgcc_s.so.1`, which the
  default base image lacks, so the unchanged `Dockerfile.supervisor` was
  built with `SUPERVISOR_BASE_IMAGE=gcr.io/distroless/cc-debian13:latest`.
  The same resulting image served both runs.
- Every benchmark workload container (the supervisor uses host network)
  runs as UID/GID 1000 with `--network none`,
  `--cap-drop ALL`, `no-new-privileges`, Docker default seccomp and
  AppArmor, and no provider volume.
- Harness matrix: 31 cases × 9 pairs = 558 invocations producing 774 class
  reports (mixed cases report two classes). Driver comparison: 468 accepted
  samples. Focus follow-up: 2 cases × 5 pairs = 20 invocations.
- Host load: unrelated Rust builds were observed during 68 of 558 matrix
  invocations and 0 of 20 focus invocations. The Docker driver "after" batch
  ran first, under more builds, then the "before" batch; the two were not
  interleaved by variant. Failed and reduced-count smokes are excluded.

## Reading the tables

Latency columns are the median across trials of each variant's reported
p50 or p99. Change columns are the median across trials of the per-pair
relative change. A median of per-pair ratios is not the ratio of the two
medians, so a row can show lower after-p50 with a positive paired change
(see `ordinary-mixed-file-tcp-stream@t1`), or near-zero paired change next
to different medians. Negative latency change and positive throughput change
favor `after`.

## Managed config opens

`provider-open-read` opens the synthetic provider file, reads 64 bytes, and
closes it. Nine pairs per row.

| Config | Threads | Before p50 µs | After p50 µs | Paired p50 | Paired p99 | Paired ops/s | p50 lower |
|---|---:|---:|---:|---:|---:|---:|---:|
| 4 KiB | 1 | 17.953 | 11.553 | -33.3% | -42.3% | +63.1% | 9/9 |
| 4 KiB | 4 | 63.410 | 47.073 | -23.3% | +142.5% | +6.3% | 9/9 |
| 4 KiB | 16 | 263.176 | 766.118 | +185.4% | +313.3% | -64.4% | 0/9 |
| 64 KiB | 1 | 42.625 | 8.832 | -78.0% | -81.1% | +340.7% | 9/9 |
| 64 KiB | 4 | 137.700 | 49.218 | -63.5% | +40.4% | +102.3% | 9/9 |
| 64 KiB | 16 | 589.296 | 764.004 | +24.8% | +102.5% | -21.2% | 0/9 |

Every 1- and 4-thread pair improves p50; every 16-thread pair regresses.
The 4-thread rows already show p99 growth despite the p50 gain.

Mixed workloads follow the same split. `provider-mixed-file-tcp-stream`
file opens improve at all thread counts (-46.0%, -29.0%, -39.4% p50).
`provider-mixed-file-tcp-connect` improves at 1 thread (-28.0% file,
-6.0% connect) but regresses at 4 threads (+41.9% file, +41.3% connect
p50; p99 roughly doubles) and 16 threads (+25.0% file, +32.6% connect p50;
-23% throughput for both classes). The ordinary-file and standalone TCP
controls are not uniformly flat: `ordinary-open-read@t1` is -9.1% p50, the
`ordinary-mixed-file-tcp-stream@t16` TCP class is +7.4% p50, the
`ordinary-mixed-file-tcp-stream@t1` file class is +17.1% p99, and standalone
`tcp-connect@t1` is -27.3% p50. The same binaries do not reproduce the
`tcp-connect@t1` shift at 4 or 16 threads. Control variance of this size
bounds how small a managed-path change these numbers can resolve.

The paired standalone `tcp-connect@t16` result is +2.5% p50 and +0.3% p99
with 3/9 pairs lower. The managed mixed 16-thread connect class is the
+32.6% p50 above. There is no universal no-regression result and no
whole-agent gain in these numbers.

## Focus follow-up with CPU pinning

Five more pairs for two 16-thread cases with each container pinned to
`--cpuset-cpus 5-9,15-19` and the same 10,000 operations per worker. No
builds were observed during these 20 invocations.

| Case | Before p50 µs | After p50 µs | Paired p50 | Paired p99 | Paired ops/s | p50 lower |
|---|---:|---:|---:|---:|---:|---:|
| ordinary-open-read@t16 | 50.562 | 50.386 | -2.1% | -0.9% | +1.7% | 3/5 |
| provider-open-read-4096@t16 | 255.832 | 254.167 | -5.9% | +292.1% | -31.3% | 3/5 |

Pinning flattened the 4 KiB p50 but not the tail: p99 is still almost 4×
and throughput is down by a third. The ordinary control is flat. Pinning on
a shared host is a confounded experiment, not CPU isolation, so this does
not separate a scheduling cause from a contention cause. Shared inode or
page contention on the cached revision file versus scheduler behavior are
hypotheses only. Source review found no obvious retry on the successful
open path.

## Full Docker driver comparison

Median OpenShell time per workload in milliseconds, nine trials per variant.
The change column is the percent change between the two OpenShell variant
medians, not a median of paired before/after changes: the variant batches
were not interleaved, so no before/after pairing exists across them. Within
each batch, the Docker and OpenShell runs remain paired. Docker medians are
shown for scale. The two batches ran at different times under different load.

| Case | Docker before | OpenShell before | Docker after | OpenShell after | OpenShell change |
|---|---:|---:|---:|---:|---:|
| provision | 198.183 | 706.149 | 203.273 | 719.310 | +1.9% |
| exec | 47.446 | 13.610 | 44.739 | 14.485 | +6.4% |
| cpu | 226.923 | 222.103 | 219.313 | 218.865 | -1.5% |
| getpid | 117.831 | 116.686 | 119.524 | 116.733 | +0.0% |
| file | 82.966 | 612.804 | 91.516 | 659.609 | +7.6% |
| spawn | 94.911 | 107.530 | 95.190 | 122.610 | +14.0% |
| tcp-connect | 28.228 | 86.292 | 24.980 | 125.158 | +45.0% |
| tcp-stream | 245.098 | 247.793 | 243.643 | 258.898 | +4.5% |
| file-open | 73.112 | 653.901 | 76.755 | 672.013 | +2.8% |
| file-read | 122.064 | 110.246 | 112.874 | 116.880 | +6.0% |
| file-t4 | 68.045 | 218.317 | 66.170 | 221.269 | +1.4% |
| file-t16 | 53.757 | 161.804 | 41.280 | 164.900 | +1.9% |
| file-latency | 87.206 | 699.206 | 95.383 | 698.880 | -0.0% |

The driver `tcp-connect` +45.0% measures 1,000 loopback connect plus 64-byte
echo operations inside the sandbox, in a batch that overlapped more builds.
The gateway and supervisor are part of the sandbox lifecycle, not of every
connect's data path. It is not the same measurement as the paired harness
`tcp-connect@t16` (+2.5% p50, +0.3% p99), which measures connect and close
without an echo across 16 threads, so the absolute timing definitions
differ. The driver workloads open `/etc/passwd`, not a managed file, so they do not
exercise the cached reopen path.

## Code review, `e9f4a42..8dd0a0c`

Scope is the performance checkpoint only. Inherited development history
relative to `main` was excluded. No PR exists and no acceptance label was
verified.

1. **Concurrency and tail regression at the cached reopen path.** The
   16-thread regressions above sit on the new per-open
   `reopen_read_only` call in `crates/openshell-sandbox/src/provider_files.rs:151-152`.
   The measurements locate the regression; they do not prove its cause.
2. **Page-size assumption in the new sockaddr test.** The test at
   `crates/openshell-sandbox/src/network_broker.rs:4454` hardcodes a 4 KiB
   page and protects the second page at line 4468. Forcing the
   `/proc/<tid>/mem` fallback reproduces a failure at line 4485 for length 17:

   ```shell
   strace -f -qq -e trace=process_vm_readv -e inject=process_vm_readv:error=ENOSYS \
     target/debug/deps/openshell_sandbox-cb97d6c43098bf13 \
     --exact network_broker::tests::single_copy_socket_address_matches_the_separate_reads --nocapture
   ```

   The fallback is a supported path, so the test should use the runtime page
   size and a real unmapped boundary. The 16 KiB and 64 KiB page cases were
   inspected in source, not run.
3. **Throughput over-reports short reads.** `crates/openshell-sandbox/src/perf.rs:757`
   multiplies operations by the requested 64-byte payload for
   `file-open-read` and `file-read`, even when the file is shorter.
   `--provider-file-bytes 1` is accepted. A 1,000-operation `file-read` run
   reported 1169.214 Mbit/s against 18.269 Mbit/s actual, a 64× error. The
   main grid reads 64 bytes from 4 KiB and 64 KiB files, so its throughput
   columns are unaffected; other accepted inputs are.

Source review found no confirmed production correctness or isolation defect
in the reviewed diff.

## Validation

| Suite | Result |
|---|---|
| `openshell-sandbox` unit tests | 346 passed, 2 ignored |
| Docker driver unit tests, feature off | 156 passed, 2 ignored |
| Docker driver unit tests, feature on | 156 passed, 2 ignored |
| Python runner tests | 5 passed |
| Full Docker workload and broker content checks | pass |
| Fallback diagnostic (finding 2) | 1 failure, intentionally demonstrated |

No new provider-update end-to-end test ran, and no 64 KiB-page host was
exercised in this run.
