# Performance changes and benchmark rerun

Measured November 13, 2026. Both fresh nine-trial Docker comparisons completed:
234 measurements for the preserved baseline and 234 for the optimized runtime.
The [artifact](results/2026-11-13-before-after.json) contains all 468 driver
samples, 72 host seccomp samples, runtime binary and image identities, source
hashes, and representative execution settings. The [original run](RESULTS.md)
is preserved separately.

## Results

Repeated open/read/close became **86.5% faster** (7.4× throughput for this
single-threaded loop), TCP connection setup **43.5% faster**, and fork/exec/wait
**13.8% faster**. Provisioning became **10.6% slower**, adding about 77 ms.

Times below are medians of nine trials. Negative time changes mean faster.
The before and after columns each have their own paired Docker control.
Workload timers exclude exec transport; provisioning and warm exec include
the client and control plane.

| Workload | Docker before ms | OpenShell before ms | Docker after ms | OpenShell after ms | OpenShell time change |
|---|---:|---:|---:|---:|---:|
| `provision` | 199.029 | 727.147 | 200.514 | 804.193 | +10.6% |
| `exec` | 41.628 | 15.435 | 41.307 | 15.593 | +1.0% |
| `cpu` | 87.113 | 90.544 | 86.811 | 87.728 | -3.1% |
| `getpid` | 113.654 | 116.279 | 114.123 | 116.573 | +0.3% |
| `file` | 86.421 | 791.401 | 89.115 | 107.091 | -86.5% |
| `spawn` | 105.638 | 125.095 | 103.170 | 107.832 | -13.8% |
| `tcp-connect` | 36.008 | 195.008 | 35.400 | 110.234 | -43.5% |
| `tcp-stream` | 378.345 | 389.316 | 366.678 | 377.848 | -2.9% |

The median paired OpenShell/Docker overhead for `file` fell from
+820.8% to +23.2%; for
`tcp-connect`, from +439.6% to
+211.4%; and for `spawn`, from
+19.4% to +1.9%.
TCP connection setup remains substantially more expensive than ordinary Docker.

CPU, raw `getpid`, reads on an existing descriptor, and established TCP show
small or variable changes. These results do not establish improvements in
those paths. The warm-exec comparison uses different client/control-plane
implementations; it is not a measure of intrinsic child-process speed.

Provisioning now creates and initializes a dedicated provider-file volume and
its two mounts, and qualifies the native delivery path before starting the
workload. The extra approximately 77 ms is consistent with that added startup
work; this run does not isolate the cost of each provisioning step.

## File-open controls

| Workload | Docker before ms | OpenShell before ms | Docker after ms | OpenShell after ms | OpenShell time change |
|---|---:|---:|---:|---:|---:|
| `file-open` | 73.081 | 766.343 | 74.184 | 92.155 | -88.0% |
| `file-read` | 129.978 | 132.606 | 128.695 | 133.109 | +0.4% |
| `file-t4` | 71.702 | 268.227 | 72.925 | 91.056 | -66.1% |
| `file-t16` | 56.577 | 222.796 | 58.351 | 70.457 | -68.4% |
| `file-latency` | 92.853 | 796.226 | 89.959 | 112.762 | -85.8% |

`file-open` omits the read; `file-read` uses repeated 64-byte reads at offset
zero on a descriptor opened before timing. The 4- and 16-thread cases split
50,000 open/read/close operations across threads. See the [runbook](README.md)
for every workload definition.

Per-operation latency of open/read/close, medians across trials:

| Runtime / mode | p50 µs | p99 µs | Median trial maximum µs |
|---|---:|---:|---:|
| baseline / docker | 1.788 | 2.600 | 60.763 |
| baseline / openshell | 15.548 | 21.836 | 374.654 |
| after / docker | 1.722 | 2.477 | 85.874 |
| after / openshell | 2.120 | 3.035 | 76.152 |

The latency case includes two clock reads per iteration. A trial maximum is
sensitive to scheduling; these maxima do not establish a tail-latency bound.

## Changes implemented

Claude Code CLI made the code changes using `--model fable`; completion metadata
identifies `claude-fable-5-2`. The [candidate review](PERFORMANCE-IDEAS.md)
records the attribution experiments and implementation decisions.

- The Docker driver provisions a private writable provider-file store and a
  read-only public subdirectory mount. Complete generations are exchanged
  atomically. Ordinary read opens stay in the kernel after validation and an
  active Landlock capability check; mutation-capable opens and `openat2` still
  notify. File mode 0600, update/detach behavior, and already-open file snapshots
  are retained. Retired generations have count/byte limits and a one-second
  grace; unchanged updates do not republish.
- The startup check tests a directory exchange in a temporary thread confined
  with the real workload Landlock layers. A kernel that refuses the resulting
  open uses virtual delivery only after the validated physical store is proven
  empty. Invalid mounts, failed cleanup, and incomplete probes fail startup.
  This guards the kernel behavior described by the
  [upstream disconnected-directory fix](https://kernel.googlesource.com/pub/scm/linux/security/vulns/+/9396a53e84ab963f18554fecd839680cce96b373/cve/published/2025/CVE-2025-68736.mbox).
- Narrow scalar socket-option allowances avoid unnecessary notifications.
  Descriptor admission counts once on its ordinary path, with a feature-probed
  procfs count and enumeration fallback. Socket addresses are copied once,
  retaining the previous error fallback.
- Blocking connections reuse workers with an explicit live-thread limit,
  four parked workers at most, and idle expiry. Admission, timeout, and
  unrelated-notification behavior have regression coverage.
- Task-memory measurements used `process_vm_readv` without fallback on this
  host, so backend caching was not added. Parallel notification receivers and
  synchronous wakeup were evaluated but left disabled because the experiments
  showed concurrency or tail-latency regressions.

Older Docker APIs, legacy descriptors, and the other compute drivers keep
virtual provider-file delivery. The measured file-open improvement applies to
this qualified Docker native-delivery path.

## Separate host seccomp comparison

Nine paired trials, alternating baseline/optimized and native/filtered order,
1,000 measured operations, 100 warmups, one client, 64-byte payloads.
Both TCP protocols were selected explicitly to preserve the original cases.
Values are medians of each trial's elapsed time divided by operation count.

| Protocol | Native before µs/op | Filtered before µs/op | Native after µs/op | Filtered after µs/op | Filtered time change |
|---|---:|---:|---:|---:|---:|
| `tcp-connect` | 17.953 | 113.750 | 18.084 | 95.350 | -16.2% |
| `tcp-stream` | 19.959 | 20.441 | 20.572 | 20.406 | -0.2% |

This harness uses nonblocking connection setup internally; the Docker workload
uses blocking connects. Its absolute times cannot be subtracted from the
Docker results to isolate a supervisor cost.

Two host-harness attempts at 10,000 operations / 1,000 warmups failed on native
connect timeouts, in trials 8 and 7. Adding one-second gaps did not resolve the
failure. Subsequent isolated native runs succeeded, so the cause remains
unresolved; those incomplete samples are excluded. The entire nine-trial
comparison was restarted at 1,000 operations / 100 warmups with 100 ms gaps
outside measurement, identically for both binaries and without per-sample retries.
The table therefore describes the smaller run and is not a direct repeat of the
original report's 10,000-operation seccomp comparison. The Docker comparisons
completed on their first uninterrupted final runs. An earlier Docker timing attempt was explicitly
stopped and discarded when a repeat test pass overlapped it.

## Validation

- Sandbox: 328 library tests, 4 binary tests, and the stdout logging test passed.
- Docker driver: 153 tests passed; sandbox backend: 103 library tests and its
  crypto-dispatch test passed. Existing unrelated ignored tests were not run.
- Both sandbox tests requiring real Docker mounts passed explicitly. The
  confined concurrent-reader test completed 12,714 baseline and 10,952 user-policy
  exchanges with no failed opens, preserving an already-open file's content.
- All five Docker E2E tests passed on the final images: `provider_files`,
  `policy_activation`, and the three `host_gateway_alias` tests. The provider
  test exercised mode 0600, update, and detach through actual runtime startup.
- Clippy with warnings denied passed for the affected crates and the sandbox
  `perf-harness` feature; formatting passed. Five benchmark-runner tests passed.
- Native release builds and the musl sandbox release build passed. The sandbox
  passed static-link verification. All Docker workload samples validated UID/GID
  1000, `/sandbox`, iteration counts, image identity, and successful execution.

The real capability probe passed on this kernel. Its negative branch was tested
with real Landlock on an unmounted layout and injected outcomes on the Docker
mounts; an older failing kernel was not available.

## Environment and reproduction

Same eight-vCPU Intel Xeon Platinum 8581C VM as the original report: Ubuntu
26.04.1, kernel 7.0.0-1017-gcp, Docker 29.1.3. Both modes used UID/GID 1000,
`/sandbox`, no external workload network, no capabilities, no-new-privileges,
Docker's default seccomp profile, and `docker-default` AppArmor. OpenShell
additionally applied its sandbox enforcement.

Both before and after used the same rebuilt workload image:
`sha256:f26afa7f641a412595b3643e9e030918413c2bb10baad87fff6781c0797c6723`.
The baseline runtime binaries and images were archived before code changes;
the optimized runtime was built from the working tree at `e9f4a4269`.
Gateway/CLI/supervisor are optimized native GNU builds, telemetry disabled,
with only the Docker compute driver linked into the gateway. Sandbox is static
musl. Both supervisor images use the same Ubuntu 26.04 base and public CA bundle,
as in the first report, rather than the published distroless base.

Collection began at 2026-11-13T09:04:57.884977+00:00 (baseline) and
2026-11-13T09:07:01.830229+00:00 (optimized). Each collection alternated Docker/
OpenShell order, shuffled case order reproducibly, warmed each case once,
and removed each container before advancing. No compiler or test processes
ran during the accepted measurements. Baseline and optimized batches ran
sequentially, so the Docker controls expose rather than eliminate host drift.

Use the [runbook](README.md) to build and prepare each runtime, then run the
same command with its CLI and dedicated gateway:

```shell
uv run --no-project tasks/scripts/perf-docker.py \
  --openshell /path/to/variant/openshell --gateway perf-docker \
  --trials 9 --output .cache/perf-docker-VARIANT
```

Runtime images were tagged `openshell/{sandbox,supervisor}:perf-baseline`
and `:perf-after`. Local orchestration and raw outputs are retained in
`.cache/perf-run-variant.py`, `.cache/perf-docker-{baseline,after}/`, and
`.cache/perf-seccomp-before-after-small/`. The saved artifact is
self-contained and includes exact runtime/source identities.

These are warm-cache microbenchmarks on one VM, not application-level or
external-network measurements. Nine trials do not provide a confidence bound
or a production regression threshold. Small deltas should be treated as noise.
