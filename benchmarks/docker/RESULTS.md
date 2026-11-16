# Docker driver benchmark results

Measured November 12, 2026 (America/Denver); collection began November 13 at
06:18:52 UTC. All nine paired trials completed, including container cleanup.
The [measurement artifact](results/2026-11-12.json) contains 144 driver samples,
36 seccomp samples, image identities, representative container settings, and
binary/source hashes. The complete local runner output remains at
`.cache/perf-docker/results.json` and `.cache/perf-seccomp/results.json`.

## Findings

On this host, the additional cost concentrates in operations that invoke
mediation. Repeated file opens cost about 9.1 times the Docker baseline, new
local TCP connections about 5.5 times, and fork/exec about 24% more. CPU work
and ordinary `getpid` syscalls showed no meaningful slowdown. Established TCP
request/reply traffic showed a much smaller difference: 4.7% in the full driver
comparison and 0.5% in the separate broker harness. These small differences
should be treated cautiously given the observed spread and the single host.

The file case adds approximately 14.6 microseconds per open/read/close iteration.
The runtime's workload filter explicitly sends `open`, `openat`, and `openat2`
through seccomp notification to the provider-file broker, including this
non-provider `/etc/passwd` access. That is consistent with the large difference;
the full-driver test does not isolate notification handling from Landlock and
other runtime costs. See `install_workload_listener` in
`crates/openshell-sandbox/src/linux/seccomp_notify.rs` and
`dispatch_notification` in `crates/openshell-sandbox/src/network_broker.rs`.

## Docker versus the full OpenShell Docker driver

Times are medians across nine trials, in milliseconds. Parentheses contain
min-max. Overhead is the median of paired OpenShell/Docker ratios minus one,
so it can differ from the ratio of the two displayed medians. Each workload
had one unrecorded full warmup before measurement.

| Case | Docker ms (range) | OpenShell ms (range) | Paired overhead |
|---|---:|---:|---:|
| Provision through ready exec | 201.066 (197.472-218.102) | 710.472 (675.920-744.124) | +250.6% |
| Warm `/bin/true` exec | 43.770 (41.002-47.449) | 16.297 (15.478-17.637) | -62.8% |
| CPU, 100 million iterations | 92.359 (90.297-93.564) | 92.204 (87.824-93.042) | -0.1% |
| `getpid`, 1 million calls | 120.366 (118.541-122.383) | 119.735 (116.433-121.310) | -0.6% |
| Open/read/close, 50,000 iterations | 89.719 (88.126-90.982) | 819.160 (814.170-835.114) | +815.6% |
| Fork/exec/wait, 200 iterations | 107.498 (102.774-112.842) | 130.707 (129.080-138.914) | +24.1% |
| TCP connect/request/reply/close, 1,000 iterations | 36.447 (34.325-38.667) | 199.981 (181.270-213.035) | +446.8% |
| Established TCP request/reply, 20,000 iterations | 387.174 (351.613-394.505) | 401.501 (379.132-413.150) | +4.7% |

The exec row measures different client/control-plane implementations: Docker
exec versus OpenShell's gRPC exec. Its lower OpenShell time does not imply
faster child process execution. The fork/exec row measures child launch inside
the workload, with transport excluded, and shows the additional runtime cost.
Provisioning uses locally cached images and includes a successful readiness
exec; it excludes image builds and pulls.

## Native versus production seccomp network broker

The existing `openshell-seccomp-perf` harness ran nine paired trials, alternating
native/filtered order, with 10,000 measured operations, 1,000 warmup operations,
one client, and 64-byte payloads. The table reports the median across trials of
each trial's elapsed time divided by its operation count, in microseconds.

| Case | Native us/op (range) | Filtered us/op (range) | Paired overhead |
|---|---:|---:|---:|
| TCP connect | 17.133 (16.857-17.715) | 110.510 (108.453-116.052) | +537.7% |
| Established TCP stream | 20.452 (19.441-21.837) | 20.663 (16.744-21.258) | +0.5% |

This narrower test supports the connection-setup versus established-stream
distinction. It uses the production launcher and network broker without the
full gateway/supervisor lifecycle. Its connection operation differs from the
Docker workload; subtracting the two harnesses' absolute timings would not
isolate a supervisor cost.

## Environment and reproduction

- GCP Linux VM, Intel Xeon Platinum 8581C at 2.10 GHz, 8 vCPUs, 31.3 GiB RAM.
- Ubuntu 26.04.1 LTS, kernel `7.0.0-1017-gcp`, Docker `29.1.3`, overlayfs.
- Checkout `e9f4a4269`; CLI `0.1.6-dev.112+ge9f4a4269`; benchmark additions uncommitted.
- Release builds with telemetry disabled; gateway enabled only the Docker
  compute-driver feature. The attribution binary enabled `perf-harness`.
- Sandbox: statically linked `x86_64-unknown-linux-musl` build, verified by
  `tasks/scripts/verify-static-binary.sh`. Supervisor: native GNU build in the
  production supervisor Dockerfile with an Ubuntu 26.04 base plus the host's
  public CA bundle. This differs from the published distroless supervisor image.
- Both workload modes used UID/GID 1000, `/sandbox`, no external network,
  no capabilities, no-new-privileges, Docker's default seccomp profile, and
  `docker-default` AppArmor. OpenShell additionally applied its normal sandbox
  enforcement. The dedicated gateway set `app_armor_profile = "RuntimeDefault"`.
- Shared workload image ID:
  `sha256:93923652a62dc368323d04540f71bd4a2cac385749eb7f5ee082e6f241776b3e`.
- No compiler processes ran during collection. Trials alternated mode order,
  shuffled case order reproducibly, and used fresh containers. The runner
  waited for asynchronous container deletion before advancing.

See the [runbook](README.md) for image and gateway preparation. The full-driver
collection command, with the prepared dedicated gateway, was:

```shell
uv run --no-project tasks/scripts/perf-docker.py \
  --openshell ./target/release/openshell \
  --gateway perf-docker --trials 9 --output .cache/perf-docker
```

For the attribution run, invoke the existing binary once per layer per trial,
alternating the order across nine trials:

```shell
target/release/openshell-seccomp-perf --layer native --iterations 10000 --warmup 1000
target/release/openshell-seccomp-perf --layer filtered --iterations 10000 --warmup 1000
```

These measurements characterize single-client, warm-cache local operations on
one VM. They do not establish application-level overhead, external network or
HTTP/TLS performance, concurrent scaling, memory overhead, cold-pull startup,
or a statistically justified regression threshold.
