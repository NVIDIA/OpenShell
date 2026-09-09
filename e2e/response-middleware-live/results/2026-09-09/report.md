# PR #3074 live middleware test report

85 of 86 live scenarios passed. The remaining check exposed missing Content-Length metadata in preflight. All 14 multi-stage event-order checks passed, as did 33 selected response-runtime and 32 response-relay regression tests.

## Protocol mismatch

One protocol mismatch reproduced. The upstream sends `Content-Length: 19`, and the sandbox receives it, but the external middleware preflight omits it. The [protocol contract](https://github.com/NVIDIA/OpenShell/blob/555ff32896a225020b670902a601707624bbadc5/proto/supervisor_middleware.proto#L167-L170) says `Content-Length`, `Content-Encoding`, and `Content-Range` retain their read-only upstream values. The [relay filters protected fields](https://github.com/NVIDIA/OpenShell/blob/555ff32896a225020b670902a601707624bbadc5/crates/openshell-supervisor-network/src/l7/rest.rs#L4178-L4181), and [that filter includes content-length](https://github.com/NVIDIA/OpenShell/blob/555ff32896a225020b670902a601707624bbadc5/crates/openshell-supervisor-network/src/l7/rest.rs#L4234-L4238).

This prevents middleware from inspecting the advertised response size through its promised header metadata. Internal length-based mode eligibility still worked, including the 32-byte-cap checks. Suggested fix: distinguish fields hidden from middleware from fields visible but immutable, retain Content-Length for preflight, and keep writes/removals forbidden. Evidence: `responses/preflight-content-length-contract.json`. No fix was applied in this testing task.

## Live coverage and observed behavior

- Single stages: header-only, whole-body, and streaming pass-through; preflight skip/block; header writes; whole/stream redaction, replacement with empty bytes, body block, and skip_remaining.
- Failures: bad sequence numbers, explicit gRPC failure, 350 ms fixture sleeps exceeding the 150 ms RPC timeout, invalid mode selection, and attempts to mutate protected headers. Both fail-open and fail-closed were exercised.
- Chains: all nine ordered pairs of body modes; five three-stage combinations; later stages after skip_remaining and fail-open; transformed data and headers reaching subsequent stages; block despite fail-open. Event checks verified policy order, contiguous per-stage body sequences, one final unit, and trailer events for all 14 pair/triple cases.
- Delivery boundaries: preflight/whole-body blocks returned canonical 403; fail-closed before commitment returned canonical 502. Stream-only blocks/failures after commitment retained status 200 and ended with curl error 18, without injected error bytes. A delayed second-unit block delivered only `alpha` before truncation. Both stream→whole and whole→stream blocking produced 403 because the whole-body stage delayed commitment.
- Response shapes: HEAD, 204, partial responses, gzip, no-transform, empty bodies, chunked responses, and trailer mutation. Ineligible whole-body requests followed the selected failure policy. The header-only shape tests verified permitted modes; they did not exhaustively assert every byte of compressed/partial responses.
- Limits: known and unknown lengths exceeding 32 bytes; fail-open overflow followed by another stage; growth beyond a later stage's limit; one and two streaming stages delivering 1 MiB despite a 256 KiB per-stage payload cap.
- Unit boundaries: with the literal `secret` split into `sec` and `ret` by a delayed upstream, the stateless streaming redactor delivered `secret`; whole-body redaction returned `[REDACTED]`. This matches the documented V1 limitation: stream units have no application meaning and this fixture does not retain cross-unit matching state.

## Latency with CONNECT connection reuse

All numbers below are milliseconds. Added latency is the difference between the configuration's pooled median and the no-middleware pooled median at the same payload size.

| Middleware chain | 19 B median / p95 | Added | 64 KiB median / p95 | Added | 256 KiB median / p95 | Added |
|---|---:|---:|---:|---:|---:|---:|
| No middleware | 0.79 / 1.06 | +0.00 | 0.75 / 1.15 | +0.00 | 0.91 / 1.36 | +0.00 |
| 1 header-only | 1.53 / 2.18 | +0.74 | 1.65 / 2.12 | +0.90 | 1.91 / 2.60 | +1.00 |
| 1 whole-body | 2.38 / 3.42 | +1.59 | 2.54 / 3.31 | +1.79 | 3.80 / 4.66 | +2.89 |
| 1 streaming | 2.60 / 3.81 | +1.81 | 3.10 / 3.98 | +2.35 | 4.98 / 6.49 | +4.07 |
| 2 header-only | 2.44 / 2.95 | +1.65 | 2.42 / 3.36 | +1.67 | 2.63 / 3.33 | +1.72 |
| 2 whole-body | 3.95 / 5.15 | +3.16 | 4.53 / 5.62 | +3.78 | 6.32 / 7.61 | +5.41 |
| 2 streaming | 5.17 / 6.52 | +4.38 | 5.29 / 6.70 | +4.55 | 9.80 / 11.62 | +8.89 |
| Streaming → whole-body | 3.97 / 5.44 | +3.18 | 5.06 / 6.46 | +4.31 | 7.39 / 9.00 | +6.48 |
| Header-only → whole-body → streaming | 5.39 / 6.74 | +4.60 | 6.06 / 7.41 | +5.31 | 7.96 / 10.12 | +7.05 |

## Latency through the ordinary HTTP proxy

| Middleware chain | 19 B median / p95 | Added | 64 KiB median / p95 | Added | 256 KiB median / p95 | Added |
|---|---:|---:|---:|---:|---:|---:|
| No middleware | 4.96 / 5.67 | +0.00 | 4.79 / 5.63 | +0.00 | 4.97 / 5.90 | +0.00 |
| 1 header-only | 5.18 / 6.65 | +0.23 | 5.59 / 6.77 | +0.80 | 5.85 / 6.91 | +0.88 |
| 1 whole-body | 5.43 / 7.06 | +0.48 | 6.21 / 7.75 | +1.42 | 7.43 / 9.45 | +2.46 |
| 1 streaming | 6.93 / 8.45 | +1.98 | 7.25 / 8.60 | +2.46 | 9.23 / 10.84 | +4.26 |
| 2 header-only | 6.57 / 7.69 | +1.61 | 6.45 / 7.58 | +1.67 | 6.27 / 7.90 | +1.30 |
| 2 whole-body | 7.79 / 9.34 | +2.83 | 8.74 / 10.51 | +3.96 | 10.44 / 12.13 | +5.47 |
| 2 streaming | 8.42 / 10.56 | +3.46 | 9.19 / 10.98 | +4.40 | 13.39 / 16.34 | +8.42 |
| Streaming → whole-body | 8.43 / 10.10 | +3.47 | 8.91 / 10.52 | +4.12 | 12.12 / 14.00 | +7.15 |
| Header-only → whole-body → streaming | 9.18 / 10.91 | +4.22 | 9.10 / 10.80 | +4.31 | 12.72 / 14.63 | +7.76 |

## Delayed response and buffering

The upstream emitted three chunks with two 60 ms gaps. These are ordinary HTTP-proxy measurements, 12 retained observations per configuration. First byte refers to receipt of the response head, not the first body byte.

| Chain | Median first byte, ms | Median complete response, ms |
|---|---:|---:|
| No middleware | 5.20 | 126.12 |
| 1 header-only | 5.98 | 125.78 |
| 1 whole-body | 127.19 | 127.29 |
| 1 streaming | 6.61 | 128.14 |
| Streaming → whole-body | 130.26 | 130.37 |

Whole-body inspection withholds the head and body until accumulation finishes. Adding a whole-body stage to a streaming chain also removes early delivery. Streaming needs a round trip for each normalized body unit, which explains why its overhead grows with larger responses and additional stages. The 1 MiB trace shows 64 KiB units going through both services in order, plus final/trailer handling.

## Method and limits

Tested commit `555ff32896a225020b670902a601707624bbadc5` on 2026-09-09. Built a dedicated gateway and CLI from the PR, and built the sandbox supervisor with the repository's Docker task in the optimized release profile. No tracked source files changed.

The test ran on Linux 6.17, ARM64, 20 logical CPUs with Cortex-X925/Cortex-A725 cores. A dedicated Docker sandbox sent requests through the actual OpenShell policy and response relay. The local upstream used HTTP/1.1 and TCP_NODELAY. Four Python gRPC servers ran in one fixture process on separate ports, three with 256 KiB caps and one with a 32-byte cap. Policies selected independent modes and actions per stage. gRPC used plaintext local transport and a 150 ms RPC timeout. The fixture base image set the existing policy polling interval to one second; each policy update waited for the sandbox's loaded acknowledgement.

For each of nine middleware configurations and three payload sizes, each transport path ran three rounds in a reproducible randomized order. Each batch sent 40 sequential curl requests from a single process inside the sandbox; the first five were discarded. Each reported cell therefore contains 105 observations. Time is curl `time_total`, which excludes CLI launch, SSH setup, policy updates, and the Python wrapper. It includes response writes to the same sandbox temporary file and external gRPC/service processing. Fixture event logging was disabled during timing. Every measured response was checked for HTTP 200 and the expected byte count.

The ordinary HTTP forward-proxy path closes each connection. The measured samples recorded 105 new connections per cell. CONNECT tunnels reused the existing connection, recording zero new connections after warm-up. Neither series uses TLS. The machine was shared and CPU frequency/load was not controlled. These are serial latency measurements, not a concurrency, CPU, memory, production-network, or saturation-throughput benchmark. Sub-millisecond differences, especially on the ordinary HTTP path, are sensitive to background noise. Median and nearest-rank p95 are reported; p95 is an observation, not a guarantee.

## Evidence and reproduction

- `services.py`: configurable gRPC middleware and HTTP upstream.
- `run.py`, `policies/`, `responses/`, `matrix-results.json`: all 86 case definitions, loaded policies, wire results, and middleware events.
- `functional-summary.json`: case totals and extra chain event checks.
- `bench.py`, `tunnel-bench.py`, `extras-bench.py`: timing drivers.
- `benchmark-raw.json`, `tunnel-raw.json`, `streaming-latency.json`: unaggregated curl samples, including warm-ups and connection counts.
- `benchmark-summary.json`, `tunnel-summary.json`: derived medians, p95, and deltas.
- `runtime-tests.log`, `relay-tests.log`: selected repository regression results.
- `build.log`, `supervisor-docker-build.log`, `sandbox.log`: build and live runtime evidence.

The initial matrix had fixture-only false failures: the 502 checker expected the wrong error identifier, and curl could leave an earlier output file intact when no body arrived. Both were corrected, and the entire matrix was rerun. The initial benchmark attempted `/dev/null`, which was not writable under the fixture policy; successful runs use a temporary file. An unsupported curl fresh-connection option failed after the main timing rounds; the separate explicit-Connection-close controls were rerun with a valid header. Those controls are retained but excluded from the primary tables. Initial logs are retained for audit.

To rerun, build the gateway/CLI and supervisor at the recorded commit, create a Python environment with grpcio-tools, PyYAML, and matplotlib using uv, and regenerate the bindings from `proto/supervisor_middleware.proto`. Start `services.py`, then `start-gateway.sh`, run `run.py create`, `run.py matrix`, `bench.py`, and `tunnel-bench.py`. Run the two benchmark drivers sequentially because they update the same sandbox policy. Run `analyze.py` and `report.py` after results are complete. `start-gateway.sh` contains this host's reachable address and port choices; adapt them for another host. Keep temporary JWT private keys outside the report directory.

The disposable sandbox and fixture services were stopped after measurements. Test scripts and reports remain under the ignored `architecture/plans/pr-3074-live-tests` directory. The HTML report follows the OpenShell docs' NVIDIA green, white, gray, and dark-green palette from `fern/main.css` and `fern/docs.yml`.
