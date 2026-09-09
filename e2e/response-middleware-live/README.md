# Live response middleware tests

This standalone test fixture preserves the live testing of [PR #3074](https://github.com/NVIDIA/OpenShell/pull/3074). It starts four configurable external gRPC middleware services and an HTTP upstream, then exercises the actual response relay through a Docker sandbox.

The fixture is not wired into CI. It uses a dedicated local gateway, fixed ports, and the sandbox name `pr3074-live`. Run only one copy at a time. The gateway and middleware use unauthenticated plaintext connections for local testing. The middleware and upstream listen on all interfaces so the sandbox can reach them. Use a trusted development host.

## Saved results

[The 2026-09-09 snapshot](results/2026-09-09/README.md) contains the report, charts, raw timing samples, and every final case's request configuration, response, and middleware events. It tested commit `555ff32896a225020b670902a601707624bbadc5`: 85 of 86 live cases passed, as did 65 selected runtime/relay regression tests.

The original failing case, `preflight-content-length-contract`, checks that middleware receives the upstream Content-Length. The recorded revision omitted it. The current relay exposes it as read-only metadata and emits downstream framing separately; the case remains a regression check. The original results snapshot is unchanged.

[The fix validation snapshot](results/2026-09-09-content-length-fix/README.md) records 86/86 passing live cases and 14/14 passing chain-event checks after rebuilding the supervisor with the fix.

## Setup

Use the repository's installed mise toolchain, uv, Docker, curl, jq, and OpenSSL. Python 3.12 was used for the recorded run. Set `MIDDLEWARE_LIVE_PYTHON` to an interpreter path if needed.

From the repository root:

```shell
bash e2e/response-middleware-live/setup.sh
mise exec -- cargo build -p openshell-gateway -p openshell-cli --bin openshell-gateway --bin openshell
CONTAINER_ENGINE=docker PREBUILT_AUTO_STAGE=1 IMAGE_REGISTRY=localhost/openshell-pr3074 IMAGE_TAG=555ff3289 mise run docker:build:supervisor
```

The image tag is the fixture's default name. The build command rebuilds from the current checkout; it does not fetch that Git commit. Check out the intended revision before building. The supervisor uses the release profile; the gateway and CLI use the dev profile.

Generated protobuf bindings and the Python environment stay untracked. Runtime output defaults to `e2e/response-middleware-live/output/`. Set an absolute `MIDDLEWARE_LIVE_OUTPUT` path consistently in every terminal to change it.

## Run the services and sandbox

Reserve ports 18081, 18191–18194, 18201, and 18202. In the first terminal:

```shell
uv run --no-project --python e2e/response-middleware-live/.venv/bin/python e2e/response-middleware-live/services.py
```

In the second terminal, start the dedicated gateway. On Linux, the launcher detects a host IPv4 address. Override `MIDDLEWARE_LIVE_HOST` with an address reachable by both the gateway and sandbox when necessary.

```shell
bash e2e/response-middleware-live/start-gateway.sh
```

After the gateway's health endpoint responds, create the sandbox and run the scenarios in a third terminal:

```shell
curl --fail http://127.0.0.1:18202/healthz
uv run --no-project --python e2e/response-middleware-live/.venv/bin/python e2e/response-middleware-live/run.py create
uv run --no-project --python e2e/response-middleware-live/.venv/bin/python e2e/response-middleware-live/run.py matrix
```

The fixture base image changes only the existing policy polling interval to one second. Each case waits for policy load acknowledgement. An optional substring after `matrix` selects cases, for example `matrix preflight-content-length-contract`. Each matrix invocation replaces the output summary; use separate output directories to retain independent runs. Failures are recorded and the matrix continues, then exits nonzero if any assertion failed.

## Benchmark and report

Run the drivers sequentially; both update the same sandbox's policy:

```shell
uv run --no-project --python e2e/response-middleware-live/.venv/bin/python e2e/response-middleware-live/bench.py
uv run --no-project --python e2e/response-middleware-live/.venv/bin/python e2e/response-middleware-live/tunnel-bench.py
uv run --no-project --python e2e/response-middleware-live/.venv/bin/python e2e/response-middleware-live/analyze.py
uv run --no-project --python e2e/response-middleware-live/.venv/bin/python e2e/response-middleware-live/report.py
```

`bench.py` measures ordinary HTTP proxy requests plus explicit-close controls and delayed upstream responses. `tunnel-bench.py` measures reused CONNECT tunnels. Both retain raw curl JSON, warm-ups, and connection counts. `extras-bench.py` is a recovery helper retained from the original session; do not run it after a successful `bench.py`, because it appends duplicate control samples.

The report generator preserves the original PR-specific narrative and known totals. For future revisions or a changed matrix, use the JSON summaries as the source of truth and update that narrative before publishing. It writes `report.md`, `.lavish/report.html`, and standalone PNG/SVG charts. The HTML opens directly without a viewer or network dependencies.

## Cleanup

```shell
target/debug/openshell --gateway-endpoint http://127.0.0.1:18201 sandbox delete pr3074-live
```

Then stop the gateway and fixture processes in their terminals. The gateway launcher writes the temporary credential directory to `output/runtime-path`; remove that directory after stopping the gateway. Do not commit runtime credentials, databases, or gateway/sandbox logs.
