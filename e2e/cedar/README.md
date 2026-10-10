<!-- SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Cedar policy end-to-end test

Runs a sandbox whose policy is written in pure Cedar and checks that every
layer enforces it:

| Area | Source | Checks |
|---|---|---|
| Network | `policy.template.cedar` | Permitted `GET` reaches the upstream; other paths, a path one segment deeper than a delimited glob allows, other methods, a `forbid`, another binary, and an unlisted host are denied. A delimited host glob (`*.github.com`) admits `api.github.com` through policy DNS but not `github.com`. A staged `@enforcement("audit")` `forbid` lets its request through and is logged. |
| Middleware | `middleware.template.yaml` via `--middleware` | The `openshell/regex` middleware redacts a secret in the request body before it reaches the upstream. |
| Filesystem | `policy.template.cedar` | A `WriteFile` grant makes `/sandbox` writable, a `ReadFile` grant makes `/opt` readable, and `/srv` stays unreadable. |
| Syscalls | sandbox runtime | `memfd_create`, `ptrace`, user-namespace `unshare`, `mount`, `io_uring_setup`, raw netlink sockets, and direct TCP connects that bypass the proxy return `EPERM`. |

Syscall filtering is not authored policy, in YAML or Cedar. The syscall checks
confirm that the sandbox's seccomp restrictions still apply when the policy is
Cedar. Middleware is configuration rather than access control, so it is passed
as a separate YAML file instead of being part of the Cedar policy.

The network checks use `echo-server.py`, a small HTTP server the test starts
on the host and reaches at `host.openshell.internal`, so the suite does not
depend on the internet except for confirming that `example.com` is
unreachable and that the host glob check can reach `api.github.com`.

The sandbox only trusts `host.openshell.internal` when it maps to the host
gateway address the gateway configured, as in CI. Where it does not (for
example a gateway started with `mise run gateway:docker` on macOS), the suite
needs an echo service that reflects request bodies. On macOS it defaults to
`https://httpbin.org/anything`, so it needs internet access there. On other
platforms, select one yourself:

```shell
CEDAR_E2E_UPSTREAM_URL=https://httpbin.org/anything bash e2e/cedar/test.sh
```

The test substitutes that URL's host, port, and path into the Cedar policy and
the middleware selector.

## Run it

Against an ephemeral Docker gateway:

```shell
mise run e2e:cedar
```

The suite is also part of `mise run e2e`, and CI runs it as the `cedar` entry of
the Docker E2E matrix. When `OPENSHELL_BIN` is set, as in CI, the task uses that
CLI instead of building one.

Against a gateway you already started with `mise run gateway:docker`:

```shell
OPENSHELL_GATEWAY=<gateway-name> \
OPENSHELL_BIN="$PWD/target/debug/openshell" \
bash e2e/cedar/test.sh
```

Set `CEDAR_E2E_KEEP_SANDBOX=1` to keep the sandbox for debugging. The test
needs `python3` on the host and a sandbox image that provides `curl`,
`python3`, and the `/sandbox`, `/opt`, and `/srv` directories. `mise run
e2e:cedar` builds and uses the shared `openshell/e2e-python:dev` workload image.
