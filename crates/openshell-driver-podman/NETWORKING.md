# Podman Networking

Only the external supervisor has external network connectivity. The workload
container uses `network=none`; its loopback DNS relay and TCP socket mediation
reach the supervisor through a protected Unix socket, not a veth or proxy
environment variable.

```text
workload container                       supervisor container
agent -> sandbox -- private UDS / gRPC -> policy proxy -> Podman network -> destination
                                            |
                                            +-- authenticated gateway callback
```

## Outer network fence

The driver creates the workload without networks, host aliases, published
ports, or added capabilities. It checks the Podman inspect response before
launch and restart. The sandbox installs seccomp mediation and Landlock before
executing the agent. It does not create network namespaces, configure nftables,
or require `CAP_NET_ADMIN`.

TCP opens, TCP byte streams, DNS requests/replies, and lifecycle operations
share the authenticated gRPC channel. DNS is resolved and authorized by the
supervisor. General UDP is unsupported.

## Supervisor callback network

The configured `network_name`, host-gateway aliases, upstream corporate proxy,
and published SSH port apply only to the supervisor companion. The gateway's
SSH tunnel still uses the supervisor relay, not the published port.

Rootful Podman uses the configured bridge and its gateway address. Rootless
local callbacks require the existing pasta path; slirp4netns or unknown helpers
require an explicitly remote `grpc_endpoint`. On macOS, Podman Machine provides
the runtime and host-loopback forwarding.

These runtime-managed network helpers are outside the workload trust boundary.
Sharing the workload's user namespace preserves volume UID/GID mapping; it
does not share the workload's PID, mount, or network namespaces.

## Troubleshooting

Inspect both containers with the same sandbox-ID label, distinguishing
`openshell.io/isolation-role=sandbox` from
`openshell.io/isolation-role=supervisor`.

- Sandbox fails its qualification probe: use its log to identify the denied
  kernel/runtime primitive. Do not add capabilities or disable runtime seccomp.
- Sandbox cannot authenticate to supervisor: check the private channel volume,
  matching user namespace mappings, and shared SELinux label.
- Supervisor cannot call back: inspect its configured gateway endpoint,
  credentials, Podman network, and gateway callback listener.
- DNS or egress denied: inspect supervisor policy decisions. Do not add a
  workload network, resolver bypass, or direct gateway route.
- Pair is not Ready: check the supervisor health socket and gateway session.
  A running workload container alone does not establish readiness.

See the [driver overview](README.md) and
[Podman runtime documentation](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
for runtime options.
