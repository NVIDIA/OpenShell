# Podman Networking

Only the external supervisor has external network connectivity. The workload
container uses `network=none`; its loopback DNS relay and TCP socket mediation
reach the supervisor through a protected Unix socket, not a veth or proxy
environment variable.

```text
workload container                       supervisor container
agent -> sandbox -- private UDS / gRPC -> policy proxy -> host network -> destination
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

The supervisor companion uses Podman's host network. Host-gateway aliases and
the upstream corporate proxy apply only to the supervisor. The gateway's SSH
tunnel uses the supervisor relay over its private Unix socket, so the driver
does not publish a supervisor port.

On Linux, the supervisor's host network namespace is the same as the
gateway's, for both rootful and rootless Podman, so the automatic callback
route resolves the sandbox host aliases to loopback directly rather than
Podman's `host-gateway` resolver, which can select a different, unreachable
interface on multi-homed hosts. Set `host_gateway_ip` explicitly to override
with a different address (for example, a containerized or remote gateway).
On macOS, Podman Machine provides the runtime and host-loopback forwarding.

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
  credentials, host network, and gateway callback listener.
- DNS or egress denied: inspect supervisor policy decisions. Do not add a
  workload network, resolver bypass, or direct gateway route.
- Pair is not Ready: check the supervisor health socket and gateway session.
  A running workload container alone does not establish readiness.

See the [driver overview](README.md) and
[Podman runtime documentation](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
for runtime options.
