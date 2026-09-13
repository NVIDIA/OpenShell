# Compute-driver placement

This non-normative guide shows how each compute driver places RFC 0012's
components and protects the supervisor-to-sandbox channel. Placement is a
driver concern; every driver presents the same Isolation Backend interface to
the supervisor.

| Compute driver | Supervisor | Sandbox runtime | Protected channel | Outer egress fence | Status |
|---|---|---|---|---|---|
| **Docker** | Host process | `openshell-sandbox` in the workload container | Authenticated Unix-domain socket | `network_mode=none` | Implemented in #2965 |
| **Podman** | Host process | `openshell-sandbox` in the workload container | Authenticated Unix-domain socket | `--network=none` | Implemented in #3230 |
| **Kubernetes** | Separate trusted Pod | `openshell-sandbox` in the workload Pod | Authenticated TLS over a private Service | `NetworkPolicy` | Implemented in #3144; requires a conforming NetworkPolicy CNI and trusted namespace |
| **VM** | Host process | `openshell-sandbox` as guest PID 1 | Authenticated vsock | No guest NIC | Implemented in #2945 |

The Kubernetes driver creates the workload fence, pair labels, private Service,
supervisor workload, immutable bootstrap Secret, and stable
namespace/Sandbox/workload/NetworkPolicy claims. The workload Pod has no direct
egress. DNS and TCP requests cross the protected channel, and the supervisor
initiates approved external connections. Admission requires a conforming CNI
and a namespace where untrusted principals cannot create Pods, mutate pair
labels, or read bootstrap Secrets. Pod readiness or the existence of a
`NetworkPolicy` object alone does not prove enforcement.

## Durable rules

- Every active boundary has one verified descriptor, one trusted
  `SandboxContext`, one supervisor, and one sandbox runtime.
- Physical processes and listeners may be shared, but lifecycle state, policy,
  binary identity, enforcement, and cleanup remain isolated per boundary.
- Moving a privileged component does not itself provide kernel separation.

## Kernel relationships

| Relationship | Meaning |
|---|---|
| **Shared host kernel** | The workload and the trusted components relied on for containment run on the host's kernel. |
| **Shared guest kernel** | The workload and those trusted components share one isolated VM guest kernel. |
| **Kernel-separated** | The trusted components relied on for containment run outside the workload's kernel. |

This guide is non-normative. It illustrates implementations of RFC 0012; it
does not extend the contract.
