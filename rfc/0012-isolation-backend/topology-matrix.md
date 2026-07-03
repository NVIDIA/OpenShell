# Topology matrix

This non-normative matrix compares representative mappings of RFC 0012's logical
roles. It records role placement, sharing, and relationship to the workload
kernel; it does not select a deployment or establish conformance.

## Representative placements

| Pattern | Supervisor placement | Backend and network-mediation placement | Workload-kernel relationship |
|---|---|---|---|
| **Co-located/in-pod** | With the workload | Backend runs in the supervisor process; network mediation is co-located | Trusted components share the workload's host, guest, or application kernel, depending on the runtime |
| **Same-pod composite** | With the workload | Backend runs with the supervisor; network mediation may run in a sidecar | Components share the workload's kernel |
| **Delegated backend components** | With the workload | A node or remote helper establishes some controls; network mediation may be co-located or delegated | Depends on which trusted components remain with the workload |
| **Driver-hosted/shared service** | With the compute driver or another trusted service | Backend and network mediation may be co-located with the supervisor; one host may operate many isolated boundaries | Depends on the workload runtime |

## Durable rules

- Every active boundary has one verified descriptor, one trusted
  `SandboxContext`, and one logical supervisor.
- Physical processes and listeners may be shared, but lifecycle state, policy,
  binary identity, enforcement, and cleanup remain isolated per boundary.
- `Ready` means network mediation is initialized, standing enforcement is
  confirmed, and launch-time controls will be in force before untrusted
  execution.
- Moving a privileged component does not itself provide kernel separation.

## Kernel relationships

| Relationship | Meaning |
|---|---|
| **Shared host kernel** | The workload and the trusted components relied on for containment run on the host's kernel. |
| **Shared guest or application kernel** | The workload and those trusted components share one isolated kernel: a VM guest kernel or a userspace application kernel. |
| **Kernel-separated** | The trusted components relied on for containment run outside the workload's kernel. |

## Status

This matrix is non-normative. It illustrates implementations of RFC 0012; it
does not extend the contract.
