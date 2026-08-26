# Topology matrix

This non-normative matrix compares representative mappings of RFC 0012's logical
roles. It records role placement, sharing, and relationship to the workload
kernel; it does not select a deployment or establish conformance.

## Representative placements

| Pattern | Logical supervisor and network-mediation placement | Backend placement | Workload-kernel relationship | Topology status |
|---|---|---|---|---|
| **Co-located/in-pod** | With the workload | In the supervisor process | Trusted components share the workload's host, guest, or application kernel, depending on the runtime | Placement implemented (original topology) |
| **Same-pod composite** | Spans the workload-local supervisor process and, when used, a network-mediation sidecar | In the workload-local supervisor process | Components share the workload's kernel | Placement implemented (#2076) |
| **Delegated backend components** | With the workload and any delegated mediation component | A node or remote helper establishes some controls behind a workload-local backend | Depends on which trusted components remain with the workload | Placement proposed (#2606) |
| **Driver-hosted/shared service** | With the compute driver or another trusted service; no in-sandbox supervisor process is required | May be co-located with the logical supervisor; one host may operate many isolated boundaries | Depends on the workload runtime | Placement proposed |

## Durable rules

- Every active boundary has one verified descriptor, one trusted
  `SandboxContext`, and at most one logical supervisor, which may span multiple
  coupled processes.
- Physical processes and listeners may be shared, but lifecycle state, policy,
  binary identity, enforcement, and cleanup remain isolated per boundary.
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
