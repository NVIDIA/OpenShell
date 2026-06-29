# Topology selection matrix

This is a **lite, draft** decision aid that maps a deployment's starting point to a
recommended isolation topology from [RFC 0012](./README.md). It is supporting
material, not part of the normative RFC. It is seeded from the design meeting that
shaped RFC 0012 and is expected to be refined jointly (target-infrastructure
dimensions, usage personas, and the kata-enablement work) and to eventually
graduate into a docs page: "what are you trying to do, here is the recommended
configuration."

[RFC 0012](./README.md) defines the interface and the design logic (the kernel-sharing
axis, the forbidden cell, sequencing). This file holds the **placement catalog**
(the per-placement detail) and the **selection matrix** (which to choose).

## Placement catalog

The interface offers no single universal placement; different infrastructure and
workloads warrant different ones (istio went the same way). Three near-term
placements that share the agent's kernel, then the moves that separate it. Which
share the agent's kernel, and their build status, is in [RFC 0012's Representative
topologies](./README.md#representative-topologies).

**Today-hardened (fallback).** The supervisor runs in the agent's pod, but non-root. Better hygiene than today, the simplest step, the fallback when no internal isolation exists. Privilege still sits in the pod, so it does not reach `restricted`. (Kata-enablement work can move a sandbox from the `privileged` to the `anyuid` SCC by treating the hypervisor as the boundary, but `anyuid` is a waypoint, not the destination: it still permits root and is not `restricted`.)

**Sidecar-assisted (easiest UX).** A privileged sidecar in the **same pod** runs the Isolation Backend that programs interception; the supervisor stays with the agent and remains its proxy. This is a composite backend: it moves only the privileged network setup to the sidecar, while the in-pod supervisor still operates the proxy and applies the filesystem and syscall ceilings at process entry. Setting up interception still needs `NET_ADMIN`/`NET_RAW`, but only the sidecar carries it, not the agent container, making the pod spec defensible. Standard pod semantics; agent and sidecar share the pod's kernel. A native sidecar (an init container with `restartPolicy: Always`; beta and on by default since Kubernetes 1.29, GA in 1.33) realizes the `boundary_ready` gate: the kubelet starts the agent container only after the sidecar has started, and a startup probe on the sidecar holds it until the boundary is ready (a readiness probe only affects Pod readiness, not container start order), which this design requires. Moving the supervisor itself into the sidecar later is a different backend, one that needs an agent-side process shim to start and confine processes in the agent container; its own design defines that shim.

**Node enforcer / daemon-set (no pod privilege).** A privileged per-node daemon does the boundary setup, so the agent pod needs no elevated capabilities. In the prototype, the unprivileged in-pod supervisor's `attach` call reaches the daemon, which enters the agent pod's network namespace and installs the egress rules (the registration is the contract call, not a separate protocol). CNI and `NetworkPolicy` do not fit: a NetworkPolicy needs a policy-enforcing CNI, is default-allow and L3/L4 only, and programs eventually-consistently, and OpenShell must update enforcement on a running sandbox as policy changes, so the daemon stays resident. The boundary still funnels egress to the supervisor's proxy; the daemon does the privileged setup, it does not replace the proxy. Like the sidecar, this is a composite backend: it relocates only the network setup, while the in-pod supervisor still operates the proxy and applies the filesystem and syscall ceilings. The supervisor stays in the agent pod, sharing the host kernel. Cost: a privileged node component and bespoke node setup. A node enforcer alone does not make the pod capability-free or `restricted`-compatible; it removes the network capabilities, and the rest of the seven-capability grant comes off only as process, filesystem, and identity placement move too (see "Capabilities, and how they come off").

```mermaid
graph LR
    subgraph SCPod["sidecar: agent pod"]
        direction TB
        SCBackend["Isolation Backend (privileged sidecar)"]
        subgraph SCAgent["agent (unprivileged)"]
            SCWork["workload"]
            SCSup["supervisor"]
        end
        SCBackend -.->|installs egress rules| SCAgent
        SCWork ==>|only egress| SCSup
    end
    SCSup -->|egress| GW1["gateway"]

    NodeD["node daemon (privileged)"]
    subgraph NodePod["node enforcer: agent pod (unprivileged)"]
        direction TB
        NodeWork["workload"]
        NodeSup["supervisor"]
        NodeWork ==>|only egress| NodeSup
    end
    NodeD -.->|installs egress rules| NodePod
    NodeSup -->|egress| GW2["gateway"]

    style SCPod fill:#f0f7ff,stroke:#7aaede,color:#00084D
    style SCAgent fill:none,stroke:#9575cd,color:#00084D
    style SCBackend fill:#fff5f5,stroke:#e57373,color:#00084D
    style NodePod fill:none,stroke:#9575cd,color:#00084D
    style SCSup fill:#b39ddb,stroke:#9575cd,color:#fff
    style NodeSup fill:#b39ddb,stroke:#9575cd,color:#fff
    style SCWork fill:#a5d6a7,stroke:#81c784,color:#384D54
    style NodeWork fill:#a5d6a7,stroke:#81c784,color:#384D54
    style NodeD fill:#fff5f5,stroke:#e57373,color:#00084D
    style GW1 fill:#a5d6a7,stroke:#81c784,color:#00084D
    style GW2 fill:#a5d6a7,stroke:#81c784,color:#00084D
```

Splitting the supervisor into a separate pod is one move; whether it separates kernels depends on the agent pod's RuntimeClass. The two variants land in different containment rows (see [RFC 0012's containment table](./README.md#representative-topologies)).

- **Split-pod, `runc` agent (privilege separation, shared host kernel).** The supervisor moves to a separate pod; the agent pod drops its privileged capabilities and is confined by NetworkPolicy. Both pods still share the host kernel, so this separates privilege, not kernels. Standard pod semantics, at the cost of coordinating two scheduled units per sandbox. NetworkPolicy here is a proof obligation, not a free win: it requires a policy-enforcing CNI, is default-allow and L3/L4 only, programs eventually-consistently (a pod can egress before the policy lands), and is label-scoped (so it is defense-in-depth unless pod-mutation RBAC is locked down). (A concrete proposal is tracked in #981.)
- **Split-pod, VM or gVisor agent (kernel separation, expressible today).** The same separate-supervisor-pod move, but the agent pod runs under a Kata or gVisor `runtimeClassName`, so the agent gets its own kernel (a VM guest kernel under Kata, gVisor's application kernel under gVisor) and the supervisor sits outside it. Buildable on stock Kubernetes today. A stock one-pod Kata or gVisor RuntimeClass is not this: it puts the supervisor and agent under one such kernel (the outer-sandbox case, where they stay co-located).
- **Future node runtime (kernel separation, off the standard path).** Keeping the supervisor outside the agent's kernel without a per-agent guest needs a node runtime built to place them on opposite sides of the boundary. Nobody has built one; it is the seam a kernel-separated backend would fill. Real backend work.

### The design space, and the one cell stock Kubernetes forbids

Two axes set the space: whether the supervisor shares the agent's kernel, and the pod count or plug point. One combination is impossible on stock Kubernetes.

| | Supervisor shares the agent's kernel (host or guest) | Supervisor in its own kernel, separate from the agent |
|---|---|---|
| One pod | Today-hardened, sidecar-assisted, and the single-pod outer sandbox (gVisor, Kata, or Firecracker). Per-container `securityContext` varies privilege; the proxy mediates within the pod netns. An outer sandbox isolates the host but runs the supervisor inside the agent's isolated kernel (a VM guest under Kata or Firecracker, gVisor's application kernel under gVisor), so it shares that kernel. | **Not expressible on stock Kubernetes.** The runtime that owns the kernel boundary is selected per pod (`runtimeClassName`), not per container, so two containers of one pod cannot have different kernels. |
| Two pods / node runtime | Node enforcer, or a `runc` split-pod: both share the host kernel. | Split-pod with the agent pod under a VM or gVisor `runtimeClassName` (the supervisor stays in its own pod, outside the agent's guest), or a future node runtime that runs the supervisor outside the agent's kernel. |

The forbidden cell holds because of the CRI shape: the kubelet calls `RunPodSandbox` with the runtime handler once, per pod, then `CreateContainer` inside that one sandbox. The handler, and so the kernel, is fixed per sandbox; selecting it per container would need a new per-container CRI field plus a runtime that acts on it, not just a different backend behind the interface. The right column costs more: the supervisor can no longer read `/proc` or enter the netns directly, so those reach-ins route through the backend.

### Capabilities, and how they come off

An unprivileged agent container means shedding the whole seven-capability grant, not just `NET_ADMIN`, and that happens in stages:

- A backend removes `NET_ADMIN` and the network use of `SYS_ADMIN` by moving network setup out of the agent's container.
- Removing `SYS_ADMIN` fully needs process and filesystem placement to move too.
- Removing `SYS_PTRACE`/`DAC_READ_SEARCH` needs identity attested by the backend instead of read from `/proc`.

A same-pod sidecar moves `NET_ADMIN` out of the agent container but not the pod's security profile: the pod still needs an elevated security context, and on OpenShift an SCC exception, that `restricted` forbids (a service account carries no Linux capabilities itself; this is the friction adopters dislike). Only the node enforcer or split-pod reaches an unprivileged pod, and even that is necessary, not sufficient, for `restricted`: SELinux/MCS labels, seccomp, arbitrary UIDs, procfs-based identity, and execution-domain preservation must all be handled too. (RFC 0012's Risks section carries the normative requirement that admission gate what the agent container may reach.)

## The dimensions

Two dimensions drive the recommendation, with a third that bumps the posture up a
level rather than forming its own axis.

1. **Infrastructure available (the top-level question).** Do you have nested
   virtualization / kernel isolation (kata, gVisor) on your nodes? This is the
   first thing to decide. If yes, a kernel-grade boundary is on the table. If no,
   you are choosing among namespace-based topologies and trading off sidecar
   versus node placement.
2. **What the agent does.** A privacy-router that only talks to an LLM has a small
   blast radius; an agent that runs arbitrary, never-reviewed code has a large
   one. The industry has no crisp definition of "agent," which is exactly why this
   dimension matters for the recommended posture.
3. **Data sensitivity (the tie-breaker).** Whether PII or other sensitive data is
   in play. Rather than a third axis, treat it as a rule that moves you one cell
   toward stronger isolation within the table below.

## The matrix

Rows are infrastructure; columns are what the agent does. Cells name the
recommended topology from RFC 0012.

| | Agent = privacy-router only (talks to an LLM, low blast radius) | Agent = arbitrary code execution (untrusted code, high blast radius) |
|---|---|---|
| **Has kernel isolation** (nested virt / bare metal; kata or gVisor available) | **Sidecar-assisted.** A privacy router's blast radius is small, so a kernel boundary's overhead rarely pays for itself against that threat model; keep it simple. (Move to kata if PII is in play.) | **Kernel-separated.** Put the agent in its own guest kernel, but keep the supervisor outside it: split-pod with the agent pod under Kata/gVisor, or a future node runtime. A stock one-pod Kata/gVisor RuntimeClass is not sufficient, it co-locates the supervisor in the same guest kernel. The recommended strong posture. |
| **No kernel isolation** (managed Kubernetes, no nested virt) | **Today-hardened.** Non-root supervisor in the agent pod; the simplest fallback. (Move to sidecar if PII is in play.) | **Sidecar-assisted, then node enforcer.** Sidecar to keep privilege off the agent container; node enforcer to move privilege off the pod entirely. The best achievable without a VM. |

**PII tie-breaker.** If sensitive data is in play, move one cell toward stronger
isolation: a privacy-router deployment adopts the posture its arbitrary-code
neighbor would use, and an arbitrary-code deployment with kernel isolation
available should prefer the kernel-separated path rather than a same-kernel
sidecar.

## How to read a recommendation

1. Start with infrastructure (the row). No nested virt means the right-hand
   column's strongest option (kernel separation) is simply unavailable; do not
   recommend it.
2. Within the row, pick the column by what the agent does.
3. Apply the PII tie-breaker if relevant.
4. The named topology links back to RFC 0012 for its mechanism, trade-offs, and
   the capabilities it removes.

## Status and ownership

- **Draft, lite.** Deliberately small to keep RFC 0012 reviewable. Expect the
  cells and dimensions to change.
- **Open contributions.** Forthcoming work will propose roughly three target
  infrastructures and the trade-off dimensions, and a set of usage personas; the
  kata-enablement work (the `privileged` to `anyuid` SCC change) informs the
  "has kernel isolation" row. This file is the collection point until it graduates
  to docs.
- **Not normative.** RFC 0012 defines the interface and the topologies. This file
  only recommends which topology to choose; it does not add requirements.
