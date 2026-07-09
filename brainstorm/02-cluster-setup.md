# Brainstorm: Cluster Setup & OpenShell Deployment

**Date:** 2026-07-09
**Status:** active
**Parent:** 01-warm-pool-feasibility

## Problem Framing

Before any measurements can happen, we need an OpenShift cluster with OpenShell and the Agent Sandbox extension CRDs running. This phase covers provisioning, installation, and validation.

Three components must work together:
1. A ROSA HCP cluster with a Kubernetes version that supports native sidecar containers (K8s 1.33+)
2. The Agent Sandbox operator with extension CRDs (SandboxTemplate, SandboxWarmPool, SandboxClaim)
3. OpenShell deployed and functional (can create cold-start sandboxes)

## Approaches Considered

### A: ROSA HCP with Upstream Agent Sandbox Manifests

Provision ROSA, install agent-sandbox from upstream manifests (both `manifest.yaml` and `extensions.yaml`), deploy OpenShell with the OpenShell OpenShift deploy chart.

- Pros: Uses upstream directly, most current version, full control over version
- Cons: No operator lifecycle management, manual CRD updates, no OperatorHub integration

### B: ROSA HCP with Red Hat Agent Sandbox Operator (Tech Preview)

Provision ROSA, install the Red Hat build of Agent Sandbox from OperatorHub, deploy OpenShell with the OpenShell OpenShift deploy chart.

- Pros: Operator manages CRD lifecycle, OperatorHub integration, downstream supported path
- Cons: Tech preview may not include extension CRDs yet, version may lag upstream

### C: Both Paths Available

Install the Red Hat operator for the core Sandbox CRD, then layer upstream extension manifests on top if the operator doesn't include them.

- Pros: Best of both worlds, flexibility
- Cons: Mixed provenance (downstream operator + upstream extensions), potential version conflicts

## Decision

**Approach C: Start with the Red Hat operator, fall back to upstream extensions.** Install the tech preview operator from OperatorHub first. If it includes the extension CRDs, use them. If not, apply upstream `extensions.yaml` on top. This gives us the downstream operator path for the core CRDs while ensuring we have warm pool primitives available.

## Key Requirements

1. **ROSA HCP cluster** via `rosa:create` with the AAET profile
   - OpenShift version must support K8s 1.33+ for native sidecar containers (KEP-753 GA)
   - Region: us-east-2 (matches AAET profile subnets)
   - Worker nodes: at least 3 for realistic scheduling behavior

2. **Agent Sandbox installation**
   - Red Hat Agent Sandbox operator from OperatorHub (if available)
   - Upstream extensions.yaml as fallback for SandboxTemplate/SandboxWarmPool/SandboxClaim
   - Verify all four CRDs are served: `kubectl api-resources | grep agents`

3. **OpenShell deployment**
   - Clone github.com/2000krysztof/Openshell-Openshift-Deploy at a pinned commit/tag for reproducibility
   - Run `deploy.sh` with default configuration
   - Verify: `openshell status` shows Connected
   - Verify: `openshell sandbox create --from base` succeeds (cold-start baseline works)

4. **Image pre-pulling**
   - Pre-pull the OpenShell base sandbox image and supervisor image on all worker nodes
   - This removes image pull latency from warm pool measurements
   - Use a DaemonSet with `initContainers` that pull and exit, or `oc debug node/` to pre-pull

5. **Validation checklist**
   - Gateway pod is Running
   - Agent Sandbox controller is Running
   - Extension CRDs are registered
   - Cold-start sandbox creation works end-to-end
   - Images are pre-pulled on all nodes

## Open Questions

- What OpenShift version does ROSA HCP currently offer that includes K8s 1.33+? Need to check `rosa list versions`.
- Does the Red Hat Agent Sandbox operator tech preview install from the default OperatorHub catalog, or does it require a custom CatalogSource?
- Does the deploy script handle OpenShift 4.20+ or does it need updates for newer SCC/security changes?
- How much cluster capacity do we need? The warm pool experiments will create 5-20 pre-provisioned pods simultaneously.
