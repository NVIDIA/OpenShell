# Three Sandboxes on a Kubernetes Cluster

Install the OpenShell gateway into a Kubernetes cluster of your choice, then
create three sandboxes that run as pods on that cluster.

The walkthrough picks the target cluster via a `KUBE_CONTEXT` environment
variable so the same commands work against any kubeconfig context.

## Prerequisites

- OpenShell CLI installed (`openshell`)
- `kubectl` and `helm` configured with a context for your target cluster
- Permission to create namespaces, services, and pods in that cluster
- A Kubernetes cluster whose container runtime permits sandbox network-namespace
  setup (see [Cluster compatibility](#cluster-compatibility) below)

Pick the cluster you want to use and verify it is reachable:

```bash
export KUBE_CONTEXT=<your-context>           # e.g. testmember-5
export OPENSHELL_NAMESPACE=openshell         # optional, defaults to "openshell"
export OPENSHELL_RELEASE=openshell           # optional, defaults to "openshell"

kubectl --context "$KUBE_CONTEXT" cluster-info
```

## What's in this example

| File                  | Description                                                            |
| --------------------- | ---------------------------------------------------------------------- |
| `install-gateway.sh`  | Installs the OpenShell gateway Helm chart on `$KUBE_CONTEXT`           |
| `create-sandboxes.sh` | Creates three sandboxes (`alpha`, `beta`, `gamma`) via the gateway     |
| `values.yaml`         | Helm values used for the gateway install                                |

Both scripts read the same environment variables (`KUBE_CONTEXT`,
`OPENSHELL_NAMESPACE`, `OPENSHELL_RELEASE`), so `export`ing them once in
your shell is enough.

The `values.yaml` is tuned for a self-contained evaluation install:

- **TLS off, unauthenticated CLI access** (`server.disableTls: true`,
  `server.disableGatewayAuth: true`) so the CLI can talk to the
  gateway over plaintext through `kubectl port-forward` without minting and
  distributing client certs. Do **not** use these settings in production —
  front the gateway with OIDC or mTLS instead.
- **ClusterIP service** so nothing is exposed outside the cluster.
- **Explicit `server.grpcEndpoint`** pinned to
  `http://openshell.openshell.svc.cluster.local:8080` so sandbox pods know
  how to dial back into the gateway. The chart auto-derives this when left
  blank; we set it so the example is copy-paste safe across namespaces.
- **Sandbox pods run privileged** (`server.sandboxPrivileged: true`). Required
  on AKS because containerd 2.1 rejects `mount --make-shared /run/netns`
  even with `hostUsers: false` (see
  [Cluster compatibility](#cluster-compatibility) for the full story).
  On runtimes that support it, prefer `server.enableUserNamespaces: true`
  instead.
- **Auto sideload** (`supervisor.sideloadMethod: ""`). On K8s ≥ 1.35 this
  picks `image-volume`; on older clusters it falls back to `init-container`.
  Both work because we are not combining `hostUsers: false` with
  `image-volume`.
- **`pkiInitJob.enabled: true`** — this pre-install hook creates the JWT
  signing-key Secret the gateway StatefulSet mounts, so it must stay on
  even when TLS itself is disabled.

### Pinned component versions

For reproducibility, this example pins every external image to a specific
tag. Bump these together when you want to track a newer release.

The values file currently targets a **HEAD build of the gateway and
supervisor** because the `sandboxPrivileged` knob is post-`v0.0.47`. You
need to build them yourself and push to a registry the cluster can pull
from. The values file defaults to `ryanclaw.azurecr.io/openshell/...:dev`;
override `image.repository`, `image.tag`, `supervisor.image.repository`,
and `supervisor.image.tag` in your own values overlay if you publish
somewhere else.

| Component                  | Image                                                                | Tag in `values.yaml` |
| -------------------------- | -------------------------------------------------------------------- | -------------------- |
| OpenShell gateway          | `ryanclaw.azurecr.io/openshell/gateway`                              | `dev` (HEAD build)   |
| OpenShell sandbox supervisor | `ryanclaw.azurecr.io/openshell/supervisor`                         | `dev` (HEAD build)   |
| Sandbox base image (default) | `ghcr.io/nvidia/openshell-community/sandboxes/base`                | `latest`             |
| `agent-sandbox` controller | `registry.k8s.io/agent-sandbox/agent-sandbox-controller`             | `v0.1.0`             |

- The gateway and supervisor tags live in [`values.yaml`](./values.yaml).
- The sandbox base image is the gateway's chart default
  (`server.sandboxImage`); override it in `values.yaml` if you want to pin
  the sandbox image too.
- The `agent-sandbox` controller version is pinned by the manifest at
  `deploy/kube/manifests/agent-sandbox.yaml`.

To build the gateway and supervisor images yourself and push them to your
own registry:

```bash
export IMAGE_REGISTRY=<your-registry>            # e.g. ryanclaw.azurecr.io
export IMAGE_TAG=dev                              # or any tag you like
DOCKER_PUSH=1 mise run build:docker:gateway
DOCKER_PUSH=1 mise run build:docker:supervisor
```

Then update `image.repository`, `image.tag`, `supervisor.image.repository`,
and `supervisor.image.tag` in `values.yaml` to point at your registry and
tag.

## Walkthrough

### 1. Install the agent-sandbox controller (one-time, per cluster)

The OpenShell gateway represents each sandbox as a `Sandbox` custom resource
(group `agents.x-k8s.io`). The upstream
[`agent-sandbox`](https://github.com/kubernetes-sigs/agent-sandbox)
controller turns those CRs into running pods, so it must be installed on
the cluster before the gateway can create sandboxes. The repository ships a
pinned manifest:

```bash
kubectl --context "$KUBE_CONTEXT" apply -f deploy/kube/manifests/agent-sandbox.yaml
kubectl --context "$KUBE_CONTEXT" wait --for=condition=Established \
  crd/sandboxes.agents.x-k8s.io --timeout=120s
kubectl --context "$KUBE_CONTEXT" -n agent-sandbox-system \
  rollout status statefulset/agent-sandbox-controller --timeout=180s
```

You only need to do this once per cluster, regardless of how many gateways
or sandboxes you later install.

### 2. Install the gateway

Install the chart into a dedicated namespace on the target cluster. This
example uses the **HEAD chart** in this checkout (`deploy/helm/openshell`)
paired with a HEAD-built gateway/supervisor image (see
[Pinned component versions](#pinned-component-versions) above for the build
commands). The HEAD chart drives the gateway via environment variables
(`OPENSHELL_*`); released `v0.0.x` charts read a TOML file and will not
honor this values overlay.

```bash
kubectl --context "$KUBE_CONTEXT" create namespace "$OPENSHELL_NAMESPACE"
helm --kube-context "$KUBE_CONTEXT" upgrade --install "$OPENSHELL_RELEASE" \
  deploy/helm/openshell \
  --namespace "$OPENSHELL_NAMESPACE" \
  --values examples/three-sandboxes-on-kubernetes/values.yaml
```

Or run the helper script, which does the same thing against `deploy/helm/openshell`
in your working tree:

```bash
bash examples/three-sandboxes-on-kubernetes/install-gateway.sh
```

Set `CHART_PATH` to override the chart location (for example, to pin a
released chart version checked out at a tag via `git worktree`).

> **Why HEAD and not v0.0.47?**
> The `server.sandboxPrivileged` knob this example uses to unblock AKS
> only exists in the HEAD Rust gateway and HEAD chart; it is not in
> `v0.0.47`. Released charts also drive the gateway via a TOML ConfigMap,
> while the HEAD chart drives it via environment variables. Mixing the two
> leaves sandboxes with an empty `OPENSHELL_ENDPOINT` and
> `invalid gRPC endpoint`. Pin the chart and image to the same revision.

Wait for the gateway pod to become ready:

```bash
kubectl --context "$KUBE_CONTEXT" -n "$OPENSHELL_NAMESPACE" \
  rollout status statefulset/"$OPENSHELL_RELEASE"
```

The values file disables TLS and uses a `ClusterIP` service, which keeps the
example short. For production deployments keep TLS enabled and place the
gateway behind a trusted ingress or load balancer.

### 3. Forward the gateway and register it with the CLI

Forward the gateway service to your workstation. Leave this running in a
separate terminal:

```bash
kubectl --context "$KUBE_CONTEXT" -n "$OPENSHELL_NAMESPACE" \
  port-forward svc/"$OPENSHELL_RELEASE" 8080:8080
```

Register the forwarded endpoint with the CLI and select it as active:

```bash
openshell gateway add http://127.0.0.1:8080 --local --name "$KUBE_CONTEXT"
openshell status
```

`openshell status` should report the gateway as `HEALTHY`.

### 4. Create three sandboxes

Each `openshell sandbox create` call provisions one sandbox pod in the
cluster's sandbox namespace (defaults to the gateway's release namespace).
`--keep` keeps the sandbox running after the create command exits.

```bash
openshell sandbox create --name alpha --keep --no-auto-providers --no-tty -- echo "alpha ready"
openshell sandbox create --name beta  --keep --no-auto-providers --no-tty -- echo "beta ready"
openshell sandbox create --name gamma --keep --no-auto-providers --no-tty -- echo "gamma ready"
```

Or run the helper script, which creates all three:

```bash
bash examples/three-sandboxes-on-kubernetes/create-sandboxes.sh
```

### 5. Verify

List the sandboxes registered with the gateway:

```bash
openshell sandbox list
```

Confirm the corresponding pods exist on your cluster:

```bash
kubectl --context "$KUBE_CONTEXT" -n "$OPENSHELL_NAMESPACE" \
  get pods -l 'agents.x-k8s.io/sandbox-name-hash'
```

You should see three sandbox pods, one per sandbox. Connect into any of
them:

```bash
openshell sandbox connect alpha
```

### 6. Clean up

Delete the sandboxes through the CLI (which removes the pods from the
cluster):

```bash
openshell sandbox delete alpha
openshell sandbox delete beta
openshell sandbox delete gamma
```

Optionally uninstall the gateway and namespace when you are done:

```bash
helm --kube-context "$KUBE_CONTEXT" uninstall "$OPENSHELL_RELEASE" \
  --namespace "$OPENSHELL_NAMESPACE"
kubectl --context "$KUBE_CONTEXT" delete namespace "$OPENSHELL_NAMESPACE"
```

The `agent-sandbox` controller is shared infrastructure — leave it installed
if you plan to run more gateways on the same cluster. To remove it:

```bash
kubectl --context "$KUBE_CONTEXT" delete -f deploy/kube/manifests/agent-sandbox.yaml
```

## Cluster compatibility

This example needs the cluster to satisfy two independent runtime
requirements: the supervisor binary must be sideloadable into sandbox
pods, **and** the sandbox container must be able to set up its own network
namespace.

### Supervisor sideload

The gateway can deliver the `openshell-sandbox` supervisor binary into each
sandbox pod in one of two ways. `values.yaml` leaves
`supervisor.sideloadMethod: ""`, which auto-picks per cluster K8s version:

| Method            | Pros                              | Cons                                                                                                |
| ----------------- | --------------------------------- | --------------------------------------------------------------------------------------------------- |
| `init-container`  | Works on any Kubernetes version   | Adds an init container and an emptyDir per sandbox                                                  |
| `image-volume`    | No init container, no extra volume | Requires K8s ≥ 1.33 with the `ImageVolume` feature gate (GA in 1.36); incompatible with `hostUsers: false` on filesystems that do not support idmap mounts (notably AKS) |

The privileged sandbox path used by this example does **not** set
`hostUsers: false`, so `image-volume` works even on AKS. If you switch to
`server.enableUserNamespaces: true` on AKS, force `init-container` to
avoid the idmap-mount conflict.

### Network-namespace setup

The supervisor's first action inside a sandbox pod is:

```text
mkdir /run/netns
mount --bind /run/netns /run/netns
mount --make-shared /run/netns
ip netns add sandbox-<id>
```

That `mount --make-shared` requires more than just `CAP_SYS_ADMIN` /
`CAP_NET_ADMIN` — the kernel must allow changing mount propagation from
inside the container. Two ways to get that, both wired into the chart:

1. **User-namespaced sandbox** (`server.enableUserNamespaces: true`). The
   pod runs with `hostUsers: false`, capabilities become namespaced, and
   the supervisor can mark `/run/netns` shared. Needs K8s ≥ 1.33 with
   `UserNamespacesSupport` (beta in 1.33–1.35, GA in 1.36+) and Linux
   ≥ 5.12 on the nodes. Works on kind, k3d/k3s, minikube (with a real
   VM driver), GKE on Ubuntu node images, EKS on AL2023, etc.

2. **Privileged sandbox** (`server.sandboxPrivileged: true`). The pod runs
   with `securityContext.privileged: true`, which drops the seccomp,
   AppArmor, and locked-mount restrictions that block mount-propagation
   changes. Bigger hammer, but the only knob that works on AKS today (see
   below). Use this only on dedicated single-tenant clusters.

`values.yaml` in this example uses the privileged path because the
walkthrough's reference cluster is AKS. Switch to user namespaces (and
turn `sandboxPrivileged` off) on any runtime that supports them.

### Known-good runtimes

| Runtime / provider | Default `values.yaml` (`sandboxPrivileged: true`) | With `enableUserNamespaces: true` instead |
| ------------------ | ------------------------------------------------ | ----------------------------------------- |
| `kind` (≥ 1.33)    | ✅ Works                                         | ✅ Works (preferred)                       |
| `k3d` / `k3s` (≥ 1.33) | ✅ Works                                     | ✅ Works (preferred)                       |
| `minikube` (`--driver=kvm2` or `qemu`, ≥ 1.33) | ✅ Works           | ✅ Works (preferred)                       |
| GKE (Ubuntu node image, ≥ 1.33) | ✅ Works                          | ✅ Works (preferred)                       |
| AKS (Ubuntu, ≥ 1.35) | ✅ Works                                       | ❌ Pod crash-loops on `mount --make-shared` (see below) |

### AKS specifics

AKS up through 1.35 ships containerd 2.1 on Ubuntu 24.04 nodes, and its
default seccomp/AppArmor configuration **rejects `mount --make-shared` from
inside the container even when `hostUsers: false` is set**. With user
namespaces alone the pod crash-loops with:

```text
× Network namespace creation failed and proxy mode requires isolation.
  Error: mount --make-shared /run/netns failed: Permission denied
```

The fix on AKS is to use `server.sandboxPrivileged: true` (the default in
this example's `values.yaml`). Privileged sandboxes drop the security
boundary that AKS leans on, so the trade-off is real:

- Sandboxes run as full-host-capable containers. Treat the cluster as
  trusted infrastructure for trusted workloads only.
- Do not mix tenant workloads with sandbox workloads on the same node
  pool.
- Watch [`enableUserNamespaces`](https://kubernetes.io/docs/concepts/workloads/pods/user-namespaces/)
  rollout in AKS — once the underlying containerd seccomp profile allows
  mount-propagation changes from a user-namespaced container, switch to
  the user-namespace path and turn `sandboxPrivileged` back off.

### Quick diagnosis

If `openshell sandbox create` reports
`DependenciesNotReady: Pod is Running but not Ready` or
`supervisor session not connected`, inspect the sandbox pod's logs:

```bash
kubectl --context "$KUBE_CONTEXT" -n "$OPENSHELL_NAMESPACE" logs <sandbox-name>
```

| Error                                              | Cause                                                                                  |
| -------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `exec: "/opt/openshell/bin/openshell-sandbox": no such file or directory` | Supervisor sideload failed — switch `sideloadMethod` (init-container vs image-volume) |
| `invalid gRPC endpoint` / `Policy fetch failed`    | `OPENSHELL_ENDPOINT` is empty — the chart and gateway image revisions are out of sync (HEAD chart needs HEAD image; v0.0.x chart needs same v0.0.x image) |
| `mount --make-shared /run/netns failed: Permission denied` | Container runtime blocks mount-propagation changes — enable `server.sandboxPrivileged` (works on AKS) or `server.enableUserNamespaces` (works on most other runtimes) |
| `failed to set MOUNT_ATTR_IDMAP ... invalid argument` | `image-volume` sideload + `hostUsers: false` on a filesystem that doesn't support idmap mounts — switch `sideloadMethod` to `init-container` or turn off `enableUserNamespaces` |
| `missing authorization header`                     | `server.disableGatewayAuth` is not `true` — see [What's in this example](#whats-in-this-example) |

## Notes

- Sandbox pods land in the gateway's release namespace by default. Override
  this with `server.sandboxNamespace` in `values.yaml` if you want a
  separate namespace for sandboxes.
- The CLI talks to the gateway, not directly to the Kubernetes API. Once
  the gateway is reachable, sandbox lifecycle commands work the same on
  any cluster.
- For remote-only access (no port-forward), expose the gateway through an
  ingress or load balancer and register the public URL instead.
