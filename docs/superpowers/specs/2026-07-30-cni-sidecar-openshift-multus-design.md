# CNI-sidecar on OpenShift (Multus / OVN-Kubernetes) — Design

Date: 2026-07-30
Branch: `feat/kubernetes-cni-sidecar-topology`
Status: Approved design, pending implementation plan

## Problem

The `cni-sidecar` topology installs a chained CNI plugin (`openshell-cni`) on every
node via a privileged DaemonSet. During CNI `ADD`, the plugin reads pod annotations
and installs nftables/iptables bypass-prevention rules in the sandbox pod's network
namespace so the workload's egress is forced through the sidecar proxy
(`SIDECAR_PROXY_PORT = 3128`).

The installer as written targets a **vanilla / k3s CNI layout**: it searches
`cni.confDir` for a `*.conflist`, appends `openshell-cni` to that file's `.plugins`
array, backs it up, and unpatches on `preStop`.

This model does not work on OpenShift. Verified on a single-node OpenShift 4.22
cluster (RHCOS, cri-o 1.35, **OVNKubernetes + Multus**):

- CNI bin dir is `/var/lib/cni/bin` (cri-o `plugin_dirs`); `/opt/cni/bin` does not exist.
- CNI conf dir is `/etc/kubernetes/cni/net.d/` (cri-o `network_dir`); `/etc/cni/net.d`
  does not exist.
- The only conf there is `00-multus.conf` (type `multus-shim`) — a single `.conf`
  with **no `.plugins` array**.
- The delegated OVN config (`/run/multus/cni/net.d/10-ovn-kubernetes.conf`) is also a
  single-plugin `.conf`, CNO-managed and regenerated.

So there is no `.conflist` to append to. The installer's `find ... -name '*.conflist'`
step exits 1 (safe, but non-functional). Forcing it at a CNO-managed `.conf` would be
reverted and risks breaking cluster networking.

## Chosen mechanism: Multus auxiliary CNI chain

The Multus thick daemon on this cluster has `auxiliaryCNIChainName: "vendor-cni-chain"`
set (`multus-daemon-config` ConfigMap). Multus runs an **isolated auxiliary CNI chain
for every pod**, loading configs from a `vendor-cni-chain/` subdirectory of the
cluster-network config directory — **without touching any CNO-managed file**. The base
directory is derived from the `clusterNetwork` path in `00-multus.conf`
(`/host/run/multus/cni/net.d/10-ovn-kubernetes.conf`), so the on-host chain directory is:

```text
/run/multus/cni/net.d/vendor-cni-chain/
```

Dropping a standalone `openshell-cni` `.conf` there causes Multus to run our plugin as
an isolated auxiliary chain for all pods. Our plugin already no-ops for pods without the
`openshell.ai/cni: enabled` annotation (unit test `add_passes_through_non_openshell_pod`)
and passes `prevResult` through, so it does not disturb other pods.

References:

- Multus configuration reference: <https://k8snetworkplumbingwg.github.io/multus-cni/docs/configuration.html>
- Multus thick plugin: <https://k8snetworkplumbingwg.github.io/multus-cni/docs/thick-plugin.html>

## Approach

Approach 1 (chosen): add a second **install mode** to the existing CNI DaemonSet,
selected by a new `cni.mode` value. Keep the conflist-append logic unchanged for
k3s/vanilla (preserves the existing `mise run e2e:kubernetes:cni-sidecar` CI path). Add
a `multus-chain` mode for OpenShift. Isolate the OpenShift difference to (a) a script
branch, (b) path defaults, and (c) an SCC template.

Rejected: a separate OpenShift DaemonSet template (duplicates pod spec / volumes /
cert-refresh loop / RBAC) and a bespoke operator (YAGNI for a chained-plugin drop-in).

## Design

### Install modes

`cni.mode` selects behavior:

- `conflist` (default, unchanged): find first non-openshell `*.conflist` in
  `cni.confDir`, append `openshell-cni` to `.plugins`, back up the original, unpatch on
  `preStop`.
- `multus-chain` (new): write a standalone CNI `.conf`
  (`{"cniVersion", "name":"openshell-cni", "type":"openshell-cni", "openshell":{...}}`)
  into `cni.chainDir`. Never modify a CNO-managed file. `preStop` removes the `.conf`
  and the credential files.

The `openshell-cni` binary is installed into `cni.binDir` in both modes.

### Paths & credentials

New/updated values (OpenShift defaults):

| Value | OpenShift default | Purpose |
|-------|-------------------|---------|
| `cni.mode` | `multus-chain` (overlay); `conflist` (chart default) | Install strategy |
| `cni.binDir` | `/var/lib/cni/bin` | Plugin binary location |
| `cni.chainDir` | `/run/multus/cni/net.d/vendor-cni-chain` | Aux-chain `.conf` (multus-chain only) |
| `cni.stateDir` | `/etc/kubernetes/cni/openshell` | **Persistent** kubeconfig/token/ca.crt/log |

`cni.chainDir` is tmpfs (`/run`), so credentials cannot live there. The DaemonSet writes
kubeconfig/token/ca.crt to the persistent `cni.stateDir`, and the plugin `.conf`
references those `stateDir` paths. The DaemonSet's periodic loop (already refreshing the
SA token every 300s) additionally **re-asserts the chain `.conf` if missing**, so it
survives a Multus restart; on a full node reboot the DaemonSet re-writes at startup.

For back-compat, when `cni.mode == conflist` the `stateDir` default resolves to
`cni.confDir` (current behavior).

### RBAC & SCC

- Add `pods: get` for the CNI ServiceAccount, scoped to the sandbox namespace(s). Under
  Multus, pod annotations are not passed via `CNI_ARGS`, so the plugin queries the API by
  pod name/namespace and requires this verb. (Implicitly required on k3s too; verify the
  existing e2e path.)
- New template `templates/cni-scc.yaml`, gated by `cni.openshift.privilegedSCC`
  (default `false`): a ClusterRole granting `use` on
  `securitycontextconstraints/privileged` (apiGroup `security.openshift.io`) plus a
  ClusterRoleBinding to the CNI ServiceAccount. Gating keeps non-OpenShift installs from
  referencing OpenShift-only APIs.

### Chart guardrails

- The existing `fail` guard (`topology=cni-sidecar` requires `cni.enabled=true`) stays.
- Add validation: `cni.mode` must be `conflist` or `multus-chain`; `multus-chain`
  requires `cni.chainDir`.

## Files

- `deploy/helm/openshell/templates/cni-daemonset.yaml` — branch install/preStop on
  `cni.mode`; add `chainDir`/`stateDir` volumes and mounts; re-assert conf in the loop.
- `deploy/helm/openshell/templates/cni-scc.yaml` — new, gated SCC ClusterRole+binding.
- `deploy/helm/openshell/templates/clusterrole.yaml` (or `role.yaml`) — add `pods: get`.
- `deploy/helm/openshell/values.yaml` — new `cni.mode`, `cni.chainDir`, `cni.stateDir`,
  `cni.openshift.privilegedSCC`; updated comments.
- `deploy/helm/openshell/README.md` — regenerated via `mise run helm:docs`.
- `deploy/helm/openshell/ci/values-cni-sidecar-openshift.yaml` — new overlay.
- `deploy/helm/openshell/tests/cni_daemonset_test.yaml` — add multus-chain assertions.
- `deploy/helm/openshell/tests/cni_scc_test.yaml` — new SCC unit tests.
- `docs/kubernetes/topology.mdx`, `architecture/compute-runtimes.md` — document the
  OpenShift/Multus mode.
- `crates/openshell-cni/*` — likely no functional change; confirm pod-annotation lookup
  path and log-file writability under the aux chain.

## Testing plan (on the OpenShift cluster)

Prerequisites:

1. Confirm the supervisor image ships `/openshell-cni` (DaemonSet copies it from the image).
2. Images onto the cluster: expose the internal registry (patch
   `configs.imageregistry/cluster`: set `storage` and `defaultRoute: true`),
   `oc registry login`, build via `mise run build:docker:gateway` /
   `build:docker:supervisor`, tag/push; or push to ghcr. Set the image repo in the overlay.
3. Install the `agent-sandbox` CRDs + controller (`AGENT_SANDBOX_VERSION`) — not present
   on the cluster.

Steps:

1. Helm install gateway + CNI with the OpenShift overlay.
2. Verify: DaemonSet Running; `openshell-cni` in `/var/lib/cni/bin`; `.conf` in
   `/run/multus/cni/net.d/vendor-cni-chain/`; a throwaway pod confirms the aux chain runs
   without breaking normal networking.
3. Functional: create a `cni-sidecar` sandbox; inspect the pod netns for the nft/iptables
   redirect rules; confirm egress is forced through the sidecar proxy (allowed dest works,
   direct bypass blocked).

Validation gates before deploying:
`mise run pre-commit`, `mise run test`, `mise run helm:test`, `mise run helm:lint`,
`mise run helm:docs`.

## Known limitations / follow-ups

- **Fail-open**: the chained-plugin model does not block pod networking if the
  `openshell-cni` conf is absent (e.g. brief window after a node reboot before the
  DaemonSet re-asserts). This is inherent to `cni-sidecar` generally, not
  OpenShift-specific. Fail-closed hardening is out of scope here and left as a follow-up.
- `vendor-cni-chain` availability depends on the Multus thick daemon having
  `auxiliaryCNIChainName` set. Present on OpenShift 4.22; the chart should document the
  requirement rather than attempt to configure Multus.
