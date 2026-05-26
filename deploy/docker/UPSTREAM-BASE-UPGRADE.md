# Upstream Base Image Upgrade

The Aible fork builds `docker.io/aible/openshell-gateway` and `docker.io/aible/openshell-cluster` by layering our changes on top of the upstream NVIDIA images:

- Base for gateway: `ghcr.io/nvidia/openshell/gateway` ([Dockerfile.gateway](Dockerfile.gateway))
- Base for cluster: `ghcr.io/nvidia/openshell/cluster` ([Dockerfile.cluster](Dockerfile.cluster))

Both bases are pinned by digest so our builds are reproducible. We bump deliberately rather than tracking `:latest`.

## When to bump

Bump the upstream base when:

- Upstream ships a security patch that affects the runtime (ca-certs, libssl, the NVIDIA Ubuntu base).
- Upstream changes something we depend on indirectly (k3s version inside the cluster image, NVIDIA container toolkit, runtime libs).
- We need a fix or feature from a newer upstream release.

Do **not** bump just because time passed. A stale pin that works is better than a fresh pin that surprises us.

## Bump procedure

### 1. Pull the new upstream tags

```shell
docker pull ghcr.io/nvidia/openshell/gateway:latest
docker pull ghcr.io/nvidia/openshell/cluster:latest
```

### 2. Capture the new digests

```shell
docker inspect ghcr.io/nvidia/openshell/gateway:latest --format='{{index .RepoDigests 0}}'
docker inspect ghcr.io/nvidia/openshell/cluster:latest --format='{{index .RepoDigests 0}}'
```

### 3. Diff against the current pin

Compare what changed in the upstream gateway stage. The full delta the upstream adds on top of `nvcr.io/nvidia/base/ubuntu` is in [Dockerfile.images](Dockerfile.images) (target `gateway`). Sanity-check that none of these have changed in a way that breaks our overlay:

- **Binary names** — we currently overwrite both `openshell-gateway` and `openshell-server` and set `ENTRYPOINT ["openshell-gateway"]`. If upstream renames the binary again, update [Dockerfile.gateway](Dockerfile.gateway) to match.
- **Migrations path** — we copy `crates/openshell-server/migrations` to `/build/crates/openshell-server/migrations`. Check the upstream Dockerfile still uses that path.
- **`USER openshell`** — our COPY layers must remain readable by uid 1000.

For the cluster image, also diff against the bundled manifests and entrypoint scripts:

```shell
# Extract the new upstream cluster image's bundled files for comparison
docker create --name _tmp ghcr.io/nvidia/openshell/cluster:latest
docker cp _tmp:/opt/openshell/manifests/openshell-helmchart.yaml /tmp/upstream-helmchart.yaml
docker cp _tmp:/usr/local/bin/cluster-entrypoint.sh /tmp/upstream-entrypoint.sh
docker rm _tmp

diff deploy/kube/manifests/openshell-helmchart.yaml /tmp/upstream-helmchart.yaml
diff deploy/docker/cluster-entrypoint.sh /tmp/upstream-entrypoint.sh
```

If the upstream entrypoint script changed materially (e.g., new env var handling, new manifest substitutions), reconcile our fork's copy at [deploy/docker/cluster-entrypoint.sh](cluster-entrypoint.sh). If the upstream manifest template gained new placeholders the entrypoint substitutes, ensure our local manifest at [deploy/kube/manifests/openshell-helmchart.yaml](../kube/manifests/openshell-helmchart.yaml) either uses them or omits the block (we currently omit OIDC and `supervisorImage`).

### 4. Update the pins

Edit the `ARG BASE_IMAGE=` line in each Dockerfile to reference the new digest and update the date comment:

- [Dockerfile.gateway](Dockerfile.gateway)
- [Dockerfile.cluster](Dockerfile.cluster)

### 5. Rebuild and smoke-test

```shell
IMAGE_TAG=$(date +%Y%m%d) tasks/scripts/docker-build-local.sh all
```

Quick binary sanity check (catches the entrypoint/binary-rename failure mode):

```shell
docker run --rm --entrypoint openshell-gateway docker.io/aible/openshell-gateway:$(date +%Y%m%d) --help | head -5
```

Expected output starts with `OpenShell gRPC/HTTP server` and lists `--bind-address` as the first option.

### 6. Deploy and verify

Update the image tag in:

- [deployments/helm/edge/dgx-spark/bundle/charts/openshell/values.yaml](../../../../../deployments/helm/edge/dgx-spark/bundle/charts/openshell/values.yaml) — `image.tag`, `cluster.imageTag`, and the entry in `cluster.preloadImages`

Re-run `setup.sh` (or `helm upgrade` on the outer chart) and confirm:

```shell
sudo microk8s kubectl get pod -n aible openshell-0   # 2/2 Running
sudo microk8s kubectl exec -n aible openshell-0 -c openshell -- \
  env KUBECONFIG=/etc/rancher/k3s/k3s.yaml /usr/bin/kubectl -n openshell get pod,svc
# inner gateway 1/1 Running, service openshell NodePort 8080:30051
```

End-to-end check from the control plane host:

```shell
curl -s -H "Authorization: Bearer $TOKEN" 'http://127.0.0.1:9000/sandboxes?folder_id=1'
# expected: [] (or a JSON list)
```

## Known incompatibilities to watch for

These are the places where the upstream has historically shifted in ways that broke our overlay. Check each on every bump.

| Surface | Where to check | What changed in the past |
|---|---|---|
| Gateway ENTRYPOINT | `docker inspect <new-base> --format='{{.Config.Entrypoint}}'` | Was `["openshell-server"]` even though Dockerfile said `["openshell-gateway"]` — published image lagged the Dockerfile |
| Inner chart `service.type` default | [deploy/helm/openshell/values.yaml](../helm/openshell/values.yaml) | Changed from NodePort (with `nodePort: 30051`) to ClusterIP — broke the outer-to-inner port mapping. Our HelmChart manifest now sets `service.type: NodePort, nodePort: 30051` explicitly. |
| Gateway CLI default for `--bind-address` | `crates/openshell-server/src/cli.rs` | Was `127.0.0.1`. Our fork pins to `0.0.0.0`. If upstream changes the arg name, the inner chart's StatefulSet `args:` block needs to match. |
| Manifest template placeholders | [deploy/kube/manifests/openshell-helmchart.yaml](../kube/manifests/openshell-helmchart.yaml) vs the upstream copy | Upstream may add new `__PLACEHOLDER__` strings the entrypoint substitutes. If we use the field, mirror the upstream entry. If we don't, omit it — literal `__FOO__` strings get passed to Helm as values. |
| `cluster.preloadImages` list completeness | [deployments/helm/edge/dgx-spark/bundle/charts/openshell/values.yaml](../../../../../deployments/helm/edge/dgx-spark/bundle/charts/openshell/values.yaml) | Must include every image the inner k3s pulls: gateway, supervisor, agent-sandbox-controller, and every sandbox runtime image (e.g. openclaw, base sandbox). Missing images surface as `ImagePullBackOff` on sandbox pods because the inner k3s can't reach external registries. |
| Entrypoint `IMAGE_TAG` sed is global | [deploy/docker/cluster-entrypoint.sh](cluster-entrypoint.sh) around the `Overriding gateway image tag` block | The sed `s\|tag:[[:space:]]*"?latest"?\|tag: "${IMAGE_TAG}"\|` rewrites EVERY `tag: latest` in the HelmChart valuesContent — not just the gateway's. If the manifest template has `supervisor.image.tag: latest`, it will be rewritten to `${IMAGE_TAG}` too. Either ensure every aible-built image carries the same tag, or use non-`latest` literals (e.g. a digest reference) in the manifest. |
| `appVersion: 0.0.0` in inner Chart.yaml | [deploy/helm/openshell/Chart.yaml](../helm/openshell/Chart.yaml) | When `supervisor.image.tag` is empty, the inner chart's helper falls back to `appVersion` = `0.0.0` — a tag that doesn't exist on any registry. Always set `supervisor.image.tag` explicitly in the HelmChart valuesContent. |

## File provenance: extracted from image vs sourced from `upstream/main`

Some files in this directory came from the **published image** rather than the
upstream `main` branch. This matters because NVIDIA's CI builds `:latest` from
an internal branch that runs ahead of public `main`, so the published image
contains code that simply isn't in the public repo yet.

| File | Origin | Why |
|---|---|---|
| [cluster-entrypoint.sh](cluster-entrypoint.sh) | Extracted from `ghcr.io/nvidia/openshell/cluster:latest` | Newer than `upstream/main`. The `main` version doesn't substitute `__IMAGE_PULL_POLICY__`, `__SANDBOX_IMAGE_PULL_POLICY__`, `__DB_URL__`, `__SSH_GATEWAY_HOST__`, `__SSH_GATEWAY_PORT__`, `__HOST_GATEWAY_IP__`, `__DISABLE_GATEWAY_AUTH__`, or `__DISABLE_TLS__` placeholders that our HelmChart manifest relies on. Using `main` would leave those literal strings in Helm values and the install would fail. The file carries a header comment explaining this. |
| [cluster-healthcheck.sh](cluster-healthcheck.sh) | Identical to `upstream/main` | No provenance issue. Could be sourced from either; happens to be the same bytes. |

### Resync procedure when bumping the cluster image

When the cluster image digest is bumped (see "Bump procedure" above), recheck
these files against the new published image:

```shell
docker create --name _tmp ghcr.io/nvidia/openshell/cluster:latest
docker cp _tmp:/usr/local/bin/cluster-entrypoint.sh /tmp/new-entrypoint.sh
docker cp _tmp:/usr/local/bin/cluster-healthcheck.sh /tmp/new-healthcheck.sh
docker rm _tmp

diff deploy/docker/cluster-entrypoint.sh /tmp/new-entrypoint.sh
diff deploy/docker/cluster-healthcheck.sh /tmp/new-healthcheck.sh
```

Then either:

- **Diff is small and obvious** — apply the changes and update the header
  comment in cluster-entrypoint.sh to note the new origin.
- **Upstream `main` has caught up** — verify by diffing against
  `upstream/main:deploy/docker/cluster-entrypoint.sh`; if it now contains the
  placeholder-substitution logic we depend on, switch the file's origin back
  to `upstream/main` and remove the divergence note from the header comment.

## Rollback

If a bump breaks, revert the digest in the affected Dockerfile and rebuild. Because images carry date tags (e.g. `20260513`), redeploys are fully reversible by changing the tag in the outer chart's `values.yaml`.
