# Testing User Namespaces on OCP

Step-by-step guide to deploy OpenShell with user namespace isolation on an OpenShift cluster and verify end-to-end functionality.

## Prerequisites

- An OCP cluster (tested on OCP 4.22 / K8s 1.35.3 / CRI-O 1.35 / RHEL CoreOS / kernel 5.14)
- `KUBECONFIG` pointing at the cluster (e.g., `export KUBECONFIG=/path/to/kubeconfig`)
- `kubectl` binary (the examples below use the full path; adjust as needed)
- `helm` binary
- `podman` for building and pushing images
- The OpenShell repo checked out with the user namespace branch built

Throughout this guide:

```shell
K=/home/mrunalp/repos/kubernetes/_output/local/bin/linux/amd64/kubectl
HELM=/home/mrunalp/.local/share/mise/installs/helm/4.1.4/linux-amd64/helm
export KUBECONFIG=/path/to/your/kubeconfig
```

## 1. Build binaries

```shell
cargo build -p openshell-server --features openshell-core/dev-settings
cargo build -p openshell-sandbox --features openshell-core/dev-settings
cargo build -p openshell-cli --features openshell-core/dev-settings
```

## 2. Create namespace and install the Sandbox CRD

```shell
$K create ns openshell
$K apply -f deploy/kube/manifests/agent-sandbox.yaml
```

Label the namespace to allow privileged pods:

```shell
$K label ns openshell pod-security.kubernetes.io/enforce=privileged --overwrite
$K label ns openshell pod-security.kubernetes.io/warn=privileged --overwrite
```

## 3. Grant SCCs

The gateway pod needs `anyuid` (runs as UID 1000) and sandbox pods need `privileged` (capabilities for supervisor):

```shell
$K create clusterrolebinding openshell-sa-anyuid \
  --clusterrole=system:openshift:scc:anyuid \
  --serviceaccount=openshell:openshell

$K create clusterrolebinding openshell-sa-privileged \
  --clusterrole=system:openshift:scc:privileged \
  --serviceaccount=openshell:openshell

$K create clusterrolebinding openshell-default-privileged \
  --clusterrole=system:openshift:scc:privileged \
  --serviceaccount=openshell:default
```

Grant the sandbox CRD controller full permissions (it needs to set ownerReferences with blockOwnerDeletion):

```shell
$K create clusterrolebinding agent-sandbox-admin \
  --clusterrole=cluster-admin \
  --serviceaccount=agent-sandbox-system:agent-sandbox-controller
```

## 4. Generate TLS certificates

```shell
TLSDIR=$(mktemp -d)

# CA
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout $TLSDIR/ca.key -out $TLSDIR/ca.crt \
  -days 365 -subj "/CN=openshell-ca" 2>/dev/null

# Server cert
openssl req -newkey rsa:2048 -nodes \
  -keyout $TLSDIR/server.key -out $TLSDIR/server.csr \
  -subj "/CN=openshell.openshell.svc.cluster.local" \
  -addext "subjectAltName=DNS:openshell.openshell.svc.cluster.local,DNS:openshell,DNS:localhost,IP:127.0.0.1" 2>/dev/null

openssl x509 -req -in $TLSDIR/server.csr \
  -CA $TLSDIR/ca.crt -CAkey $TLSDIR/ca.key -CAcreateserial \
  -out $TLSDIR/server.crt -days 365 \
  -extfile <(echo "subjectAltName=DNS:openshell.openshell.svc.cluster.local,DNS:openshell,DNS:localhost,IP:127.0.0.1") 2>/dev/null

# Client cert
openssl req -newkey rsa:2048 -nodes \
  -keyout $TLSDIR/client.key -out $TLSDIR/client.csr \
  -subj "/CN=openshell-client" 2>/dev/null

openssl x509 -req -in $TLSDIR/client.csr \
  -CA $TLSDIR/ca.crt -CAkey $TLSDIR/ca.key -CAcreateserial \
  -out $TLSDIR/client.crt -days 365 2>/dev/null
```

Create Kubernetes secrets:

```shell
$K create secret tls openshell-server-tls -n openshell \
  --cert=$TLSDIR/server.crt --key=$TLSDIR/server.key

$K create secret generic openshell-server-client-ca -n openshell \
  --from-file=ca.crt=$TLSDIR/ca.crt

$K create secret generic openshell-client-tls -n openshell \
  --from-file=ca.crt=$TLSDIR/ca.crt \
  --from-file=tls.crt=$TLSDIR/client.crt \
  --from-file=tls.key=$TLSDIR/client.key

$K create secret generic openshell-ssh-handshake -n openshell \
  --from-literal=secret=$(openssl rand -hex 32)
```

Note: the `openshell-client-tls` secret must include `ca.crt`, `tls.crt`, and `tls.key` (not a `kubernetes.io/tls` type secret, which only has `tls.crt` and `tls.key`).

## 5. Expose the OCP internal registry and push images

```shell
# Enable the default route for the internal registry
$K patch configs.imageregistry.operator.openshift.io/cluster \
  --type merge -p '{"spec":{"defaultRoute":true}}'

sleep 5
REGISTRY=$($K get route default-route -n openshift-image-registry -o jsonpath='{.spec.host}')
TOKEN=$($K create token builder -n openshell)

podman login --tls-verify=false -u kubeadmin -p "$TOKEN" "$REGISTRY"
```

Build and push the gateway image:

```shell
podman build -f deploy/docker/Dockerfile.images --target gateway \
  -t localhost/openshell/gateway:dev .

podman tag localhost/openshell/gateway:dev $REGISTRY/openshell/gateway:dev
podman push --tls-verify=false $REGISTRY/openshell/gateway:dev
```

Pull and push the sandbox base image:

```shell
podman pull ghcr.io/nvidia/openshell-community/sandboxes/base:latest

podman tag ghcr.io/nvidia/openshell-community/sandboxes/base:latest \
  $REGISTRY/openshell/sandbox-base:latest
podman push --tls-verify=false $REGISTRY/openshell/sandbox-base:latest
```

## 6. Install the supervisor binary on cluster nodes

The sandbox supervisor binary is mounted into pods via a hostPath volume at `/opt/openshell/bin/`. A DaemonSet distributes it to every node with the correct SELinux label.

Build and push a minimal image containing the supervisor binary:

```shell
cp target/debug/openshell-sandbox /tmp/openshell-sandbox

cat > /tmp/Dockerfile.supervisor <<'EOF'
FROM registry.access.redhat.com/ubi9/ubi-minimal:latest
COPY openshell-sandbox /openshell-sandbox
RUN chmod 755 /openshell-sandbox
EOF

podman build -f /tmp/Dockerfile.supervisor -t localhost/openshell/supervisor:dev /tmp/
podman tag localhost/openshell/supervisor:dev $REGISTRY/openshell/supervisor:dev
podman push --tls-verify=false $REGISTRY/openshell/supervisor:dev
```

Deploy the installer DaemonSet:

```shell
INTERNAL_REG="image-registry.openshift-image-registry.svc:5000"

cat <<EOF | $K apply -f -
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: openshell-supervisor-installer
  namespace: openshell
spec:
  selector:
    matchLabels:
      app: openshell-supervisor-installer
  template:
    metadata:
      labels:
        app: openshell-supervisor-installer
    spec:
      serviceAccountName: default
      initContainers:
      - name: install
        image: $INTERNAL_REG/openshell/supervisor:dev
        command:
        - sh
        - -c
        - |
          mkdir -p /host/opt/openshell/bin &&
          cp /openshell-sandbox /host/opt/openshell/bin/openshell-sandbox &&
          chmod 755 /host/opt/openshell/bin/openshell-sandbox &&
          chcon -t container_file_t /host/opt/openshell/bin &&
          chcon -t container_file_t /host/opt/openshell/bin/openshell-sandbox &&
          echo installed
        securityContext:
          privileged: true
        volumeMounts:
        - name: host-root
          mountPath: /host
      containers:
      - name: pause
        image: registry.k8s.io/pause:3.10
      volumes:
      - name: host-root
        hostPath:
          path: /
      tolerations:
      - operator: Exists
EOF
```

Wait for all pods to be Running:

```shell
$K get pods -n openshell -l app=openshell-supervisor-installer -o wide
```

The `chcon -t container_file_t` step is required on RHEL/CoreOS nodes where SELinux enforces file labels. Without it, the container runtime cannot access the supervisor binary through the hostPath mount.

## 7. Deploy the gateway with Helm

```shell
INTERNAL_REG="image-registry.openshift-image-registry.svc:5000"

$HELM install openshell deploy/helm/openshell -n openshell \
  --set image.repository=$INTERNAL_REG/openshell/gateway \
  --set image.tag=dev \
  --set image.pullPolicy=Always \
  --set server.sandboxImage="$INTERNAL_REG/openshell/sandbox-base:latest" \
  --set server.sandboxImagePullPolicy=Always \
  --set server.enableUserNamespaces=true \
  --set server.grpcEndpoint="https://openshell.openshell.svc.cluster.local:8080" \
  --set server.dbUrl="sqlite:/tmp/openshell.db" \
  --set service.type=ClusterIP
```

Wait for the gateway to be ready:

```shell
$K rollout status statefulset/openshell -n openshell --timeout=120s
```

Note: `server.dbUrl` is set to `/tmp/openshell.db` to avoid PVC permission issues on clusters without a properly configured storage class. For production, use a PVC-backed path.

## 8. Configure the CLI

Port-forward the gateway service to localhost:

```shell
nohup $K port-forward svc/openshell -n openshell 18443:8080 >/tmp/pf.log 2>&1 &
```

Set up the CLI gateway configuration with mTLS:

```shell
mkdir -p ~/.config/openshell/gateways/ocp-userns/mtls

cp $TLSDIR/ca.crt ~/.config/openshell/gateways/ocp-userns/mtls/
cp $TLSDIR/client.crt ~/.config/openshell/gateways/ocp-userns/mtls/tls.crt
cp $TLSDIR/client.key ~/.config/openshell/gateways/ocp-userns/mtls/tls.key

cat > ~/.config/openshell/gateways/ocp-userns/metadata.json <<'EOF'
{
  "name": "ocp-userns",
  "gateway_endpoint": "https://127.0.0.1:18443",
  "is_remote": false,
  "gateway_port": 18443,
  "auth_mode": "mtls"
}
EOF
```

Verify connectivity:

```shell
OPENSHELL_GATEWAY=ocp-userns target/debug/openshell status
```

Expected output:

```
Server Status
  Gateway: ocp-userns
  Server:  https://127.0.0.1:18443
  Status:  Connected
```

## 9. Create a sandbox and verify user namespaces

```shell
export OPENSHELL_GATEWAY=ocp-userns

target/debug/openshell sandbox create --no-bootstrap -- sh -lc \
  "echo '=== uid_map ==='; cat /proc/self/uid_map; \
   echo '=== gid_map ==='; cat /proc/self/gid_map; \
   echo '=== id ==='; id; \
   echo '=== userns-e2e-ok ==='"
```

Expected output (UID values will vary):

```
=== uid_map ===
         0 3285581824      65536
=== gid_map ===
         0 3285581824      65536
=== id ===
uid=998(sandbox) gid=998(sandbox) groups=998(sandbox)
=== userns-e2e-ok ===
```

This confirms:
- UID 0 inside the container maps to a high host UID (non-identity mapping)
- The sandbox user (UID 998) is active
- The SSH tunnel through the gateway works end-to-end
- Workspace init, supervisor startup, network namespace creation, and proxy all function correctly under user namespace isolation

## 10. Cleanup

```shell
# Delete all sandboxes
$K delete sandbox --all -n openshell

# Uninstall the Helm release
$HELM uninstall openshell -n openshell

# Remove the supervisor installer
$K delete daemonset openshell-supervisor-installer -n openshell

# Remove RBAC
$K delete clusterrolebinding openshell-sa-anyuid openshell-sa-privileged \
  openshell-default-privileged agent-sandbox-admin 2>/dev/null

# Remove the Sandbox CRD and its controller
$K delete -f deploy/kube/manifests/agent-sandbox.yaml

# Remove the namespace
$K delete ns openshell

# Kill port-forward
pkill -f "port-forward.*18443"

# Remove CLI gateway config
rm -rf ~/.config/openshell/gateways/ocp-userns
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `ErrImageNeverPull` on gateway pod | Image not in the internal registry | Push with `podman push --tls-verify=false` to the OCP registry |
| `unable to validate against any security context constraint` | Missing SCC grants | Run the `clusterrolebinding` commands from step 3 |
| `cannot set blockOwnerDeletion` on sandbox creation | Sandbox CRD controller lacks RBAC | Grant `cluster-admin` to the controller SA (step 3) |
| `hostPath type check failed: /opt/openshell/bin is not a directory` | Supervisor binary not installed on node | Deploy the DaemonSet from step 6 |
| `Permission denied` accessing supervisor binary | SELinux blocking hostPath access | Ensure `chcon -t container_file_t` was applied (step 6) |
| `failed to set MOUNT_ATTR_IDMAP` | Filesystem doesn't support ID-mapped mounts | Only happens in nested container environments (DinD); native nodes work |
| Gateway pod `CrashLoopBackOff` with `unable to open database file` | PVC permissions | Use `--set server.dbUrl="sqlite:/tmp/openshell.db"` |
| `dns error: failed to lookup address` from supervisor | In-cluster DNS not resolving | Use the ClusterIP directly in `server.grpcEndpoint` instead of the DNS name |
