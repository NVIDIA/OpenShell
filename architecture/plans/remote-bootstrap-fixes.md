# Remote Bootstrap Fixes

This document outlines issues discovered during testing of remote cluster bootstrapping via SSH, and proposed fixes.

## Issues

### 1. Image Transfer Loses Healthcheck Metadata

**Severity**: Blocking (deploy fails without manual workaround)

**Problem**: The bootstrap code uses `docker export/import` for transferring images to remote hosts, which strips image metadata including the HEALTHCHECK. This causes the deploy to fail with:
```
Error: cluster container does not expose a health check
```

**Location**: `crates/navigator-bootstrap/src/lib.rs`

**Root Cause**: `docker export` creates a filesystem tarball without image metadata. `docker import` creates a new image from that tarball but loses labels, healthchecks, entrypoints, etc.

**Solution**: Use `docker save/load` instead of `export/import` to preserve all image metadata:
```rust
// Current (broken):
docker export <container> | ssh host docker import - image:tag

// Fixed:
docker save image:tag | ssh host docker load
```

**Testing**: After fix, verify:
```bash
# Remote image should have healthcheck
ssh remote-host 'docker inspect -f "{{json .Config.Healthcheck}}" navigator-cluster:dev'
# Should return healthcheck config, not "null"
```

---

### 2. DNS Doesn't Work on Linux Docker Hosts

**Severity**: Blocking for TLS (PKI job fails)

**Status**: Fixed in `deploy/docker/cluster-entrypoint.sh`

**Problem**: The cluster entrypoint assumed `host.docker.internal` (host-gateway) provides DNS forwarding, but on Linux Docker:
- `host-gateway` maps to the docker0 bridge IP (e.g., 172.17.0.1)
- This IP doesn't provide DNS forwarding (unlike Docker Desktop's VM)
- Pods inside the cluster can't resolve external names
- The PKI job fails because it can't download alpine packages

**Root Cause**: Docker Desktop (Mac/Windows) runs a VM that provides DNS forwarding via the host gateway. Native Linux Docker doesn't have this - the bridge IP is just a network gateway, not a DNS resolver.

**Solution Applied**: Detect Docker Desktop vs Linux Docker by checking the host gateway IP pattern:
- `192.168.x.x` = Docker Desktop VM network → use host gateway for DNS
- `172.x.x.x` = Linux bridge network → use public DNS (8.8.8.8)

**Code Change**:
```sh
# In deploy/docker/cluster-entrypoint.sh
is_docker_desktop() {
    case "$HOST_GATEWAY_IP" in
        192.168.*) return 0 ;;  # Docker Desktop VM network
        *) return 1 ;;           # Linux bridge or other
    esac
}

if [ -n "$HOST_GATEWAY_IP" ] && is_docker_desktop; then
    echo "nameserver $HOST_GATEWAY_IP" > "$RESOLV_CONF"
else
    echo "nameserver 8.8.8.8" > "$RESOLV_CONF"
    echo "nameserver 8.8.4.4" >> "$RESOLV_CONF"
fi
```

---

### 3. TLS Cert SANs Don't Include Remote Host IP/Hostname

**Severity**: Medium (usability - requires SSH tunnel workaround)

**Status**: Fixed — remote host IP/hostname is now added to both gateway and k3s API server certificate SANs during deploy.

**Problem**: The gateway TLS certificate was only valid for:
- `localhost`
- `navigator`
- `navigator.navigator.svc`
- `navigator.navigator.svc.cluster.local`
- `host.docker.internal`
- `127.0.0.1`

When connecting directly to a remote host's public IP, TLS validation failed:
```
Error: invalid peer certificate: certificate not valid for name "160.211.47.2"
```

**Solution Applied** (Option A): The remote host's resolved IP/hostname is now automatically included in both certificate chains during `nav cluster admin deploy --remote`:

1. **k3s API server cert**: Extra `--tls-san=<ip>` flags are appended to the k3s CMD in `ensure_container()` (`docker.rs`).
2. **Gateway mTLS cert**: The `EXTRA_SANS` env var is set on the container, picked up by `cluster-entrypoint.sh` to patch the HelmChart manifest, and the Helm PKI job reads `extraSANs` from values to append additional entries to the server certificate's SAN list.

**Files changed**:
- `crates/navigator-bootstrap/src/docker.rs` — `ensure_container` accepts `extra_sans` param; passes as `--tls-san` flags and `EXTRA_SANS` env var
- `crates/navigator-bootstrap/src/lib.rs` — resolves remote host IP and passes to `ensure_container`
- `deploy/docker/cluster-entrypoint.sh` — reads `EXTRA_SANS` env and injects into HelmChart manifest
- `deploy/kube/manifests/navigator-helmchart.yaml` — added `extraSANs: []` placeholder
- `deploy/helm/navigator/values.yaml` — added `gateway.tls.extraSANs` default
- `deploy/helm/navigator/templates/gateway-pki-job.yaml` — reads `EXTRA_SANS` env and appends to `server-ext.cnf`

**Note**: Existing clusters require a redeploy to regenerate certificates with the new SANs.

---

### 4. CLI Cert Lookup Uses URL Hostname, Not Cluster Name

**Severity**: Low (usability - requires manual env var)

**Problem**: When connecting with `--cluster https://160.211.47.2:443`, the CLI looks for mTLS certificates at:
```
~/.config/navigator/clusters/160.211.47.2/mtls/
```

But certificates are stored under the cluster name:
```
~/.config/navigator/clusters/navigator-dev/mtls/
```

**Current Workaround**: Set environment variable:
```bash
NAVIGATOR_CLUSTER_NAME=navigator-dev nav --cluster https://160.211.47.2:443 cluster status
```

**Proposed Solutions**:

Option A: Auto-detect cluster name from metadata
- When given a URL, scan `~/.config/navigator/clusters/*/metadata.json`
- Find cluster where `gateway_endpoint` or `remote_host` matches
- Use that cluster's cert directory

Option B: Add explicit `--cluster-name` flag
```bash
nav --cluster https://160.211.47.2:443 --cluster-name navigator-dev cluster status
```

Option C: Store certs by gateway endpoint hash
- Use consistent naming that doesn't depend on cluster name vs URL

**Recommendation**: Option A provides best UX, Option B is simpler to implement.

---

## Implementation Priority

1. **Image transfer** - Blocking issue, deploy fails without manual `docker save/load`
2. **DNS on Linux** - Already fixed
3. **CLI cert lookup** - Quality of life improvement
4. **Cert SANs** - Can be worked around with SSH tunnel

## Testing Checklist

After implementing fixes, verify:

- [ ] `nav cluster admin deploy --remote ssh-host` succeeds without manual image transfer
- [ ] Pods in remote cluster can resolve external DNS names
- [ ] `nav cluster status` works without manually setting `NAVIGATOR_CLUSTER_NAME`
- [ ] TLS connection works (via tunnel or direct if SANs are fixed)
- [ ] mTLS certificates are properly saved to `~/.config/navigator/clusters/<name>/mtls/`
- [ ] Cluster metadata is saved to `~/.config/navigator/clusters/<name>_metadata.json`
