# Private IP Routing via `allowed_ips`

Demonstrates the `allowed_ips` sandbox policy feature, which lets sandboxes
reach services on private IP space (e.g. cluster-internal pods) that would
normally be blocked by the proxy's SSRF protection.

## How it works

The sandbox proxy blocks all connections to RFC 1918 addresses by default.
When an endpoint in the sandbox policy includes an `allowed_ips` field, the
proxy validates the resolved IP against that CIDR allowlist instead of
blanket-blocking. Loopback and link-local remain always-blocked regardless.

The dev sandbox policy (`deploy/docker/sandbox/dev-sandbox-policy.yaml`) includes a `cluster_pods`
entry that allows any binary to reach port 8080 on the k3s pod network:

```yaml
cluster_pods:
  name: cluster_pods
  endpoints:
    - port: 8080
      allowed_ips:
        - "10.42.0.0/16"
  binaries:
    - { path: "/**" }
```

## Launch the demo server

Build the image and push it to the local cluster registry:

```bash
docker build -t 127.0.0.1:5000/demo/private-api:latest examples/private-ip-routing/
docker push 127.0.0.1:5000/demo/private-api:latest
```

Deploy the pod:

```bash
docker exec navigator-cluster-navigator \
  kubectl run private-api \
    --image=127.0.0.1:5000/demo/private-api:latest \
    --port=8080 \
    --restart=Never
```

Wait for it to be running and note the pod IP:

```bash
docker exec navigator-cluster-navigator kubectl get pod private-api -o wide
```

Example output:

```
NAME          READY   STATUS    IP            NODE
private-api   1/1     Running   10.42.0.128   ...
```

## Verify from a sandbox

Create a sandbox and curl the private API through the proxy. Replace the IP
with whatever `kubectl get pod` showed above:

```bash
nav sandbox create -- bash -c \
  'curl -s --proxytunnel -x http://10.200.0.1:3128 http://10.42.0.128:8080/'
```

Expected output:

```json
{
  "message": "Hello from the private network!",
  "hostname": "private-api",
  "path": "/",
  "client": "10.42.0.130",
  "timestamp": 1772501542.15
}
```

The proxy allowed the connection because `10.42.0.128` matches the
`10.42.0.0/16` CIDR in `allowed_ips`. Without that policy field, the same
request returns `HTTP/1.1 403 Forbidden`.

## Cleanup

```bash
docker exec navigator-cluster-navigator kubectl delete pod private-api
```
