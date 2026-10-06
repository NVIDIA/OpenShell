# Deploying and Connecting to a Gateway

Deploy or register an Ryno gateway, verify it is reachable, and run your first sandbox. This example covers Helm-managed Kubernetes gateways, existing gateway endpoints, and Cloudflare-fronted deployments.

## Prerequisites

- Ryno CLI installed (`ryno`)
- A reachable gateway endpoint, or access to a Kubernetes cluster where you can install the Helm chart
- For Kubernetes installs, a CNI that enforces ingress and egress `NetworkPolicy` in sandbox namespaces

## Helm Deployment

Install the gateway into a Kubernetes cluster you manage:

```bash
kubectl create namespace ryno
helm upgrade --install ryno deploy/helm/ryno \
  --namespace ryno \
  --set server.disableTls=true \
  --set service.type=ClusterIP
```

For local evaluation, forward the service and register the forwarded endpoint:

```bash
kubectl -n ryno port-forward svc/ryno 8080:8080
ryno gateway add http://127.0.0.1:8080 --local --name local
```

Production deployments should keep TLS enabled or place the gateway behind a trusted TLS-terminating ingress, load balancer, or access proxy.

## Existing Gateway Endpoint

Register a gateway that is already running:

```bash
ryno gateway add https://gateway.example.com --name production
```

Verify the gateway:

```bash
ryno status
```

Expected output:

```text
Gateway: https://gateway.example.com
Status:  HEALTHY
Version: <version>
```

## Create a Sandbox

```bash
ryno sandbox create --name hello -- echo "it works"
ryno sandbox connect hello
```

Clean up the sandbox when finished:

```bash
ryno sandbox delete hello
```

## Edge-Authenticated Gateway

For gateways running behind a reverse proxy that handles authentication, such as Cloudflare Access, register the endpoint and authenticate via browser:

```bash
ryno gateway add https://gateway.example.com
```

This opens your browser for the proxy's login flow. After authentication, the CLI stores a bearer token and sets the gateway as active.

To re-authenticate after token expiry:

```bash
ryno gateway login
```

### How Edge-Authenticated Connections Differ

Reverse proxies that authenticate via browser-style GET requests are incompatible with gRPC's HTTP/2 POST transport. To work around this, the CLI uses a WebSocket tunnel:

1. The CLI starts a local proxy that listens on an ephemeral port.
2. gRPC traffic is sent as plaintext HTTP/2 to this local proxy.
3. The proxy opens a WebSocket (`wss://`) to the gateway's tunnel endpoint, attaching the bearer token in the upgrade headers.
4. The edge proxy authenticates the WebSocket upgrade request.
5. The gateway receives the WebSocket connection and pipes it into the same gRPC service that handles direct mTLS connections.

This is transparent to the user. CLI commands work the same regardless of whether the gateway uses mTLS or edge authentication.

## Managing Multiple Gateways

List all registered gateways:

```bash
ryno gateway select
```

Switch the active gateway:

```bash
ryno gateway select production
```

Override the active gateway for a single command:

```bash
ryno status -g production
```

## Troubleshooting

Check gateway registration details:

```bash
ryno gateway info
ryno status
```

For Helm deployments, inspect the release and gateway workload:

```bash
helm -n ryno status ryno
kubectl -n ryno get statefulset,pod,svc,pvc
kubectl -n ryno logs statefulset/ryno --tail=100
```
