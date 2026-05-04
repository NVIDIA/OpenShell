# Deploying and Connecting to a Gateway

Deploy or register an OpenShell gateway, verify it is reachable, and run your first sandbox. This example covers Helm-managed Kubernetes gateways, existing gateway endpoints, and Cloudflare-fronted deployments.

## Prerequisites

- OpenShell CLI installed (`openshell`)
- A reachable gateway endpoint, or access to a Kubernetes cluster where you can install the Helm chart

## Helm Deployment

Install the gateway into a Kubernetes cluster you manage:

```bash
kubectl create namespace openshell
helm upgrade --install openshell deploy/helm/openshell \
  --namespace openshell \
  --set server.disableTls=true \
  --set service.type=ClusterIP \
  --set server.grpcEndpoint=http://openshell.openshell.svc.cluster.local:8080
```

For local evaluation, forward the service and register the forwarded endpoint:

```bash
kubectl -n openshell port-forward svc/openshell 8080:8080
openshell gateway add http://127.0.0.1:8080 --local --name local
```

Production deployments should keep TLS enabled or place the gateway behind a trusted TLS-terminating ingress, load balancer, or access proxy.

## Existing Gateway Endpoint

Register a gateway that is already running:

```bash
openshell gateway add https://gateway.example.com --name production
```

Verify the gateway:

```bash
openshell status
```

Expected output:

```text
Gateway: https://gateway.example.com
Status:  HEALTHY
Version: <version>
```

## Create a Sandbox

```bash
openshell sandbox create --name hello -- echo "it works"
openshell sandbox connect hello
```

Clean up the sandbox when finished:

```bash
openshell sandbox delete hello
```

## Edge-Authenticated Gateway

For gateways running behind a reverse proxy that handles authentication, such as Cloudflare Access, register the endpoint and authenticate via browser:

```bash
openshell gateway add https://gateway.example.com
```

This opens your browser for the proxy's login flow. After authentication, the CLI stores a bearer token and sets the gateway as active.

To re-authenticate after token expiry:

```bash
openshell gateway login
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
openshell gateway select
```

Switch the active gateway:

```bash
openshell gateway select production
```

Override the active gateway for a single command:

```bash
openshell status -g production
```

## Troubleshooting

Check gateway registration details:

```bash
openshell gateway info
openshell status
```

For Helm deployments, inspect the release and gateway workload:

```bash
helm -n openshell status openshell
kubectl -n openshell get statefulset,pod,svc,pvc
kubectl -n openshell logs statefulset/openshell --tail=100
```
