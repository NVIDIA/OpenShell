# Deploying and Connecting to a Gateway

Deploy a OpenShell gateway, verify it is reachable, and run your first
sandbox. This example covers local, remote, and Cloudflare-fronted
deployments.

## Prerequisites

- Docker daemon running
- OpenShell CLI installed (`openshell`)

## Local deployment

### 1. Deploy the gateway

```bash
openshell gateway start
```

This provisions a single-node k3s cluster inside a Docker container,
deploys the gateway workload, generates mTLS certificates, and stores
connection artifacts locally. The gateway becomes reachable at
`https://127.0.0.1:8080` by default.

### 2. Verify the gateway is running

```bash
openshell status
```

Expected output:

```
Gateway: https://127.0.0.1:8080
Status:  HEALTHY
Version: <version>
```

### 3. Create a sandbox

```bash
openshell sandbox create --name hello -- echo "it works"
```

### 4. Clean up

```bash
openshell sandbox delete hello
openshell gateway destroy
```

## Remote deployment

Deploy the gateway on a remote machine accessible via SSH. The only
dependency on the remote host is Docker.

### 1. Deploy

```bash
openshell gateway start --remote user@hostname
```

The CLI creates an SSH-based Docker client, pulls the cluster image on
the remote host, and provisions the cluster there. The gateway is
reachable at `https://<hostname>:8080`.

### 2. Verify and use

```bash
openshell status
openshell sandbox create --name remote-test -- echo "running on remote host"
openshell sandbox connect remote-test
```

### 3. View gateway logs (optional)

To inspect the gateway container logs:

```bash
openshell doctor logs
```

### 4. Clean up

```bash
openshell sandbox delete remote-test
openshell gateway destroy
```

## Custom port

If port 8080 is in use, specify a different host port:

```bash
openshell gateway start --port 9090
```

The CLI stores the port in cluster metadata, so subsequent commands
resolve it automatically.

## Edge-authenticated gateway

For gateways running behind a reverse proxy that handles
authentication (e.g. Cloudflare Access), no deployment is needed --
register the endpoint and authenticate via browser:

```bash
openshell gateway add https://gateway.example.com
```

This opens your browser for the proxy's login flow. After
authentication, the CLI stores a bearer token and sets the gateway as
active.

To re-authenticate after token expiry:

```bash
openshell gateway login
```

### How edge-authenticated connections differ

Reverse proxies that authenticate via browser-style GET requests are
incompatible with gRPC's HTTP/2 POST transport. To work around this,
the CLI uses a **WebSocket tunnel**:

1. The CLI starts a local proxy that listens on an ephemeral port.
2. gRPC traffic is sent as plaintext HTTP/2 to this local proxy.
3. The proxy opens a WebSocket (`wss://`) to the gateway's tunnel
   endpoint, attaching the bearer token in the upgrade headers.
4. The edge proxy authenticates the WebSocket upgrade request.
5. The gateway receives the WebSocket connection and pipes it into the
   same gRPC service that handles direct mTLS connections.

This is transparent to the user -- all CLI commands work the same
regardless of whether the gateway uses mTLS or edge authentication.

## Managing multiple gateways

List all registered gateways:

```bash
openshell gateway select
```

Switch the active gateway:

```bash
openshell gateway select my-other-cluster
```

Override the active gateway for a single command:

```bash
openshell status -g my-other-cluster
```

## How it works

The `gateway start` command:

1. Pulls the OpenShell cluster image and provisions a container.
2. Waits for the gateway to become healthy.
3. Generates mTLS certificates for secure communication.
4. Stores connection credentials and metadata locally.
5. Sets the cluster as the active gateway.

All subsequent CLI commands automatically resolve the active gateway
and authenticate using stored credentials.

For local and remote gateways, the CLI connects directly over mTLS.
For edge-authenticated gateways, the CLI routes gRPC traffic through
a local WebSocket tunnel proxy (see
[How edge-authenticated connections differ](#how-edge-authenticated-connections-differ)
above).

## Troubleshooting

Check gateway deployment details:

```bash
openshell gateway info
```

If the gateway is unreachable, inspect the container:

```bash
docker logs openshell-cluster-openshell
```

Re-running `gateway start` is idempotent -- it reuses existing
infrastructure or reconciles only what changed.
