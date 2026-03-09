# Deploying and Connecting to a Gateway

Deploy a NemoClaw gateway, verify it is reachable, and run your first
sandbox. This example covers local, remote, and Cloudflare-fronted
deployments.

## Prerequisites

- Docker daemon running
- NemoClaw CLI installed (`nemoclaw`)

## Local deployment

### 1. Deploy the gateway

```bash
nemoclaw gateway start
```

This provisions a single-node k3s cluster inside a Docker container,
deploys the gateway workload, generates mTLS certificates, and stores
connection artifacts locally. The gateway becomes reachable at
`https://127.0.0.1:8080` by default.

### 2. Verify the gateway is running

```bash
nemoclaw status
```

Expected output:

```
Gateway: https://127.0.0.1:8080
Status:  HEALTHY
Version: <version>
```

### 3. Create a sandbox

```bash
nemoclaw sandbox create --name hello -- echo "it works"
```

### 4. Clean up

```bash
nemoclaw sandbox delete hello
nemoclaw gateway destroy
```

## Remote deployment

Deploy the gateway on a remote machine accessible via SSH. The only
dependency on the remote host is Docker.

### 1. Deploy

```bash
nemoclaw gateway start --remote user@hostname
```

The CLI creates an SSH-based Docker client, pulls the cluster image on
the remote host, and provisions the cluster there. The gateway is
reachable at `https://<hostname>:8080`.

### 2. Verify and use

```bash
nemoclaw status
nemoclaw sandbox create --name remote-test -- echo "running on remote host"
nemoclaw sandbox connect remote-test
```

### 3. Access the Kubernetes API (optional)

The Kubernetes API on a remote cluster is only reachable through an
SSH tunnel:

```bash
# Start a tunnel in the background
nemoclaw gateway tunnel

# In another terminal
kubectl get pods -n navigator
```

### 4. Clean up

```bash
nemoclaw sandbox delete remote-test
nemoclaw gateway destroy
```

## Custom port

If port 8080 is in use, specify a different host port:

```bash
nemoclaw gateway start --port 9090
```

The CLI stores the port in cluster metadata, so subsequent commands
resolve it automatically.

## Cloudflare-fronted gateway

For gateways already running behind Cloudflare Access, no deployment
is needed -- register the endpoint and authenticate via browser:

```bash
nemoclaw gateway add https://gateway.example.com
```

This opens your browser for Cloudflare Access login. After
authentication, the CLI stores a JWT token and sets the gateway as
active.

To re-authenticate after token expiry:

```bash
nemoclaw gateway login
```

## Managing multiple gateways

List all registered gateways:

```bash
nemoclaw gateway select
```

Switch the active gateway:

```bash
nemoclaw gateway select my-other-cluster
```

Override the active gateway for a single command:

```bash
nemoclaw status -g my-other-cluster
```

## How it works

The `gateway start` command runs a full bootstrap sequence:

1. Pulls the NemoClaw cluster image (k3s + gateway + sandbox images).
2. Creates a Docker network, volume, and privileged container.
3. Waits for k3s to start and the gateway workload to become healthy.
4. Generates (or reuses) a TLS PKI: cluster CA, server cert, client cert.
5. Stores mTLS credentials at `~/.config/nemoclaw/clusters/<name>/mtls/`.
6. Writes cluster metadata to `~/.config/nemoclaw/clusters/<name>_metadata.json`.
7. Sets the cluster as the active gateway.

All subsequent CLI commands resolve the active gateway, load TLS
credentials from disk, and open a gRPC channel over mTLS. For
Cloudflare-fronted gateways, the CLI routes traffic through a local
WebSocket tunnel proxy instead of direct mTLS.

## Troubleshooting

Check gateway deployment details:

```bash
nemoclaw gateway info
```

If the gateway is unreachable, inspect the container:

```bash
docker logs navigator-cluster-nemoclaw
```

Re-running `gateway start` is idempotent -- it reuses existing
infrastructure or reconciles only what changed.
