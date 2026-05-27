# OpenShell Node.js SDK

Node.js client for the OpenShell gateway gRPC API. Mirrors the interface of the [Python SDK](../python/) and is consumed as a local workspace dependency by TypeScript services that need to manage sandbox lifecycle without shelling out to the `openshell` CLI.

## Installation

Reference the package from your service's `package.json` using a local path:

```json
{
  "dependencies": {
    "openshell": "file:../OpenShell/node"
  }
}
```

Then run `npm install`. The package ships pre-built `dist/` output, so no build step is needed in the consuming project.

## Quick start

```typescript
import { SandboxClient, ForwardManager, InferenceRouteClient } from "openshell";

// Connect to the gateway (insecure — Istio handles mTLS in cluster)
const client = new SandboxClient("openshell.aible.svc.cluster.local:8080");

// Create a sandbox
const sandbox = await client.create({ /* SandboxSpec fields */ });

// Wait for it to be ready
await client.waitReady(sandbox.name, { timeoutSeconds: 120 });

// Run a command and collect output
const result = await client.exec(sandbox.id, ["echo", "hello"]);
console.log(result.stdout); // "hello\n"

// Forward a port through SSH into the sandbox (e.g. the OpenClaw gateway on 8080)
const fwd = new ForwardManager(client);
const localPort = await fwd.startForward(sandbox.name, 8080);
// localPort is now a TCP port on 127.0.0.1 tunnelled to sandbox:8080

// Tear down
await fwd.stopAll();
await client.delete(sandbox.name);
client.close();
```

## Connection

### Insecure (default in cluster with Istio)

```typescript
const client = new SandboxClient("openshell.aible.svc.cluster.local:8080");
```

### mTLS

```typescript
const client = new SandboxClient("gateway.example.com:443", {
  tls: {
    caPath: "/etc/openshell/tls/ca.crt",
    certPath: "/etc/openshell/tls/tls.crt",
    keyPath: "/etc/openshell/tls/tls.key",
  },
});
```

### From environment variables

```typescript
const client = SandboxClient.fromEnv();
```

| Variable | Default | Description |
|---|---|---|
| `OPENSHELL_GATEWAY_ENDPOINT` | `127.0.0.1:8080` | Gateway address. Scheme prefix (`http://`, `https://`) is stripped. |
| `OPENSHELL_GATEWAY_INSECURE` | `true` | Set to `false` to enable TLS. |
| `OPENSHELL_TLS_CA_PATH` | — | Path to CA certificate (required when insecure=false). |
| `OPENSHELL_TLS_CERT_PATH` | — | Path to client certificate. |
| `OPENSHELL_TLS_KEY_PATH` | — | Path to client private key. |

## API reference

### `SandboxClient`

```typescript
new SandboxClient(grpcTarget: string, options?: SandboxClientOptions)
SandboxClient.fromEnv(): SandboxClient
```

#### Sandbox lifecycle

```typescript
// Create a sandbox; name defaults to server-generated when omitted
.create(spec: SandboxSpec, name?: string, labels?: Record<string, string>): Promise<SandboxRef>

// Fetch the full Sandbox object (includes spec, status, policy version)
.get(name: string): Promise<Sandbox>

// List all sandboxes, optionally filtered by label selector ("key=val,...")
.list(options?: { limit?: number; offset?: number; labelSelector?: string }): Promise<SandboxRef[]>

// Delete by name; returns true if the sandbox existed
.delete(name: string): Promise<boolean>

// Poll until phase === READY, throws on ERROR or timeout
.waitReady(name: string, options?: { timeoutSeconds?: number; pollIntervalMs?: number }): Promise<void>

// Poll until the get() returns not-found
.waitDeleted(name: string, options?: { timeoutSeconds?: number; pollIntervalMs?: number }): Promise<void>
```

#### Execution

```typescript
// Run a command and collect all output; returns when the process exits
.exec(sandboxId: string, command: string[], options?: ExecOptions): Promise<ExecResult>

// Stream stdout/stderr chunks as they arrive
.execStream(sandboxId: string, command: string[], options?: ExecOptions): AsyncIterable<ExecChunk>
```

`ExecOptions`: `{ workdir?, env?, stdin?, timeoutSeconds? }`

`ExecResult`: `{ exitCode: number; stdout: string; stderr: string }`

`ExecChunk`: `{ stream: "stdout" | "stderr"; data: Buffer }`

#### Providers

```typescript
.createProvider(name, type, credentials, config): Promise<ProviderRef>
.getProvider(name): Promise<ProviderRef>
.listProviders(options?): Promise<ProviderRef[]>
.updateProvider(name, type, credentials, config): Promise<ProviderRef>
.deleteProvider(name): Promise<boolean>
.detachSandboxProvider(sandboxName, providerName): Promise<boolean>
```

#### Draft policy

```typescript
.getDraftPolicy(sandboxName, options?: { statusFilter? }): Promise<GetDraftPolicyResponse>
.approveDraftChunk(sandboxName, chunkId): Promise<void>
.rejectDraftChunk(sandboxName, chunkId, reason?): Promise<void>
.approveAllDraftChunks(sandboxName, options?: { includeSecurityFlagged? }): Promise<void>
```

#### SSH session (used internally by ForwardManager)

```typescript
.createSshSession(sandboxId: string): Promise<CreateSshSessionResponse>
```

---

### `ForwardManager`

Opens a port-forward tunnel into a sandbox by chaining `CreateSshSession` → `ForwardTcp` gRPC stream → SSH via `ssh2` → local TCP server. One tunnel per sandbox name; calling `startForward` again for the same sandbox returns the existing port.

```typescript
new ForwardManager(client: SandboxClient)

.startForward(sandboxName: string, remotePort?: number): Promise<number>
// returns the local port bound on 127.0.0.1 (remotePort defaults to 8080)

.stopForward(sandboxName: string): Promise<boolean>
.stopAll(): Promise<void>
.getForwardPort(sandboxName: string): number | undefined
```

---

### `InferenceRouteClient`

```typescript
new InferenceRouteClient(grpcTarget: string, sandboxClient: SandboxClient, options?: { routeName? })

.setCluster(providerName, modelId, options?: { noVerify?, timeoutSecs? }): Promise<SetClusterInferenceResponse>
.getCluster(): Promise<ClusterInferenceConfig | undefined>
.close(): void
```

The `routeName` option defaults to `""` which resolves to the `inference.local` user-facing route. Pass `"sandbox-system"` for the sandbox system-level route.

---

### `SandboxError`

All gRPC failures are wrapped in `SandboxError` (extends `Error`). The original `ServiceError` is available on `.cause`.

```typescript
try {
  await client.get("my-sandbox");
} catch (err) {
  if (err instanceof SandboxError) {
    console.error(err.message, err.cause?.code);
  }
}
```

## Development

### Regenerate gRPC stubs

The `src/_proto/` directory contains generated TypeScript stubs from `../proto/*.proto`. Regenerate after any proto change:

```sh
cd OpenShell/node
npm install        # ensure ts-proto plugin is present
bash scripts/generate.sh
```

`protoc` is managed via [mise](https://mise.jdx.dev/) at the version pinned in `../mise.toml`. Run the script inside `mise exec` if `protoc` is not on your `PATH`:

```sh
mise exec -- bash node/scripts/generate.sh
```

### Build

```sh
npm run build      # tsc → dist/
npm run typecheck  # type-check without emitting
```
