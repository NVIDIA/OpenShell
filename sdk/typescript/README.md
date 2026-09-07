# @nvidia/openshell-sdk

TypeScript client for the OpenShell gateway — thin, idiomatic bindings generated from the OpenShell protobufs.

Distributed via GitHub Packages. A public npm release under the same name follows once the npm org is in place; the install specifier and API are unchanged across that move.

Use the SDK and gateway from the same OpenShell release when possible. The raw
types and RPC descriptors are generated from the protobuf definitions in that
release; curated methods remain compatible while those RPC contracts remain
compatible.

## Install

Published to GitHub Packages, so point the `@nvidia` scope at it with a project `.npmrc`:

```shell
@nvidia:registry=https://npm.pkg.github.com
```

Authenticate with a GitHub token that has `read:packages`, then:

```shell
npm install @nvidia/openshell-sdk
```

## Usage

```ts
import { OpenShellClient } from '@nvidia/openshell-sdk'

const client = await OpenShellClient.connect({
  gateway: 'https://gateway.example.com',
  oidcToken: process.env.OPENSHELL_TOKEN,
})

const sandbox = await client.sandbox.create({
  image: 'ghcr.io/nvidia/openshell-community/sandboxes/python:latest',
})
await client.sandbox.waitReady(sandbox.name, 120)

const result = await client.sandbox.exec(sandbox.name, ['/bin/sh', '-c', 'echo hello'])
console.log(result.stdout.toString())

await client.sandbox.delete(sandbox.name)
```

`connect()` constructs a lazy client; call `health()` when startup must verify
gateway reachability. Static `oidcToken` and `edgeToken` values remain fixed for
the client's lifetime. For long-running service automation, use the renewable
client-credentials provider:

```ts
import { clientCredentials, OpenShellClient } from '@nvidia/openshell-sdk'

const client = await OpenShellClient.connect({
  gateway,
  oidcTokenProvider: clientCredentials({
    issuer: 'https://idp.example.com/realms/openshell',
    clientId: 'openshell-service',
    clientSecret: () => process.env.OPENSHELL_OIDC_CLIENT_SECRET!,
    scopes: ['sandbox:read', 'sandbox:write'],
    audience: 'openshell-gateway',
  }),
})
```

The provider discovers and validates the issuer, keeps credentials and tokens
in memory, and renews before expiry. The root client has no explicit close
method because Connect does not retain a dedicated session. Close
operation-scoped streams and forward handles instead.

Express the create-time safety boundary with `policy`. Sandbox-scoped `setPolicy`
cannot introduce static policy fields later, so set filesystem, landlock,
process, and initial network policy at creation. For proto spec fields the
curated shape does not surface, `rawSpec` is an escape hatch that shallow-
overrides the assembled spec at the top level (any field it sets wins):

```ts
await client.sandbox.create({
  image,
  policy: { version: 1, networkPolicies: {} },
  rawSpec: { logLevel: 'debug', template: { runtimeClassName: 'gvisor' } },
})
```

### Scoped clients

`client.sandbox` is a `SandboxClient`. If you only need sandboxes, connect one
directly — same API, one less hop:

```ts
import { SandboxClient } from '@nvidia/openshell-sdk'

const sandbox = await SandboxClient.connect({ gateway, oidcToken })
await sandbox.create({ image })
```

## Streaming and interactive exec

`execStream` yields stdout/stderr chunks as they arrive, so long or chatty commands surface output incrementally instead of buffering until exit. The stream ends with a terminal `{ type: 'exit', exitCode }` event, yielded in-band so a failing command cannot look successful under `for await`. Discriminate it with `'type' in event`. If the gateway closes the stream without an exit event, `execStream` throws. `exec` drains `execStream` internally, so its buffered `ExecResult` is unchanged.

```ts
for await (const event of client.sandbox.execStream(name, ['pytest', '-q'])) {
  if ('type' in event) console.log(`exit ${event.exitCode}`)
  else process[event.stream].write(event.data) // 'stdout' | 'stderr'
}
```

`execInteractive` is the TTY + stdin transport primitive. Drive it by consuming `output`, which yields the same chunk/exit events; `done` resolves with the exit code once the stream reaches its exit event and rejects if it ends without one. It ships raw bytes only; raw mode, signal forwarding, and SIGWINCH stay with the caller.

```ts
const session = await client.sandbox.execInteractive(name, ['bash'])
session.write(Buffer.from('echo hi\n'))
session.resize(120, 40)
for await (const event of session.output) {
  if (!('type' in event)) process.stdout.write(event.data)
}
const code = await session.done
```

## Port forwarding

`forward` binds a local TCP listener and tunnels each accepted connection into the sandbox for the lifetime of the Node process. Call `close()` on teardown.

```ts
const fwd = await client.sandbox.forward(name, {
  targetPort: 8000,
  onConnectionError: (error) => console.error(error),
})
// ... reach the sandbox service at 127.0.0.1:fwd.localPort ...
await fwd.close()
```

`close()` is idempotent. It cancels active forwarding RPCs, destroys accepted
sockets, and waits for their cleanup.

## SSH sessions, providers, config and policy

```ts
const ssh = await client.sandbox.createSshSession(name)
await client.sandbox.revokeSshSession(ssh.token)

await client.sandbox.attachProvider(name, 'claude')
await client.sandbox.listProviders(name)
await client.sandbox.detachProvider(name, 'claude')

const config = await client.sandbox.getConfig(name)
config.policy!.networkPolicies['web'] = { name: 'web', endpoints: [], binaries: [] }
await client.sandbox.setPolicy(name, config.policy!, { wait: true })
await client.sandbox.setSetting(name, 'feature.enabled', { value: { case: 'boolValue', value: true } })
```

Sandbox-scoped `setPolicy` may only change `networkPolicies`; static fields (`filesystem`, `landlock`, `process`) must match the create-time policy. Sandbox-scoped setting deletes are rejected by the gateway, so only upsert (`setSetting`) is exposed here.

## Sandbox templates

Sandbox workload templates are reusable, workspace-scoped runtime shapes. They
own image, environment, resource, and driver-specific settings; sandbox creation
from a template can still attach labels, providers, and create-time policy.

```ts
import { OpenShellClient, type SandboxWorkloadTemplate } from '@nvidia/openshell-sdk'

const client = await OpenShellClient.connect({ gateway, oidcToken })

const template: SandboxWorkloadTemplate = await client.sandboxTemplates.create(
  {
    metadata: { name: 'python', labels: { team: 'runtime' } },
    spec: {
      workload: {
        image: 'ghcr.io/nvidia/openshell-community/sandboxes/python:latest',
        environment: { FEATURE_FLAG: 'on' },
        resources: { cpu: '1', memory: '512Mi' },
      },
      driverConfig: { kubernetes: { pod: { runtime_class_name: 'kata-containers' } } },
    },
  },
  { workspace: 'default' },
)

const sandbox = await client.sandbox.createFromTemplate({
  templateName: template.metadata!.name,
  workspace: 'default',
  providers: ['github'],
  policy: { version: 1, networkPolicies: {} },
})

await client.sandboxTemplates.get('python', { workspace: 'default' })
await client.sandboxTemplates.list({ workspace: 'default', limit: 100 })
await client.sandboxTemplates.delete('python', { workspace: 'default' })
```

Use `allWorkspaces: true` on `list()` for a platform-admin view. The SDK clears
the workspace field in that request because the gateway treats `workspace` and
`allWorkspaces` as mutually exclusive.

## Surface and roadmap

The SDK's goal is agent parity: anything the OpenShell gateway can do should be reachable from typed code, not only the CLI. The API is organized as scoped sub-clients over one shared connection, mirroring the CLI's verbs.

- `client.sandbox` (`SandboxClient`) is available today: sandbox lifecycle, exec, forward, SSH, sandbox-scoped providers, config, and policy.
- `client.sandboxTemplates` (`SandboxTemplateClient`) is available today: reusable sandbox workload template CRUD.
- `client.gateway` (`GatewayClient`) is planned: gateway-scoped config and settings, health, and cluster status.
- `client.providers` (`ProviderClient`) is planned: gateway-scoped provider CRUD and profiles.

`health()` lives at the root today and will move under `client.gateway` (with a root alias) when that lands.

Curated methods are added deliberately, so some gateway RPCs are not yet wrapped in a typed helper. Rather than ship methods that exist but throw, the SDK omits what it has not curated and gives you the raw escape hatch below to reach the full gateway surface today. Omission means "not yet ergonomic," never "impossible."

### Advanced: raw escape hatch

`client.raw` is a generated client for every gateway RPC, including surface the curated sub-clients do not wrap yet (gateway config, provider CRUD, policy status, watch, logs, and the full observed `Sandbox`). `client.transport` is the shared connection, so extra clients reuse one socket. Generated request and response types live at `@nvidia/openshell-sdk/raw`.

```ts
import { OpenShellClient } from '@nvidia/openshell-sdk'
import type { GetGatewayConfigResponse } from '@nvidia/openshell-sdk/raw'

const client = await OpenShellClient.connect({ gateway, oidcToken })

// Reach RPCs the curated surface does not wrap yet:
const cfg: GetGatewayConfigResponse = await client.raw.getGatewayConfig({})
const status = await client.raw.getSandboxPolicyStatus({ name: 'my-sandbox', version: 0, global: false })
```

The raw layer returns the generated wire messages verbatim, preserving proto distinctions (an omitted optional versus an explicitly empty map) that the curated types may smooth over. As curated sub-clients land, prefer them; `raw` stays as the always-available floor.

## Boundaries

The SDK ships primitives, not the CLI's terminal experience. Some things are intentionally out of scope:

- **Interactive `connect()` / PTY ownership.** `execInteractive`, `createSshSession`, and `forward` are the transport primitives; raw mode, OpenSSH `ProxyCommand`, and terminal glue stay in the CLI.
- **`upload()` / `download()`.** There is no file-transfer RPC — the CLI does tar-over-SSH. For small payloads, `exec`/`execStream` with `stdin` covers it. A first-class gateway file-transfer RPC is a follow-up.
- **Detached / background forwards.** An in-process forward cannot outlive its caller; `forward` is process-lifetime only.

## Development

The version field is a `0.0.0` placeholder; CI stamps the real version from the git release tag at publish time, matching the Rust and Python packages.

```shell
mise run sdk:ts:proto       # generate stubs from proto/ with buf
mise run sdk:ts:format      # Biome: format + safe fixes (writes)
mise run sdk:ts:lint        # Biome: lint + format check (read-only)
mise run sdk:ts:typecheck   # tsc --noEmit
mise run sdk:ts:test        # Vitest unit tests with an 80% line-coverage gate
mise run sdk:ts:build       # emit dist/
```

Formatting and linting are handled by [Biome](https://biomejs.dev) (`biome.json`): 2-space indent, single quotes, semicolons, 120-column width. Generated `src/gen/` is excluded. `sdk:ts:lint` runs in CI as part of `sdk:ts:ci`.
