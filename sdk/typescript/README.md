# @nvidia/openshell-sdk

TypeScript client for the OpenShell gateway — thin, idiomatic bindings generated from the OpenShell protobufs.

Distributed via GitHub Packages. A public npm release under the same name follows once the npm org is in place; the install specifier and API are unchanged across that move.

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

### Scoped clients

`client.sandbox` is a `SandboxClient`. If you only need sandboxes, connect one
directly — same API, one less hop:

```ts
import { SandboxClient } from '@nvidia/openshell-sdk'

const sandbox = await SandboxClient.connect({ gateway, oidcToken })
await sandbox.create({ image })
```

## Streaming and interactive exec

`execStream` yields stdout/stderr chunks as they arrive, so long or chatty commands surface output incrementally instead of buffering until exit. The terminal value carries the exit code; the chunks carry the bytes. `exec` drains `execStream` internally, so its buffered `ExecResult` is unchanged.

```ts
for await (const chunk of client.sandbox.execStream(name, ['pytest', '-q'])) {
  process[chunk.stream].write(chunk.data) // 'stdout' | 'stderr'
}
```

`execInteractive` is the TTY + stdin transport primitive. Drive it by consuming `output`; `done` resolves with the exit code once the stream ends. It ships raw bytes only — raw mode, signal forwarding, and SIGWINCH stay with the caller.

```ts
const session = await client.sandbox.execInteractive(name, ['bash'])
session.write(Buffer.from('echo hi\n'))
session.resize(120, 40)
for await (const chunk of session.output) process.stdout.write(chunk.data)
const code = await session.done
```

## Port forwarding

`forward` binds a local TCP listener and tunnels each accepted connection into the sandbox for the lifetime of the Node process. Call `close()` on teardown.

```ts
const fwd = await client.sandbox.forward(name, { targetPort: 8000 })
// ... reach the sandbox service at 127.0.0.1:fwd.localPort ...
await fwd.close()
```

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
mise run sdk:ts:test        # Vitest unit tests
mise run sdk:ts:build       # emit dist/
```

Formatting and linting are handled by [Biome](https://biomejs.dev) (`biome.json`): 2-space indent, single quotes, semicolons, 120-column width. Generated `src/gen/` is excluded. `sdk:ts:lint` runs in CI as part of `sdk:ts:ci`.
