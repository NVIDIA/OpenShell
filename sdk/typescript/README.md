# openshell-sdk

TypeScript client for the OpenShell gateway — thin, idiomatic bindings generated from the OpenShell protobufs.

Published on public npm.

## Install

```shell
npm install openshell-sdk
```

## Usage

```ts
import { OpenShellClient } from 'openshell-sdk'

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
import { SandboxClient } from 'openshell-sdk'

const sandbox = await SandboxClient.connect({ gateway, oidcToken })
await sandbox.create({ image })
```

## Development

The version field is a `0.0.0` placeholder; CI stamps the real version from the git release tag at publish time, matching the Rust and Python packages.

```shell
mise run sdk:ts:proto       # generate stubs from proto/ with buf
mise run sdk:ts:typecheck   # tsc --noEmit
mise run sdk:ts:build       # emit dist/
```
