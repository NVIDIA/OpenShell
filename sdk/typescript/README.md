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

## Development

The version field is a `0.0.0` placeholder; CI stamps the real version from the git release tag at publish time, matching the Rust and Python packages.

```shell
mise run sdk:ts:proto       # generate stubs from proto/ with buf
mise run sdk:ts:typecheck   # tsc --noEmit
mise run sdk:ts:build       # emit dist/
```
