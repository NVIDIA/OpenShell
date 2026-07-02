# @nvidia/openshell-sdk

TypeScript client for the OpenShell gateway — thin, idiomatic bindings generated from the OpenShell protobufs.

Distributed via GitHub Packages during pre-GA. Public npm (`@openshell/sdk`) follows at GA; the public API is unchanged across the move, so only the install specifier changes.

## Install

Published to GitHub Packages, so add a project `.npmrc`:

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

const sandbox = await client.createSandbox({
  image: 'ghcr.io/nvidia/openshell-community/sandboxes/python:latest',
})
await client.waitReady(sandbox.name, 120)

const result = await client.exec(sandbox.name, ['/bin/sh', '-c', 'echo hello'])
console.log(result.stdout.toString())

await client.deleteSandbox(sandbox.name)
```

## Development

The version field is a `0.0.0` placeholder; CI stamps the real version from the git release tag at publish time, matching the Rust and Python packages.

```shell
mise run sdk:ts:proto       # generate stubs from proto/ (protoc + protoc-gen-es)
mise run sdk:ts:typecheck   # tsc --noEmit
mise run sdk:ts:build       # emit dist/
```
