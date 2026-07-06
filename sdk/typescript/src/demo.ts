// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Runnable smoke test exercising the v0.1 surface against any OpenShell gateway:
//
//   OPENSHELL_GATEWAY=http://127.0.0.1:8080 \
//   OPENSHELL_DEFAULT_IMAGE=ghcr.io/nvidia/openshell-community/sandboxes/python:latest \
//   npm run demo
//
// Auth: set OPENSHELL_OIDC_TOKEN / OPENSHELL_EDGE_TOKEN / OPENSHELL_CA_CERT /
// OPENSHELL_INSECURE as needed. With none set it assumes a plaintext local gateway.

import { readFileSync } from 'node:fs'
import { OpenShellClient, errorCode, type ExecResult, type SandboxSpec } from './index.js'

const env = process.env
const gateway = env.OPENSHELL_GATEWAY ?? 'http://127.0.0.1:8080'
const caCert = env.OPENSHELL_CA_CERT ? readFileSync(env.OPENSHELL_CA_CERT) : undefined

async function main() {
  const client = await OpenShellClient.connect({
    gateway,
    caCert,
    oidcToken: env.OPENSHELL_OIDC_TOKEN,
    edgeToken: env.OPENSHELL_EDGE_TOKEN,
    insecureSkipVerify: env.OPENSHELL_INSECURE === '1',
  })

  const health = await client.health()
  console.log(`health: ${health.status} (v${health.version})`)

  const spec: SandboxSpec = {
    image: env.OPENSHELL_DEFAULT_IMAGE,
    labels: { 'openshell.dev/demo': 'sdk-ts' },
  }
  const ref = await client.sandbox.create(spec)
  console.log(`created: ${ref.name} [${ref.phase}]`)

  await client.sandbox.waitReady(ref.name, 120)
  console.log(`ready: ${ref.name}`)

  const result: ExecResult = await client.sandbox.exec(ref.name, ['/bin/sh', '-c', 'echo hello from $(hostname)'], {
    timeoutSecs: 30,
  })
  console.log(`exec exit=${result.exitCode} stdout=${result.stdout.toString().trim()}`)

  const all = await client.sandbox.list({ labelSelector: 'openshell.dev/demo=sdk-ts' })
  console.log(`listed ${all.length} demo sandbox(es)`)

  console.log(`deleted: ${await client.sandbox.delete(ref.name)}`)
}

main().catch((e) => {
  console.error(`demo failed [code=${errorCode(e) ?? 'unknown'}]:`, e instanceof Error ? e.message : e)
  process.exit(1)
})
