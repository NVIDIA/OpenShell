// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Smoke test for @openshell/sdk.
//
// Verifies the binding's surface: exports, error mapping, and the
// `OidcRefresher` single-flight contract. End-to-end RPC verification
// requires a running mock gateway and lives in the Rust crate's mock tests
// (see `crates/openshell-sdk/tests/client_mock.rs`).
//
// Implemented as a plain async script rather than `node --test` because
// the napi-rs `tokio_rt` feature holds the libuv event loop open and the
// test runner never exits cleanly. We explicitly `process.exit(0)` here.

import { strict as assert } from 'node:assert'
import { errorCode, OidcRefresher, OpenShellClient } from '../lib.mjs'

const cases = []
function test(name, fn) {
  cases.push({ name, fn })
}

test('module exports the documented classes', () => {
  assert.equal(typeof OpenShellClient, 'function')
  assert.equal(typeof OpenShellClient.connect, 'function')
  assert.equal(typeof OidcRefresher, 'function')
  assert.equal(typeof errorCode, 'function')
})

test('connect rejects against a closed port with a typed error', async () => {
  let caught
  try {
    await OpenShellClient.connect({ gateway: 'http://127.0.0.1:1' })
  } catch (err) {
    caught = err
  }
  assert.ok(caught, 'expected connect to fail against 127.0.0.1:1')
  assert.equal(errorCode(caught), 'connect', `unexpected error: ${caught?.message}`)
})

test('connect rejects with invalid_config for a malformed gateway URL', async () => {
  let caught
  try {
    await OpenShellClient.connect({ gateway: 'not-a-url' })
  } catch (err) {
    caught = err
  }
  assert.ok(caught, 'expected connect to fail on malformed URL')
  assert.equal(errorCode(caught), 'invalid_config', `unexpected error: ${caught?.message}`)
})

test('OidcRefresher coalesces concurrent refresh calls', async () => {
  let calls = 0
  // expiresAt = 1 (Unix epoch 1970) is in the past, so the SDK's reactive
  // path treats the token as expired. See refresh.rs `needs_refresh`.
  const refresher = new OidcRefresher('initial', 1, async () => {
    calls += 1
    await new Promise((resolve) => setTimeout(resolve, 25))
    return {
      accessToken: `token-${calls}`,
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
    }
  })

  const results = await Promise.all([
    refresher.refresh(),
    refresher.refresh(),
    refresher.refresh(),
    refresher.refresh(),
  ])

  assert.equal(calls, 1, 'callback should have been invoked once for coalesced calls')
  assert.equal(new Set(results).size, 1, 'all waiters should observe the same token')
  assert.equal(results[0], 'token-1')
  assert.equal(refresher.currentToken(), 'token-1')
})

test('OidcRefresher surfaces callback rejections as auth errors', async () => {
  const refresher = new OidcRefresher('stale', 1, async () => {
    throw new Error('IdP unreachable')
  })

  let caught
  try {
    await refresher.refresh()
  } catch (err) {
    caught = err
  }
  assert.ok(caught, 'expected refresh to reject when callback throws')
  assert.equal(errorCode(caught), 'auth', `unexpected error: ${caught?.message}`)
})

let failed = 0
for (const { name, fn } of cases) {
  try {
    await fn()
    console.log(`ok  ${name}`)
  } catch (err) {
    failed += 1
    console.error(`fail ${name}`)
    console.error(err)
  }
}
console.log(`\n${cases.length - failed}/${cases.length} passed`)
process.exit(failed === 0 ? 0 : 1)
