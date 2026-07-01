// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Manual smoke test: drive the napi OidcRefresher against a live Keycloak.
//
// The Rust SDK's refresh_token function isn't exposed through napi — the
// JS-side callback is responsible for hitting the OIDC token endpoint. This
// script exercises that callback bridge under real network conditions and
// validates single-flight coalescing against the live server.
//
// Driven by scripts/openshell-sdk-oidc-smoke.sh.
//
// Env:
//   OPENSHELL_OIDC_ISSUER, OPENSHELL_OIDC_CLIENT_ID, OPENSHELL_OIDC_REFRESH_TOKEN

import { OidcRefresher, errorCode } from '../lib.mjs'

function mustEnv(name) {
  const value = process.env[name]
  if (!value) {
    console.error(`${name} is required`)
    process.exit(2)
  }
  return value
}

const issuer = mustEnv('OPENSHELL_OIDC_ISSUER')
const clientId = mustEnv('OPENSHELL_OIDC_CLIENT_ID')
let currentRefreshToken = mustEnv('OPENSHELL_OIDC_REFRESH_TOKEN')

console.log(`    issuer    = ${issuer}`)
console.log(`    client_id = ${clientId}`)

const failures = []
function ok(cond, msg) {
  console.log(cond ? '  ok' : 'FAIL', msg)
  if (!cond) failures.push(msg)
}

async function discoverTokenEndpoint() {
  const url = `${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`
  const res = await fetch(url)
  if (!res.ok) throw new Error(`discovery ${res.status}`)
  const doc = await res.json()
  return doc.token_endpoint
}

async function callTokenEndpoint(tokenEndpoint) {
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    client_id: clientId,
    refresh_token: currentRefreshToken,
  })
  const res = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
  })
  if (!res.ok) throw new Error(`token endpoint ${res.status}: ${await res.text()}`)
  const payload = await res.json()
  if (payload.refresh_token) currentRefreshToken = payload.refresh_token
  return {
    accessToken: payload.access_token,
    expiresAt: payload.expires_in
      ? Math.floor(Date.now() / 1000) + payload.expires_in
      : undefined,
  }
}

console.log('==> discovering token endpoint')
const tokenEndpoint = await discoverTokenEndpoint()
console.log(`    token_endpoint = ${tokenEndpoint}`)

console.log('==> 5 concurrent refresh() calls on an expired token (single-flight)')
let callbackInvocations = 0
const refresher = new OidcRefresher('', 1, async () => {
  callbackInvocations += 1
  return callTokenEndpoint(tokenEndpoint)
})
const tokens = await Promise.all(Array.from({ length: 5 }, () => refresher.refresh()))
ok(tokens.every((t) => typeof t === 'string' && t.length > 50), `all 5 promises returned access tokens`)
ok(tokens[0].split('.').length === 3, 'access token looks like a JWT')
ok(
  callbackInvocations === 1,
  `5 concurrent calls collapsed to ${callbackInvocations} token endpoint hit (expected 1)`,
)

console.log('==> follow-up refresh() short-circuits on a non-expired cached token')
const beforeFollowup = callbackInvocations
await refresher.refresh()
ok(
  callbackInvocations === beforeFollowup,
  `cached non-expired token did not trigger another callback (${callbackInvocations - beforeFollowup} new hits)`,
)

console.log('==> callback rejection surfaces as auth error')
const broken = new OidcRefresher('', 1, async () => {
  throw new Error('simulated failure')
})
try {
  await broken.refresh()
  ok(false, 'expected refresh() to reject')
} catch (e) {
  ok(errorCode(e) === 'auth', `error code = ${errorCode(e)}`)
}

if (failures.length) {
  console.error(`\n${failures.length} assertion(s) failed`)
  process.exit(1)
}
console.log('==> ok')
// napi-rs holds the libuv event loop open; exit explicitly. Same workaround
// the unit smoke (test/smoke.mjs) uses.
process.exit(0)
