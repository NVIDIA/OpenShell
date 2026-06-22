// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Client command for the upstream MCP conformance runner, executed inside the
// runner container.
//
// Why this indirection exists: the conformance runner runs untrusted upstream
// node off the host, so it deliberately has no openshell binary and no gateway
// credentials. But the MCP client under test must run inside an OpenShell
// sandbox so its traffic crosses the policy-enforced proxy (the whole point of
// the e2e). This script bridges that gap without widening the runner's
// privileges: instead of running the MCP client itself, it posts the test
// server URL to the host bridge, which holds the gateway credentials and runs
// the real client in a sandbox, then returns its result. The runner can only
// ask "run a client against this URL" — it cannot touch the gateway control
// plane.

import http from 'node:http';
import os from 'node:os';
import process from 'node:process';

// Resolve the routable IPv4 address of the runner container on the e2e Docker
// network. The conformance runner reports its test server URL as localhost; the
// client sandbox connects from a different container, so localhost must be
// rewritten to this container's network address.
function runnerAddress() {
  for (const addrs of Object.values(os.networkInterfaces())) {
    for (const addr of addrs ?? []) {
      if (addr.family === 'IPv4' && !addr.internal) {
        return addr.address;
      }
    }
  }
  throw new Error('failed to resolve runner container IPv4 address');
}

function rewriteServerUrl(rawUrl) {
  const url = new URL(rawUrl);
  if (['localhost', '127.0.0.1', '[::1]', '::1'].includes(url.hostname)) {
    url.hostname = runnerAddress();
  }
  return url.toString();
}

const bridgeUrl = process.env.MCP_CONFORMANCE_HOST_BRIDGE_URL;
if (!bridgeUrl) {
  throw new Error('MCP_CONFORMANCE_HOST_BRIDGE_URL is required');
}
const parsedBridgeUrl = new URL(bridgeUrl);
if (parsedBridgeUrl.protocol !== 'http:') {
  throw new Error(`bridge URL must use http:, got ${parsedBridgeUrl.protocol}`);
}
const serverUrl = process.argv[2];
if (!serverUrl) {
  throw new Error('usage: node runner-shim.mjs <server-url>');
}

// POST the rewritten server URL to the host bridge, which runs the real MCP
// client inside an OpenShell sandbox and returns its result. The runner is a
// plain container with ordinary egress, so this is a direct HTTP call.
function postJson(url, payload) {
  const body = Buffer.from(JSON.stringify(payload), 'utf8');
  const timeoutMs = Number.parseInt(process.env.MCP_CONFORMANCE_HOST_BRIDGE_TIMEOUT_MS ?? '600000', 10);

  function snippet(raw) {
    return raw.length > 4096 ? `${raw.slice(0, 4096)}...` : raw;
  }

  return new Promise((resolve, reject) => {
    const request = http.request({
      hostname: url.hostname,
      port: url.port || 80,
      path: `${url.pathname}${url.search}`,
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': body.length,
      },
      agent: false,
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        const statusCode = response.statusCode ?? 0;
        try {
          const parsed = JSON.parse(raw);
          if (statusCode < 200 || statusCode >= 300) {
            reject(new Error(`bridge callback failed (HTTP ${statusCode}): ${snippet(raw)}`));
            return;
          }
          resolve(parsed);
        } catch (error) {
          reject(new Error(`bridge returned invalid JSON (HTTP ${statusCode}): ${snippet(raw) || error.message}`));
        }
      });
    });
    request.on('error', reject);
    request.setTimeout(timeoutMs, () => {
      request.destroy(new Error(`bridge callback timed out after ${timeoutMs}ms to ${url.toString()}`));
    });
    request.end(body);
  });
}

const forwardedEnv = {};
for (const name of [
  'MCP_CONFORMANCE_SCENARIO',
  'MCP_CONFORMANCE_CONTEXT',
  'MCP_CONFORMANCE_PROTOCOL_VERSION',
]) {
  if (process.env[name] !== undefined) {
    forwardedEnv[name] = process.env[name];
  }
}

const body = await postJson(parsedBridgeUrl, {
  server_url: rewriteServerUrl(serverUrl),
  env: forwardedEnv,
});
if (typeof body.exit_code !== 'number') {
  const raw = JSON.stringify(body);
  throw new Error(`bridge returned JSON without numeric exit_code: ${raw.length > 4096 ? `${raw.slice(0, 4096)}...` : raw}`);
}
if (body.stdout) {
  process.stdout.write(body.stdout);
}
if (body.stderr) {
  process.stderr.write(body.stderr);
}
process.exit(body.exit_code);
