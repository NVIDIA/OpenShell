// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Run through mise run e2e:sdk:ts:exec, which supplies an isolated gateway.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { SandboxClient } from '../dist/index.js';

test('public interactive helper drains output after input EOF and verifies completion', {
  timeout: 300_000,
}, async () => {
  assert.ok(process.env.XDG_CONFIG_HOME, 'run with the Docker gateway wrapper');
  assert.ok(process.env.OPENSHELL_GATEWAY, 'run with the Docker gateway wrapper');
  const dir = join(process.env.XDG_CONFIG_HOME, 'openshell', 'gateways', process.env.OPENSHELL_GATEWAY);
  const metadata = JSON.parse(readFileSync(join(dir, 'metadata.json'), 'utf8'));
  const client = await SandboxClient.connect({
    gateway: metadata.gateway_endpoint,
    ...(metadata.gateway_endpoint.startsWith('https:')
      ? {
          caCert: readFileSync(join(dir, 'mtls', 'ca.crt')),
          clientCert: readFileSync(join(dir, 'mtls', 'tls.crt')),
          clientKey: readFileSync(join(dir, 'mtls', 'tls.key')),
        }
      : {}),
  });
  const name = `ts-eof-${Date.now().toString(36)}`;
  await client.create({
    name,
    image: process.env.OPENSHELL_E2E_DOCKER_SANDBOX_IMAGE ?? 'ghcr.io/nvidia/openshell-community/sandboxes/base:latest',
  });
  try {
    await client.waitReady(name, 180);
    const session = await client.execInteractive(
      name,
      ['/bin/sh', '-c', 'input=$(cat); printf "stdout:%s" "$input"; printf "stderr:drained" >&2; exit 7'],
      { tty: false, timeoutSecs: 30, signal: AbortSignal.timeout(45_000) },
    );
    try {
      // cat cannot finish until closeInput reaches the sandbox. All command
      // output therefore proves that request EOF left the response open.
      session.write(Buffer.from('input-before-eof'));
      session.closeInput();
      session.closeInput(); // The public control remains idempotent.
      const stdout = [];
      const stderr = [];
      const exits = [];
      for await (const event of session.output) {
        assert.equal(exits.length, 0, 'exit must be the final application event');
        if ('type' in event) exits.push(event.exitCode);
        else (event.stream === 'stdout' ? stdout : stderr).push(event.data);
      }
      assert.equal(Buffer.concat(stdout).toString(), 'stdout:input-before-eof');
      assert.equal(Buffer.concat(stderr).toString(), 'stderr:drained');
      assert.deepEqual(exits, [7]);
      // A nonzero process exit is not a failed transport. done resolves only
      // after the helper has verified the final gRPC status.
      assert.equal(await session.done, 7);
      assert.equal(session.exitCode, 7);
    } finally {
      session.cancel();
    }
  } finally {
    await client.delete(name);
  }
});
