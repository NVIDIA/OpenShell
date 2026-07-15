// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Runnable smoke test exercising the SDK surface against any OpenShell gateway:
//
//   OPENSHELL_GATEWAY=http://127.0.0.1:8080 \
//   OPENSHELL_DEFAULT_IMAGE=ghcr.io/nvidia/openshell-community/sandboxes/python:latest \
//   npm run demo
//
// Auth: set OPENSHELL_OIDC_TOKEN / OPENSHELL_EDGE_TOKEN / OPENSHELL_CA_CERT /
// OPENSHELL_INSECURE as needed. With none set it assumes a plaintext local gateway.
// Set OPENSHELL_DEMO_PROVIDER=<name> to exercise the provider attach/detach path
// against an existing gateway provider.

import { readFileSync } from 'node:fs';
import * as http from 'node:http';
import { type ExecResult, errorCode, OpenShellClient, type SandboxSpec } from './index.js';

const env = process.env;
const gateway = env.OPENSHELL_GATEWAY ?? 'http://127.0.0.1:8080';
const caCert = env.OPENSHELL_CA_CERT ? readFileSync(env.OPENSHELL_CA_CERT) : undefined;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function httpGet(url: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = http.get(url, (res) => {
      res.resume();
      resolve(res.statusCode ?? 0);
    });
    req.on('error', reject);
  });
}

async function main() {
  const client = await OpenShellClient.connect({
    gateway,
    caCert,
    oidcToken: env.OPENSHELL_OIDC_TOKEN,
    edgeToken: env.OPENSHELL_EDGE_TOKEN,
    insecureSkipVerify: env.OPENSHELL_INSECURE === '1',
  });

  const health = await client.health();
  console.log(`health: ${health.status} (v${health.version})`);

  const spec: SandboxSpec = {
    image: env.OPENSHELL_DEFAULT_IMAGE,
    labels: { 'openshell.dev/demo': 'sdk-ts' },
  };
  const ref = await client.sandbox.create(spec);
  console.log(`created: ${ref.name} [${ref.phase}]`);

  await client.sandbox.waitReady(ref.name, 120);
  console.log(`ready: ${ref.name}`);

  const result: ExecResult = await client.sandbox.exec(ref.name, ['/bin/sh', '-c', 'echo hello from $(hostname)'], {
    timeoutSecs: 30,
  });
  console.log(`exec exit=${result.exitCode} stdout=${result.stdout.toString().trim()}`);

  // execStream: incremental chunks as they arrive.
  process.stdout.write('execStream: ');
  for await (const chunk of client.sandbox.execStream(ref.name, [
    '/bin/sh',
    '-c',
    'for i in 1 2 3; do echo line $i; done',
  ])) {
    process.stdout.write(chunk.data);
  }

  // execInteractive: scripted (non-TTY) bidi round-trip through `cat`.
  const session = await client.sandbox.execInteractive(ref.name, ['cat'], {
    tty: false,
  });
  let echoed = '';
  const collect = (async () => {
    for await (const chunk of session.output) echoed += chunk.data.toString();
  })();
  session.write(Buffer.from('interactive hello\n'));
  await sleep(300);
  session.close();
  await collect;
  console.log(`execInteractive: echo=${echoed.trim()} exit=${await session.done}`);

  // SSH session mint + revoke.
  const ssh = await client.sandbox.createSshSession(ref.name);
  console.log(
    `ssh session: token=${ssh.token.slice(0, 8)}… gateway=${ssh.gatewayScheme}://${ssh.gatewayHost}:${ssh.gatewayPort}`,
  );
  console.log(`ssh revoked: ${await client.sandbox.revokeSshSession(ssh.token)}`);

  // Config + policy round-trip (network-policy-safe: re-apply the current policy).
  const config = await client.sandbox.getConfig(ref.name);
  console.log(
    `config: policyHash=${config.policyHash} version=${config.version} settings=${Object.keys(config.settings).length}`,
  );
  if (config.policy) {
    const update = await client.sandbox.setPolicy(ref.name, config.policy, {
      wait: true,
    });
    const after = await client.sandbox.getConfig(ref.name);
    console.log(`setPolicy: version=${update.version} hashMatches=${after.policyHash === update.policyHash}`);
  }

  // Providers (optional: requires an existing gateway provider).
  const providerName = env.OPENSHELL_DEMO_PROVIDER;
  if (providerName) {
    const attach = await client.sandbox.attachProvider(ref.name, providerName);
    console.log(`attach ${providerName}: changed=${attach.changed}`);
    const providers = await client.sandbox.listProviders(ref.name);
    console.log(`providers: ${providers.map((p) => `${p.name}(${p.type})`).join(', ')}`);
    const detach = await client.sandbox.detachProvider(ref.name, providerName);
    console.log(`detach ${providerName}: changed=${detach.changed}`);
  }

  // Forward: start an in-sandbox listener and drive a request through the tunnel.
  await client.sandbox.exec(ref.name, [
    '/bin/sh',
    '-c',
    'nohup python3 -m http.server 8111 >/tmp/http.log 2>&1 & sleep 1',
  ]);
  const forward = await client.sandbox.forward(ref.name, { targetPort: 8111 });
  console.log(`forward: 127.0.0.1:${forward.localPort} -> sandbox:8111`);
  const status = await httpGet(`http://127.0.0.1:${forward.localPort}/`);
  console.log(`forward GET status: ${status}`);
  await forward.close();

  const all = await client.sandbox.list({
    labelSelector: 'openshell.dev/demo=sdk-ts',
  });
  console.log(`listed ${all.length} demo sandbox(es)`);

  console.log(`deleted: ${await client.sandbox.delete(ref.name)}`);
}

main().catch((e) => {
  console.error(`demo failed [code=${errorCode(e) ?? 'unknown'}]:`, e instanceof Error ? e.message : e);
  process.exit(1);
});
