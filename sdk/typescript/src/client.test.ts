// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Unit tests for SandboxClient against an in-memory OpenShell service. Every
// RPC is stubbed with createRouterTransport, so these exercise request
// assembly, u64/int64->string rendering, enum lowercasing, fromConnect code
// mapping, the exec/execStream drain, execInteractive framing, and the
// forward() byte relay without a running gateway.

import * as net from 'node:net';
import type { MessageInitShape } from '@bufbuild/protobuf';
import { Code, ConnectError, createRouterTransport, type ServiceImpl, type Transport } from '@connectrpc/connect';
import { describe, expect, it } from 'vitest';
import { errorCode, SandboxClient } from './client.js';
import { OpenShell, SandboxPhase } from './gen/openshell_pb.js';
import { PolicySource, SettingScope } from './gen/sandbox_pb.js';

function client(impl: Partial<ServiceImpl<typeof OpenShell>>): SandboxClient {
  const transport: Transport = createRouterTransport((router) => {
    router.service(OpenShell, impl);
  });
  return new SandboxClient(transport);
}

function readySandbox(
  name: string,
  id: string,
  resourceVersion = 7n,
): MessageInitShape<typeof OpenShell.method.getSandbox.output> {
  return {
    sandbox: {
      metadata: { id, name, labels: { team: 'aire' }, resourceVersion },
      status: { phase: SandboxPhase.READY },
    },
  };
}

const enc = (s: string) => new TextEncoder().encode(s);

describe('exec / execStream', () => {
  it('resolves the id via get, frames tty:false, and buffers the result (backward compat)', async () => {
    let execReq: { sandboxId?: string; tty?: boolean; command?: string[] } = {};
    const sandbox = client({
      getSandbox: () => readySandbox('sb', 'sb-id-1'),
      // eslint-disable-next-line require-yield
      execSandbox: async function* (req) {
        execReq = req;
        yield { payload: { case: 'stdout', value: { data: enc('hello ') } } };
        yield { payload: { case: 'stderr', value: { data: enc('warn') } } };
        yield { payload: { case: 'stdout', value: { data: enc('world') } } };
        yield { payload: { case: 'exit', value: { exitCode: 3 } } };
      },
    });

    const result = await sandbox.exec('sb', ['/bin/sh', '-c', 'echo hi']);
    expect(execReq.sandboxId).toBe('sb-id-1');
    expect(execReq.tty).toBe(false);
    expect(execReq.command).toEqual(['/bin/sh', '-c', 'echo hi']);
    expect(result.exitCode).toBe(3);
    expect(result.stdout.toString()).toBe('hello world');
    expect(result.stderr.toString()).toBe('warn');
    expect(Buffer.isBuffer(result.stdout)).toBe(true);
  });

  it('execStream yields incremental chunks and returns an exit-only ExecResult', async () => {
    const sandbox = client({
      getSandbox: () => readySandbox('sb', 'sb-id-1'),
      // eslint-disable-next-line require-yield
      execSandbox: async function* () {
        yield { payload: { case: 'stdout', value: { data: enc('a') } } };
        yield { payload: { case: 'stderr', value: { data: enc('b') } } };
        yield { payload: { case: 'exit', value: { exitCode: 0 } } };
      },
    });

    const chunks: Array<{ stream: string; data: string }> = [];
    const gen = sandbox.execStream('sb', ['x']);
    let next = await gen.next();
    for (; next.done !== true; next = await gen.next()) {
      chunks.push({
        stream: next.value.stream,
        data: next.value.data.toString(),
      });
    }
    expect(chunks).toEqual([
      { stream: 'stdout', data: 'a' },
      { stream: 'stderr', data: 'b' },
    ]);
    expect(next.value.exitCode).toBe(0);
    expect(next.value.stdout.length).toBe(0);
    expect(next.value.stderr.length).toBe(0);
  });

  it('maps a NotFound from get() to an SdkError not_found', async () => {
    const sandbox = client({
      getSandbox: () => {
        throw new ConnectError('missing', Code.NotFound);
      },
    });
    await expect(sandbox.exec('sb', ['x'])).rejects.toMatchObject({
      code: 'not_found',
    });
    await expect(sandbox.exec('sb', ['x'])).rejects.toSatisfy((e) => errorCode(e) === 'not_found');
  });
});

describe('execInteractive', () => {
  it('sends start first with tty/cols/rows, streams output, and resolves done', async () => {
    const cases: string[] = [];
    let started: { tty?: boolean; cols?: number; rows?: number; sandboxId?: string } | undefined;
    const sandbox = client({
      getSandbox: () => readySandbox('sb', 'sb-id-9'),
      execSandboxInteractive: async function* (requests) {
        for await (const input of requests) {
          cases.push(input.payload.case ?? 'none');
          if (input.payload.case === 'start') {
            started = input.payload.value;
            yield {
              payload: { case: 'stdout', value: { data: enc('ready\n') } },
            };
          } else if (input.payload.case === 'stdin') {
            yield {
              payload: { case: 'stdout', value: { data: input.payload.value } },
            };
          }
        }
        yield { payload: { case: 'exit', value: { exitCode: 0 } } };
      },
    });

    const session = await sandbox.execInteractive('sb', ['bash'], {
      cols: 120,
      rows: 40,
    });
    const out: string[] = [];
    const collector = (async () => {
      for await (const chunk of session.output) out.push(chunk.data.toString());
    })();

    session.write(Buffer.from('echo hi'));
    // Let the echo round-trip before closing the input stream.
    await new Promise((r) => setTimeout(r, 20));
    session.close();

    await collector;
    const code = await session.done;
    expect(code).toBe(0);
    expect(cases[0]).toBe('start');
    expect(started?.tty).toBe(true);
    expect(started?.cols).toBe(120);
    expect(started?.rows).toBe(40);
    expect(started?.sandboxId).toBe('sb-id-9');
    expect(out.join('')).toContain('ready\n');
    expect(out.join('')).toContain('echo hi');
  });
});

describe('providers', () => {
  it('attach/detach assemble the request and map the changed flag + sandbox ref', async () => {
    let attachReq: {
      sandboxName?: string;
      providerName?: string;
      expectedResourceVersion?: bigint;
    } = {};
    let detachReq: { expectedResourceVersion?: bigint } = {};
    const sandbox = client({
      attachSandboxProvider: (req) => {
        attachReq = req;
        return { sandbox: readySandbox('sb', 'sb-id').sandbox, attached: true };
      },
      detachSandboxProvider: (req) => {
        detachReq = req;
        return {
          sandbox: readySandbox('sb', 'sb-id').sandbox,
          detached: false,
        };
      },
    });

    const attach = await sandbox.attachProvider('sb', 'claude');
    expect(attachReq.sandboxName).toBe('sb');
    expect(attachReq.providerName).toBe('claude');
    expect(attachReq.expectedResourceVersion).toBe(0n);
    expect(attach.changed).toBe(true);
    expect(attach.sandbox.resourceVersion).toBe('7');

    const detach = await sandbox.detachProvider('sb', 'claude', {
      expectedResourceVersion: '42',
    });
    expect(detachReq.expectedResourceVersion).toBe(42n);
    expect(detach.changed).toBe(false);
  });

  it('lists providers with u64 resourceVersion rendered as a string', async () => {
    const sandbox = client({
      listSandboxProviders: () => ({
        providers: [
          {
            metadata: {
              id: 'p1',
              name: 'claude',
              labels: { a: 'b' },
              resourceVersion: 99n,
            },
            type: 'claude',
          },
        ],
      }),
    });
    const providers = await sandbox.listProviders('sb');
    expect(providers).toEqual([
      {
        id: 'p1',
        name: 'claude',
        type: 'claude',
        labels: { a: 'b' },
        resourceVersion: '99',
      },
    ]);
  });
});

describe('config / policy', () => {
  it('getConfig lowercases scope + policySource and renders u64 as strings', async () => {
    const sandbox = client({
      getSandbox: () => readySandbox('sb', 'sb-id'),
      getSandboxConfig: () => ({
        policy: { version: 1, networkPolicies: {} },
        version: 4,
        policyHash: 'hash-a',
        settings: {
          'net.timeout': {
            value: { value: { case: 'intValue', value: 30n } },
            scope: SettingScope.SANDBOX,
          },
        },
        configRevision: 123n,
        policySource: PolicySource.GLOBAL,
        globalPolicyVersion: 2,
        providerEnvRevision: 456n,
      }),
    });
    const config = await sandbox.getConfig('sb');
    expect(config.version).toBe(4);
    expect(config.policyHash).toBe('hash-a');
    expect(config.policySource).toBe('global');
    expect(config.configRevision).toBe('123');
    expect(config.providerEnvRevision).toBe('456');
    expect(config.settings['net.timeout']?.scope).toBe('sandbox');
    expect(config.settings['net.timeout']?.value?.value).toEqual({
      case: 'intValue',
      value: 30n,
    });
  });

  it('setPolicy sends global=false + version pin and (wait) polls until the hash matches', async () => {
    let updateReq: {
      name?: string;
      global?: boolean;
      expectedResourceVersion?: bigint;
      policy?: unknown;
    } = {};
    let configCalls = 0;
    const sandbox = client({
      getSandbox: () => readySandbox('sb', 'sb-id'),
      updateConfig: (req) => {
        updateReq = req;
        return {
          version: 5,
          policyHash: 'target',
          settingsRevision: 10n,
          deleted: false,
        };
      },
      getSandboxConfig: () => {
        configCalls += 1;
        const policyHash = configCalls >= 2 ? 'target' : 'stale';
        return {
          policy: { version: 1, networkPolicies: {} },
          version: 5,
          policyHash,
          settings: {},
          configRevision: 1n,
          policySource: PolicySource.SANDBOX,
          globalPolicyVersion: 0,
          providerEnvRevision: 0n,
        };
      },
    });

    const result = await sandbox.setPolicy(
      'sb',
      {
        version: 1,
        networkPolicies: { web: { name: 'web', endpoints: [], binaries: [] } },
      },
      { wait: true, expectedResourceVersion: '7' },
    );
    expect(updateReq.name).toBe('sb');
    expect(updateReq.global).toBe(false);
    expect(updateReq.expectedResourceVersion).toBe(7n);
    expect(updateReq.policy).toBeDefined();
    expect(result.version).toBe(5);
    expect(result.policyHash).toBe('target');
    expect(result.settingsRevision).toBe('10');
    expect(configCalls).toBeGreaterThanOrEqual(2);
  });

  it('setSetting upserts a single sandbox-scoped setting (global=false)', async () => {
    let req: {
      name?: string;
      settingKey?: string;
      global?: boolean;
      settingValue?: unknown;
    } = {};
    const sandbox = client({
      updateConfig: (r) => {
        req = r;
        return {
          version: 6,
          policyHash: '',
          settingsRevision: 11n,
          deleted: false,
        };
      },
    });
    const result = await sandbox.setSetting('sb', 'feature.enabled', {
      value: { case: 'boolValue', value: true },
    });
    expect(req.name).toBe('sb');
    expect(req.settingKey).toBe('feature.enabled');
    expect(req.global).toBe(false);
    expect(req.settingValue).toMatchObject({
      value: { case: 'boolValue', value: true },
    });
    expect(result.settingsRevision).toBe('11');
  });
});

describe('ssh sessions', () => {
  it('creates a session, omitting expiresAtMs when 0 and rendering it as a string otherwise', async () => {
    const withExpiry = client({
      getSandbox: () => readySandbox('sb', 'sb-id'),
      createSshSession: () => ({
        sandboxId: 'sb-id',
        token: 'tok-1',
        gatewayHost: 'gw.example',
        gatewayPort: 8443,
        gatewayScheme: 'https',
        hostKeyFingerprint: 'SHA256:abc',
        expiresAtMs: 1730000000000n,
      }),
    });
    const session = await withExpiry.createSshSession('sb');
    expect(session).toEqual({
      sandboxId: 'sb-id',
      token: 'tok-1',
      gatewayHost: 'gw.example',
      gatewayPort: 8443,
      gatewayScheme: 'https',
      hostKeyFingerprint: 'SHA256:abc',
      expiresAtMs: '1730000000000',
    });

    const noExpiry = client({
      getSandbox: () => readySandbox('sb', 'sb-id'),
      createSshSession: () => ({
        sandboxId: 'sb-id',
        token: 'tok-2',
        gatewayHost: 'gw',
        gatewayPort: 80,
        gatewayScheme: 'http',
        hostKeyFingerprint: '',
        expiresAtMs: 0n,
      }),
    });
    const bare = await noExpiry.createSshSession('sb');
    expect(bare.expiresAtMs).toBeUndefined();
    expect(bare.hostKeyFingerprint).toBeUndefined();
  });

  it('revokeSshSession returns the revoked flag', async () => {
    const sandbox = client({ revokeSshSession: () => ({ revoked: true }) });
    expect(await sandbox.revokeSshSession('tok')).toBe(true);
  });
});

describe('forward', () => {
  it('binds a local port and relays bytes both ways, minting + revoking a token', async () => {
    let sshReq: { sandboxId?: string } = {};
    let revokedToken: string | undefined;
    let initFrame: { sandboxId?: string; authorizationToken?: string; target?: unknown } | undefined;
    const sandbox = client({
      getSandbox: () => readySandbox('sb', 'sb-id-forward'),
      createSshSession: (req) => {
        sshReq = req;
        return {
          sandboxId: 'sb-id-forward',
          token: 'fwd-tok',
          gatewayHost: 'gw',
          gatewayPort: 443,
          gatewayScheme: 'https',
          hostKeyFingerprint: '',
          expiresAtMs: 0n,
        };
      },
      revokeSshSession: (req) => {
        revokedToken = req.token;
        return { revoked: true };
      },
      forwardTcp: async function* (requests) {
        for await (const frame of requests) {
          if (frame.payload.case === 'init') {
            initFrame = frame.payload.value;
          } else if (frame.payload.case === 'data') {
            yield { payload: { case: 'data', value: frame.payload.value } };
          }
        }
      },
    });

    const handle = await sandbox.forward('sb', { targetPort: 9000 });
    expect(handle.localPort).toBeGreaterThan(0);
    expect(handle.targetPort).toBe(9000);
    expect(handle.targetHost).toBe('127.0.0.1');

    const echoed = await new Promise<string>((resolve, reject) => {
      const socket = net.connect(handle.localPort, handle.localHost, () => {
        socket.write('ping-through-forward');
      });
      const buf: Buffer[] = [];
      socket.on('data', (d) => {
        buf.push(d);
        if (Buffer.concat(buf).length >= 'ping-through-forward'.length) {
          resolve(Buffer.concat(buf).toString());
          socket.end();
        }
      });
      socket.on('error', reject);
    });

    expect(echoed).toBe('ping-through-forward');
    expect(sshReq.sandboxId).toBe('sb-id-forward');
    expect(initFrame?.sandboxId).toBe('sb-id-forward');
    expect(initFrame?.authorizationToken).toBe('fwd-tok');
    expect(initFrame?.target).toMatchObject({
      case: 'tcp',
      value: { host: '127.0.0.1', port: 9000 },
    });

    await handle.close();
    await handle.closed;
    // The per-connection revoke is best-effort and fires on teardown.
    await new Promise((r) => setTimeout(r, 20));
    expect(revokedToken).toBe('fwd-tok');
  });

  it('rejects when the sandbox is not ready', async () => {
    const sandbox = client({
      getSandbox: () => ({
        sandbox: {
          metadata: { id: 'sb-id', name: 'sb' },
          status: { phase: SandboxPhase.PROVISIONING },
        },
      }),
    });
    await expect(sandbox.forward('sb', { targetPort: 9000 })).rejects.toMatchObject({ code: 'connect' });
  });
});
