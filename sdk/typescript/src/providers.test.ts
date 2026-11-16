// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import type { MessageInitShape } from '@bufbuild/protobuf';
import { Code, ConnectError, createRouterTransport, type ServiceImpl } from '@connectrpc/connect';
import { describe, expect, it, vi } from 'vitest';
import {
  OpenShellClient,
  ProviderClient,
  type ProviderCredentialsOptions,
  type ProviderCredentialValue,
} from './index.js';
import { OpenShell } from './raw.js';
import * as transportModule from './transport.js';

function providers(impl: Partial<ServiceImpl<typeof OpenShell>>, useBinaryFormat = true): ProviderClient {
  return new ProviderClient(
    createRouterTransport((router) => router.service(OpenShell, impl), { transport: { useBinaryFormat } }),
  );
}

describe('provider credential retrieval', () => {
  it.each([true, false])('curates selected secrets and optional expiration (binary: %s)', async (binary) => {
    const calls: MessageInitShape<typeof OpenShell.method.getProviderCredentials.input>[] = [];
    const provider = providers(
      {
        getProviderCredentials: (request) => {
          calls.push(request);
          return {
            credentials: {
              ACCESS_TOKEN: { value: 'access-secret', expirationTime: { seconds: 1893456000n, nanos: 123456789 } },
              STATIC_KEY: { value: 'static-secret' },
              EPOCH_KEY: { value: 'epoch-secret', expirationTime: { seconds: 0n, nanos: 0 } },
            },
          };
        },
      },
      binary,
    );
    const result: Record<string, ProviderCredentialValue> = await provider.getCredentials(
      'provider',
      ['ACCESS_TOKEN', 'STATIC_KEY', 'EPOCH_KEY'],
      { workspace: 'production', minimumRemainingLifetimeSecs: 300.123456789 },
    );
    expect(Object.keys(result)).toEqual(['ACCESS_TOKEN', 'STATIC_KEY', 'EPOCH_KEY']);
    expect(result.ACCESS_TOKEN).toEqual({
      value: 'access-secret',
      expirationTime: new Date('2030-01-01T00:00:00.123Z'),
    });
    expect(result.STATIC_KEY).toEqual({ value: 'static-secret' });
    expect(result.EPOCH_KEY).toEqual({ value: 'epoch-secret', expirationTime: new Date(0) });
    expect(result.ACCESS_TOKEN).not.toHaveProperty('$typeName');
    expect(calls[0]).toMatchObject({
      name: 'provider',
      workspaceScope: { selection: { case: 'workspace', value: 'production' } },
      credentialKeys: ['ACCESS_TOKEN', 'STATIC_KEY', 'EPOCH_KEY'],
      minimumRemainingLifetime: { seconds: 300n, nanos: 123456789 },
    });
  });

  it.each([undefined, 0, 86400])('preserves default/zero/max lifetime: %s', async (lifetime) => {
    let observed: MessageInitShape<typeof OpenShell.method.getProviderCredentials.input> | undefined;
    const provider = providers({
      getProviderCredentials: (request) => {
        observed = request;
        return { credentials: { KEY: { value: 'secret' } } };
      },
    });
    await provider.getCredentials('provider', ['KEY'], {
      workspace: 'default',
      minimumRemainingLifetimeSecs: lifetime,
    });
    expect(observed?.minimumRemainingLifetime).toEqual(
      lifetime === undefined ? undefined : expect.objectContaining({ seconds: BigInt(lifetime), nanos: 0 }),
    );
  });

  it('rounds a positive sub-nanosecond margin up', async () => {
    const provider = providers({
      getProviderCredentials: (request) => {
        expect(request.minimumRemainingLifetime).toMatchObject({ seconds: 0n, nanos: 1 });
        return { credentials: { KEY: { value: 'secret' } } };
      },
    });
    const result = await provider.getCredentials('provider', ['KEY'], {
      workspace: 'default',
      minimumRemainingLifetimeSecs: 1e-12,
    });
    expect(result).toEqual({ KEY: { value: 'secret' } });
  });

  it.each([
    ['', ['KEY'], { workspace: 'default' }],
    [' provider', ['KEY'], { workspace: 'default' }],
    ['p'.repeat(254), ['KEY'], { workspace: 'default' }],
    ['provider', [], { workspace: 'default' }],
    ['provider', ['KEY', 'KEY'], { workspace: 'default' }],
    ['provider', Array.from({ length: 33 }, (_, i) => `KEY_${i}`), { workspace: 'default' }],
    ['provider', ['KEY=secret-input'], { workspace: 'default' }],
    ['provider', ['1KEY'], { workspace: 'default' }],
    ['provider', ['KEY\n'], { workspace: 'default' }],
    ['provider', ['é'], { workspace: 'default' }],
    ['provider', ['K'.repeat(257)], { workspace: 'default' }],
    ['provider', ['KEY'], { workspace: '' }],
    ['provider', ['KEY'], { workspace: ' default' }],
    ['provider', ['KEY'], { workspace: 'default', minimumRemainingLifetimeSecs: -1 }],
    ['provider', ['KEY'], { workspace: 'default', minimumRemainingLifetimeSecs: 86400.1 }],
    ['provider', ['KEY'], { workspace: 'default', minimumRemainingLifetimeSecs: Number.NaN }],
    ['provider', ['KEY'], { workspace: 'default', minimumRemainingLifetimeSecs: Infinity }],
    ['provider', ['KEY'], { workspace: 'default', timeoutMs: 0 }],
    ['provider', ['KEY'], { workspace: 'default', timeoutMs: Infinity }],
  ] satisfies [string, string[], ProviderCredentialsOptions][])(
    'rejects invalid selectors or options before contacting the gateway: %s',
    async (name, keys, options) => {
      const retrieve = vi.fn();
      const provider = providers({ getProviderCredentials: retrieve });
      await expect(provider.getCredentials(name, keys, options)).rejects.toMatchObject({ code: 'invalid_config' });
      expect(retrieve).not.toHaveBeenCalled();
      try {
        await provider.getCredentials(name, keys, options);
      } catch (error) {
        expect(String(error)).not.toContain('secret-input');
      }
    },
  );

  it.each([
    [Code.Unauthenticated, 'auth'],
    [Code.PermissionDenied, 'auth'],
    [Code.NotFound, 'not_found'],
    [Code.FailedPrecondition, 'rpc'],
    [Code.Unavailable, 'rpc'],
    [Code.Aborted, 'aborted'],
    [Code.DeadlineExceeded, 'canceled'],
  ])('preserves status without retry: %s', async (status, code) => {
    const retrieve = vi.fn(() => {
      throw new ConnectError('retrieval failed', status as Code);
    });
    const provider = providers({ getProviderCredentials: retrieve });
    await expect(provider.getCredentials('provider', ['KEY'], { workspace: 'other' })).rejects.toMatchObject({
      code,
      connectCode: status,
    });
    expect(retrieve).toHaveBeenCalledOnce();
  });

  it.each([['ACCESS_TOKEN'], ['ACCESS_TOKEN', 'STATIC_KEY', 'PRIVATE_KEY']])(
    'rejects partial or extra responses without revealing values: %s',
    async (...keys) => {
      const provider = providers({
        getProviderCredentials: () => ({
          credentials: Object.fromEntries(keys.map((key) => [key, { value: 'must-not-deliver' }])),
        }),
      });
      const call = provider.getCredentials('provider', ['ACCESS_TOKEN', 'STATIC_KEY'], { workspace: 'other' });
      await expect(call).rejects.toMatchObject({
        code: 'rpc',
        message: '[rpc] gateway returned an unexpected credential selection',
      });
    },
  );

  it('snapshots selection across an in-flight RPC', async () => {
    let start!: () => void;
    let release!: () => void;
    const started = new Promise<void>((resolve) => {
      start = resolve;
    });
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const provider = providers({
      getProviderCredentials: async (request) => {
        start();
        await gate;
        expect(request.credentialKeys).toEqual(['KEY']);
        return { credentials: { KEY: { value: 'secret' } } };
      },
    });
    const keys = ['KEY'];
    const response = provider.getCredentials('provider', keys, { workspace: 'default' });
    await started;
    keys.push('PRIVATE_KEY');
    release();
    expect(Object.keys(await response)).toEqual(['KEY']);
  });

  it.each([false, true])('forwards cancellation/deadlines (deadline: %s)', async (deadline) => {
    let start!: () => void;
    const started = new Promise<void>((resolve) => {
      start = resolve;
    });
    const provider = providers({
      getProviderCredentials: (_, context) =>
        new Promise((_, reject) => {
          start();
          context.signal.addEventListener('abort', () => reject(new ConnectError('canceled', Code.Canceled)), {
            once: true,
          });
        }),
    });
    const controller = new AbortController();
    const response = provider.getCredentials('provider', ['KEY'], {
      workspace: 'default',
      signal: controller.signal,
      ...(deadline ? { timeoutMs: 20 } : {}),
    });
    const assertion = expect(response).rejects.toMatchObject({ code: 'canceled' });
    await started;
    if (!deadline) controller.abort();
    await assertion;
  });

  it('composes on the root transport and supports standalone connect', async () => {
    const transport = createRouterTransport((router) =>
      router.service(OpenShell, {
        getProviderCredentials: () => ({ credentials: { KEY: { value: 'secret' } } }),
      }),
    );
    const build = vi.spyOn(transportModule, 'buildTransport').mockReturnValue(transport);
    const options = {
      gateway: 'https://gateway.example.com',
      clientCert: Buffer.from('operator-cert'),
      clientKey: Buffer.from('operator-key'),
    };
    try {
      const root = await OpenShellClient.connect(options);
      expect(root.providers.transport).toBe(root.transport);
      expect(root.providers.transport).toBe(root.sandbox.transport);
      const standalone = await ProviderClient.connect(options);
      expect(await standalone.getCredentials('provider', ['KEY'], { workspace: 'other' })).toEqual({
        KEY: { value: 'secret' },
      });
      expect(build).toHaveBeenCalledWith(options);
    } finally {
      build.mockRestore();
    }
  });
});
