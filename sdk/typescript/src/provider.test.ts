// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { Code, ConnectError, createRouterTransport, type ServiceImpl, type Transport } from '@connectrpc/connect';
import { describe, expect, it } from 'vitest';
import { OpenShell } from './gen/openshell_pb.js';
import { ProviderClient } from './provider.js';

function client(impl: Partial<ServiceImpl<typeof OpenShell>>): ProviderClient {
  const transport: Transport = createRouterTransport((router) => router.service(OpenShell, impl));
  return new ProviderClient(transport);
}

function record(name = 'user-token', resourceVersion = 7n) {
  return {
    provider: {
      metadata: {
        id: `id-${name}`,
        name,
        labels: { owner: 'app' },
        annotations: { purpose: 'per-sandbox' },
        workspace: 'tenant-a',
        resourceVersion,
        createdAtMs: 123n,
      },
      type: 'backend-api',
      config: { endpoint: 'https://api.example.com' },
      credentialExpiresAtMs: { USER_JWT: 456n },
      profileWorkspace: 'tenant-a',
    },
  };
}

describe('ProviderClient', () => {
  it('creates a provider without returning credential plaintext', async () => {
    let request: Parameters<NonNullable<Partial<ServiceImpl<typeof OpenShell>>['createProvider']>>[0] | undefined;
    const providers = client({
      createProvider: (req) => {
        request = req;
        return record();
      },
    });

    const created = await providers.create('tenant-a', {
      name: 'user-token',
      type: 'backend-api',
      credentials: { USER_JWT: 'secret-value' },
      credentialExpiresAtMs: { USER_JWT: '456' },
    });

    expect(request?.workspace).toBe('tenant-a');
    expect(request?.provider?.credentials).toEqual({ USER_JWT: 'secret-value' });
    expect(request?.provider?.credentialExpiresAtMs.USER_JWT).toBe(456n);
    expect(created).not.toHaveProperty('credentials');
    expect(created.resourceVersion).toBe('7');
    expect(created.credentialExpiresAtMs).toEqual({ USER_JWT: '456' });
  });

  it('lists providers and validates pagination before the RPC', async () => {
    let request: { workspace?: string; limit?: number; offset?: number; allWorkspaces?: boolean } | undefined;
    const providers = client({
      listProviders: (req) => {
        request = req;
        return { providers: [record('one').provider, record('two').provider] };
      },
    });

    const listed = await providers.list('tenant-a', { limit: 10, offset: 2 });
    expect(request).toMatchObject({ workspace: 'tenant-a', limit: 10, offset: 2, allWorkspaces: false });
    expect(listed.map((provider) => provider.name)).toEqual(['one', 'two']);
    await expect(providers.list('tenant-a', { limit: -1 })).rejects.toMatchObject({ code: 'invalid_config' });
    await expect(providers.list('tenant-a', { allWorkspaces: true })).rejects.toMatchObject({
      code: 'invalid_config',
    });
  });

  it('updates credentials with a resource-version pin for safe rotation', async () => {
    let request: Parameters<NonNullable<Partial<ServiceImpl<typeof OpenShell>>['updateProvider']>>[0] | undefined;
    const providers = client({
      updateProvider: (req) => {
        request = req;
        return record('user-token', 9n);
      },
    });

    const updated = await providers.update('tenant-a', {
      name: 'user-token',
      type: 'backend-api',
      credentials: { USER_JWT: 'rotated-value' },
      resourceVersion: '7',
    });

    expect(request?.provider?.metadata?.resourceVersion).toBe(7n);
    expect(request?.provider?.credentials).toEqual({ USER_JWT: 'rotated-value' });
    expect(updated.resourceVersion).toBe('9');
  });

  it('ensure creates when absent and updates with the current resource version when present', async () => {
    let exists = false;
    let createCount = 0;
    let updateVersion = 0n;
    const providers = client({
      getProvider: () => {
        if (!exists) throw new ConnectError('missing', Code.NotFound);
        return record('user-token', 42n);
      },
      createProvider: () => {
        createCount += 1;
        exists = true;
        return record();
      },
      updateProvider: (req) => {
        updateVersion = req.provider?.metadata?.resourceVersion ?? 0n;
        return record('user-token', 43n);
      },
    });

    const desired = { name: 'user-token', type: 'backend-api', credentials: { USER_JWT: 'value' } };
    await providers.ensure('tenant-a', desired);
    expect(createCount).toBe(1);
    await providers.ensure('tenant-a', desired);
    expect(updateVersion).toBe(42n);
  });

  it('does not turn an update race into a create', async () => {
    let createCount = 0;
    const providers = client({
      getProvider: () => record('user-token', 42n),
      updateProvider: () => {
        throw new ConnectError('deleted concurrently', Code.NotFound);
      },
      createProvider: () => {
        createCount += 1;
        return record();
      },
    });

    await expect(providers.ensure('tenant-a', { name: 'user-token', type: 'backend-api' })).rejects.toMatchObject({
      code: 'not_found',
    });
    expect(createCount).toBe(0);
  });

  it('maps delete and malformed gateway responses through the SDK error taxonomy', async () => {
    const providers = client({
      deleteProvider: () => ({ deleted: true }),
      getProvider: () => ({ provider: { type: 'backend-api' } }),
    });
    await expect(providers.delete('tenant-a', 'user-token')).resolves.toBe(true);
    await expect(providers.get('tenant-a', 'user-token')).rejects.toMatchObject({ code: 'invalid_config' });
  });
});
