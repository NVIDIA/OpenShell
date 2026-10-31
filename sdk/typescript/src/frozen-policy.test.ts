// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { Code, createRouterTransport } from '@connectrpc/connect';
import { describe, expect, it } from 'vitest';
import { SandboxClient } from './client.js';
import { type CreateFrozenSandboxRequest, FrozenSandboxPolicies, OpenShell } from './gen/openshell_pb.js';
import { PolicySource } from './gen/sandbox_pb.js';

describe('optional frozen policy service', () => {
  it.each(
    [undefined, false, true].flatMap((acknowledged) => [false, true].map((template) => ({ acknowledged, template }))),
  )(
    'uses a distinct creation RPC and requires acknowledgement ($template, $acknowledged)',
    async ({ acknowledged, template }) => {
      let ordinaryCreates = 0;
      let requested: CreateFrozenSandboxRequest | undefined;
      const transport = createRouterTransport((router) => {
        router.service(OpenShell, {
          createSandbox: () => {
            ordinaryCreates++;
            return {};
          },
        });
        router.service(FrozenSandboxPolicies, {
          createSandbox: (request) => {
            requested = request;
            return {
              sandbox: { metadata: { id: 'created-id', name: request.name, workspace: 'staging' } },
              frozenPolicy: acknowledged === undefined ? undefined : { requested: acknowledged },
              serviceUrls: { web: 'https://web.example' },
            };
          },
        });
      });
      const client = new SandboxClient(transport);
      const spec = { workspace: 'staging', name: 'frozen', policy: { version: 1 }, providers: ['github'] };
      const created = template
        ? client.createFrozenFromTemplate({ ...spec, workloadTemplate: 'agent' })
        : client.createFrozen(spec);
      if (acknowledged) {
        expect((await created).serviceUrls).toEqual({ web: 'https://web.example' });
      } else {
        await expect(created).rejects.toMatchObject({
          message: expect.stringContaining('did not acknowledge frozen creation'),
        });
      }
      expect(ordinaryCreates).toBe(0);
      expect(requested?.workspaceScope?.selection).toEqual({ case: 'workspace', value: 'staging' });
      expect(requested?.spec?.policy?.version).toBe(1);
      expect(requested?.spec?.providers).toEqual(['github']);
      expect(requested?.workloadTemplate).toBe(template ? 'agent' : '');
    },
  );

  it('does not fall back to ordinary creation on an older gateway', async () => {
    let ordinaryCreates = 0;
    const transport = createRouterTransport((router) => {
      router.service(OpenShell, {
        createSandbox: () => {
          ordinaryCreates++;
          return {};
        },
      });
    });
    await expect(new SandboxClient(transport).createFrozen({})).rejects.toMatchObject({
      connectCode: Code.Unimplemented,
    });
    expect(ordinaryCreates).toBe(0);
  });

  it('reads pending and captured snapshots and reports global exceptions', async () => {
    let captured = false;
    let observedGlobal = false;
    const transport = createRouterTransport((router) => {
      router.service(FrozenSandboxPolicies, {
        getPolicy: () => ({
          requested: true,
          policy: captured
            ? {
                policy: { version: 1 },
                version: 3,
                policyHash: 'accepted-hash',
                frozenTime: { seconds: 600n, nanos: 0 },
                policySource: PolicySource.GLOBAL,
                globalPolicyVersion: 7,
              }
            : undefined,
        }),
        updateGlobalConfig: (request) => {
          observedGlobal = request.global;
          return { update: { version: 7 }, frozenSandboxes: ['staging/frozen'] };
        },
      });
    });
    const client = new SandboxClient(transport);
    expect(await client.getFrozenPolicy('frozen', { workspace: 'staging' })).toEqual({
      requested: true,
      policy: undefined,
    });
    captured = true;
    const policy = (await client.getFrozenPolicy('frozen', { workspace: 'staging' })).policy;
    expect(policy).toMatchObject({
      version: 3,
      policyHash: 'accepted-hash',
      frozenAtMs: 600_000,
      policySource: 'global',
      globalPolicyVersion: 7,
    });
    expect(policy?.policy?.version).toBe(1);
    const update = await client.updateGlobalConfig({ policy: { version: 1 } });
    expect(update.update.version).toBe(7);
    expect(update.frozenSandboxes).toEqual(['staging/frozen']);
    expect(observedGlobal).toBe(true);
  });
});
