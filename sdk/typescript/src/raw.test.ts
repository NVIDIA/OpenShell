// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import type { MessageInitShape } from '@bufbuild/protobuf';
import { timestampFromDate } from '@bufbuild/protobuf/wkt';
import { createClient, createRouterTransport } from '@connectrpc/connect';
import { describe, expect, it } from 'vitest';
import { SandboxClient } from './index.js';
import { EndpointResult, type EndpointStatusSchema, OpenShell, SandboxPhase, SandboxUpdates } from './raw.js';

describe('raw sandbox image updates', () => {
  it.each([true, false])('uses a separate service on the existing transport (binary: %s)', async (useBinaryFormat) => {
    const transport = createRouterTransport(
      (router) => {
        router.service(OpenShell, {
          getSandbox: () => ({ sandbox: { metadata: { id: 'stable-id' } } }),
        });
        router.service(SandboxUpdates, {
          updateSandbox: (request) => {
            expect(request.workspaceScope?.selection).toEqual({ case: 'workspace', value: 'team' });
            expect(request.name).toBe('sandbox');
            expect(request.expectedResourceVersion).toBe(42n);
            expect(request.requestId).toBe('550e8400-e29b-41d4-a716-446655440000');
            return {
              sandbox: {
                metadata: { id: 'stable-id', name: request.name, workspace: 'team' },
                spec: { template: { image: request.image } },
                status: { phase: SandboxPhase.STOPPED },
              },
            };
          },
        });
      },
      { transport: { useBinaryFormat } },
    );
    const legacy = new SandboxClient(transport);
    const updates = createClient(SandboxUpdates, legacy.transport);
    expect(Object.hasOwn(OpenShell.method, 'updateSandbox')).toBe(false);
    expect(SandboxUpdates.typeName).toBe('openshell.v1.SandboxUpdates');
    const before = await legacy.raw.getSandbox({ name: 'sandbox' });
    const response = await updates.updateSandbox({
      workspaceScope: { selection: { case: 'workspace', value: 'team' } },
      name: 'sandbox',
      image: 'example/workload:new',
      expectedResourceVersion: 42n,
      requestId: '550e8400-e29b-41d4-a716-446655440000',
    });
    expect(response.sandbox?.metadata?.id).toBe(before.sandbox?.metadata?.id);
    expect(response.sandbox?.spec?.template?.image).toBe('example/workload:new');
    expect(response.sandbox?.status?.phase).toBe(SandboxPhase.STOPPED);
    expect(response.sandbox?.status).not.toHaveProperty('imageUpdate');
    expect(response.sandbox?.status).not.toHaveProperty('imageRevision');
  });
});

describe('raw sandbox endpoint status', () => {
  it.each([true, false])(
    'keeps the address and result together through a reset (binary: %s)',
    async (useBinaryFormat) => {
      const endpoints: MessageInitShape<typeof EndpointStatusSchema>[] = [
        { endpointId: 'endpoint-a', host: 'tools.example.test', ports: [443, 8443], path: '/first' },
        { endpointId: 'endpoint-b', host: 'tools.example.test', ports: [443], path: '/second' },
      ];
      let lastResult = EndpointResult.TRANSPORT_FAILED;
      const reportedAt = '2026-09-11T10:00:01Z';
      const reportedTime = timestampFromDate(new Date(reportedAt));
      const readyCondition = { type: 'Ready', status: 'True', reason: 'Ready', message: 'Sandbox is ready' };
      const sandbox = new SandboxClient(
        createRouterTransport(
          (router) => {
            router.service(OpenShell, {
              getSandbox: (request) => {
                expect(request.name).toBe('tool-sandbox');
                expect(request.workspaceScope?.selection.value).toBe('tool-workspace');
                return {
                  sandbox: {
                    metadata: { id: 'sandbox-id', name: request.name, workspace: 'tool-workspace' },
                    status: {
                      phase: SandboxPhase.READY,
                      endpointStatuses: endpoints.map((endpoint) => ({
                        ...endpoint,
                        lastResult,
                        ...(lastResult === EndpointResult.NO_OBSERVED_EXCHANGE
                          ? {}
                          : { lastReportedTime: reportedTime }),
                      })),
                      conditions: [readyCondition],
                    },
                  },
                };
              },
            });
          },
          { transport: { useBinaryFormat } },
        ),
      );

      for (const result of [
        EndpointResult.TRANSPORT_FAILED,
        EndpointResult.HTTP_RESPONSE_RECEIVED,
        EndpointResult.NO_OBSERVED_EXCHANGE,
      ]) {
        lastResult = result;
        const response = await sandbox.raw.getSandbox({
          name: 'tool-sandbox',
          workspaceScope: { selection: { case: 'workspace', value: 'tool-workspace' } },
        });
        const status = response.sandbox?.status;
        expect(status?.phase).toBe(SandboxPhase.READY);
        expect(status?.conditions).toMatchObject([readyCondition]);
        expect(status?.conditions).toHaveLength(1);
        expect(status?.endpointStatuses).toHaveLength(2);
        expect(status?.endpointStatuses).toMatchObject(
          endpoints.map((endpoint) => ({
            ...endpoint,
            lastResult: result,
            ...(result === EndpointResult.NO_OBSERVED_EXCHANGE ? {} : { lastReportedTime: reportedTime }),
          })),
        );
      }
    },
  );
});
