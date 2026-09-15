// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import type { MessageInitShape } from '@bufbuild/protobuf';
import { createRouterTransport } from '@connectrpc/connect';
import { describe, expect, it } from 'vitest';
import { SandboxClient } from './index.js';
import { EndpointResult, type EndpointStatusSchema, OpenShell, SandboxPhase } from './raw.js';

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
      const readyCondition = { type: 'Ready', status: 'True', reason: 'Ready', message: 'Sandbox is ready' };
      const sandbox = new SandboxClient(
        createRouterTransport(
          (router) => {
            router.service(OpenShell, {
              getSandbox: (request) => {
                expect(request.name).toBe('tool-sandbox');
                expect(request.workspaceScope?.selection).toEqual({ case: 'workspace', value: 'tool-workspace' });
                return {
                  sandbox: {
                    metadata: { id: 'sandbox-id', name: request.name, workspace: 'tool-workspace' },
                    status: {
                      phase: SandboxPhase.READY,
                      endpointStatuses: endpoints.map((endpoint) => ({
                        ...endpoint,
                        lastResult,
                        lastReportedAt: lastResult === EndpointResult.NO_OBSERVED_EXCHANGE ? '' : reportedAt,
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
            lastReportedAt: result === EndpointResult.NO_OBSERVED_EXCHANGE ? '' : reportedAt,
          })),
        );
      }
    },
  );
});
