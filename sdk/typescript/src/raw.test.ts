// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { create, fromBinary, fromJson, type MessageInitShape, toBinary, toJson } from '@bufbuild/protobuf';
import { timestampFromDate } from '@bufbuild/protobuf/wkt';
import { createClient, createRouterTransport } from '@connectrpc/connect';
import { describe, expect, it } from 'vitest';
import { SandboxClient } from './index.js';
import {
  ConfigureProviderRefreshRequestSchema,
  EndpointResult,
  type EndpointStatusSchema,
  OpenShell,
  ProviderCredentialRefreshSchema,
  ProviderCredentialRefreshStatusSchema,
  ProviderCredentialRefreshStrategy,
  SandboxPhase,
  SandboxUpdates,
} from './raw.js';

describe.each([
  { schema: ProviderCredentialRefreshSchema, nameTag: 106, enumTag: 1 },
  { schema: ProviderCredentialRefreshStatusSchema, nameTag: 114, enumTag: 4 },
  { schema: ConfigureProviderRefreshRequestSchema, nameTag: 107, enumTag: 3 },
])('raw refresh strategy selectors: $schema.typeName', ({ schema, nameTag, enumTag }) => {
  it('adds optional strategy_name without changing the enum field identity', () => {
    const field = schema.fields.find((field) => field.name === 'strategy_name');
    expect(field?.number).toBe(nameTag);
    expect(field?.jsonName).toBe('strategyName');
    expect(field?.proto.proto3Optional).toBe(true);
    expect(schema.fields.find((field) => field.name === 'strategy')?.number).toBe(enumTag);
  });

  it.each([
    [ProviderCredentialRefreshStrategy.OAUTH2_REFRESH_TOKEN, 'oauth2_refresh_token'],
    [ProviderCredentialRefreshStrategy.OAUTH2_CLIENT_CREDENTIALS, 'oauth2_client_credentials'],
    [ProviderCredentialRefreshStrategy.GOOGLE_SERVICE_ACCOUNT_JWT, 'google_service_account_jwt'],
    [ProviderCredentialRefreshStrategy.AWS_STS_ASSUME_ROLE, 'aws_sts_assume_role'],
  ] as const)('round-trips enum/name presence through binary and JSON (%s, %s)', (strategy, canonicalName) => {
    // Empty is intentionally distinct from absent here; rejection belongs to
    // server configuration validation, not the generated wire representation.
    for (const selectors of [
      {},
      { strategyName: '' },
      { strategy },
      { strategyName: canonicalName },
      { strategy, strategyName: canonicalName },
    ]) {
      const original = create(schema, selectors);
      const hasName = 'strategyName' in selectors;
      expect(original.strategyName).toBe(hasName ? selectors.strategyName : undefined);
      const wire = toBinary(schema, original);
      if ('strategy' in selectors) {
        expect([...wire.subarray(0, 2)]).toEqual([enumTag << 3, strategy]);
      }
      if (hasName) {
        const nameBytes = new TextEncoder().encode(selectors.strategyName);
        const tag = (nameTag << 3) | 2;
        const expectedField = [(tag & 0x7f) | 0x80, tag >> 7, nameBytes.length, ...nameBytes];
        expect([...wire.subarray(-expectedField.length)]).toEqual(expectedField);
      }
      const decoded = fromBinary(schema, wire);
      expect(decoded).toEqual(original);
      expect(decoded.strategyName === undefined).toBe(!hasName);
      const json = toJson(schema, original);
      if (json === null || typeof json !== 'object' || Array.isArray(json)) {
        throw new Error('refresh JSON must be an object');
      }
      expect(Object.hasOwn(json, 'strategyName')).toBe(hasName);
      if (hasName) {
        expect(json).toMatchObject({ strategyName: selectors.strategyName });
      }
      for (const payload of [json, toJson(schema, original, { useProtoFieldName: true })]) {
        const restored = fromJson(schema, payload);
        expect(restored).toEqual(original);
        expect(restored.strategyName === undefined).toBe(!hasName);
      }
    }
  });
});

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
