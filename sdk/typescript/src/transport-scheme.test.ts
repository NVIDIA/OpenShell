// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { createGrpcTransport } from '@connectrpc/connect-node';
import { expect, it, vi } from 'vitest';
import { buildTransport } from './transport.js';

vi.mock('@connectrpc/connect-node', () => ({ createGrpcTransport: vi.fn(() => ({})) }));

it('accepts an HTTPS gateway with an uppercase scheme and a bearer token', () => {
  expect(new URL('HTTPS://gw.remote').protocol).toBe('https:');
  expect(buildTransport({ gateway: 'HTTPS://gw.remote', oidcToken: 'token' })).toBeTruthy();
});

it('passes mTLS credentials for an HTTPS gateway with an uppercase scheme', () => {
  const clientCert = Buffer.from('cert');
  const clientKey = Buffer.from('key');
  buildTransport({ gateway: 'HTTPS://gw.remote', clientCert, clientKey });
  expect(vi.mocked(createGrpcTransport).mock.lastCall?.[0].nodeOptions).toEqual(
    expect.objectContaining({ cert: clientCert, key: clientKey }),
  );
});
