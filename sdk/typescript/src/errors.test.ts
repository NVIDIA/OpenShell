// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Unit tests for the error taxonomy: fromConnect() status mapping, the
// preserved ConnectError cause/connectCode, and the errorCode() prefix parser.

import { Code, ConnectError } from '@connectrpc/connect';
import { describe, expect, it } from 'vitest';
import { errorCode, fromConnect, SdkError, type SdkErrorCode } from './errors.js';
import { BadRequestSchema, ErrorInfoSchema, RetryInfoSchema } from './gen/google/rpc/error_details_pb.js';

describe('fromConnect', () => {
  it('decodes standard details and preserves unknown and malformed wire details', () => {
    const raw = new ConnectError('try later', Code.Unavailable, { 'request-id': 'correlation' }, [
      { desc: BadRequestSchema, value: { fieldViolations: [{ field: 'name', description: 'invalid' }] } },
      {
        desc: ErrorInfoSchema,
        value: { reason: 'GATEWAY_NOT_READY', domain: 'openshell.nvidia.com', metadata: { scope: 'test' } },
      },
      { desc: RetryInfoSchema, value: { retryDelay: { seconds: 1n, nanos: 250000000 } } },
    ]);
    raw.details.push({ type: 'google.rpc.BadRequest', value: new Uint8Array([255]) });
    raw.details.push({ type: 'future.ErrorDetail', value: new Uint8Array([8, 1]) });
    const error = fromConnect(raw);
    expect(error.fieldViolations).toEqual([{ field: 'name', description: 'invalid' }]);
    expect(error.errorInfo).toEqual({
      reason: 'GATEWAY_NOT_READY',
      domain: 'openshell.nvidia.com',
      metadata: { scope: 'test' },
    });
    expect(error.retryDelayMs).toBe(1250);
    expect(error.cause).toBe(raw);
    expect(raw.details).toHaveLength(5);
    expect(raw.metadata.get('request-id')).toBe('correlation');
  });

  it('does not fabricate retry guidance from the status code', () => {
    expect(fromConnect(new ConnectError('temporary', Code.Unavailable)).retryDelayMs).toBeUndefined();
    const raw = new ConnectError('invalid delay', Code.Unavailable, undefined, [
      { desc: RetryInfoSchema, value: { retryDelay: { seconds: -1n } } },
    ]);
    expect(fromConnect(raw).retryDelayMs).toBeUndefined();
  });
  const cases: Array<[Code, SdkErrorCode]> = [
    [Code.NotFound, 'not_found'],
    [Code.AlreadyExists, 'already_exists'],
    [Code.Aborted, 'aborted'],
    [Code.Canceled, 'canceled'],
    [Code.DeadlineExceeded, 'canceled'],
    [Code.InvalidArgument, 'invalid_config'],
    [Code.Unauthenticated, 'auth'],
    [Code.PermissionDenied, 'auth'],
    [Code.Internal, 'rpc'],
  ];

  for (const [code, expected] of cases) {
    it(`maps Connect ${Code[code]} to '${expected}'`, () => {
      const ce = new ConnectError('boom', code);
      const err = fromConnect(ce);
      expect(err).toBeInstanceOf(SdkError);
      expect(err.code).toBe(expected);
      // The originating ConnectError is preserved for inspection.
      expect(err.cause).toBe(ce);
      expect(err.connectCode).toBe(code);
      // errorCode() still recovers the prefix from the message.
      expect(errorCode(err)).toBe(expected);
    });
  }

  it('distinguishes optimistic-concurrency conflicts from generic rpc failures', () => {
    const aborted = fromConnect(new ConnectError('version mismatch', Code.Aborted));
    const generic = fromConnect(new ConnectError('boom', Code.Internal));
    expect(aborted.code).toBe('aborted');
    expect(generic.code).toBe('rpc');
    expect(aborted.code).not.toBe(generic.code);
  });
});

describe('SdkError', () => {
  it('prefixes the message with [code] and exposes the union member', () => {
    const err = new SdkError('invalid_config', 'bad value');
    expect(err.message).toBe('[invalid_config] bad value');
    expect(err.code).toBe('invalid_config');
    expect(errorCode(err)).toBe('invalid_config');
  });

  it('preserves the cause and connectCode when provided', () => {
    const ce = new ConnectError('missing', Code.NotFound);
    const err = new SdkError('not_found', ce.rawMessage, { cause: ce, connectCode: ce.code });
    expect(err.cause).toBe(ce);
    expect(err.connectCode).toBe(Code.NotFound);
  });
});
