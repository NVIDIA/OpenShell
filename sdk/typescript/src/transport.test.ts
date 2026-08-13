// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Unit tests for buildTransport. These cover the mTLS client-material pairing
// contract without a live gateway: only PEM bytes are validated, no handshake
// is performed.

import { describe, expect, it } from 'vitest';
import { errorCode } from './errors.js';
import { buildTransport } from './transport.js';

const pem = (label: string) => Buffer.from(`-----BEGIN ${label}-----\ntest\n-----END ${label}-----\n`);

describe('buildTransport mTLS pairing', () => {
  it('throws when only clientCert is provided', () => {
    const fn = () => buildTransport({ gateway: 'https://gw.local', clientCert: pem('CERTIFICATE') });
    expect(fn).toThrow(/clientKey is missing/);
    try {
      fn();
    } catch (e) {
      expect(errorCode(e)).toBe('invalid_config');
    }
  });

  it('throws when only clientKey is provided', () => {
    const fn = () => buildTransport({ gateway: 'https://gw.local', clientKey: pem('PRIVATE KEY') });
    expect(fn).toThrow(/clientCert is missing/);
    try {
      fn();
    } catch (e) {
      expect(errorCode(e)).toBe('invalid_config');
    }
  });

  it('accepts both clientCert and clientKey', () => {
    const transport = buildTransport({
      gateway: 'https://gw.local',
      clientCert: pem('CERTIFICATE'),
      clientKey: pem('PRIVATE KEY'),
    });
    expect(transport).toBeTruthy();
  });

  it('accepts neither (server-only trust)', () => {
    const transport = buildTransport({ gateway: 'https://gw.local', caCert: pem('CERTIFICATE') });
    expect(transport).toBeTruthy();
  });

  it('accepts neither on an http gateway', () => {
    const transport = buildTransport({ gateway: 'http://gw.local' });
    expect(transport).toBeTruthy();
  });
});

describe('buildTransport token exclusivity', () => {
  it('throws when both oidcToken and edgeToken are set', () => {
    const fn = () => buildTransport({ gateway: 'https://gw.local', oidcToken: 'a', edgeToken: 'b' });
    expect(fn).toThrow(/mutually exclusive/);
    try {
      fn();
    } catch (e) {
      expect(errorCode(e)).toBe('invalid_config');
    }
  });

  it('rejects edge tokens that could inject cookies or headers', () => {
    for (const edgeToken of ['', 'jwt; other=value', 'jwt\r\nx-injected: yes', 'jwt with spaces']) {
      const fn = () => buildTransport({ gateway: 'https://gw.local', edgeToken });
      expect(fn).toThrow(/cookie-safe JWT characters/);
      try {
        fn();
      } catch (e) {
        expect(errorCode(e)).toBe('invalid_config');
      }
    }
  });

  it('accepts a base64url JWT edge token', () => {
    expect(
      buildTransport({ gateway: 'https://gw.local', edgeToken: 'eyJhbGciOiJSUzI1NiJ9.payload_signature' }),
    ).toBeTruthy();
  });
});

describe('buildTransport plaintext auth guard', () => {
  it('rejects a token over http:// to a non-loopback host', () => {
    const fn = () => buildTransport({ gateway: 'http://gw.remote:8080', oidcToken: 'a' });
    expect(fn).toThrow(/non-loopback/);
    try {
      fn();
    } catch (e) {
      expect(errorCode(e)).toBe('invalid_config');
    }
  });

  it('allows a token over http:// to loopback hosts', () => {
    expect(buildTransport({ gateway: 'http://127.0.0.1:8080', oidcToken: 'a' })).toBeTruthy();
    expect(buildTransport({ gateway: 'http://[::1]:8080', edgeToken: 'a' })).toBeTruthy();
    expect(buildTransport({ gateway: 'http://localhost:8080', oidcToken: 'a' })).toBeTruthy();
  });

  it('allows a token over http:// to a remote host when allowInsecureAuth is set', () => {
    expect(buildTransport({ gateway: 'http://gw.remote:8080', oidcToken: 'a', allowInsecureAuth: true })).toBeTruthy();
  });

  it('allows a token over https:// to any host', () => {
    expect(buildTransport({ gateway: 'https://gw.remote', oidcToken: 'a' })).toBeTruthy();
  });

  it('allows a tokenless http:// gateway to any host', () => {
    expect(buildTransport({ gateway: 'http://gw.remote:8080' })).toBeTruthy();
  });
});
