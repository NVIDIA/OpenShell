// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { clientCredentials } from './oidc.js';

const conformance = JSON.parse(
  readFileSync(new URL('../../conformance/oauth-client-credentials.json', import.meta.url), 'utf8'),
) as {
  request: Record<string, string | string[]>;
  urls: { allowed: string[]; rejected: string[] };
  expiry: { leeway_seconds: number; valid_expires_in: number; invalid_expires_in: unknown[] };
  discovery: {
    configured_issuer: string;
    matching_issuer: string;
    mismatched_issuer: string;
    redirect_statuses: number[];
  };
  limits: { max_response_bytes: number };
};

const servers: ReturnType<typeof createServer>[] = [];
afterEach(async () => {
  vi.useRealTimers();
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

async function providerServer(
  expiresIn: unknown = conformance.expiry.valid_expires_in,
): Promise<{ issuer: string; forms: URLSearchParams[] }> {
  const forms: URLSearchParams[] = [];
  let issuer = '';
  const server = createServer((req, res) => {
    if (req.url === '/.well-known/openid-configuration') {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ issuer, token_endpoint: `${issuer}/token` }));
      return;
    }
    let body = '';
    req.setEncoding('utf8');
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => {
      forms.push(new URLSearchParams(body));
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ access_token: `token-${forms.length}`, expires_in: expiresIn }));
    });
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('missing address');
  issuer = `http://127.0.0.1:${address.port}`;
  return { issuer, forms };
}

describe('clientCredentials', () => {
  it('accepts and rejects the shared URL vectors', () => {
    for (const issuer of conformance.urls.allowed) {
      expect(() => clientCredentials({ issuer, clientId: 'client', clientSecret: 'secret' })).not.toThrow();
    }
    for (const issuer of conformance.urls.rejected) {
      expect(() => clientCredentials({ issuer, clientId: 'client', clientSecret: 'secret' })).toThrow();
    }
    expect(conformance.expiry.leeway_seconds).toBe(30);
  });

  it('sends exact explicit fields without interactive scopes and caches the token', async () => {
    const { issuer, forms } = await providerServer();
    const provider = clientCredentials({
      issuer,
      clientId: conformance.request.client_id as string,
      clientSecret: conformance.request.client_secret as string,
      scopes: conformance.request.scopes as string[],
      audience: conformance.request.audience as string,
    });
    expect(await provider.getToken()).toBe('token-1');
    expect(await provider.getToken()).toBe('token-1');
    expect(forms).toHaveLength(1);
    expect(Object.fromEntries(forms[0])).toEqual(
      Object.fromEntries(
        ['grant_type', 'client_id', 'client_secret', 'scope', 'audience'].map((field) => [
          field,
          conformance.request[field],
        ]),
      ),
    );
  });

  it('coalesces concurrent acquisition', async () => {
    const { issuer, forms } = await providerServer();
    const provider = clientCredentials({ issuer, clientId: 'client', clientSecret: 'secret' });
    expect(await Promise.all(Array.from({ length: 12 }, () => provider.getToken()))).toEqual(Array(12).fill('token-1'));
    expect(forms).toHaveLength(1);
  });

  it('renews inside the leeway instead of returning a stale token', async () => {
    const { issuer, forms } = await providerServer(30);
    const provider = clientCredentials({ issuer, clientId: 'client', clientSecret: 'secret' });
    expect(await provider.getToken()).toBe('token-1');
    expect(await provider.getToken()).toBe('token-2');
    expect(forms).toHaveLength(2);
  });

  it.each(conformance.expiry.invalid_expires_in)('rejects invalid expires_in value %j', async (expiresIn) => {
    const { issuer } = await providerServer(expiresIn);
    const provider = clientCredentials({ issuer, clientId: 'client', clientSecret: 'secret' });
    await expect(provider.getToken()).rejects.toThrow(/positive finite expires_in/);
  });

  it.each(conformance.discovery.redirect_statuses)('refuses discovery redirect status %i', async (status) => {
    let issuer = '';
    let redirected = false;
    const server = createServer((req, res) => {
      if (req.url === '/redirected') redirected = true;
      res.writeHead(status, { location: `${issuer}/redirected` });
      res.end();
    });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('missing address');
    issuer = `http://127.0.0.1:${address.port}`;
    const provider = clientCredentials({ issuer, clientId: 'client', clientSecret: 'secret' });
    await expect(provider.getToken()).rejects.toThrow(new RegExp(`HTTP ${status}`));
    expect(redirected).toBe(false);
  });

  it.each(conformance.discovery.redirect_statuses)('refuses token redirect status %i', async (status) => {
    let issuer = '';
    let redirected = false;
    const server = createServer((req, res) => {
      if (req.url === '/.well-known/openid-configuration') {
        res.end(JSON.stringify({ issuer, token_endpoint: `${issuer}/token` }));
        return;
      }
      if (req.url === '/redirected') redirected = true;
      res.writeHead(status, { location: `${issuer}/redirected` });
      res.end();
    });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('missing address');
    issuer = `http://127.0.0.1:${address.port}`;
    const provider = clientCredentials({ issuer, clientId: 'client', clientSecret: 'secret' });
    await expect(provider.getToken()).rejects.toThrow(new RegExp(`HTTP ${status}`));
    expect(redirected).toBe(false);
  });

  it('rejects a mismatched discovery issuer', async () => {
    let issuer = '';
    const server = createServer((_req, res) => {
      res.end(
        JSON.stringify({
          issuer: conformance.discovery.mismatched_issuer,
          token_endpoint: `${issuer}/token`,
        }),
      );
    });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('missing address');
    issuer = `http://127.0.0.1:${address.port}`;
    const provider = clientCredentials({ issuer, clientId: 'client', clientSecret: 'secret' });
    await expect(provider.getToken()).rejects.toThrow(/issuer mismatch/);
  });

  it('rejects responses larger than the shared bound', async () => {
    let issuer = '';
    const server = createServer((req, res) => {
      if (req.url === '/.well-known/openid-configuration') {
        res.end('x'.repeat(conformance.limits.max_response_bytes + 1));
        return;
      }
      res.end(JSON.stringify({ issuer, token_endpoint: `${issuer}/token` }));
    });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('missing address');
    issuer = `http://127.0.0.1:${address.port}`;
    const provider = clientCredentials({ issuer, clientId: 'client', clientSecret: 'secret' });
    await expect(provider.getToken()).rejects.toThrow(/too large/);
  });

  it('times out while reading a stalled body and retries cleanly', async () => {
    let issuer = '';
    let discoveryCalls = 0;
    const server = createServer((req, res) => {
      if (req.url === '/.well-known/openid-configuration') {
        discoveryCalls += 1;
        if (discoveryCalls === 1) {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.write('{"issuer":');
          return;
        }
        res.end(JSON.stringify({ issuer, token_endpoint: `${issuer}/token` }));
        return;
      }
      res.end(JSON.stringify({ access_token: 'recovered', expires_in: 120 }));
    });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('missing address');
    issuer = `http://127.0.0.1:${address.port}`;
    const provider = clientCredentials({ issuer, clientId: 'client', clientSecret: 'secret', timeoutMs: 100 });

    await expect(provider.getToken()).rejects.toThrow(/discovery request timed out/);
    await expect(provider.getToken()).resolves.toBe('recovered');
    expect(discoveryCalls).toBe(2);
  });

  it('lets one waiter cancel without canceling the shared exchange', async () => {
    let issuer = '';
    let releaseToken!: () => void;
    let markStarted!: () => void;
    const release = new Promise<void>((resolve) => (releaseToken = resolve));
    const started = new Promise<void>((resolve) => (markStarted = resolve));
    const server = createServer(async (req, res) => {
      if (req.url === '/.well-known/openid-configuration') {
        res.end(JSON.stringify({ issuer, token_endpoint: `${issuer}/token` }));
        return;
      }
      markStarted();
      await release;
      res.end(JSON.stringify({ access_token: 'shared', expires_in: 120 }));
    });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('missing address');
    issuer = `http://127.0.0.1:${address.port}`;
    const provider = clientCredentials({ issuer, clientId: 'client', clientSecret: 'secret' });
    const controller = new AbortController();
    const canceled = provider.getToken(controller.signal);
    await started;
    const remaining = provider.getToken();
    controller.abort();
    await expect(canceled).rejects.toThrow(/canceled/);
    releaseToken();
    await expect(remaining).resolves.toBe('shared');
  });

  it('rejects remote plaintext and redacts supplier errors', async () => {
    expect(() => clientCredentials({ issuer: 'http://example.com', clientId: 'c', clientSecret: 's' })).toThrow(
      /HTTPS/,
    );
    const { issuer } = await providerServer();
    const provider = clientCredentials({
      issuer,
      clientId: 'client',
      clientSecret: () => {
        throw new Error('supplier-sensitive-detail');
      },
    });
    await expect(provider.getToken()).rejects.not.toThrow(/supplier-sensitive-detail/);
  });
});
