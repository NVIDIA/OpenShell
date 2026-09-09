// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { isIP } from 'node:net';
import { SdkError } from './errors.js';

const EXPIRY_LEEWAY_MS = 30_000;
const MAX_RESPONSE_BYTES = 1 << 20;

export interface OidcTokenProvider {
  getToken(signal?: AbortSignal): Promise<string>;
}

export interface ClientCredentialsOptions {
  issuer: string;
  clientId: string;
  clientSecret: string | (() => string | Promise<string>);
  scopes?: readonly string[];
  audience?: string;
  /** Timeout for each complete discovery or token response, including its body. */
  timeoutMs?: number;
}

interface CachedToken {
  accessToken: string;
  expiresAt: number;
}

function isLoopback(hostname: string): boolean {
  const host = hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;
  if (host.toLowerCase() === 'localhost' || host === '::1') return true;
  if (isIP(host) === 4) return host.startsWith('127.');
  return false;
}

function secureUrl(name: string, raw: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new SdkError('invalid_config', `invalid OAuth ${name} URL`);
  }
  if (url.username || url.password || url.hash) {
    throw new SdkError('invalid_config', `OAuth ${name} URL must not contain userinfo or a fragment`);
  }
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLoopback(url.hostname))) {
    throw new SdkError('invalid_config', `OAuth ${name} URL must use HTTPS (HTTP is allowed only for loopback hosts)`);
  }
  return url;
}

function withoutTrailingSlash(raw: string): string {
  return raw.replace(/\/+$/, '');
}

async function boundedJson(response: Response, kind: string): Promise<Record<string, unknown>> {
  if (!response.body) throw new SdkError('auth', `OAuth ${kind} returned an empty response`);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      throw new SdkError('auth', `OAuth ${kind} response is too large`);
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    const value: unknown = JSON.parse(new TextDecoder().decode(bytes));
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('not an object');
    return value as Record<string, unknown>;
  } catch {
    throw new SdkError('auth', `OAuth ${kind} returned invalid JSON`);
  }
}

function waitFor<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) return promise;
  if (signal.aborted) return Promise.reject(new SdkError('canceled', 'OAuth token request was canceled'));
  return new Promise<T>((resolve, reject) => {
    const canceled = () => reject(new SdkError('canceled', 'OAuth token request was canceled'));
    signal.addEventListener('abort', canceled, { once: true });
    promise.then(resolve, reject).finally(() => signal.removeEventListener('abort', canceled));
  });
}

class ClientCredentialsProvider implements OidcTokenProvider {
  readonly #options: ClientCredentialsOptions;
  readonly #issuer: string;
  #tokenEndpoint?: string;
  #cached?: CachedToken;
  #inFlight?: Promise<string>;

  constructor(options: ClientCredentialsOptions) {
    if (!options.clientId) throw new SdkError('invalid_config', 'OAuth clientId is required');
    if (typeof options.clientSecret === 'string' && !options.clientSecret) {
      throw new SdkError('invalid_config', 'OAuth clientSecret must not be empty');
    }
    this.#issuer = withoutTrailingSlash(secureUrl('issuer', options.issuer).toString());
    this.#options = { ...options, scopes: options.scopes ? [...options.scopes] : undefined };
  }

  async getToken(signal?: AbortSignal): Promise<string> {
    if (this.#cached && Date.now() + EXPIRY_LEEWAY_MS < this.#cached.expiresAt) return this.#cached.accessToken;
    if (!this.#inFlight) {
      this.#inFlight = this.#exchange().finally(() => {
        this.#inFlight = undefined;
      });
    }
    return waitFor(this.#inFlight, signal);
  }

  async #secret(): Promise<string> {
    try {
      const value =
        typeof this.#options.clientSecret === 'string'
          ? this.#options.clientSecret
          : await this.#options.clientSecret();
      if (!value) throw new Error('empty');
      return value;
    } catch {
      throw new SdkError('auth', 'OAuth client secret supplier failed');
    }
  }

  async #requestJson(
    url: string,
    init: RequestInit,
    responseKind: string,
    operation: string,
  ): Promise<Record<string, unknown>> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.#options.timeoutMs ?? 30_000);
    try {
      const response = await fetch(url, { ...init, redirect: 'manual', signal: controller.signal });
      if (response.status !== 200) {
        await response.body?.cancel();
        throw new SdkError('auth', `OAuth ${operation} failed with HTTP ${response.status}`);
      }
      return await boundedJson(response, responseKind);
    } catch (error) {
      if (error instanceof SdkError) throw error;
      if (controller.signal.aborted) {
        throw new SdkError('auth', `OAuth ${operation} request timed out`);
      }
      throw new SdkError('auth', 'OAuth client credentials request failed');
    } finally {
      clearTimeout(timeout);
    }
  }

  async #exchange(): Promise<string> {
    if (!this.#tokenEndpoint) {
      const discovery = await this.#requestJson(
        `${this.#issuer}/.well-known/openid-configuration`,
        { headers: { accept: 'application/json' } },
        'discovery',
        'discovery',
      );
      if (typeof discovery.issuer !== 'string' || withoutTrailingSlash(discovery.issuer) !== this.#issuer) {
        throw new SdkError('auth', 'OAuth discovery issuer mismatch');
      }
      if (typeof discovery.token_endpoint !== 'string') {
        throw new SdkError('auth', 'OAuth discovery document is missing token_endpoint');
      }
      this.#tokenEndpoint = secureUrl('token endpoint', discovery.token_endpoint).toString();
    }

    const form = new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: this.#options.clientId,
      client_secret: await this.#secret(),
    });
    if (this.#options.scopes?.length) form.set('scope', this.#options.scopes.join(' '));
    if (this.#options.audience) form.set('audience', this.#options.audience);
    const token = await this.#requestJson(
      this.#tokenEndpoint,
      {
        method: 'POST',
        headers: { accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded' },
        body: form,
      },
      'client credentials response',
      'client credentials exchange',
    );
    if (typeof token.access_token !== 'string' || !token.access_token) {
      throw new SdkError('auth', 'OAuth client credentials response is missing access_token');
    }
    if (typeof token.expires_in !== 'number' || !Number.isFinite(token.expires_in) || token.expires_in <= 0) {
      throw new SdkError('auth', 'OAuth client credentials response requires a positive finite expires_in');
    }
    this.#cached = { accessToken: token.access_token, expiresAt: Date.now() + token.expires_in * 1000 };
    return token.access_token;
  }
}

export function clientCredentials(options: ClientCredentialsOptions): OidcTokenProvider {
  return new ClientCredentialsProvider(options);
}
