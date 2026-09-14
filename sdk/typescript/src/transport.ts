// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Transport + auth layer. h2c for `http://` (local dev), Node TLS passthrough
// for `https://` (CA pinning, insecure-skip-verify), and an interceptor that
// attaches the OIDC bearer or Cloudflare Access headers.
//
// Not covered here: the Cloudflare-Access WebSocket tunnel (the gateway's edge
// proxy). That ships as a language-agnostic sidecar bound to 127.0.0.1 — point
// `gateway` at it. When the edge passes gRPC POST directly, the header mode
// below suffices.

import type { Interceptor, Transport } from '@connectrpc/connect';
import { createGrpcTransport } from '@connectrpc/connect-node';
import { SdkError } from './errors.js';
import type { OidcTokenProvider } from './oidc.js';

export interface ConnectOptions {
  /** Gateway URL (`http://...` or `https://...`). */
  gateway: string;
  /** CA certificate (PEM). Omit to use system roots. */
  caCert?: Buffer;
  /**
   * Client certificate (PEM) for mTLS. Authenticates the CALLER, not just the
   * server. The default local OpenShell gateway (Docker, VM, Homebrew, Linux
   * package) requires this. Must be paired with clientKey.
   */
  clientCert?: Buffer;
  /** Client private key (PEM) for mTLS. Must be paired with clientCert. */
  clientKey?: Buffer;
  /** Bearer token for direct OIDC auth. Mutually exclusive with edgeToken. */
  oidcToken?: string;
  /** Renewable OIDC bearer provider. Mutually exclusive with oidcToken and edgeToken. */
  oidcTokenProvider?: OidcTokenProvider;
  /** Cloudflare Access token. See the sidecar note above for CF-fronted gateways. */
  edgeToken?: string;
  /** Disable TLS verification (dev/debug only). */
  insecureSkipVerify?: boolean;
  /**
   * Permit sending an auth token (oidcToken/oidcTokenProvider/edgeToken) over
   * plaintext `http://` to a non-loopback host. Off by default: tokens over
   * cleartext to a remote host leak credentials on the wire. Loopback hosts are
   * always allowed.
   */
  allowInsecureAuth?: boolean;
}

// OIDC bearer takes precedence; otherwise attach the Cloudflare Access header +
// cookie. No-op when neither token is set.
/** @internal Exported for transport contract tests; not part of the package root API. */
export function authInterceptor(opts: ConnectOptions): Interceptor {
  return (next) => async (req) => {
    if (opts.oidcTokenProvider) {
      req.header.set('authorization', `Bearer ${await opts.oidcTokenProvider.getToken(req.signal)}`);
    } else if (opts.oidcToken) {
      req.header.set('authorization', `Bearer ${opts.oidcToken}`);
    } else if (opts.edgeToken) {
      req.header.set('cf-access-jwt-assertion', opts.edgeToken);
      req.header.set('cookie', `CF_Authorization=${opts.edgeToken}`);
    }
    return next(req);
  };
}

// The client certificate and key are an all-or-nothing pair: a cert without a
// key (or a key without a cert) cannot complete an mTLS handshake, so reject it
// up front rather than surfacing an opaque TLS failure at connect time.
function assertMtlsPair(opts: ConnectOptions): void {
  const hasCert = opts.clientCert !== undefined;
  const hasKey = opts.clientKey !== undefined;
  if (hasCert !== hasKey) {
    const missing = hasCert ? 'clientKey' : 'clientCert';
    throw new SdkError('invalid_config', `mTLS requires both clientCert and clientKey; ${missing} is missing`);
  }
}

// oidcToken and edgeToken are documented as mutually exclusive; the interceptor
// silently prefers OIDC when both are set. Reject that ambiguity up front so a
// caller does not think an edge token is in effect when it is being ignored.
function assertTokenExclusivity(opts: ConnectOptions): void {
  const configured = [opts.oidcToken, opts.oidcTokenProvider, opts.edgeToken].filter(
    (value) => value !== undefined,
  ).length;
  if (configured > 1) {
    throw new SdkError('invalid_config', 'oidcToken, oidcTokenProvider, and edgeToken are mutually exclusive');
  }
}

// edgeToken is also interpolated into a Cookie header. Restrict it to the
// cookie-safe base64url/JWT character set so a caller cannot inject a second
// cookie or a new header through an untrusted token value.
function assertEdgeToken(opts: ConnectOptions): void {
  if (opts.edgeToken !== undefined && !/^[A-Za-z0-9._~-]+$/.test(opts.edgeToken)) {
    throw new SdkError('invalid_config', 'edgeToken must contain only cookie-safe JWT characters');
  }
}

function isLoopbackHost(host: string): boolean {
  // URL.hostname keeps the brackets on IPv6 literals (e.g. `[::1]`); strip them.
  const h = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
  if (h === 'localhost' || h === '::1') return true;
  return /^127(?:\.\d{1,3}){3}$/.test(h);
}

// Attaching a bearer/CF token to a plaintext `http://` request to a non-loopback
// host puts the credential on the wire in the clear. Refuse it unless the caller
// explicitly opts in. Loopback (local-dev / edge-sidecar) is always fine.
function assertTokenTransportSecurity(opts: ConnectOptions): void {
  const hasToken = opts.oidcToken !== undefined || opts.oidcTokenProvider !== undefined || opts.edgeToken !== undefined;
  if (!hasToken || opts.allowInsecureAuth || opts.gateway.startsWith('https://')) return;
  let host: string;
  try {
    host = new URL(opts.gateway).hostname;
  } catch {
    return; // A malformed gateway URL surfaces from the transport itself.
  }
  if (!isLoopbackHost(host)) {
    throw new SdkError(
      'invalid_config',
      `refusing to send an auth token over plaintext http:// to non-loopback host '${host}'; use https:// or set allowInsecureAuth`,
    );
  }
}

export function buildTransport(opts: ConnectOptions): Transport {
  assertMtlsPair(opts);
  assertTokenExclusivity(opts);
  assertEdgeToken(opts);
  assertTokenTransportSecurity(opts);
  const isTls = opts.gateway.startsWith('https://');
  return createGrpcTransport({
    baseUrl: opts.gateway,
    interceptors: [authInterceptor(opts)],
    // For https:// gateways, pass Node TLS options straight through. For
    // http:// (local dev) these are ignored and the client speaks h2c.
    nodeOptions: isTls
      ? {
          ca: opts.caCert,
          cert: opts.clientCert,
          key: opts.clientKey,
          rejectUnauthorized: opts.insecureSkipVerify ? false : undefined,
        }
      : undefined,
  });
}
