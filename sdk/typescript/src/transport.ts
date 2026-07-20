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
  /** Cloudflare Access token. See the sidecar note above for CF-fronted gateways. */
  edgeToken?: string;
  /** Disable TLS verification (dev/debug only). */
  insecureSkipVerify?: boolean;
}

// OIDC bearer takes precedence; otherwise attach the Cloudflare Access header +
// cookie. No-op when neither token is set.
function authInterceptor(opts: ConnectOptions): Interceptor {
  return (next) => async (req) => {
    if (opts.oidcToken) {
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

export function buildTransport(opts: ConnectOptions): Transport {
  assertMtlsPair(opts);
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
