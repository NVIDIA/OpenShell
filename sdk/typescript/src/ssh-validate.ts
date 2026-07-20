// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Trust-boundary validation for CreateSshSession responses. The gateway's
// values are interpolated into an OpenSSH `ProxyCommand` that OpenSSH runs
// through `/bin/sh -c` on the caller's workstation, so proto/openshell.proto
// (CreateSshSessionResponse) says clients MUST reject responses outside the
// specified character sets and ranges. This enforces exactly that contract at
// the SDK edge so no consumer has to rediscover the invariant.

import { SdkError } from './errors.js';

// Charsets and bounds mirror the proto CreateSshSessionResponse field comments.
const SANDBOX_ID = /^[A-Za-z0-9._-]{1,128}$/;
const TOKEN = /^[A-Za-z0-9._~+/=-]+$/;
const GATEWAY_HOST = /^[A-Za-z0-9.\-:[\]]+$/;
const FINGERPRINT = /^[A-Za-z0-9:+/=-]+$/;

/** The subset of the response the SDK validates and forwards. */
export interface SshResponseFields {
  sandboxId: string;
  token: string;
  gatewayHost: string;
  gatewayPort: number;
  gatewayScheme: string;
  hostKeyFingerprint: string;
}

function reject(field: string, detail: string): never {
  throw new SdkError('invalid_config', `CreateSshSession response ${field} ${detail}`);
}

// Throw SdkError('invalid_config') if any field violates the proto contract.
export function validateSshResponse(resp: SshResponseFields): void {
  if (!SANDBOX_ID.test(resp.sandboxId)) {
    reject('sandbox_id', 'must match [A-Za-z0-9._-]{1,128}');
  }

  const tokenBytes = Buffer.byteLength(resp.token, 'utf8');
  if (tokenBytes < 1 || tokenBytes > 4096 || !TOKEN.test(resp.token)) {
    reject('token', 'must be 1..4096 bytes of [A-Za-z0-9._~+/=-]');
  }

  const hostBytes = Buffer.byteLength(resp.gatewayHost, 'utf8');
  if (hostBytes < 1 || hostBytes > 253 || !GATEWAY_HOST.test(resp.gatewayHost)) {
    reject('gateway_host', 'must be 1..253 bytes of [A-Za-z0-9.-:[]]');
  }

  if (!Number.isInteger(resp.gatewayPort) || resp.gatewayPort < 1 || resp.gatewayPort > 65535) {
    reject('gateway_port', 'must be an integer in 1..65535');
  }

  if (resp.gatewayScheme !== 'http' && resp.gatewayScheme !== 'https') {
    reject('gateway_scheme', "must be exactly 'http' or 'https'");
  }

  if (resp.hostKeyFingerprint !== '' && !FINGERPRINT.test(resp.hostKeyFingerprint)) {
    reject('host_key_fingerprint', 'must match [A-Za-z0-9:+/=-] when non-empty');
  }
}
