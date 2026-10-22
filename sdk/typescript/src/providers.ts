// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { type Client, createClient, type Transport } from '@connectrpc/connect';
import { fromConnect, SdkError } from './errors.js';
import { OpenShell } from './gen/openshell_pb.js';
import { buildTransport, type ConnectOptions } from './transport.js';

/** An exported runtime secret. Never log or serialize it into shared output. */
export interface ProviderCredentialValue {
  value: string;
  /** Absent for non-expiring values; sub-millisecond precision is truncated. */
  expirationTime?: Date;
}

export interface ProviderCredentialsOptions {
  /** Required explicit workspace. There is no implicit default or all-workspaces export. */
  workspace: string;
  /** Omitted or zero uses the gateway's five-minute margin. Maximum: 24 hours. */
  minimumRemainingLifetimeSecs?: number;
  /** Abort delivery. An already-started gateway refresh can still commit. */
  signal?: AbortSignal;
  /** Deadline for this RPC in milliseconds. */
  timeoutMs?: number;
}

/** Provider operations over a shared transport; no sandbox is required. */
export class ProviderClient {
  readonly raw: Client<typeof OpenShell>;
  readonly transport: Transport;

  constructor(transport: Transport) {
    this.transport = transport;
    this.raw = createClient(OpenShell, transport);
  }

  /**
   * Use direct gateway HTTPS with a trusted OU=operator client certificate/key
   * and no OIDC or edge token. Operator authentication must be enabled at the gateway.
   */
  static async connect(options: ConnectOptions): Promise<ProviderClient> {
    return new ProviderClient(buildTransport(options));
  }

  /**
   * Export exactly the selected runtime keys, or reject without a result.
   * Requires direct operator mTLS. The gateway refreshes eligible missing or
   * short-lived outputs, never exports private refresh inputs, and may commit
   * refresh effects even if delivery fails. This helper does not retry or cache.
   */
  async getCredentials(
    name: string,
    credentialKeys: readonly string[],
    options: ProviderCredentialsOptions,
  ): Promise<Record<string, ProviderCredentialValue>> {
    if (!options?.workspace || options.workspace.trim() !== options.workspace) {
      throw new SdkError('invalid_config', 'an explicit canonical workspace is required');
    }
    if (!name || name.trim() !== name || new TextEncoder().encode(name).byteLength > 253) {
      throw new SdkError('invalid_config', 'a canonical provider name is required');
    }
    // Copy before awaiting, so caller mutation cannot affect response validation.
    const keys = [...credentialKeys];
    if (
      !Array.isArray(credentialKeys) ||
      keys.length < 1 ||
      keys.length > 32 ||
      keys.some((key) => key.length > 256 || key.trim() !== key || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) ||
      new Set(keys).size !== keys.length
    ) {
      throw new SdkError('invalid_config', 'select between 1 and 32 unique runtime environment keys');
    }
    const lifetime = options.minimumRemainingLifetimeSecs;
    if (lifetime !== undefined && (!Number.isFinite(lifetime) || lifetime < 0 || lifetime > 86400)) {
      throw new SdkError('invalid_config', 'minimumRemainingLifetimeSecs must be between zero and 24 hours');
    }
    if (options.timeoutMs !== undefined && (!Number.isFinite(options.timeoutMs) || options.timeoutMs <= 0)) {
      throw new SdkError('invalid_config', 'timeoutMs must be finite and positive');
    }
    // Round up to nanoseconds rather than silently weakening a fractional margin.
    const nanos = lifetime === undefined ? undefined : Math.ceil(lifetime * 1e9);
    try {
      const response = await this.raw.getProviderCredentials(
        {
          workspaceScope: { selection: { case: 'workspace', value: options.workspace } },
          name,
          credentialKeys: keys,
          minimumRemainingLifetime:
            nanos === undefined ? undefined : { seconds: BigInt(Math.floor(nanos / 1e9)), nanos: nanos % 1e9 },
        },
        { signal: options.signal, timeoutMs: options.timeoutMs },
      );
      const returned = Object.entries(response.credentials);
      if (returned.length !== keys.length || returned.some(([key]) => !keys.includes(key))) {
        throw new SdkError('rpc', 'gateway returned an unexpected credential selection');
      }
      return Object.fromEntries(
        returned.map(([key, credential]) => {
          const expiration = credential.expirationTime;
          // Keep an explicit Unix epoch and truncate rather than round up expiry.
          const expirationTime = expiration
            ? new Date(Number(expiration.seconds) * 1000 + Math.floor(expiration.nanos / 1e6))
            : undefined;
          return [key, { value: credential.value, ...(expirationTime ? { expirationTime } : {}) }];
        }),
      );
    } catch (error) {
      throw fromConnect(error);
    }
  }
}
