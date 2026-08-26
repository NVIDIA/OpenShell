// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import type { Client, Transport } from '@connectrpc/connect';
import { createClient } from '@connectrpc/connect';
import { fromConnect, SdkError } from './errors.js';
import type { Provider as ProtoProvider } from './gen/datamodel_pb.js';
import { OpenShell } from './gen/openshell_pb.js';
import { buildTransport, type ConnectOptions } from './transport.js';

/** Secret and non-secret values used to create or update a provider. */
export interface ProviderDefinition {
  name: string;
  type: string;
  labels?: Record<string, string>;
  annotations?: Record<string, string>;
  /** Secret values. Responses never return their plaintext values. */
  credentials?: Record<string, string>;
  config?: Record<string, string>;
  /** Milliseconds since Unix epoch, represented as strings to preserve int64 precision. Zero removes an expiry. */
  credentialExpiresAtMs?: Record<string, string>;
  profileWorkspace?: string;
  /** Optimistic-concurrency version, represented as a string to preserve uint64 precision. */
  resourceVersion?: string;
}

/** A provider returned by the gateway. Credential plaintext is intentionally absent. */
export interface ProviderRecord {
  id: string;
  name: string;
  type: string;
  labels: Record<string, string>;
  annotations: Record<string, string>;
  workspace: string;
  resourceVersion: string;
  createdAtMs: string;
  deletionTimestampMs?: string;
  config: Record<string, string>;
  credentialExpiresAtMs: Record<string, string>;
  profileWorkspace: string;
}

export interface ProviderListOptions {
  limit?: number;
  offset?: number;
  /** List every workspace. Mutually exclusive with a non-empty workspace. */
  allWorkspaces?: boolean;
}

function integer(value: string | undefined, field: string): bigint {
  if (!value) return 0n;
  let parsed: bigint;
  try {
    parsed = BigInt(value);
  } catch {
    throw new SdkError('invalid_config', `${field} is not an integer: '${value}'`);
  }
  if (parsed < 0n) throw new SdkError('invalid_config', `${field} must not be negative: '${value}'`);
  return parsed;
}

function providerMessage(provider: ProviderDefinition): ProtoProvider {
  if (!provider.name.trim()) throw new SdkError('invalid_config', 'provider.name is required');
  if (!provider.type.trim()) throw new SdkError('invalid_config', 'provider.type is required');

  return {
    $typeName: 'openshell.datamodel.v1.Provider',
    metadata: {
      $typeName: 'openshell.datamodel.v1.ObjectMeta',
      id: '',
      name: provider.name,
      createdAtMs: 0n,
      labels: provider.labels ?? {},
      resourceVersion: integer(provider.resourceVersion, 'provider.resourceVersion'),
      annotations: provider.annotations ?? {},
      workspace: '',
      deletionTimestampMs: 0n,
    },
    type: provider.type,
    credentials: provider.credentials ?? {},
    config: provider.config ?? {},
    credentialExpiresAtMs: Object.fromEntries(
      Object.entries(provider.credentialExpiresAtMs ?? {}).map(([name, value]) => [
        name,
        integer(value, `provider.credentialExpiresAtMs.${name}`),
      ]),
    ),
    profileWorkspace: provider.profileWorkspace ?? '',
    credentialHandles: {},
  };
}

function providerRecord(provider: ProtoProvider | undefined): ProviderRecord {
  const meta = provider?.metadata;
  if (!provider || !meta?.id || !meta.name) {
    throw new SdkError('invalid_config', 'provider metadata.id and metadata.name are required in gateway responses');
  }
  return {
    id: meta.id,
    name: meta.name,
    type: provider.type,
    labels: meta.labels,
    annotations: meta.annotations,
    workspace: meta.workspace,
    resourceVersion: meta.resourceVersion.toString(),
    createdAtMs: meta.createdAtMs.toString(),
    ...(meta.deletionTimestampMs ? { deletionTimestampMs: meta.deletionTimestampMs.toString() } : {}),
    config: provider.config,
    credentialExpiresAtMs: Object.fromEntries(
      Object.entries(provider.credentialExpiresAtMs).map(([name, value]) => [name, value.toString()]),
    ),
    profileWorkspace: provider.profileWorkspace,
  };
}

/** Curated provider CRUD and credential-update API over the shared authenticated transport. */
export class ProviderClient {
  private readonly grpc: Client<typeof OpenShell>;
  readonly raw: Client<typeof OpenShell>;
  readonly transport: Transport;

  constructor(transport: Transport, grpc = createClient(OpenShell, transport)) {
    this.transport = transport;
    this.grpc = grpc;
    this.raw = grpc;
  }

  static async connect(options: ConnectOptions): Promise<ProviderClient> {
    return new ProviderClient(buildTransport(options));
  }

  async create(workspace: string, provider: ProviderDefinition): Promise<ProviderRecord> {
    try {
      const response = await this.grpc.createProvider({ workspace, provider: providerMessage(provider) });
      return providerRecord(response.provider);
    } catch (error) {
      throw fromConnect(error);
    }
  }

  async get(workspace: string, name: string): Promise<ProviderRecord> {
    try {
      const response = await this.grpc.getProvider({ workspace, name });
      return providerRecord(response.provider);
    } catch (error) {
      throw fromConnect(error);
    }
  }

  async list(workspace: string, options?: ProviderListOptions | null): Promise<ProviderRecord[]> {
    if ((options?.limit ?? 0) < 0) throw new SdkError('invalid_config', 'limit must not be negative');
    if ((options?.offset ?? 0) < 0) throw new SdkError('invalid_config', 'offset must not be negative');
    if (options?.allWorkspaces && workspace) {
      throw new SdkError('invalid_config', 'allWorkspaces is mutually exclusive with a non-empty workspace');
    }
    try {
      const response = await this.grpc.listProviders({
        workspace,
        limit: options?.limit ?? 0,
        offset: options?.offset ?? 0,
        allWorkspaces: options?.allWorkspaces ?? false,
      });
      return response.providers.map(providerRecord);
    } catch (error) {
      throw fromConnect(error);
    }
  }

  /** Merge credentials, credential expiries, and config into an existing provider. */
  async update(workspace: string, provider: ProviderDefinition): Promise<ProviderRecord> {
    try {
      const message = providerMessage(provider);
      const response = await this.grpc.updateProvider({
        workspace,
        provider: message,
        credentialExpiresAtMs: message.credentialExpiresAtMs,
      });
      return providerRecord(response.provider);
    } catch (error) {
      throw fromConnect(error);
    }
  }

  async delete(workspace: string, name: string): Promise<boolean> {
    try {
      const response = await this.grpc.deleteProvider({ workspace, name });
      return response.deleted;
    } catch (error) {
      throw fromConnect(error);
    }
  }

  /** Create the provider when absent; otherwise update it with optimistic concurrency. */
  async ensure(workspace: string, provider: ProviderDefinition): Promise<ProviderRecord> {
    let existing: ProviderRecord;
    try {
      existing = await this.get(workspace, provider.name);
    } catch (error) {
      if (error instanceof SdkError && error.code === 'not_found') return this.create(workspace, provider);
      throw error;
    }
    return this.update(workspace, { ...provider, resourceVersion: existing.resourceVersion });
  }
}
