// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import type { ClientUnaryCall, ServiceError } from "@grpc/grpc-js";
import {
  ApproveAllDraftChunksRequest,
  ApproveAllDraftChunksResponse,
  ApproveDraftChunkRequest,
  ApproveDraftChunkResponse,
  CreateSandboxRequest,
  CreateSshSessionResponse,
  DeleteProviderRequest,
  DeleteProviderResponse,
  DeleteSandboxRequest,
  DeleteSandboxResponse,
  DetachSandboxProviderRequest,
  DetachSandboxProviderResponse,
  ExecSandboxEvent,
  ExecSandboxRequest,
  GetDraftPolicyRequest,
  GetDraftPolicyResponse,
  GetProviderRequest,
  GetSandboxRequest,
  ListProvidersRequest,
  ListProvidersResponse,
  ListSandboxesRequest,
  ListSandboxesResponse,
  OpenShellClient as OpenShellStub,
  ProviderResponse,
  RejectDraftChunkRequest,
  RejectDraftChunkResponse,
  Sandbox,
  SandboxPhase,
  SandboxResponse,
  SandboxSpec,
  UpdateProviderRequest,
} from "./_proto/openshell";
import { Provider } from "./_proto/datamodel";
import { makeChannelCredentials, TlsConfig } from "./tls";

export { SandboxPhase, SandboxSpec, Sandbox };

export interface SandboxRef {
  id: string;
  name: string;
  phase: SandboxPhase;
}

export interface ExecChunk {
  stream: "stdout" | "stderr";
  data: Buffer;
}

export interface ExecResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export interface ProviderRef {
  id: string;
  name: string;
  type: string;
}

export class SandboxError extends Error {
  readonly cause?: ServiceError;
  constructor(message: string, cause?: ServiceError) {
    super(message);
    this.name = "SandboxError";
    this.cause = cause;
  }
}

export interface SandboxClientOptions {
  tls?: TlsConfig;
  timeoutMs?: number;
}

function sandboxToRef(s: Sandbox): SandboxRef {
  return {
    id: s.metadata?.id ?? "",
    name: s.metadata?.name ?? "",
    phase: s.phase,
  };
}

function providerToRef(p: Provider): ProviderRef {
  return {
    id: p.metadata?.id ?? "",
    name: p.metadata?.name ?? "",
    type: p.type,
  };
}

function callUnary<Req, Res>(
  fn: (req: Req, cb: (err: ServiceError | null, res: Res) => void) => ClientUnaryCall,
  req: Req
): Promise<Res> {
  return new Promise((resolve, reject) => {
    fn(req, (err, res) => {
      if (err) reject(new SandboxError(err.message, err));
      else resolve(res);
    });
  });
}

export class SandboxClient {
  readonly stub: OpenShellStub;
  readonly _tls: TlsConfig | undefined;

  constructor(grpcTarget: string, options: SandboxClientOptions = {}) {
    this._tls = options.tls;
    const creds = makeChannelCredentials(options.tls);
    this.stub = new OpenShellStub(grpcTarget, creds);
  }

  static fromEnv(): SandboxClient {
    const endpoint = process.env["OPENSHELL_GATEWAY_ENDPOINT"] ?? "127.0.0.1:8080";
    const insecure = (process.env["OPENSHELL_GATEWAY_INSECURE"] ?? "true") !== "false";

    let tls: TlsConfig | undefined;
    if (!insecure) {
      const ca = process.env["OPENSHELL_TLS_CA_PATH"];
      const cert = process.env["OPENSHELL_TLS_CERT_PATH"];
      const key = process.env["OPENSHELL_TLS_KEY_PATH"];
      if (ca && cert && key) tls = { caPath: ca, certPath: cert, keyPath: key };
    }

    // Strip scheme if present — grpc-js wants host:port
    const target = endpoint.replace(/^https?:\/\//, "");
    return new SandboxClient(target, { tls });
  }

  close(): void {
    this.stub.close();
  }

  // ── Sandbox CRUD ────────────────────────────────────────────────────────────

  async create(spec: SandboxSpec, name = "", labels: Record<string, string> = {}): Promise<SandboxRef> {
    const req: CreateSandboxRequest = { spec, name, labels };
    const res = await callUnary<CreateSandboxRequest, SandboxResponse>(
      (r, cb) => this.stub.createSandbox(r, cb),
      req
    );
    if (!res.sandbox) throw new SandboxError("createSandbox returned empty response");
    return sandboxToRef(res.sandbox);
  }

  async get(name: string): Promise<Sandbox> {
    const req: GetSandboxRequest = { name };
    const res = await callUnary<GetSandboxRequest, SandboxResponse>(
      (r, cb) => this.stub.getSandbox(r, cb),
      req
    );
    if (!res.sandbox) throw new SandboxError(`sandbox '${name}' not found`);
    return res.sandbox;
  }

  async list(options: { limit?: number; offset?: number; labelSelector?: string } = {}): Promise<SandboxRef[]> {
    const req: ListSandboxesRequest = {
      limit: options.limit ?? 100,
      offset: options.offset ?? 0,
      labelSelector: options.labelSelector ?? "",
    };
    const res = await callUnary<ListSandboxesRequest, ListSandboxesResponse>(
      (r, cb) => this.stub.listSandboxes(r, cb),
      req
    );
    return res.sandboxes.map(sandboxToRef);
  }

  async delete(name: string): Promise<boolean> {
    const req: DeleteSandboxRequest = { name };
    const res = await callUnary<DeleteSandboxRequest, DeleteSandboxResponse>(
      (r, cb) => this.stub.deleteSandbox(r, cb),
      req
    );
    return res.deleted;
  }

  async waitReady(
    name: string,
    options: { timeoutSeconds?: number; pollIntervalMs?: number } = {}
  ): Promise<void> {
    const deadline = Date.now() + (options.timeoutSeconds ?? 60) * 1000;
    const interval = options.pollIntervalMs ?? 2_000;
    while (Date.now() < deadline) {
      const sandbox = await this.get(name);
      if (sandbox.phase === SandboxPhase.SANDBOX_PHASE_READY) return;
      if (sandbox.phase === SandboxPhase.SANDBOX_PHASE_ERROR) {
        throw new SandboxError(`sandbox '${name}' entered error phase`);
      }
      await sleep(interval);
    }
    throw new SandboxError(`timed out waiting for sandbox '${name}' to become ready`);
  }

  async waitDeleted(
    name: string,
    options: { timeoutSeconds?: number; pollIntervalMs?: number } = {}
  ): Promise<void> {
    const deadline = Date.now() + (options.timeoutSeconds ?? 60) * 1000;
    const interval = options.pollIntervalMs ?? 2_000;
    while (Date.now() < deadline) {
      try {
        await this.get(name);
      } catch (err) {
        if (err instanceof SandboxError) return;
        throw err;
      }
      await sleep(interval);
    }
    throw new SandboxError(`timed out waiting for sandbox '${name}' to be deleted`);
  }

  // ── Execution ───────────────────────────────────────────────────────────────

  execStream(
    sandboxId: string,
    command: string[],
    options: {
      workdir?: string;
      env?: Record<string, string>;
      stdin?: Buffer;
      timeoutSeconds?: number;
    } = {}
  ): AsyncIterable<ExecChunk> {
    const req: ExecSandboxRequest = {
      sandboxId,
      command,
      workdir: options.workdir ?? "",
      environment: options.env ?? {},
      stdin: options.stdin ?? Buffer.alloc(0),
      timeoutSeconds: options.timeoutSeconds ?? 0,
      tty: false,
      cols: 0,
      rows: 0,
    };
    const call = this.stub.execSandbox(req);
    return streamToAsyncIterable(call);
  }

  async exec(
    sandboxId: string,
    command: string[],
    options: {
      workdir?: string;
      env?: Record<string, string>;
      stdin?: Buffer;
      timeoutSeconds?: number;
    } = {}
  ): Promise<ExecResult> {
    let stdout = "";
    let stderr = "";
    let exitCode = 0;

    for await (const chunk of this.execStream(sandboxId, command, options)) {
      if (chunk.stream === "stdout") stdout += chunk.data.toString("utf8");
      else stderr += chunk.data.toString("utf8");
    }

    return { exitCode, stdout, stderr };
  }

  // ── SSH session (used by ForwardManager) ────────────────────────────────────

  async createSshSession(sandboxId: string): Promise<CreateSshSessionResponse> {
    return callUnary<{ sandboxId: string }, CreateSshSessionResponse>(
      (r, cb) => this.stub.createSshSession(r, cb),
      { sandboxId }
    );
  }

  // ── Provider CRUD ───────────────────────────────────────────────────────────

  async createProvider(
    name: string,
    type: string,
    credentials: Record<string, string>,
    config: Record<string, string>
  ): Promise<ProviderRef> {
    const provider: Provider = {
      metadata: { id: "", name, createdAtMs: 0, labels: {}, resourceVersion: 0 },
      type,
      credentials,
      config,
      credentialExpiresAtMs: {},
    };
    const res = await callUnary<{ provider?: Provider }, ProviderResponse>(
      (r, cb) => this.stub.createProvider(r, cb),
      { provider }
    );
    if (!res.provider) throw new SandboxError("createProvider returned empty response");
    return providerToRef(res.provider);
  }

  async getProvider(name: string): Promise<ProviderRef> {
    const res = await callUnary<GetProviderRequest, ProviderResponse>(
      (r, cb) => this.stub.getProvider(r, cb),
      { name }
    );
    if (!res.provider) throw new SandboxError(`provider '${name}' not found`);
    return providerToRef(res.provider);
  }

  async listProviders(options: { limit?: number; offset?: number } = {}): Promise<ProviderRef[]> {
    const req: ListProvidersRequest = {
      limit: options.limit ?? 100,
      offset: options.offset ?? 0,
    };
    const res = await callUnary<ListProvidersRequest, ListProvidersResponse>(
      (r, cb) => this.stub.listProviders(r, cb),
      req
    );
    return res.providers.map(providerToRef);
  }

  async updateProvider(
    name: string,
    type: string,
    credentials: Record<string, string>,
    config: Record<string, string>
  ): Promise<ProviderRef> {
    const provider: Provider = {
      metadata: { id: "", name, createdAtMs: 0, labels: {}, resourceVersion: 0 },
      type,
      credentials,
      config,
      credentialExpiresAtMs: {},
    };
    const req: UpdateProviderRequest = { provider, credentialExpiresAtMs: {} };
    const res = await callUnary<UpdateProviderRequest, ProviderResponse>(
      (r, cb) => this.stub.updateProvider(r, cb),
      req
    );
    if (!res.provider) throw new SandboxError("updateProvider returned empty response");
    return providerToRef(res.provider);
  }

  async deleteProvider(name: string): Promise<boolean> {
    const res = await callUnary<DeleteProviderRequest, DeleteProviderResponse>(
      (r, cb) => this.stub.deleteProvider(r, cb),
      { name }
    );
    return res.deleted;
  }

  async detachSandboxProvider(sandboxName: string, providerName: string): Promise<boolean> {
    const req: DetachSandboxProviderRequest = {
      sandboxName,
      providerName,
      expectedResourceVersion: 0,
    };
    const res = await callUnary<DetachSandboxProviderRequest, DetachSandboxProviderResponse>(
      (r, cb) => this.stub.detachSandboxProvider(r, cb),
      req
    );
    return res.detached;
  }

  // ── Draft policy ────────────────────────────────────────────────────────────

  async getDraftPolicy(
    sandboxName: string,
    options: { statusFilter?: string } = {}
  ): Promise<GetDraftPolicyResponse> {
    const req: GetDraftPolicyRequest = {
      name: sandboxName,
      statusFilter: options.statusFilter ?? "",
    };
    return callUnary<GetDraftPolicyRequest, GetDraftPolicyResponse>(
      (r, cb) => this.stub.getDraftPolicy(r, cb),
      req
    );
  }

  async approveDraftChunk(sandboxName: string, chunkId: string): Promise<void> {
    const req: ApproveDraftChunkRequest = { name: sandboxName, chunkId };
    await callUnary<ApproveDraftChunkRequest, ApproveDraftChunkResponse>(
      (r, cb) => this.stub.approveDraftChunk(r, cb),
      req
    );
  }

  async rejectDraftChunk(sandboxName: string, chunkId: string, reason = ""): Promise<void> {
    const req: RejectDraftChunkRequest = { name: sandboxName, chunkId, reason };
    await callUnary<RejectDraftChunkRequest, RejectDraftChunkResponse>(
      (r, cb) => this.stub.rejectDraftChunk(r, cb),
      req
    );
  }

  async approveAllDraftChunks(
    sandboxName: string,
    options: { includeSecurityFlagged?: boolean } = {}
  ): Promise<void> {
    const req: ApproveAllDraftChunksRequest = {
      name: sandboxName,
      includeSecurityFlagged: options.includeSecurityFlagged ?? false,
    };
    await callUnary<ApproveAllDraftChunksRequest, ApproveAllDraftChunksResponse>(
      (r, cb) => this.stub.approveAllDraftChunks(r, cb),
      req
    );
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function* streamToAsyncIterable(
  stream: NodeJS.ReadableStream & {
    on(event: "error", listener: (err: Error) => void): unknown;
  }
): AsyncIterable<ExecChunk> {
  const queue: Array<ExecChunk | Error | null> = [];
  let resolveWaiter: (() => void) | null = null;

  const notify = () => {
    if (resolveWaiter) {
      const r = resolveWaiter;
      resolveWaiter = null;
      r();
    }
  };

  stream.on("data", (event: ExecSandboxEvent) => {
    if (!event.payload) return;
    if (event.payload.$case === "stdout") {
      queue.push({ stream: "stdout", data: event.payload.stdout.data });
    } else if (event.payload.$case === "stderr") {
      queue.push({ stream: "stderr", data: event.payload.stderr.data });
    }
    notify();
  });

  stream.on("end", () => {
    queue.push(null);
    notify();
  });

  stream.on("error", (err) => {
    queue.push(err instanceof Error ? err : new SandboxError(String(err)));
    notify();
  });

  while (true) {
    while (queue.length === 0) {
      await new Promise<void>((r) => {
        resolveWaiter = r;
      });
    }
    const item = queue.shift()!;
    if (item === null) return;
    if (item instanceof Error) throw item;
    yield item;
  }
}
