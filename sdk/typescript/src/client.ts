// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// The OpenShell gateway client: a thin, idiomatic ergonomics layer over the
// protobuf-generated gRPC stubs (src/gen/). Resource operations live on scoped
// clients (`SandboxClient`, mirroring the Python SDK) that OpenShellClient
// composes as `client.sandbox.*`, mirroring the CLI's noun-verb model; each
// scoped client is also usable standalone via its own `connect()`. Gateway-
// scoped calls (`health`) stay top-level. A scoped client owns proto request
// assembly, the curated public types, the ExecSandbox server-stream drain, and
// the waitReady/waitDeleted poll loops. Transport and auth live in
// transport.ts; the error taxonomy in errors.ts.

import type { AddressInfo } from 'node:net';
import * as net from 'node:net';
import type { MessageInitShape } from '@bufbuild/protobuf';
import { type CallOptions, type Client, createClient, type Transport } from '@connectrpc/connect';
import { errorCode, fromConnect, SdkError } from './errors.js';
import type { Provider } from './gen/datamodel_pb.js';
import type { Sandbox, UpdateConfigResponse } from './gen/openshell_pb.js';
import {
  type ExecSandboxInputSchema,
  OpenShell,
  SandboxPhase,
  type SandboxSpecSchema,
  ServiceStatus,
  type TcpForwardFrameSchema,
} from './gen/openshell_pb.js';
import type { EffectiveSetting, GetSandboxConfigResponse, SandboxPolicy, SettingValue } from './gen/sandbox_pb.js';
import { PolicySource, type SandboxPolicySchema, SettingScope, type SettingValueSchema } from './gen/sandbox_pb.js';
import { validateSshResponse } from './ssh-validate.js';
import { buildTransport, type ConnectOptions } from './transport.js';

// The policy and setting value shapes are the generated protobuf messages;
// re-export them rather than re-curating a parallel surface. Callers round-trip
// `getConfig().policy` back into `setPolicy`, and build `SettingValue`s inline.
export type { SandboxPolicy, SettingValue } from './gen/sandbox_pb.js';
export type { ConnectOptions };
export { errorCode };

// ---- Curated public types --------------------------------------------------

// The gateway enums (SandboxPhase, ServiceStatus, SettingScope, PolicySource)
// arrive as protoc-gen-es numeric enums. The lowercase literal unions below are
// a hand-maintained mirror of them so consumers get exhaustive, typo-proof
// switches instead of a bare `string`. They are deliberately duplicated by
// hand, not generated, and are expected to stay stable. If a proto enum ever
// gains, removes, or renames a member, update the matching union AND its
// `*_NAMES` map below: the exhaustive `Record` stops compiling, and the
// 'enum name maps' drift test in client.test.ts fails until both sides agree.

/** Lowercase mirror of the generated `SandboxPhase` enum. Hand-maintained. */
export type SandboxPhaseName =
  | 'unspecified'
  | 'provisioning'
  | 'ready'
  | 'error'
  | 'deleting'
  | 'unknown'
  | 'stopping'
  | 'stopped'
  | 'starting'
  | 'completed';

/** Lowercase mirror of the generated `ServiceStatus` enum. Hand-maintained. */
export type HealthStatus = 'unspecified' | 'healthy' | 'degraded' | 'unhealthy';

/** Lowercase mirror of the generated `SettingScope` enum. Hand-maintained. */
export type SettingScopeName = 'unspecified' | 'sandbox' | 'global';

/** Lowercase mirror of the generated `PolicySource` enum. Hand-maintained. */
export type PolicySourceName = 'unspecified' | 'sandbox' | 'global';

export interface Health {
  status: HealthStatus;
  version: string;
}

export interface SandboxSpec {
  name?: string;
  image?: string;
  labels?: Record<string, string>;
  environment?: Record<string, string>;
  providers?: string[];
  gpu?: boolean;
  /** Exact canonical command. Empty selects the gateway scratch shell. */
  command?: string[];
  /** Allocate a retained pseudo-terminal for the canonical command. */
  tty?: boolean;
  /**
   * Create-time sandbox policy (the safety boundary). Sandbox-scoped
   * `setPolicy` cannot introduce static fields later, so express filesystem,
   * landlock, process, and initial network policy here.
   */
  policy?: MessageInitShape<typeof SandboxPolicySchema>;
  /**
   * Advanced escape hatch: the full generated proto spec. Curated fields build
   * the base spec, then `rawSpec` shallow-overrides at the top spec level, so
   * any field it sets wins. Use it to reach proto spec fields the curated shape
   * does not surface (template runtime class, resource limits, log level, and
   * future additions) without an SDK change.
   */
  rawSpec?: MessageInitShape<typeof SandboxSpecSchema>;
}

export interface SandboxRef {
  id: string;
  name: string;
  phase: SandboxPhaseName;
  labels: Record<string, string>;
  /** u64 rendered as a string — JS numbers can't hold it safely. */
  resourceVersion: string;
  mainProcessInstanceId?: string;
  exitCode?: number;
}

export interface ListOptions {
  limit?: number;
  offset?: number;
  labelSelector?: string;
}

export interface ExecOptions {
  workdir?: string;
  environment?: Record<string, string>;
  timeoutSecs?: number;
  stdin?: Buffer;
  /**
   * Skip sourcing shell login/profile startup files before the command.
   * Defaults to `false`, which preserves login-shell behavior. Set `true` for
   * automation and managed checks that need predictable startup behavior.
   */
  noLoginShell?: boolean;
  /** Abort the exec (and the in-flight stream RPC) early. */
  signal?: AbortSignal;
}

export interface ExecResult {
  exitCode: number;
  stdout: Buffer;
  stderr: Buffer;
}

/** One stdout/stderr chunk yielded by `execStream`/`execInteractive`. */
export interface ExecStreamChunk {
  stream: 'stdout' | 'stderr';
  data: Buffer;
}

// The terminal event of an exec stream, carrying the command exit code. It is
// yielded in-band (not returned) so `for await` consumers cannot discard it.
// Discriminate against ExecStreamChunk with `'type' in event`.
export interface ExecExitEvent {
  type: 'exit';
  exitCode: number;
}

/** An exec stream item: a stdout/stderr chunk or the terminal exit event. */
export type ExecStreamEvent = ExecStreamChunk | ExecExitEvent;

export interface ExecInteractiveOptions {
  workdir?: string;
  environment?: Record<string, string>;
  timeoutSecs?: number;
  /** Request a pseudo-terminal (default true). */
  tty?: boolean;
  /** Initial terminal columns (0 = server default). */
  cols?: number;
  /** Initial terminal rows (0 = server default). */
  rows?: number;
  /**
   * Skip sourcing shell login/profile startup files before the command.
   * Defaults to `false`, which preserves login-shell behavior.
   */
  noLoginShell?: boolean;
  /** Abort the interactive exec (and the in-flight stream RPC) early. */
  signal?: AbortSignal;
}

// The transport half of an interactive exec: raw stdin/stdout/stderr plus
// resize, with no terminal glue. Drive it by consuming `output`, which yields
// chunks then a terminal exit event; `done` resolves with the exit code once
// the stream reaches that exit event and rejects if the stream ends without one.
export interface ExecInteractiveSession {
  output: AsyncIterable<ExecStreamEvent>;
  write(data: Buffer): void;
  resize(cols: number, rows: number): void;
  close(): void;
  done: Promise<number>;
}

/** Cancellation for the poll-based wait helpers. */
export interface WaitOptions {
  /** Abort the wait (and the in-flight poll RPC) early. */
  signal?: AbortSignal;
}

export interface ForwardOptions {
  /** Loopback TCP port inside the sandbox to dial. */
  targetPort: number;
  /** Target host inside the sandbox (loopback only). Default 127.0.0.1. */
  targetHost?: string;
  /** Local port to bind. Default 0 (ephemeral). */
  localPort?: number;
  /** Local address to bind. Default 127.0.0.1. */
  localHost?: string;
  /** Abort forward setup and tear down the local listener early. */
  signal?: AbortSignal;
  /** Receives failures from individual accepted connections. */
  onConnectionError?: (error: SdkError) => void;
}

// A process-lifetime local listener that tunnels each accepted connection into
// the sandbox. Call `close()` on teardown; `closed` resolves once the listener
// is fully torn down. An in-process forward cannot outlive the Node process.
export interface ForwardHandle {
  localHost: string;
  localPort: number;
  targetHost: string;
  targetPort: number;
  close(): Promise<void>;
  closed: Promise<void>;
}

export interface SshSession {
  sandboxId: string;
  token: string;
  gatewayHost: string;
  gatewayPort: number;
  gatewayScheme: string;
  hostKeyFingerprint?: string;
  /** int64 ms-since-epoch rendered as a string; omitted when 0 (no expiry). */
  expiresAtMs?: string;
}

export interface ProviderRef {
  id: string;
  name: string;
  type: string;
  labels: Record<string, string>;
  /** u64 rendered as a string. */
  resourceVersion: string;
}

export interface ProviderChange {
  sandbox: SandboxRef;
  /** True when the attach/detach actually changed the attachment set. */
  changed: boolean;
}

export interface ProviderChangeOptions {
  /** Pin the sandbox resource version for optimistic concurrency (u64 as string). */
  expectedResourceVersion?: string;
}

/** Effective value of one setting plus the scope it resolved from. */
export interface EffectiveSettingView {
  value?: SettingValue;
  /** 'unspecified' | 'sandbox' | 'global'. */
  scope: SettingScopeName;
}

export interface SandboxConfig {
  policy?: SandboxPolicy;
  version: number;
  policyHash: string;
  settings: Record<string, EffectiveSettingView>;
  /** u64 rendered as a string. */
  configRevision: string;
  /** 'unspecified' | 'sandbox' | 'global'. */
  policySource: PolicySourceName;
  globalPolicyVersion: number;
  /** u64 rendered as a string. */
  providerEnvRevision: string;
}

export interface SetPolicyOptions {
  /** Pin the sandbox resource version for optimistic concurrency (u64 as string). */
  expectedResourceVersion?: string;
  /** Poll getConfig until the applied policy hash is observed. */
  wait?: boolean;
  /** Bound the `wait` poll (seconds). Default 60. */
  waitTimeoutSecs?: number;
}

export interface UpdateConfigResult {
  version: number;
  policyHash: string;
  /** u64 rendered as a string. */
  settingsRevision: string;
  deleted: boolean;
}

// ---- enum → lowercase string -----------------------------------------------

// Exported for the enum-name drift test only; not re-exported from index.ts, so
// they are not part of the public package API.
export const PHASE_NAMES: Record<SandboxPhase, SandboxPhaseName> = {
  [SandboxPhase.UNSPECIFIED]: 'unspecified',
  [SandboxPhase.PROVISIONING]: 'provisioning',
  [SandboxPhase.READY]: 'ready',
  [SandboxPhase.ERROR]: 'error',
  [SandboxPhase.DELETING]: 'deleting',
  [SandboxPhase.UNKNOWN]: 'unknown',
  [SandboxPhase.STOPPING]: 'stopping',
  [SandboxPhase.STOPPED]: 'stopped',
  [SandboxPhase.STARTING]: 'starting',
  [SandboxPhase.COMPLETED]: 'completed',
};
export const STATUS_NAMES: Record<ServiceStatus, HealthStatus> = {
  [ServiceStatus.UNSPECIFIED]: 'unspecified',
  [ServiceStatus.HEALTHY]: 'healthy',
  [ServiceStatus.DEGRADED]: 'degraded',
  [ServiceStatus.UNHEALTHY]: 'unhealthy',
};
export const SCOPE_NAMES: Record<SettingScope, SettingScopeName> = {
  [SettingScope.UNSPECIFIED]: 'unspecified',
  [SettingScope.SANDBOX]: 'sandbox',
  [SettingScope.GLOBAL]: 'global',
};
export const POLICY_SOURCE_NAMES: Record<PolicySource, PolicySourceName> = {
  [PolicySource.UNSPECIFIED]: 'unspecified',
  [PolicySource.SANDBOX]: 'sandbox',
  [PolicySource.GLOBAL]: 'global',
};

function phaseName(p: SandboxPhase): SandboxPhaseName {
  return PHASE_NAMES[p] ?? 'unspecified';
}
function statusName(s: ServiceStatus): HealthStatus {
  return STATUS_NAMES[s] ?? 'unspecified';
}
function scopeName(s: SettingScope): SettingScopeName {
  return SCOPE_NAMES[s] ?? 'unspecified';
}
function policySourceName(s: PolicySource): PolicySourceName {
  return POLICY_SOURCE_NAMES[s] ?? 'unspecified';
}

function sandboxRef(sandbox: Sandbox | undefined): SandboxRef {
  if (!sandbox) throw new SdkError('invalid_config', 'sandbox missing from gateway response');
  const meta = sandbox.metadata;
  if (!meta?.id || !meta.name) {
    throw new SdkError('invalid_config', 'sandbox metadata.id and metadata.name are required in gateway responses');
  }
  return {
    id: meta.id,
    name: meta.name,
    phase: phaseName(sandbox.status?.phase ?? SandboxPhase.UNSPECIFIED),
    labels: meta?.labels ?? {},
    resourceVersion: (meta?.resourceVersion ?? 0n).toString(),
    mainProcessInstanceId: sandbox.status?.mainProcessInstanceId || undefined,
    exitCode: sandbox.status?.exitCode,
  };
}

function providerRef(provider: Provider): ProviderRef {
  const meta = provider.metadata;
  return {
    id: meta?.id ?? '',
    name: meta?.name ?? '',
    type: provider.type,
    labels: meta?.labels ?? {},
    resourceVersion: (meta?.resourceVersion ?? 0n).toString(),
  };
}

function sandboxConfig(resp: GetSandboxConfigResponse): SandboxConfig {
  const settings: Record<string, EffectiveSettingView> = {};
  for (const [key, setting] of Object.entries(resp.settings)) {
    settings[key] = effectiveSetting(setting);
  }
  return {
    ...(resp.policy ? { policy: resp.policy } : {}),
    version: resp.version,
    policyHash: resp.policyHash,
    settings,
    configRevision: resp.configRevision.toString(),
    policySource: policySourceName(resp.policySource),
    globalPolicyVersion: resp.globalPolicyVersion,
    providerEnvRevision: resp.providerEnvRevision.toString(),
  };
}

function effectiveSetting(setting: EffectiveSetting): EffectiveSettingView {
  return {
    ...(setting.value ? { value: setting.value } : {}),
    scope: scopeName(setting.scope),
  };
}

function updateConfigResult(resp: UpdateConfigResponse): UpdateConfigResult {
  return {
    version: resp.version,
    policyHash: resp.policyHash,
    settingsRevision: resp.settingsRevision.toString(),
    deleted: resp.deleted,
  };
}

// Optimistic-concurrency version pin: absent/empty means 0n (server uses the
// current version, backward-compatible). A mismatch surfaces as Aborted →
// SdkError code 'aborted'.
function versionPin(value: string | undefined): bigint {
  if (!value) return 0n;
  let pin: bigint;
  try {
    pin = BigInt(value);
  } catch {
    // BigInt() throws a raw SyntaxError on non-integer input; keep the SdkError
    // taxonomy intact so callers' errorCode() checks still match.
    throw new SdkError('invalid_config', `expectedResourceVersion is not a u64: '${value}'`);
  }
  if (pin < 0n) {
    throw new SdkError('invalid_config', `expectedResourceVersion is not a u64: '${value}'`);
  }
  return pin;
}

const FORWARD_CHUNK = 64 * 1024;

// Build CallOptions that bound one poll RPC by the remaining wall-clock budget
// and honor caller cancellation, so a stalled RPC cannot outlive the deadline.
function deadlineOptions(remainingMs: number, signal?: AbortSignal): CallOptions {
  const timeout = AbortSignal.timeout(Math.max(0, remainingMs));
  return {
    signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
  };
}

// Translate a poll failure at the wait boundary: caller cancellation and
// deadline expiry become explicit SdkErrors; anything else propagates.
function mapWaitError(err: unknown, name: string, deadline: number, signal?: AbortSignal): SdkError {
  if (signal?.aborted) return new SdkError('connect', `wait for sandbox '${name}' aborted`);
  if (Date.now() >= deadline) return new SdkError('connect', `timed out waiting for sandbox '${name}'`);
  return err instanceof SdkError ? err : fromConnect(err);
}

// Sleep between polls, bounded by the remaining deadline and interruptible by
// the caller signal so the returned promise stays within its timeout budget.
function waitSleep(delayMs: number, deadline: number, signal?: AbortSignal): Promise<void> {
  const bounded = Math.min(delayMs, Math.max(0, deadline - Date.now()));
  return new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, bounded);
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(new SdkError('connect', 'wait aborted'));
    };
    if (signal) signal.addEventListener('abort', onAbort, { once: true });
  });
}

// Wait for a socket to drain before writing more. Resolves on 'drain', and
// also on 'close'/'error' so a pending await never leaks when the socket is
// torn down mid-backpressure; short-circuits if it is already gone.
function waitForDrain(socket: net.Socket): Promise<void> {
  if (socket.writableEnded || socket.destroyed) return Promise.resolve();
  return new Promise<void>((resolve) => {
    const done = (): void => {
      socket.removeListener('drain', done);
      socket.removeListener('close', done);
      socket.removeListener('error', done);
      resolve();
    };
    socket.once('drain', done);
    socket.once('close', done);
    socket.once('error', done);
  });
}

// An async-iterable queue for the client-send half of bidi streams. Producers
// `push()` frames; the connect transport consumes them as it drains the send
// side. `end()` closes the stream (optionally with an error). `onDrain` fires
// when the buffered queue empties via consumption, so callers can relieve TCP
// backpressure.
export class Pushable<T> implements AsyncIterable<T> {
  private readonly queue: T[] = [];
  private readonly waiting: Array<{
    resolve: (result: IteratorResult<T>) => void;
    reject: (error: unknown) => void;
  }> = [];
  private ended = false;
  private error: unknown;
  onDrain?: () => void;

  get size(): number {
    return this.queue.length;
  }

  push(value: T): void {
    if (this.ended) return;
    const waiter = this.waiting.shift();
    if (waiter) {
      waiter.resolve({ value, done: false });
    } else {
      this.queue.push(value);
    }
  }

  end(error?: unknown): void {
    if (this.ended) return;
    this.ended = true;
    this.error = error;
    let waiter = this.waiting.shift();
    while (waiter) {
      if (error !== undefined) waiter.reject(error);
      else waiter.resolve({ value: undefined as never, done: true });
      waiter = this.waiting.shift();
    }
  }

  async *[Symbol.asyncIterator](): AsyncIterator<T> {
    for (;;) {
      if (this.queue.length > 0) {
        const value = this.queue.shift() as T;
        if (this.queue.length === 0) this.onDrain?.();
        yield value;
        continue;
      }
      if (this.ended) {
        if (this.error !== undefined) throw this.error;
        return;
      }
      const next = await new Promise<IteratorResult<T>>((resolve, reject) => {
        this.waiting.push({ resolve, reject });
      });
      if (next.done) {
        if (this.error !== undefined) throw this.error;
        return;
      }
      yield next.value;
    }
  }
}

// ---- sandbox client --------------------------------------------------------

// Sandbox lifecycle + exec. Usable standalone via `SandboxClient.connect()`,
// or reached as `client.sandbox` on an OpenShellClient, which shares one
// transport (one connection) across all of its scoped clients.
export class SandboxClient {
  private readonly grpc: Client<typeof OpenShell>;

  /**
   * Advanced escape hatch: a generated client for every gateway RPC, including
   * surface the curated methods do not wrap yet. Request/response types are the
   * generated wire messages (import them from '@nvidia/openshell-sdk/raw').
   */
  readonly raw: Client<typeof OpenShell>;
  /** The shared Connect transport, for building extra clients over the same connection. */
  readonly transport: Transport;

  // Takes a transport rather than options so OpenShellClient can compose
  // several scoped clients over a single connection. For standalone use,
  // prefer the SandboxClient.connect() factory below.
  constructor(transport: Transport, grpc = createClient(OpenShell, transport)) {
    this.transport = transport;
    this.grpc = grpc;
    this.raw = this.grpc;
  }

  /**
   * Constructs a lazy Connect client. No network request is made until the
   * first RPC; call get() or another operation to verify reachability.
   */
  static async connect(options: ConnectOptions): Promise<SandboxClient> {
    return new SandboxClient(buildTransport(options));
  }

  async create(spec: SandboxSpec): Promise<SandboxRef> {
    try {
      // Curated fields build the base spec; rawSpec then shallow-overrides at
      // the top spec level (Object.assign, so any field it sets wins). The
      // runtime assign avoids the generated $typeName upgrading the literal and
      // rejecting the curated `template: { image }` init shorthand.
      const specInit: MessageInitShape<typeof SandboxSpecSchema> = {
        environment: spec.environment ?? {},
        providers: spec.providers ?? [],
        template: spec.image ? { image: spec.image } : undefined,
        resourceRequirements: spec.gpu ? { gpu: {} } : undefined,
        policy: spec.policy,
        command: spec.command ?? [],
        tty: spec.tty ?? false,
      };
      if (spec.rawSpec) Object.assign(specInit, spec.rawSpec);

      const resp = await this.grpc.createSandbox({
        name: spec.name ?? '',
        labels: spec.labels ?? {},
        spec: specInit,
      });
      return sandboxRef(resp.sandbox);
    } catch (e) {
      throw fromConnect(e);
    }
  }

  async get(name: string, callOptions?: CallOptions): Promise<SandboxRef> {
    try {
      const resp = await this.grpc.getSandbox({ name }, callOptions);
      return sandboxRef(resp.sandbox);
    } catch (e) {
      throw fromConnect(e);
    }
  }

  async list(options?: ListOptions | null): Promise<SandboxRef[]> {
    try {
      const resp = await this.grpc.listSandboxes({
        limit: options?.limit ?? 0,
        offset: options?.offset ?? 0,
        labelSelector: options?.labelSelector ?? '',
      });
      return resp.sandboxes.map((s) => sandboxRef(s));
    } catch (e) {
      throw fromConnect(e);
    }
  }

  async delete(name: string): Promise<boolean> {
    try {
      const resp = await this.grpc.deleteSandbox({ name });
      return resp.deleted;
    } catch (e) {
      throw fromConnect(e);
    }
  }

  // Poll until the sandbox is ready. The timeout bounds the returned promise,
  // not just the sleep loop: each poll RPC carries the remaining deadline (and
  // any caller signal), so a stalled get() is aborted rather than hanging.
  async waitReady(name: string, timeoutSecs: number, options?: WaitOptions | null): Promise<SandboxRef> {
    const deadline = Date.now() + timeoutSecs * 1000;
    const signal = options?.signal;
    let delay = 250;
    for (;;) {
      if (signal?.aborted) throw new SdkError('connect', `wait for sandbox '${name}' aborted`);
      if (Date.now() >= deadline) throw new SdkError('connect', `timed out waiting for sandbox '${name}'`);
      let ref: SandboxRef;
      try {
        ref = await this.get(name, deadlineOptions(deadline - Date.now(), signal));
      } catch (e) {
        throw mapWaitError(e, name, deadline, signal);
      }
      if (ref.phase === 'ready' || ref.phase === 'completed') return ref;
      if (ref.phase === 'stopped') throw new SdkError('connect', `sandbox '${name}' stopped before becoming ready`);
      if (ref.phase === 'error') throw new SdkError('connect', `sandbox '${name}' entered error phase`);
      if (Date.now() >= deadline) throw new SdkError('connect', `timed out waiting for sandbox '${name}'`);
      await waitSleep(delay, deadline, signal);
      delay = Math.min(delay * 2, 2000);
    }
  }

  // Poll until the sandbox is gone. Timeout and cancellation bound the returned
  // promise the same way as waitReady.
  async waitDeleted(name: string, timeoutSecs: number, options?: WaitOptions | null): Promise<void> {
    const deadline = Date.now() + timeoutSecs * 1000;
    const signal = options?.signal;
    let delay = 250;
    for (;;) {
      if (signal?.aborted) throw new SdkError('connect', `wait for sandbox '${name}' aborted`);
      if (Date.now() >= deadline) throw new SdkError('connect', `timed out waiting for sandbox '${name}' to delete`);
      try {
        await this.get(name, deadlineOptions(deadline - Date.now(), signal));
      } catch (e) {
        if (e instanceof SdkError && e.code === 'not_found') return;
        throw mapWaitError(e, name, deadline, signal);
      }
      if (Date.now() >= deadline) throw new SdkError('connect', `timed out waiting for sandbox '${name}' to delete`);
      await waitSleep(delay, deadline, signal);
      delay = Math.min(delay * 2, 2000);
    }
  }

  // Stream stdout/stderr as they arrive, then a terminal exit event. The exit
  // is yielded in-band (not returned) so `for await` consumers cannot silently
  // discard it: a failing command is impossible to miss. If the gateway closes
  // the stream without an exit event, this throws. `exec()` drains this same
  // path to reconstruct the buffered result.
  async *execStream(
    name: string,
    command: string[],
    options?: ExecOptions | null,
  ): AsyncGenerator<ExecStreamEvent, void, void> {
    try {
      // Resolve the sandbox id first, exactly like the gateway client.
      const sandbox = await this.get(name, options?.signal ? { signal: options.signal } : undefined);
      const stream = this.grpc.execSandbox(
        {
          sandboxId: sandbox.id,
          command,
          workdir: options?.workdir ?? '',
          environment: options?.environment ?? {},
          timeoutSeconds: options?.timeoutSecs ?? 0,
          stdin: options?.stdin ? new Uint8Array(options.stdin) : new Uint8Array(),
          tty: false,
          noLoginShell: options?.noLoginShell ?? false,
        },
        { signal: options?.signal },
      );

      let sawExit = false;
      for await (const event of stream) {
        switch (event.payload.case) {
          case 'stdout':
            yield {
              stream: 'stdout',
              data: Buffer.from(event.payload.value.data),
            };
            break;
          case 'stderr':
            yield {
              stream: 'stderr',
              data: Buffer.from(event.payload.value.data),
            };
            break;
          case 'exit':
            sawExit = true;
            yield { type: 'exit', exitCode: event.payload.value.exitCode };
            break;
        }
      }
      if (!sawExit) throw new SdkError('rpc', 'ExecSandbox stream ended without an exit event');
    } catch (e) {
      throw e instanceof SdkError ? e : fromConnect(e);
    }
  }

  async exec(name: string, command: string[], options?: ExecOptions | null): Promise<ExecResult> {
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let exitCode: number | undefined;
    for await (const event of this.execStream(name, command, options)) {
      if ('type' in event) {
        exitCode = event.exitCode;
      } else if (event.stream === 'stdout') {
        stdout.push(event.data);
      } else {
        stderr.push(event.data);
      }
    }
    if (exitCode === undefined) throw new SdkError('rpc', 'ExecSandbox stream ended without an exit event');
    return {
      exitCode,
      stdout: Buffer.concat(stdout),
      stderr: Buffer.concat(stderr),
    };
  }

  // TTY + stdin transport half of an interactive exec. The first client frame
  // is the `start` variant carrying the exec request; subsequent frames are
  // `stdin`/`resize`. No terminal glue: raw mode, signal forwarding, and
  // SIGWINCH stay with the caller.
  async execInteractive(
    name: string,
    command: string[],
    options?: ExecInteractiveOptions | null,
  ): Promise<ExecInteractiveSession> {
    let sandboxId: string;
    try {
      sandboxId = (await this.get(name, options?.signal ? { signal: options.signal } : undefined)).id;
    } catch (e) {
      throw e instanceof SdkError ? e : fromConnect(e);
    }

    const input = new Pushable<MessageInitShape<typeof ExecSandboxInputSchema>>();
    input.push({
      payload: {
        case: 'start',
        value: {
          sandboxId,
          command,
          workdir: options?.workdir ?? '',
          environment: options?.environment ?? {},
          timeoutSeconds: options?.timeoutSecs ?? 0,
          stdin: new Uint8Array(),
          tty: options?.tty ?? true,
          cols: options?.cols ?? 0,
          rows: options?.rows ?? 0,
          noLoginShell: options?.noLoginShell ?? false,
        },
      },
    });

    const stream = this.grpc.execSandboxInteractive(input, { signal: options?.signal });
    let resolveDone!: (code: number) => void;
    let rejectDone!: (err: unknown) => void;
    const done = new Promise<number>((resolve, reject) => {
      resolveDone = resolve;
      rejectDone = reject;
    });
    // `done` may settle before (or without) anyone awaiting it. A lone handler
    // keeps an unobserved rejection from surfacing as an unhandledRejection;
    // real awaiters still receive it through their own handler.
    void done.catch(() => {});
    // Settle exactly once. The exit code wins; error/abandonment only apply
    // when no exit was observed.
    let settled = false;
    const settleExit = (code: number): void => {
      if (settled) return;
      settled = true;
      resolveDone(code);
    };
    const settleError = (err: unknown): void => {
      if (settled) return;
      settled = true;
      rejectDone(err);
    };

    async function* output(): AsyncGenerator<ExecStreamEvent, void, void> {
      let sawExit = false;
      try {
        for await (const event of stream) {
          switch (event.payload.case) {
            case 'stdout':
              yield {
                stream: 'stdout',
                data: Buffer.from(event.payload.value.data),
              };
              break;
            case 'stderr':
              yield {
                stream: 'stderr',
                data: Buffer.from(event.payload.value.data),
              };
              break;
            case 'exit':
              sawExit = true;
              // Settle `done` before yielding: a consumer that breaks on the
              // exit event abandons the generator at the yield, so anything
              // after it would never run.
              settleExit(event.payload.value.exitCode);
              yield { type: 'exit', exitCode: event.payload.value.exitCode };
              break;
          }
        }
        if (!sawExit) {
          throw new SdkError('rpc', 'ExecSandboxInteractive stream ended without an exit event');
        }
      } catch (e) {
        const err = e instanceof SdkError ? e : fromConnect(e);
        settleError(err);
        throw err;
      } finally {
        input.end();
        // Consumer abandoned the stream before an exit event (early break or
        // return): settle `done` so it can never hang.
        settleError(new SdkError('rpc', 'exec output abandoned before exit'));
      }
    }

    return {
      output: output(),
      write(data: Buffer): void {
        input.push({ payload: { case: 'stdin', value: new Uint8Array(data) } });
      },
      resize(cols: number, rows: number): void {
        input.push({ payload: { case: 'resize', value: { cols, rows } } });
      },
      close(): void {
        input.end();
      },
      done,
    };
  }

  // Bind a local TCP listener that tunnels each accepted connection into the
  // sandbox. Mirrors the CLI service forward: READY check, then per socket mint
  // a short-lived SSH session token, open a forwardTcp bidi whose first frame is
  // the `init` (TCP target + token), relay bytes both ways in ~64 KiB chunks,
  // and revoke the token on close. Process-lifetime only.
  async forward(name: string, opts: ForwardOptions): Promise<ForwardHandle> {
    const targetHost = opts.targetHost ?? '127.0.0.1';
    const targetPort = opts.targetPort;
    const localHost = opts.localHost ?? '127.0.0.1';
    const localPort = opts.localPort ?? 0;

    let sandboxId: string;
    try {
      const ref = await this.get(name, opts.signal ? { signal: opts.signal } : undefined);
      if (ref.phase !== 'ready') {
        throw new SdkError('connect', `sandbox '${name}' is not ready (phase: ${ref.phase})`);
      }
      sandboxId = ref.id;
    } catch (e) {
      throw e instanceof SdkError ? e : fromConnect(e);
    }

    const sockets = new Set<net.Socket>();
    const controllers = new Set<AbortController>();
    const connectionTasks = new Set<Promise<void>>();
    let closing = false;
    const server = net.createServer((socket) => {
      sockets.add(socket);
      socket.on('close', () => sockets.delete(socket));
      // Guard the window before forwardConnection attaches its own handlers
      // (it first awaits createSshSession). Without a synchronous 'error'
      // listener a peer reset here emits an unhandled 'error' and crashes the
      // process; forwardConnection's catch still tears the socket down.
      socket.on('error', () => {});
      const controller = new AbortController();
      controllers.add(controller);
      const task = this.forwardConnection(socket, sandboxId, name, targetHost, targetPort, controller.signal)
        .catch((error: unknown) => {
          if (!closing) {
            try {
              opts.onConnectionError?.(error instanceof SdkError ? error : fromConnect(error));
            } catch {
              // Consumer callbacks must not turn a handled connection failure
              // into an unhandled rejection or prevent forward cleanup.
            }
          }
        })
        .finally(() => {
          controllers.delete(controller);
          connectionTasks.delete(task);
        });
      connectionTasks.add(task);
    });

    let resolveClosed!: () => void;
    const closed = new Promise<void>((resolve) => {
      resolveClosed = resolve;
    });

    await new Promise<void>((resolve, reject) => {
      const onError = (err: unknown): void => {
        reject(
          new SdkError(
            'io',
            `failed to bind local forward on ${localHost}:${localPort}: ${err instanceof Error ? err.message : String(err)}`,
          ),
        );
      };
      server.once('error', onError);
      server.listen(localPort, localHost, () => {
        server.removeListener('error', onError);
        resolve();
      });
    });

    let teardownPromise: Promise<void> | undefined;
    const onAbort = (): void => {
      void teardown();
    };
    const teardown = (): Promise<void> => {
      if (teardownPromise) return teardownPromise;
      closing = true;
      opts.signal?.removeEventListener('abort', onAbort);
      teardownPromise = (async () => {
        for (const controller of controllers) controller.abort();
        for (const socket of sockets) socket.destroy();
        if (server.listening) {
          await new Promise<void>((resolve) => server.close(() => resolve()));
        }
        await Promise.allSettled([...connectionTasks]);
        resolveClosed();
      })();
      return teardownPromise;
    };

    // Caller cancellation tears the local listener down the same way close() does.
    if (opts.signal) {
      if (opts.signal.aborted) void teardown();
      else opts.signal.addEventListener('abort', onAbort, { once: true });
    }

    const addr = server.address() as AddressInfo | null;
    return {
      localHost,
      localPort: addr ? addr.port : localPort,
      targetHost,
      targetPort,
      close: teardown,
      closed,
    };
  }

  private async forwardConnection(
    socket: net.Socket,
    sandboxId: string,
    name: string,
    targetHost: string,
    targetPort: number,
    signal: AbortSignal,
  ): Promise<void> {
    let token: string | undefined;
    const input = new Pushable<MessageInitShape<typeof TcpForwardFrameSchema>>();
    input.onDrain = () => socket.resume();
    try {
      const session = await this.grpc.createSshSession({ sandboxId }, { signal });
      // Defense-in-depth: the token feeds forwardTcp authorization, so hold it
      // to the same trust-boundary contract as createSshSession. A violation
      // tears down this one socket via the catch below.
      validateSshResponse(session, sandboxId);
      token = session.token;
      input.push({
        payload: {
          case: 'init',
          value: {
            sandboxId,
            serviceId: `service-forward:${name}:${targetHost}:${targetPort}`,
            target: {
              case: 'tcp',
              value: { host: targetHost, port: targetPort },
            },
            authorizationToken: token,
          },
        },
      });

      socket.on('data', (chunk: Buffer) => {
        for (let off = 0; off < chunk.length; off += FORWARD_CHUNK) {
          const slice = chunk.subarray(off, Math.min(off + FORWARD_CHUNK, chunk.length));
          input.push({
            payload: { case: 'data', value: new Uint8Array(slice) },
          });
        }
        if (input.size >= 64) socket.pause();
      });
      socket.on('end', () => input.end());
      socket.on('error', (error) => input.end(error));
      socket.on('close', () => input.end());

      const onAbort = (): void => {
        input.end(new SdkError('canceled', 'forward connection closed'));
        socket.destroy();
      };
      signal.addEventListener('abort', onAbort, { once: true });

      try {
        for await (const frame of this.grpc.forwardTcp(input, { signal })) {
          if (frame.payload.case !== 'data') continue;
          const data = frame.payload.value;
          if (data.length === 0) continue;
          // Respect backpressure: if the local socket buffer is full, stop
          // pulling sandbox data until it drains so memory stays bounded.
          if (!socket.write(Buffer.from(data))) await waitForDrain(socket);
        }
      } finally {
        signal.removeEventListener('abort', onAbort);
      }
      socket.end();
    } catch (e) {
      socket.destroy();
      throw e instanceof SdkError ? e : fromConnect(e);
    } finally {
      input.end();
      if (token !== undefined) {
        try {
          await this.grpc.revokeSshSession({ token }, { signal });
        } catch {
          // Best-effort revoke; the token expires on its own regardless.
        }
      }
    }
  }

  // Mint a short-lived SSH session token for the sandbox — the input side of
  // ssh-config / ProxyCommand and forwardTcp authorization.
  async createSshSession(name: string): Promise<SshSession> {
    try {
      const sandbox = await this.get(name);
      const resp = await this.grpc.createSshSession({ sandboxId: sandbox.id });
      // Reject any response outside the proto trust-boundary contract before
      // handing these values to the caller (they feed OpenSSH ProxyCommand).
      validateSshResponse(resp, sandbox.id);
      return {
        sandboxId: resp.sandboxId,
        token: resp.token,
        gatewayHost: resp.gatewayHost,
        gatewayPort: resp.gatewayPort,
        gatewayScheme: resp.gatewayScheme,
        ...(resp.hostKeyFingerprint ? { hostKeyFingerprint: resp.hostKeyFingerprint } : {}),
        ...(resp.expiresAtMs !== 0n ? { expiresAtMs: resp.expiresAtMs.toString() } : {}),
      };
    } catch (e) {
      throw e instanceof SdkError ? e : fromConnect(e);
    }
  }

  async revokeSshSession(token: string): Promise<boolean> {
    try {
      const resp = await this.grpc.revokeSshSession({ token });
      return resp.revoked;
    } catch (e) {
      throw fromConnect(e);
    }
  }

  async attachProvider(
    name: string,
    provider: string,
    options?: ProviderChangeOptions | null,
  ): Promise<ProviderChange> {
    try {
      const resp = await this.grpc.attachSandboxProvider({
        sandboxName: name,
        providerName: provider,
        expectedResourceVersion: versionPin(options?.expectedResourceVersion),
      });
      return { sandbox: sandboxRef(resp.sandbox), changed: resp.attached };
    } catch (e) {
      throw fromConnect(e);
    }
  }

  async detachProvider(
    name: string,
    provider: string,
    options?: ProviderChangeOptions | null,
  ): Promise<ProviderChange> {
    try {
      const resp = await this.grpc.detachSandboxProvider({
        sandboxName: name,
        providerName: provider,
        expectedResourceVersion: versionPin(options?.expectedResourceVersion),
      });
      return { sandbox: sandboxRef(resp.sandbox), changed: resp.detached };
    } catch (e) {
      throw fromConnect(e);
    }
  }

  async listProviders(name: string): Promise<ProviderRef[]> {
    try {
      const resp = await this.grpc.listSandboxProviders({ sandboxName: name });
      return resp.providers.map((p) => providerRef(p));
    } catch (e) {
      throw fromConnect(e);
    }
  }

  async getConfig(name: string, callOptions?: CallOptions): Promise<SandboxConfig> {
    try {
      const sandbox = await this.get(name, callOptions);
      const resp = await this.grpc.getSandboxConfig({ sandboxId: sandbox.id }, callOptions);
      return sandboxConfig(resp);
    } catch (e) {
      throw e instanceof SdkError ? e : fromConnect(e);
    }
  }

  // Update the sandbox-scoped policy. Sandbox scope (global=false) may only
  // change network_policies; static fields must match the create-time policy or
  // the gateway rejects the update. With `wait`, poll getConfig until the
  // applied policy hash is observed.
  async setPolicy(
    name: string,
    policy: MessageInitShape<typeof SandboxPolicySchema>,
    options?: SetPolicyOptions | null,
  ): Promise<UpdateConfigResult> {
    try {
      const resp = await this.grpc.updateConfig({
        name,
        policy,
        global: false,
        expectedResourceVersion: versionPin(options?.expectedResourceVersion),
      });
      const result = updateConfigResult(resp);
      if (options?.wait) await this.waitForPolicyHash(name, result.policyHash, options.waitTimeoutSecs);
      return result;
    } catch (e) {
      throw e instanceof SdkError ? e : fromConnect(e);
    }
  }

  // Upsert a single sandbox-scoped setting. Sandbox-scoped deletes are rejected
  // by the gateway, so there is no sandbox-scoped delete on this surface.
  async setSetting(
    name: string,
    key: string,
    value: MessageInitShape<typeof SettingValueSchema>,
  ): Promise<UpdateConfigResult> {
    try {
      const resp = await this.grpc.updateConfig({
        name,
        settingKey: key,
        settingValue: value,
        global: false,
      });
      return updateConfigResult(resp);
    } catch (e) {
      throw fromConnect(e);
    }
  }

  // Poll getConfig until the applied policy hash is observed. Each poll RPC is
  // bounded by the remaining deadline (deadlineOptions), so a stalled getConfig
  // cannot make the returned promise outlive timeoutSecs.
  private async waitForPolicyHash(name: string, policyHash: string, timeoutSecs = 60): Promise<void> {
    const deadline = Date.now() + timeoutSecs * 1000;
    let delay = 100;
    for (;;) {
      let config: SandboxConfig;
      try {
        config = await this.getConfig(name, deadlineOptions(deadline - Date.now()));
      } catch (e) {
        if (Date.now() >= deadline) {
          throw new SdkError('connect', `timed out waiting for policy '${policyHash}' on sandbox '${name}'`);
        }
        throw e instanceof SdkError ? e : fromConnect(e);
      }
      if (config.policyHash === policyHash) return;
      if (Date.now() >= deadline) {
        throw new SdkError('connect', `timed out waiting for policy '${policyHash}' on sandbox '${name}'`);
      }
      await waitSleep(delay, deadline);
      delay = Math.min(delay * 2, 2000);
    }
  }
}

// ---- The client ------------------------------------------------------------

export class OpenShellClient {
  /** Sandbox lifecycle + exec: create/get/list/delete, waitReady/waitDeleted, exec. */
  readonly sandbox: SandboxClient;

  /**
   * Advanced escape hatch: a generated client for every gateway RPC, including
   * surface the curated sub-clients do not wrap yet (gateway config, provider
   * CRUD, policy status, watch, logs, and the full observed Sandbox). See
   * '@nvidia/openshell-sdk/raw' for the generated request/response types.
   */
  readonly raw: Client<typeof OpenShell>;
  /** The shared Connect transport, for building extra clients over the same connection. */
  readonly transport: Transport;

  private readonly grpc: Client<typeof OpenShell>;

  private constructor(transport: Transport) {
    // One transport (one connection) shared across every scoped client.
    this.transport = transport;
    this.grpc = createClient(OpenShell, transport);
    this.raw = this.grpc;
    this.sandbox = new SandboxClient(transport, this.grpc);
  }

  /**
   * Constructs a lazy Connect client. No network request is made until the
   * first RPC; call health() when startup must verify gateway reachability.
   */
  static async connect(options: ConnectOptions): Promise<OpenShellClient> {
    return new OpenShellClient(buildTransport(options));
  }

  // Gateway-scoped, so it stays top-level rather than under a namespace.
  async health(): Promise<Health> {
    try {
      const resp = await this.grpc.health({});
      return { status: statusName(resp.status), version: resp.version };
    } catch (e) {
      throw fromConnect(e);
    }
  }
}
