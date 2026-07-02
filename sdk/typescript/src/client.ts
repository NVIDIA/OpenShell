// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// The OpenShell gateway client: a thin, idiomatic ergonomics layer over the
// protobuf-generated gRPC stubs (src/gen/). It owns proto request assembly,
// curated public types, the ExecSandbox server-stream drain, and the
// waitReady/waitDeleted poll loops. Transport and auth live in transport.ts;
// the error taxonomy in errors.ts.

import { createClient, type Client } from '@connectrpc/connect'
import { OpenShell, SandboxPhase, ServiceStatus } from './gen/openshell_pb.js'
import type { Sandbox } from './gen/openshell_pb.js'
import { buildTransport, type ConnectOptions } from './transport.js'
import { errorCode, fromConnect, SdkError } from './errors.js'

export { errorCode }
export type { ConnectOptions }

// ---- Curated public types --------------------------------------------------

export interface Health {
  status: string
  version: string
}

export interface SandboxSpec {
  name?: string
  image?: string
  labels?: Record<string, string>
  environment?: Record<string, string>
  providers?: string[]
  gpu?: boolean
}

export interface SandboxRef {
  id: string
  name: string
  phase: string
  labels: Record<string, string>
  /** u64 rendered as a string — JS numbers can't hold it safely. */
  resourceVersion: string
}

export interface ListOptions {
  limit?: number
  offset?: number
  labelSelector?: string
}

export interface ExecOptions {
  workdir?: string
  environment?: Record<string, string>
  timeoutSecs?: number
  stdin?: Buffer
}

export interface ExecResult {
  exitCode: number
  stdout: Buffer
  stderr: Buffer
}

// ---- enum → lowercase string -----------------------------------------------

function phaseName(p: SandboxPhase): string {
  return (SandboxPhase[p] ?? 'UNSPECIFIED').toLowerCase()
}
function statusName(s: ServiceStatus): string {
  return (ServiceStatus[s] ?? 'UNSPECIFIED').toLowerCase()
}

function sandboxRef(sandbox: Sandbox | undefined): SandboxRef {
  if (!sandbox) throw new SdkError('invalid_config', 'sandbox missing from gateway response')
  const meta = sandbox.metadata
  return {
    id: meta?.id ?? '',
    name: meta?.name ?? '',
    phase: phaseName(sandbox.status?.phase ?? SandboxPhase.UNSPECIFIED),
    labels: meta?.labels ?? {},
    resourceVersion: (meta?.resourceVersion ?? 0n).toString(),
  }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

// ---- The client ------------------------------------------------------------

export class OpenShellClient {
  private constructor(private readonly grpc: Client<typeof OpenShell>) {}

  static async connect(options: ConnectOptions): Promise<OpenShellClient> {
    return new OpenShellClient(createClient(OpenShell, buildTransport(options)))
  }

  async health(): Promise<Health> {
    try {
      const resp = await this.grpc.health({})
      return { status: statusName(resp.status), version: resp.version }
    } catch (e) {
      throw fromConnect(e)
    }
  }

  async createSandbox(spec: SandboxSpec): Promise<SandboxRef> {
    try {
      const resp = await this.grpc.createSandbox({
        name: spec.name ?? '',
        labels: spec.labels ?? {},
        spec: {
          environment: spec.environment ?? {},
          providers: spec.providers ?? [],
          template: spec.image ? { image: spec.image } : undefined,
          resourceRequirements: spec.gpu ? { gpu: {} } : undefined,
        },
      })
      return sandboxRef(resp.sandbox)
    } catch (e) {
      throw fromConnect(e)
    }
  }

  async getSandbox(name: string): Promise<SandboxRef> {
    try {
      const resp = await this.grpc.getSandbox({ name })
      return sandboxRef(resp.sandbox)
    } catch (e) {
      throw fromConnect(e)
    }
  }

  async listSandboxes(options?: ListOptions | null): Promise<SandboxRef[]> {
    try {
      const resp = await this.grpc.listSandboxes({
        limit: options?.limit ?? 0,
        offset: options?.offset ?? 0,
        labelSelector: options?.labelSelector ?? '',
      })
      return resp.sandboxes.map((s) => sandboxRef(s))
    } catch (e) {
      throw fromConnect(e)
    }
  }

  async deleteSandbox(name: string): Promise<boolean> {
    try {
      const resp = await this.grpc.deleteSandbox({ name })
      return resp.deleted
    } catch (e) {
      throw fromConnect(e)
    }
  }

  async waitReady(name: string, timeoutSecs: number): Promise<SandboxRef> {
    const deadline = Date.now() + timeoutSecs * 1000
    let delay = 250
    for (;;) {
      const ref = await this.getSandbox(name)
      if (ref.phase === 'ready') return ref
      if (ref.phase === 'error') throw new SdkError('connect', `sandbox '${name}' entered error phase`)
      if (Date.now() >= deadline) throw new SdkError('connect', `timed out waiting for sandbox '${name}'`)
      await sleep(delay)
      delay = Math.min(delay * 2, 2000)
    }
  }

  async waitDeleted(name: string, timeoutSecs: number): Promise<void> {
    const deadline = Date.now() + timeoutSecs * 1000
    let delay = 250
    for (;;) {
      try {
        await this.getSandbox(name)
      } catch (e) {
        if (e instanceof SdkError && e.code === 'not_found') return
        throw e
      }
      if (Date.now() >= deadline) throw new SdkError('connect', `timed out waiting for sandbox '${name}' to delete`)
      await sleep(delay)
      delay = Math.min(delay * 2, 2000)
    }
  }

  async exec(name: string, command: string[], options?: ExecOptions | null): Promise<ExecResult> {
    try {
      // Resolve the sandbox id first, exactly like the gateway client.
      const sandbox = await this.getSandbox(name)
      const stream = this.grpc.execSandbox({
        sandboxId: sandbox.id,
        command,
        workdir: options?.workdir ?? '',
        environment: options?.environment ?? {},
        timeoutSeconds: options?.timeoutSecs ?? 0,
        stdin: options?.stdin ? new Uint8Array(options.stdin) : new Uint8Array(),
        tty: false,
      })

      const stdout: Uint8Array[] = []
      const stderr: Uint8Array[] = []
      let exitCode = -1
      for await (const event of stream) {
        switch (event.payload.case) {
          case 'stdout':
            stdout.push(event.payload.value.data)
            break
          case 'stderr':
            stderr.push(event.payload.value.data)
            break
          case 'exit':
            exitCode = event.payload.value.exitCode
            break
        }
      }
      return { exitCode, stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr) }
    } catch (e) {
      throw e instanceof SdkError ? e : fromConnect(e)
    }
  }
}
