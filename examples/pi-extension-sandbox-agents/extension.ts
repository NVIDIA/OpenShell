// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Pi extension: OpenShell sandboxes as sub-agents.
//
// Configuration is read from the environment at first tool call:
//   OPENSHELL_GATEWAY        Gateway URL (required, e.g. https://gw.example.com)
//   OPENSHELL_OIDC_TOKEN     Bearer token (one of OIDC_TOKEN or EDGE_TOKEN required)
//   OPENSHELL_EDGE_TOKEN     Cloudflare Access token (alternative to OIDC)
//   OPENSHELL_CA_CERT        Path to PEM CA bundle (optional)
//   OPENSHELL_INSECURE       "1" to disable TLS verification (dev only)
//   OPENSHELL_DEFAULT_IMAGE  Image to use when run_task omits one (optional)

import { readFileSync } from 'node:fs'
import type { ExtensionAPI } from '@earendil-works/pi-coding-agent'
import { Type, type Static } from 'typebox'
import { OpenShellClient, errorCode, type ExecResult, type SandboxSpec } from '@openshell/sdk'

const DEFAULT_READY_TIMEOUT_SECS = 120
const DEFAULT_EXEC_TIMEOUT_SECS = 300
const MAX_OUTPUT_BYTES = 64 * 1024

const RunTaskSchema = Type.Object({
  task: Type.String({
    description: 'Short human-readable label for this run (stamped onto sandbox labels).',
  }),
  command: Type.String({
    description: 'Shell command to execute via /bin/sh -c inside the fresh sandbox.',
  }),
  image: Type.Optional(
    Type.String({
      description: 'Sandbox image. Falls back to OPENSHELL_DEFAULT_IMAGE then the gateway default.',
    }),
  ),
  environment: Type.Optional(
    Type.Record(Type.String(), Type.String(), {
      description: 'Extra env vars for the command.',
    }),
  ),
  workdir: Type.Optional(
    Type.String({ description: 'Working directory inside the sandbox.' }),
  ),
  timeout_secs: Type.Optional(
    Type.Integer({ minimum: 1, description: 'Per-exec timeout. Defaults to 300s.' }),
  ),
  keep_sandbox: Type.Optional(
    Type.Boolean({
      description: 'Skip the cleanup delete so follow-up exec can reuse the sandbox. Default false.',
    }),
  ),
  labels: Type.Optional(
    Type.Record(Type.String(), Type.String(), {
      description: 'Extra labels stamped on the sandbox.',
    }),
  ),
})

const SpawnSchema = Type.Object({
  name: Type.Optional(
    Type.String({ description: 'Explicit sandbox name. The gateway generates one if omitted.' }),
  ),
  image: Type.Optional(Type.String()),
  environment: Type.Optional(Type.Record(Type.String(), Type.String())),
  labels: Type.Optional(Type.Record(Type.String(), Type.String())),
  ready_timeout_secs: Type.Optional(
    Type.Integer({ minimum: 1, description: 'How long to wait for ready. Defaults to 120s.' }),
  ),
})

const ExecSchema = Type.Object({
  sandbox: Type.String({ description: 'Sandbox name returned by openshell_spawn_sandbox.' }),
  command: Type.String({ description: 'Shell command to execute via /bin/sh -c.' }),
  environment: Type.Optional(Type.Record(Type.String(), Type.String())),
  workdir: Type.Optional(Type.String()),
  timeout_secs: Type.Optional(Type.Integer({ minimum: 1 })),
})

const ListSchema = Type.Object({
  limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 500 })),
  label_selector: Type.Optional(
    Type.String({ description: 'e.g. "pi.openshell/role=sub-agent"' }),
  ),
})

const DestroySchema = Type.Object({
  sandbox: Type.String(),
  wait: Type.Optional(
    Type.Boolean({ description: 'Block until the sandbox is fully gone. Default false.' }),
  ),
})

type RunTaskInput = Static<typeof RunTaskSchema>
type SpawnInput = Static<typeof SpawnSchema>
type ExecInput = Static<typeof ExecSchema>
type ListInput = Static<typeof ListSchema>
type DestroyInput = Static<typeof DestroySchema>

function requireEnv(name: string): string {
  const value = process.env[name]
  if (!value || value.length === 0) {
    throw new Error(`${name} is not set; pi-openshell extension needs it to connect to the gateway`)
  }
  return value
}

function decodeOutput(buf: Buffer): { text: string; truncated: boolean; total_bytes: number } {
  const total = buf.length
  if (total <= MAX_OUTPUT_BYTES) {
    return { text: buf.toString('utf8'), truncated: false, total_bytes: total }
  }
  return {
    text: buf.subarray(0, MAX_OUTPUT_BYTES).toString('utf8'),
    truncated: true,
    total_bytes: total,
  }
}

function describeError(err: unknown): { code: string; message: string } {
  if (err instanceof Error) {
    return { code: errorCode(err) ?? 'unknown', message: err.message }
  }
  return { code: 'unknown', message: String(err) }
}

async function connectClient(): Promise<OpenShellClient> {
  const gateway = requireEnv('OPENSHELL_GATEWAY')
  const oidcToken = process.env.OPENSHELL_OIDC_TOKEN
  const edgeToken = process.env.OPENSHELL_EDGE_TOKEN
  const caPath = process.env.OPENSHELL_CA_CERT
  return OpenShellClient.connect({
    gateway,
    oidcToken: oidcToken || undefined,
    edgeToken: edgeToken || undefined,
    caCert: caPath ? readFileSync(caPath) : undefined,
    insecureSkipVerify: process.env.OPENSHELL_INSECURE === '1',
  })
}

function summariseExec(result: {
  sandbox: string
  exit_code: number
  stdout: string
  stderr: string
  stdout_truncated: boolean
  stderr_truncated: boolean
}): string {
  const lines = [
    `sandbox: ${result.sandbox}`,
    `exit_code: ${result.exit_code}`,
    `--- stdout${result.stdout_truncated ? ' (truncated)' : ''} ---`,
    result.stdout.length ? result.stdout : '(empty)',
    `--- stderr${result.stderr_truncated ? ' (truncated)' : ''} ---`,
    result.stderr.length ? result.stderr : '(empty)',
  ]
  return lines.join('\n')
}

export default function (pi: ExtensionAPI): void {
  let cached: Promise<OpenShellClient> | undefined

  const client = (): Promise<OpenShellClient> => {
    if (!cached) {
      cached = connectClient().catch((err) => {
        cached = undefined
        throw err
      })
    }
    return cached
  }

  pi.registerTool({
    name: 'openshell_run_task',
    label: 'Run sub-agent task',
    description:
      'Run a one-shot task inside a fresh OpenShell sandbox. Each call is a disposable sub-agent: create a sandbox, run the command, return the result, and delete the sandbox (unless keep_sandbox=true). Use this for isolated work like running tests, building artifacts, or executing untrusted code without polluting your own environment.',
    parameters: RunTaskSchema,
    async execute(_toolCallId, params: RunTaskInput) {
      const c = await client()
      const spec: SandboxSpec = {
        labels: {
          'pi.openshell/role': 'sub-agent',
          'pi.openshell/task': params.task.slice(0, 63),
          ...(params.labels ?? {}),
        },
        environment: params.environment,
        image: params.image ?? process.env.OPENSHELL_DEFAULT_IMAGE,
      }
      const started = Date.now()
      let createdName: string | undefined
      try {
        const ref = await c.createSandbox(spec)
        createdName = ref.name
        await c.waitReady(ref.name, DEFAULT_READY_TIMEOUT_SECS)
        const result: ExecResult = await c.exec(ref.name, ['/bin/sh', '-c', params.command], {
          workdir: params.workdir,
          environment: params.environment,
          timeoutSecs: params.timeout_secs ?? DEFAULT_EXEC_TIMEOUT_SECS,
        })
        const stdout = decodeOutput(result.stdout)
        const stderr = decodeOutput(result.stderr)
        const details = {
          sandbox: ref.name,
          exit_code: result.exitCode,
          stdout: stdout.text,
          stderr: stderr.text,
          stdout_truncated: stdout.truncated,
          stderr_truncated: stderr.truncated,
          stdout_bytes: stdout.total_bytes,
          stderr_bytes: stderr.total_bytes,
          elapsed_ms: Date.now() - started,
          retained: params.keep_sandbox === true,
        }
        return {
          content: [{ type: 'text' as const, text: summariseExec(details) }],
          details,
        }
      } finally {
        if (createdName && params.keep_sandbox !== true) {
          await c.deleteSandbox(createdName).catch(() => undefined)
        }
      }
    },
  })

  pi.registerTool({
    name: 'openshell_spawn_sandbox',
    label: 'Spawn long-lived sandbox',
    description:
      'Create a long-lived OpenShell sandbox and wait until it is ready. Returns the sandbox name. Use when you plan to dispatch multiple commands into the same sub-agent — pair with openshell_exec and openshell_destroy_sandbox.',
    parameters: SpawnSchema,
    async execute(_toolCallId, params: SpawnInput) {
      const c = await client()
      const ref = await c.createSandbox({
        name: params.name,
        image: params.image ?? process.env.OPENSHELL_DEFAULT_IMAGE,
        environment: params.environment,
        labels: {
          'pi.openshell/role': 'sub-agent',
          ...(params.labels ?? {}),
        },
      })
      const ready = await c.waitReady(ref.name, params.ready_timeout_secs ?? DEFAULT_READY_TIMEOUT_SECS)
      const details = { sandbox: ready.name, phase: ready.phase, labels: ready.labels }
      return {
        content: [
          { type: 'text' as const, text: `Sandbox ${ready.name} is ${ready.phase}.` },
        ],
        details,
      }
    },
  })

  pi.registerTool({
    name: 'openshell_exec',
    label: 'Exec in sandbox',
    description:
      'Run a command inside an existing sandbox and return stdout/stderr/exit_code. Use the sandbox name returned by openshell_spawn_sandbox.',
    parameters: ExecSchema,
    async execute(_toolCallId, params: ExecInput) {
      const c = await client()
      const result = await c.exec(params.sandbox, ['/bin/sh', '-c', params.command], {
        environment: params.environment,
        workdir: params.workdir,
        timeoutSecs: params.timeout_secs ?? DEFAULT_EXEC_TIMEOUT_SECS,
      })
      const stdout = decodeOutput(result.stdout)
      const stderr = decodeOutput(result.stderr)
      const details = {
        sandbox: params.sandbox,
        exit_code: result.exitCode,
        stdout: stdout.text,
        stderr: stderr.text,
        stdout_truncated: stdout.truncated,
        stderr_truncated: stderr.truncated,
      }
      return {
        content: [{ type: 'text' as const, text: summariseExec(details) }],
        details,
      }
    },
  })

  pi.registerTool({
    name: 'openshell_list_sandboxes',
    label: 'List sandboxes',
    description:
      'List sandboxes visible to the configured gateway, optionally filtered by label selector (e.g. "pi.openshell/role=sub-agent").',
    parameters: ListSchema,
    async execute(_toolCallId, params: ListInput) {
      const c = await client()
      const sandboxes = await c.listSandboxes({
        limit: params.limit,
        labelSelector: params.label_selector,
      })
      const rows = sandboxes.map((s) => ({ name: s.name, phase: s.phase, labels: s.labels }))
      const text = rows.length
        ? rows.map((r) => `${r.name}  ${r.phase}`).join('\n')
        : '(no sandboxes)'
      return {
        content: [{ type: 'text' as const, text }],
        details: { count: rows.length, sandboxes: rows },
      }
    },
  })

  pi.registerTool({
    name: 'openshell_destroy_sandbox',
    label: 'Destroy sandbox',
    description:
      'Delete a sandbox by name. Use after openshell_spawn_sandbox + openshell_exec to release a long-lived sub-agent. openshell_run_task cleans up on its own.',
    parameters: DestroySchema,
    async execute(_toolCallId, params: DestroyInput) {
      const c = await client()
      const acknowledged = await c.deleteSandbox(params.sandbox)
      if (params.wait === true && acknowledged) {
        await c.waitDeleted(params.sandbox, 60)
      }
      const details = { sandbox: params.sandbox, acknowledged }
      return {
        content: [
          {
            type: 'text' as const,
            text: acknowledged
              ? `Deleted ${params.sandbox}.`
              : `Delete request for ${params.sandbox} was not acknowledged (already gone?).`,
          },
        ],
        details,
      }
    },
  })

  pi.registerCommand('openshell-health', {
    description: 'Probe the OpenShell gateway and report its health.',
    handler: async (_args, ctx) => {
      try {
        const c = await client()
        const health = await c.health()
        ctx.ui.notify(`OpenShell gateway: ${health.status} (version ${health.version})`, 'info')
      } catch (err) {
        const { code, message } = describeError(err)
        ctx.ui.notify(`OpenShell gateway unavailable [${code}]: ${message}`, 'error')
      }
    },
  })
}
