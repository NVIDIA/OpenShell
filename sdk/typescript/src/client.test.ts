// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Unit tests for SandboxClient against an in-memory OpenShell service. Every
// RPC is stubbed with createRouterTransport, so these exercise request
// assembly, u64/int64->string rendering, enum lowercasing, fromConnect code
// mapping, the exec/execStream drain, execInteractive framing, and the
// forward() byte relay without a running gateway.

import * as net from 'node:net';
import type { MessageInitShape } from '@bufbuild/protobuf';
import { Code, ConnectError, createRouterTransport, type ServiceImpl, type Transport } from '@connectrpc/connect';
import { describe, expect, it } from 'vitest';
import {
  errorCode,
  PHASE_NAMES,
  POLICY_SOURCE_NAMES,
  Pushable,
  SandboxClient,
  SandboxTemplateClient,
  SCOPE_NAMES,
  STATUS_NAMES,
} from './client.js';
import { OpenShell, SandboxPhase, ServiceStatus } from './gen/openshell_pb.js';
import { PolicySource, SettingScope } from './gen/sandbox_pb.js';

function client(impl: Partial<ServiceImpl<typeof OpenShell>>): SandboxClient {
  const transport: Transport = createRouterTransport((router) => {
    router.service(OpenShell, impl);
  });
  return new SandboxClient(transport);
}

function templateClient(impl: Partial<ServiceImpl<typeof OpenShell>>): SandboxTemplateClient {
  const transport: Transport = createRouterTransport((router) => {
    router.service(OpenShell, impl);
  });
  return new SandboxTemplateClient(transport);
}

function readySandbox(
  name: string,
  id: string,
  resourceVersion = 7n,
  createdFromWorkloadTemplate?: { name: string; resourceVersion: string },
  workspace = 'default',
): MessageInitShape<typeof OpenShell.method.getSandbox.output> {
  return {
    sandbox: {
      metadata: { id, name, workspace, labels: { team: 'aire' }, resourceVersion },
      status: { phase: SandboxPhase.READY },
      createdFromWorkloadTemplate,
    },
  };
}

const enc = (s: string) => new TextEncoder().encode(s);

describe('exec / execStream', () => {
  it('resolves the id via get, frames tty:false, and buffers the result (backward compat)', async () => {
    let execReq: { sandboxId?: string; tty?: boolean; command?: string[] } = {};
    const sandbox = client({
      getSandbox: () => readySandbox('sb', 'sb-id-1'),
      // eslint-disable-next-line require-yield
      execSandbox: async function* (req) {
        execReq = req;
        yield { payload: { case: 'stdout', value: { data: enc('hello ') } } };
        yield { payload: { case: 'stderr', value: { data: enc('warn') } } };
        yield { payload: { case: 'stdout', value: { data: enc('world') } } };
        yield { payload: { case: 'exit', value: { exitCode: 3 } } };
      },
    });

    const result = await sandbox.exec('sb', ['/bin/sh', '-c', 'echo hi']);
    expect(execReq.sandboxId).toBe('sb-id-1');
    expect(execReq.tty).toBe(false);
    expect(execReq.command).toEqual(['/bin/sh', '-c', 'echo hi']);
    expect(result.exitCode).toBe(3);
    expect(result.stdout.toString()).toBe('hello world');
    expect(result.stderr.toString()).toBe('warn');
    expect(Buffer.isBuffer(result.stdout)).toBe(true);
  });

  it('execStream yields incremental chunks then a terminal exit event', async () => {
    const sandbox = client({
      getSandbox: () => readySandbox('sb', 'sb-id-1'),
      // eslint-disable-next-line require-yield
      execSandbox: async function* () {
        yield { payload: { case: 'stdout', value: { data: enc('a') } } };
        yield { payload: { case: 'stderr', value: { data: enc('b') } } };
        yield { payload: { case: 'exit', value: { exitCode: 0 } } };
      },
    });

    const chunks: Array<{ stream: string; data: string }> = [];
    let exitCode: number | undefined;
    for await (const event of sandbox.execStream('sb', ['x'])) {
      if ('type' in event) exitCode = event.exitCode;
      else chunks.push({ stream: event.stream, data: event.data.toString() });
    }
    expect(chunks).toEqual([
      { stream: 'stdout', data: 'a' },
      { stream: 'stderr', data: 'b' },
    ]);
    expect(exitCode).toBe(0);
  });

  it('surfaces a nonzero exit via for-await', async () => {
    const sandbox = client({
      getSandbox: () => readySandbox('sb', 'sb-id-1'),
      // eslint-disable-next-line require-yield
      execSandbox: async function* () {
        yield { payload: { case: 'stdout', value: { data: enc('boom') } } };
        yield { payload: { case: 'exit', value: { exitCode: 2 } } };
      },
    });

    let streamed: number | undefined;
    for await (const event of sandbox.execStream('sb', ['pytest'])) {
      if ('type' in event) streamed = event.exitCode;
    }
    expect(streamed).toBe(2);
  });

  it('surfaces a nonzero exit via exec()', async () => {
    const sandbox = client({
      getSandbox: () => readySandbox('sb', 'sb-id-1'),
      // eslint-disable-next-line require-yield
      execSandbox: async function* () {
        yield { payload: { case: 'stdout', value: { data: enc('boom') } } };
        yield { payload: { case: 'exit', value: { exitCode: 2 } } };
      },
    });
    const result = await sandbox.exec('sb', ['pytest']);
    expect(result.exitCode).toBe(2);
    expect(result.stdout.toString()).toBe('boom');
  });

  it('execStream throws when the stream ends without an exit event', async () => {
    const sandbox = client({
      getSandbox: () => readySandbox('sb', 'sb-id-1'),
      // eslint-disable-next-line require-yield
      execSandbox: async function* () {
        yield { payload: { case: 'stdout', value: { data: enc('partial') } } };
      },
    });
    await expect(
      (async () => {
        for await (const _event of sandbox.execStream('sb', ['x'])) {
          // drain to completion
        }
      })(),
    ).rejects.toMatchObject({ code: 'rpc' });
  });

  it('exec throws when the stream ends without an exit event', async () => {
    const sandbox = client({
      getSandbox: () => readySandbox('sb', 'sb-id-1'),
      // eslint-disable-next-line require-yield
      execSandbox: async function* () {
        yield { payload: { case: 'stdout', value: { data: enc('partial') } } };
      },
    });
    await expect(sandbox.exec('sb', ['x'])).rejects.toMatchObject({ code: 'rpc' });
  });

  it('execStream rejects when the caller signal is already aborted', async () => {
    const sandbox = client({
      getSandbox: () => readySandbox('sb', 'sb-id-1'),
      // eslint-disable-next-line require-yield
      execSandbox: async function* () {
        yield { payload: { case: 'stdout', value: { data: enc('never') } } };
        yield { payload: { case: 'exit', value: { exitCode: 0 } } };
      },
    });
    const signal = AbortSignal.abort();
    await expect(
      (async () => {
        for await (const _event of sandbox.execStream('sb', ['x'], { signal })) {
          // drain to completion
        }
      })(),
    ).rejects.toBeInstanceOf(Error);
  });

  it('exec rejects when the caller signal aborts mid-stream', async () => {
    const controller = new AbortController();
    const sandbox = client({
      getSandbox: () => readySandbox('sb', 'sb-id-1'),
      execSandbox: async function* (_req, ctx) {
        yield { payload: { case: 'stdout', value: { data: enc('partial') } } };
        await new Promise<void>((_resolve, reject) => {
          ctx.signal.addEventListener('abort', () => reject(new ConnectError('canceled', Code.Canceled)), {
            once: true,
          });
        });
      },
    });
    setTimeout(() => controller.abort(), 10);
    await expect(sandbox.exec('sb', ['x'], { signal: controller.signal })).rejects.toBeInstanceOf(Error);
  });

  it('maps a NotFound from get() to an SdkError not_found', async () => {
    const sandbox = client({
      getSandbox: () => {
        throw new ConnectError('missing', Code.NotFound);
      },
    });
    await expect(sandbox.exec('sb', ['x'])).rejects.toMatchObject({
      code: 'not_found',
    });
    await expect(sandbox.exec('sb', ['x'])).rejects.toSatisfy((e) => errorCode(e) === 'not_found');
  });
});

describe('create', () => {
  it('sends the curated policy through spec.policy', async () => {
    let created: { spec?: { policy?: { version?: number } } } = {};
    const sandbox = client({
      createSandbox: (req) => {
        created = req;
        return readySandbox('sb', 'sb-id');
      },
    });
    await sandbox.create({ image: 'img', policy: { version: 1, networkPolicies: {} } });
    expect(created.spec?.policy?.version).toBe(1);
  });

  it('sends canonical main process fields', async () => {
    let created: { spec?: { command?: string[]; tty?: boolean } } = {};
    const sandbox = client({
      createSandbox: (req) => {
        created = req;
        return readySandbox('sb', 'sb-id');
      },
    });

    await sandbox.create({
      image: 'img',
      command: ['/opt/worker', '--serve'],
      tty: true,
    });

    expect(created.spec?.command).toEqual(['/opt/worker', '--serve']);
    expect(created.spec?.tty).toBe(true);
  });

  it('rawSpec reaches an ungated field and overrides a curated one', async () => {
    let created: {
      spec?: {
        logLevel?: string;
        template?: { image?: string };
        providers?: string[];
      };
    } = {};
    const sandbox = client({
      createSandbox: (req) => {
        created = req;
        return readySandbox('sb', 'sb-id');
      },
    });
    await sandbox.create({
      image: 'curated-image',
      providers: ['claude'],
      rawSpec: { logLevel: 'debug', template: { image: 'raw-image' } },
    });
    // Ungated field only reachable via rawSpec.
    expect(created.spec?.logLevel).toBe('debug');
    // rawSpec wins on a field the curated shape also sets.
    expect(created.spec?.template?.image).toBe('raw-image');
    // Curated fields rawSpec does not touch survive.
    expect(created.spec?.providers).toEqual(['claude']);
  });

  it('createFromTemplate sends the workload template name with governance fields only', async () => {
    let created: {
      workloadTemplateName?: string;
      name?: string;
      workspace?: string;
      labels?: Record<string, string>;
      spec?: {
        policy?: { version?: number };
        providers?: string[];
        command?: string[];
        tty?: boolean;
        template?: { image?: string };
      };
    } = {};
    const sandbox = client({
      createSandbox: (req) => {
        created = req;
        return readySandbox('job-1', 'sb-id', 7n, undefined, req.workspace || 'default');
      },
    });
    const ref = await sandbox.createFromTemplate({
      name: 'job-1',
      workspace: 'staging',
      templateName: 'gpu-kata',
      labels: { team: 'runtime' },
      providers: ['github'],
      command: ['/opt/worker', '--serve'],
      tty: true,
      policy: { version: 1, networkPolicies: {} },
    });

    expect(created.workloadTemplateName).toBe('gpu-kata');
    expect(created.name).toBe('job-1');
    expect(created.workspace).toBe('staging');
    expect(created.labels).toEqual({ team: 'runtime' });
    expect(created.spec?.providers).toEqual(['github']);
    expect(created.spec?.command).toEqual(['/opt/worker', '--serve']);
    expect(created.spec?.tty).toBe(true);
    expect(created.spec?.policy?.version).toBe(1);
    expect(created.spec?.template).toBeUndefined();
    expect(ref.workspace).toBe('staging');
  });

  it('propagates workspace through sandbox lifecycle calls', async () => {
    const observed: {
      create?: { workspace?: string };
      get?: { workspace?: string };
      list?: { workspace?: string; allWorkspaces?: boolean };
      delete?: { workspace?: string };
      attach?: { workspace?: string };
      detach?: { workspace?: string };
      listProviders?: { workspace?: string };
      updatePolicy?: { workspace?: string };
      updateSetting?: { workspace?: string };
      configGets: string[];
      execGet?: string;
      interactiveGet?: string;
      sshGet?: string;
      forwardGet?: string;
    } = { configGets: [] };
    const sandbox = client({
      createSandbox: (req) => {
        observed.create = req;
        return readySandbox(req.name || 'sb', 'sb-created', 7n, undefined, req.workspace || 'default');
      },
      getSandbox: (req) => {
        if (req.name === 'exec') observed.execGet = req.workspace;
        else if (req.name === 'interactive') observed.interactiveGet = req.workspace;
        else if (req.name === 'ssh') observed.sshGet = req.workspace;
        else if (req.name === 'forward') observed.forwardGet = req.workspace;
        else if (req.name === 'config') observed.configGets.push(req.workspace);
        else observed.get = req;
        return readySandbox(req.name, `${req.name}-id`, 7n, undefined, req.workspace || 'default');
      },
      listSandboxes: (req) => {
        observed.list = req;
        return {
          sandboxes: [
            {
              metadata: {
                id: 'listed-id',
                name: 'listed',
                workspace: req.workspace || 'default',
                labels: { team: 'aire' },
                resourceVersion: 7n,
              },
              status: { phase: SandboxPhase.READY },
            },
          ],
        };
      },
      deleteSandbox: (req) => {
        observed.delete = req;
        return { deleted: true };
      },
      attachSandboxProvider: (req) => {
        observed.attach = req;
        return {
          sandbox: readySandbox(req.sandboxName, 'attach-id', 7n, undefined, req.workspace || 'default').sandbox,
          attached: true,
        };
      },
      detachSandboxProvider: (req) => {
        observed.detach = req;
        return {
          sandbox: readySandbox(req.sandboxName, 'detach-id', 7n, undefined, req.workspace || 'default').sandbox,
          detached: true,
        };
      },
      listSandboxProviders: (req) => {
        observed.listProviders = req;
        return { providers: [] };
      },
      updateConfig: (req) => {
        if (req.settingKey) observed.updateSetting = req;
        else observed.updatePolicy = req;
        return { version: 5, policyHash: 'hash', settingsRevision: 10n, deleted: false };
      },
      getSandboxConfig: () => ({
        policy: { version: 1, networkPolicies: {} },
        version: 5,
        policyHash: 'hash',
        settings: {},
        configRevision: 1n,
        policySource: PolicySource.SANDBOX,
        globalPolicyVersion: 0,
        providerEnvRevision: 0n,
      }),
      // eslint-disable-next-line require-yield
      execSandbox: async function* () {
        yield { payload: { case: 'exit', value: { exitCode: 0 } } };
      },
      // eslint-disable-next-line require-yield
      execSandboxInteractive: async function* () {
        yield { payload: { case: 'exit', value: { exitCode: 0 } } };
      },
      createSshSession: (req) => ({
        sandboxId: req.sandboxId,
        token: 'tok',
        gatewayHost: 'gw',
        gatewayPort: 443,
        gatewayScheme: 'https',
        hostKeyFingerprint: '',
        expiresAtMs: 0n,
      }),
      revokeSshSession: () => ({ revoked: true }),
    });

    const created = await sandbox.create({ name: 'direct', workspace: 'staging', image: 'img' });
    const got = await sandbox.get('lookup', { workspace: 'staging' });
    const listed = await sandbox.list({ workspace: 'staging', limit: 10 });
    const deleted = await sandbox.delete('lookup', { workspace: 'staging' });
    await expect(sandbox.waitReady('lookup', 1, { workspace: 'staging' })).resolves.toMatchObject({
      workspace: 'staging',
    });
    await expect(sandbox.exec('exec', ['true'], { workspace: 'staging' })).resolves.toMatchObject({ exitCode: 0 });
    const interactive = await sandbox.execInteractive('interactive', ['true'], { workspace: 'staging' });
    for await (const _event of interactive.output) {
      // drain
    }
    await sandbox.createSshSession('ssh', { workspace: 'staging' });
    const attached = await sandbox.attachProvider('lookup', 'github', { workspace: 'staging' });
    const detached = await sandbox.detachProvider('lookup', 'github', { workspace: 'staging' });
    await sandbox.listProviders('lookup', { workspace: 'staging' });
    await sandbox.getConfig('config', { workspace: 'staging' });
    await sandbox.setPolicy('lookup', { version: 1, networkPolicies: {} }, { workspace: 'staging' });
    await sandbox.setSetting(
      'lookup',
      'feature.enabled',
      { value: { case: 'boolValue', value: true } },
      { workspace: 'staging' },
    );

    expect(created.workspace).toBe('staging');
    expect(got.workspace).toBe('staging');
    expect(listed[0]?.workspace).toBe('staging');
    expect(deleted).toBe(true);
    expect(attached.sandbox.workspace).toBe('staging');
    expect(detached.sandbox.workspace).toBe('staging');
    expect(observed.create?.workspace).toBe('staging');
    expect(observed.get?.workspace).toBe('staging');
    expect(observed.list).toMatchObject({ workspace: 'staging', allWorkspaces: false });
    expect(observed.delete?.workspace).toBe('staging');
    expect(observed.execGet).toBe('staging');
    expect(observed.interactiveGet).toBe('staging');
    expect(observed.sshGet).toBe('staging');
    expect(observed.attach?.workspace).toBe('staging');
    expect(observed.detach?.workspace).toBe('staging');
    expect(observed.listProviders?.workspace).toBe('staging');
    expect(observed.configGets).toContain('staging');
    expect(observed.updatePolicy?.workspace).toBe('staging');
    expect(observed.updateSetting?.workspace).toBe('staging');
  });

  it('createFromTemplate rejects an empty template name locally', async () => {
    const sandbox = client({});
    await expect(sandbox.createFromTemplate({ templateName: ' ' })).rejects.toMatchObject({
      code: 'invalid_config',
    });
  });

  it('rejects gateway sandboxes missing required metadata', async () => {
    const sandbox = client({
      getSandbox: () => ({ sandbox: { status: { phase: SandboxPhase.READY } } }),
    });
    await expect(sandbox.get('sb')).rejects.toMatchObject({ code: 'invalid_config' });
  });

  it('maps canonical main process status', async () => {
    const sandbox = client({
      getSandbox: () => ({
        sandbox: {
          metadata: { id: 'sb-id', name: 'sb', resourceVersion: 8n },
          status: {
            phase: SandboxPhase.ERROR,
            mainProcessInstanceId: 'main-1',
            exitCode: 9,
          },
        },
      }),
    });

    await expect(sandbox.get('sb')).resolves.toMatchObject({
      phase: 'error',
      mainProcessInstanceId: 'main-1',
      exitCode: 9,
    });
  });

  it('maps workload template provenance onto SandboxRef', async () => {
    const sandbox = client({
      getSandbox: () =>
        readySandbox('from-template', 'sb-id', 7n, {
          name: 'gpu-kata',
          resourceVersion: '42',
        }),
    });

    const ref = await sandbox.get('from-template');

    expect(ref.createdFromWorkloadTemplate).toEqual({
      name: 'gpu-kata',
      resourceVersion: '42',
    });
  });
});

describe('sandbox templates', () => {
  it('create sends the template resource and workspace', async () => {
    let observed: {
      workspace?: string;
      template?: {
        metadata?: { name?: string; labels?: Record<string, string> };
        spec?: {
          workload?: {
            image?: string;
            environment?: Record<string, string>;
            resources?: { cpu?: string; memory?: string; gpu?: { count?: number } };
          };
          driverConfig?: Record<string, unknown>;
        };
      };
    } = {};
    const templates = templateClient({
      createSandboxTemplate: (req) => {
        observed = req;
        return {
          template: {
            metadata: {
              id: 'template-python',
              name: req.template?.metadata?.name ?? '',
              labels: req.template?.metadata?.labels ?? {},
              workspace: req.workspace,
              resourceVersion: 1n,
            },
            spec: req.template?.spec,
          },
        };
      },
    });

    const created = await templates.create(
      {
        metadata: { name: 'python', labels: { team: 'runtime' } },
        spec: {
          workload: {
            image: 'ghcr.io/nvidia/openshell-community/sandboxes/python:latest',
            environment: { FEATURE_FLAG: 'on' },
            resources: { cpu: '1', memory: '512Mi', gpu: { count: 1 } },
          },
          driverConfig: { kubernetes: { runtime_class_name: 'kata-containers' } },
        },
      },
      { workspace: 'default' },
    );

    expect(observed.workspace).toBe('default');
    expect(observed.template?.metadata?.name).toBe('python');
    expect(observed.template?.metadata?.labels).toEqual({ team: 'runtime' });
    expect(observed.template?.spec?.workload?.environment).toEqual({ FEATURE_FLAG: 'on' });
    expect(observed.template?.spec?.workload?.resources?.gpu?.count).toBe(1);
    expect(created.metadata?.workspace).toBe('default');
    expect(created.metadata?.resourceVersion).toBe(1n);
  });

  it('get list and delete forward workspace and pagination', async () => {
    const observed: {
      get?: { name?: string; workspace?: string };
      list?: { limit?: number; offset?: number; workspace?: string; allWorkspaces?: boolean };
      delete?: { name?: string; workspace?: string };
    } = {};
    const templates = templateClient({
      getSandboxTemplate: (req) => {
        observed.get = req;
        return {
          template: {
            metadata: { id: 'template-gpu-kata', name: req.name, workspace: req.workspace },
            spec: { workload: { image: 'img:v1' } },
          },
        };
      },
      listSandboxTemplates: (req) => {
        observed.list = req;
        return {
          templates: [
            {
              metadata: { id: 'template-python', name: 'python', workspace: req.workspace || 'default' },
              spec: { workload: { image: 'img:v1' } },
            },
          ],
        };
      },
      deleteSandboxTemplate: (req) => {
        observed.delete = req;
        return { deleted: true };
      },
    });

    const got = await templates.get('gpu-kata', { workspace: 'staging' });
    const listed = await templates.list({ workspace: 'staging', limit: 10, offset: 2, labelSelector: 'team=runtime' });
    const deleted = await templates.delete('gpu-kata', { workspace: 'staging' });

    expect(got.metadata?.name).toBe('gpu-kata');
    expect(listed).toHaveLength(1);
    expect(deleted).toBe(true);
    expect(observed.get).toMatchObject({ name: 'gpu-kata', workspace: 'staging' });
    expect(observed.list).toMatchObject({
      limit: 10,
      offset: 2,
      workspace: 'staging',
      allWorkspaces: false,
      labelSelector: 'team=runtime',
    });
    expect(observed.delete).toMatchObject({ name: 'gpu-kata', workspace: 'staging' });
  });

  it('list clears workspace when allWorkspaces is set', async () => {
    let observed: { workspace?: string; allWorkspaces?: boolean } = {};
    const templates = templateClient({
      listSandboxTemplates: (req) => {
        observed = req;
        return { templates: [] };
      },
    });

    await templates.list({ workspace: 'staging', allWorkspaces: true });

    expect(observed.workspace).toBe('');
    expect(observed.allWorkspaces).toBe(true);
  });

  it('rejects empty names and missing template responses locally', async () => {
    const templates = templateClient({
      getSandboxTemplate: () => ({}),
    });

    await expect(templates.get(' ')).rejects.toMatchObject({ code: 'invalid_config' });
    await expect(templates.delete(' ')).rejects.toMatchObject({ code: 'invalid_config' });
    await expect(templates.get('missing-response')).rejects.toMatchObject({ code: 'invalid_config' });
  });
});

describe('waits', () => {
  it('waitReady accepts successful main-process completion', async () => {
    const sandbox = client({
      getSandbox: () => ({
        sandbox: {
          metadata: { id: 'sb-id', name: 'sb' },
          status: { phase: SandboxPhase.COMPLETED, exitCode: 0 },
        },
      }),
    });
    await expect(sandbox.waitReady('sb', 1)).resolves.toMatchObject({ phase: 'completed', exitCode: 0 });
  });

  it('waitReady rejects stopped main-process results without waiting for timeout', async () => {
    const sandbox = client({
      getSandbox: () => ({
        sandbox: {
          metadata: { id: 'sb-id', name: 'sb' },
          status: { phase: SandboxPhase.STOPPED, exitCode: 7 },
        },
      }),
    });
    await expect(sandbox.waitReady('sb', 30)).rejects.toMatchObject({ code: 'connect' });
  });

  it('waitReady rejects rather than hanging when get() never resolves', async () => {
    const sandbox = client({
      // Only settles when the per-poll deadline signal aborts the call.
      getSandbox: (_req, ctx) =>
        new Promise((_resolve, reject) => {
          ctx.signal.addEventListener('abort', () => reject(new ConnectError('canceled', Code.Canceled)));
        }),
    });
    await expect(sandbox.waitReady('sb', 0.2)).rejects.toMatchObject({ code: 'connect' });
  });

  it('waitReady rejects when a caller AbortController fires mid-wait', async () => {
    const controller = new AbortController();
    const sandbox = client({
      getSandbox: (_req, ctx) =>
        new Promise((_resolve, reject) => {
          ctx.signal.addEventListener('abort', () => reject(new ConnectError('canceled', Code.Canceled)));
        }),
    });
    setTimeout(() => controller.abort(), 30);
    await expect(sandbox.waitReady('sb', 30, { signal: controller.signal })).rejects.toMatchObject({
      code: 'connect',
    });
  });

  it('waitDeleted resolves when the gateway reports NotFound', async () => {
    const sandbox = client({
      getSandbox: () => {
        throw new ConnectError('gone', Code.NotFound);
      },
    });
    await expect(sandbox.waitDeleted('sb', 1)).resolves.toBeUndefined();
  });

  it('waitDeleted rejects rather than hanging when get() never resolves', async () => {
    const sandbox = client({
      getSandbox: (_req, ctx) =>
        new Promise((_resolve, reject) => {
          ctx.signal.addEventListener('abort', () => reject(new ConnectError('canceled', Code.Canceled)));
        }),
    });
    await expect(sandbox.waitDeleted('sb', 0.2)).rejects.toMatchObject({ code: 'connect' });
  });
});

describe('Pushable', () => {
  it('rejects a pending direct iterator next() when ended with an error', async () => {
    const input = new Pushable<number>();
    const iterator = input[Symbol.asyncIterator]();
    const next = iterator.next();
    const error = new Error('input failed');
    input.end(error);
    await expect(next).rejects.toBe(error);
  });
});

describe('execInteractive', () => {
  it('sends start first with tty/cols/rows, streams output, and resolves done', async () => {
    const cases: string[] = [];
    let started: { tty?: boolean; cols?: number; rows?: number; sandboxId?: string } | undefined;
    const sandbox = client({
      getSandbox: () => readySandbox('sb', 'sb-id-9'),
      execSandboxInteractive: async function* (requests) {
        for await (const input of requests) {
          cases.push(input.payload.case ?? 'none');
          if (input.payload.case === 'start') {
            started = input.payload.value;
            yield {
              payload: { case: 'stdout', value: { data: enc('ready\n') } },
            };
          } else if (input.payload.case === 'stdin') {
            yield {
              payload: { case: 'stdout', value: { data: input.payload.value } },
            };
          }
        }
        yield { payload: { case: 'exit', value: { exitCode: 0 } } };
      },
    });

    const session = await sandbox.execInteractive('sb', ['bash'], {
      cols: 120,
      rows: 40,
    });
    const out: string[] = [];
    const collector = (async () => {
      for await (const event of session.output) {
        if (!('type' in event)) out.push(event.data.toString());
      }
    })();

    session.write(Buffer.from('echo hi'));
    // Let the echo round-trip before closing the input stream.
    await new Promise((r) => setTimeout(r, 20));
    session.close();

    await collector;
    const code = await session.done;
    expect(code).toBe(0);
    expect(cases[0]).toBe('start');
    expect(started?.tty).toBe(true);
    expect(started?.cols).toBe(120);
    expect(started?.rows).toBe(40);
    expect(started?.sandboxId).toBe('sb-id-9');
    expect(out.join('')).toContain('ready\n');
    expect(out.join('')).toContain('echo hi');
  });
});

describe('exec done settlement', () => {
  it('resolves done even when the consumer breaks right after the exit event', async () => {
    const sandbox = client({
      getSandbox: () => readySandbox('sb', 'sb-id'),
      // eslint-disable-next-line require-yield
      execSandboxInteractive: async function* () {
        yield { payload: { case: 'stdout', value: { data: enc('hi') } } };
        yield { payload: { case: 'exit', value: { exitCode: 3 } } };
      },
    });
    const session = await sandbox.execInteractive('sb', ['bash']);
    for await (const event of session.output) {
      if ('type' in event) break; // break on exit: the generator never resumes
    }
    // Without settling `done` before the exit yield, this would hang forever.
    expect(await session.done).toBe(3);
  });

  it('rejects done and throws from output when the stream errors before exit', async () => {
    const sandbox = client({
      getSandbox: () => readySandbox('sb', 'sb-id'),
      execSandboxInteractive: async function* () {
        yield { payload: { case: 'stdout', value: { data: enc('partial') } } };
        throw new ConnectError('boom', Code.Internal);
      },
    });
    const session = await sandbox.execInteractive('sb', ['bash']);
    await expect(
      (async () => {
        for await (const _event of session.output) {
          // drain until the stream error surfaces
        }
      })(),
    ).rejects.toMatchObject({ code: 'rpc' });
    await expect(session.done).rejects.toMatchObject({ code: 'rpc' });
  });

  it('rejects done when the consumer abandons output before an exit event', async () => {
    const sandbox = client({
      getSandbox: () => readySandbox('sb', 'sb-id'),
      // eslint-disable-next-line require-yield
      execSandboxInteractive: async function* () {
        yield { payload: { case: 'stdout', value: { data: enc('one') } } };
        yield { payload: { case: 'stdout', value: { data: enc('two') } } };
        yield { payload: { case: 'exit', value: { exitCode: 0 } } };
      },
    });
    const session = await sandbox.execInteractive('sb', ['bash']);
    for await (const event of session.output) {
      if (!('type' in event)) break; // abandon on the first chunk, before exit
    }
    await expect(session.done).rejects.toMatchObject({ code: 'rpc' });
  });
});

describe('providers', () => {
  it('attach/detach assemble the request and map the changed flag + sandbox ref', async () => {
    let attachReq: {
      sandboxName?: string;
      providerName?: string;
      expectedResourceVersion?: bigint;
    } = {};
    let detachReq: { expectedResourceVersion?: bigint } = {};
    const sandbox = client({
      attachSandboxProvider: (req) => {
        attachReq = req;
        return { sandbox: readySandbox('sb', 'sb-id').sandbox, attached: true };
      },
      detachSandboxProvider: (req) => {
        detachReq = req;
        return {
          sandbox: readySandbox('sb', 'sb-id').sandbox,
          detached: false,
        };
      },
    });

    const attach = await sandbox.attachProvider('sb', 'claude');
    expect(attachReq.sandboxName).toBe('sb');
    expect(attachReq.providerName).toBe('claude');
    expect(attachReq.expectedResourceVersion).toBe(0n);
    expect(attach.changed).toBe(true);
    expect(attach.sandbox.resourceVersion).toBe('7');

    const detach = await sandbox.detachProvider('sb', 'claude', {
      expectedResourceVersion: '42',
    });
    expect(detachReq.expectedResourceVersion).toBe(42n);
    expect(detach.changed).toBe(false);
  });

  it('lists providers with u64 resourceVersion rendered as a string', async () => {
    const sandbox = client({
      listSandboxProviders: () => ({
        providers: [
          {
            metadata: {
              id: 'p1',
              name: 'claude',
              labels: { a: 'b' },
              resourceVersion: 99n,
            },
            type: 'claude',
          },
        ],
      }),
    });
    const providers = await sandbox.listProviders('sb');
    expect(providers).toEqual([
      {
        id: 'p1',
        name: 'claude',
        type: 'claude',
        labels: { a: 'b' },
        resourceVersion: '99',
      },
    ]);
  });
});

describe('config / policy', () => {
  it('getConfig lowercases scope + policySource and renders u64 as strings', async () => {
    const sandbox = client({
      getSandbox: () => readySandbox('sb', 'sb-id'),
      getSandboxConfig: () => ({
        policy: { version: 1, networkPolicies: {} },
        version: 4,
        policyHash: 'hash-a',
        settings: {
          'net.timeout': {
            value: { value: { case: 'intValue', value: 30n } },
            scope: SettingScope.SANDBOX,
          },
        },
        configRevision: 123n,
        policySource: PolicySource.GLOBAL,
        globalPolicyVersion: 2,
        providerEnvRevision: 456n,
      }),
    });
    const config = await sandbox.getConfig('sb');
    expect(config.version).toBe(4);
    expect(config.policyHash).toBe('hash-a');
    expect(config.policySource).toBe('global');
    expect(config.configRevision).toBe('123');
    expect(config.providerEnvRevision).toBe('456');
    expect(config.settings['net.timeout']?.scope).toBe('sandbox');
    expect(config.settings['net.timeout']?.value?.value).toEqual({
      case: 'intValue',
      value: 30n,
    });
  });

  it('setPolicy sends global=false + version pin and (wait) polls until the hash matches', async () => {
    let updateReq: {
      name?: string;
      global?: boolean;
      expectedResourceVersion?: bigint;
      policy?: unknown;
    } = {};
    let configCalls = 0;
    const sandbox = client({
      getSandbox: () => readySandbox('sb', 'sb-id'),
      updateConfig: (req) => {
        updateReq = req;
        return {
          version: 5,
          policyHash: 'target',
          settingsRevision: 10n,
          deleted: false,
        };
      },
      getSandboxConfig: () => {
        configCalls += 1;
        const policyHash = configCalls >= 2 ? 'target' : 'stale';
        return {
          policy: { version: 1, networkPolicies: {} },
          version: 5,
          policyHash,
          settings: {},
          configRevision: 1n,
          policySource: PolicySource.SANDBOX,
          globalPolicyVersion: 0,
          providerEnvRevision: 0n,
        };
      },
    });

    const result = await sandbox.setPolicy(
      'sb',
      {
        version: 1,
        networkPolicies: { web: { name: 'web', endpoints: [], binaries: [] } },
      },
      { wait: true, expectedResourceVersion: '7' },
    );
    expect(updateReq.name).toBe('sb');
    expect(updateReq.global).toBe(false);
    expect(updateReq.expectedResourceVersion).toBe(7n);
    expect(updateReq.policy).toBeDefined();
    expect(result.version).toBe(5);
    expect(result.policyHash).toBe('target');
    expect(result.settingsRevision).toBe('10');
    expect(configCalls).toBeGreaterThanOrEqual(2);
  });

  // Fix #4 residual: setPolicy(..., {wait:true}) must not hang forever when the
  // getConfig poll stalls. Each poll RPC is bounded by the remaining deadline,
  // so a getSandboxConfig that never settles on its own is aborted and the wait
  // rejects instead of pending forever. The handler resolves only on the call
  // signal firing, proving the per-poll deadline (not the sleep loop) is what
  // bounds the returned promise.
  it('setPolicy wait rejects when the config poll stalls past the deadline', async () => {
    const sandbox = client({
      getSandbox: () => readySandbox('sb', 'sb-id'),
      updateConfig: () => ({ version: 5, policyHash: 'target', settingsRevision: 10n, deleted: false }),
      getSandboxConfig: (_req, ctx) =>
        new Promise((_resolve, reject) => {
          ctx.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
        }),
    });

    await expect(
      sandbox.setPolicy('sb', { version: 1, networkPolicies: {} }, { wait: true, waitTimeoutSecs: 0.2 }),
    ).rejects.toMatchObject({ code: 'connect' });
  }, 5000);

  it('setSetting upserts a single sandbox-scoped setting (global=false)', async () => {
    let req: {
      name?: string;
      settingKey?: string;
      global?: boolean;
      settingValue?: unknown;
    } = {};
    const sandbox = client({
      updateConfig: (r) => {
        req = r;
        return {
          version: 6,
          policyHash: '',
          settingsRevision: 11n,
          deleted: false,
        };
      },
    });
    const result = await sandbox.setSetting('sb', 'feature.enabled', {
      value: { case: 'boolValue', value: true },
    });
    expect(req.name).toBe('sb');
    expect(req.settingKey).toBe('feature.enabled');
    expect(req.global).toBe(false);
    expect(req.settingValue).toMatchObject({
      value: { case: 'boolValue', value: true },
    });
    expect(result.settingsRevision).toBe('11');
  });

  it('rejects a non-u64 expectedResourceVersion with invalid_config (no raw SyntaxError)', async () => {
    // versionPin runs during request assembly, before any RPC is issued.
    const sandbox = client({});
    await expect(
      sandbox.setPolicy('sb', { version: 1, networkPolicies: {} }, { expectedResourceVersion: 'not-a-number' }),
    ).rejects.toMatchObject({ code: 'invalid_config' });
  });
});

describe('ssh sessions', () => {
  it('creates a session, omitting expiresAtMs when 0 and rendering it as a string otherwise', async () => {
    const withExpiry = client({
      getSandbox: () => readySandbox('sb', 'sb-id'),
      createSshSession: () => ({
        sandboxId: 'sb-id',
        token: 'tok-1',
        gatewayHost: 'gw.example',
        gatewayPort: 8443,
        gatewayScheme: 'https',
        hostKeyFingerprint: 'SHA256:abc',
        expiresAtMs: 1730000000000n,
      }),
    });
    const session = await withExpiry.createSshSession('sb');
    expect(session).toEqual({
      sandboxId: 'sb-id',
      token: 'tok-1',
      gatewayHost: 'gw.example',
      gatewayPort: 8443,
      gatewayScheme: 'https',
      hostKeyFingerprint: 'SHA256:abc',
      expiresAtMs: '1730000000000',
    });

    const noExpiry = client({
      getSandbox: () => readySandbox('sb', 'sb-id'),
      createSshSession: () => ({
        sandboxId: 'sb-id',
        token: 'tok-2',
        gatewayHost: 'gw',
        gatewayPort: 80,
        gatewayScheme: 'http',
        hostKeyFingerprint: '',
        expiresAtMs: 0n,
      }),
    });
    const bare = await noExpiry.createSshSession('sb');
    expect(bare.expiresAtMs).toBeUndefined();
    expect(bare.hostKeyFingerprint).toBeUndefined();
  });

  it('revokeSshSession returns the revoked flag', async () => {
    const sandbox = client({ revokeSshSession: () => ({ revoked: true }) });
    expect(await sandbox.revokeSshSession('tok')).toBe(true);
  });

  it('rejects a response that violates the ProxyCommand trust-boundary contract', async () => {
    const base = {
      sandboxId: 'sb-id',
      token: 'tok-1',
      gatewayHost: 'gw.example',
      gatewayPort: 8443,
      gatewayScheme: 'https',
      hostKeyFingerprint: 'SHA256:abc',
      expiresAtMs: 0n,
    };
    const cases: Array<Record<string, unknown>> = [
      { ...base, sandboxId: 'different-sandbox' },
      { ...base, gatewayScheme: 'ftp' },
      { ...base, token: 'tok; rm -rf /' },
      { ...base, gatewayPort: 70000 },
      { ...base, gatewayHost: 'bad[host]' },
      { ...base, gatewayHost: '::::' },
      { ...base, gatewayHost: 'bad..example' },
      { ...base, hostKeyFingerprint: `SHA256:${'a'.repeat(257)}` },
    ];
    for (const resp of cases) {
      const sandbox = client({
        getSandbox: () => readySandbox('sb', 'sb-id'),
        createSshSession: () => resp,
      });
      await expect(sandbox.createSshSession('sb')).rejects.toMatchObject({
        code: 'invalid_config',
      });
    }
  });

  it('accepts IPv4 and bracketed IPv6 gateway hosts', async () => {
    for (const gatewayHost of ['127.0.0.1', '[::1]']) {
      const sandbox = client({
        getSandbox: () => readySandbox('sb', 'sb-id'),
        createSshSession: () => ({
          sandboxId: 'sb-id',
          token: 'tok-1',
          gatewayHost,
          gatewayPort: 443,
          gatewayScheme: 'https',
          hostKeyFingerprint: '',
          expiresAtMs: 0n,
        }),
      });
      await expect(sandbox.createSshSession('sb')).resolves.toMatchObject({ gatewayHost });
    }
  });
});

describe('forward', () => {
  it('binds a local port and relays bytes both ways, minting + revoking a token', async () => {
    let sshReq: { sandboxId?: string } = {};
    let revokedToken: string | undefined;
    let initFrame: { sandboxId?: string; authorizationToken?: string; target?: unknown } | undefined;
    const sandbox = client({
      getSandbox: () => readySandbox('sb', 'sb-id-forward'),
      createSshSession: (req) => {
        sshReq = req;
        return {
          sandboxId: 'sb-id-forward',
          token: 'fwd-tok',
          gatewayHost: 'gw',
          gatewayPort: 443,
          gatewayScheme: 'https',
          hostKeyFingerprint: '',
          expiresAtMs: 0n,
        };
      },
      revokeSshSession: (req) => {
        revokedToken = req.token;
        return { revoked: true };
      },
      forwardTcp: async function* (requests) {
        for await (const frame of requests) {
          if (frame.payload.case === 'init') {
            initFrame = frame.payload.value;
          } else if (frame.payload.case === 'data') {
            yield { payload: { case: 'data', value: frame.payload.value } };
          }
        }
      },
    });

    const handle = await sandbox.forward('sb', { targetPort: 9000 });
    expect(handle.localPort).toBeGreaterThan(0);
    expect(handle.targetPort).toBe(9000);
    expect(handle.targetHost).toBe('127.0.0.1');

    const echoed = await new Promise<string>((resolve, reject) => {
      const socket = net.connect(handle.localPort, handle.localHost, () => {
        socket.write('ping-through-forward');
      });
      const buf: Buffer[] = [];
      socket.on('data', (d) => {
        buf.push(d);
        if (Buffer.concat(buf).length >= 'ping-through-forward'.length) {
          resolve(Buffer.concat(buf).toString());
          socket.end();
        }
      });
      socket.on('error', reject);
    });

    expect(echoed).toBe('ping-through-forward');
    expect(sshReq.sandboxId).toBe('sb-id-forward');
    expect(initFrame?.sandboxId).toBe('sb-id-forward');
    expect(initFrame?.authorizationToken).toBe('fwd-tok');
    expect(initFrame?.target).toMatchObject({
      case: 'tcp',
      value: { host: '127.0.0.1', port: 9000 },
    });

    await handle.close();
    await handle.closed;
    // The per-connection revoke is best-effort and fires on teardown.
    await new Promise((r) => setTimeout(r, 20));
    expect(revokedToken).toBe('fwd-tok');
  });

  it('rejects when the sandbox is not ready', async () => {
    const sandbox = client({
      getSandbox: () => ({
        sandbox: {
          metadata: { id: 'sb-id', name: 'sb' },
          status: { phase: SandboxPhase.PROVISIONING },
        },
      }),
    });
    await expect(sandbox.forward('sb', { targetPort: 9000 })).rejects.toMatchObject({ code: 'connect' });
  });

  // Backpressure (fix #6): the sandbox->local relay must stop pulling gRPC
  // frames when socket.write() returns false and resume after 'drain', so a
  // slow local reader cannot make Node buffer sandbox output without bound.
  // Flood a large payload at a paused reader that only drains in small bites;
  // every byte must still arrive intact and in order.
  it('honors socket backpressure on the sandbox->local relay without dropping bytes', async () => {
    const CHUNKS = 256;
    const CHUNK = 64 * 1024; // 16 MiB total, well past any socket highWaterMark
    const sandbox = client({
      getSandbox: () => readySandbox('sb', 'sb-id-bp'),
      createSshSession: () => ({
        sandboxId: 'sb-id-bp',
        token: 'bp-tok',
        gatewayHost: 'gw',
        gatewayPort: 443,
        gatewayScheme: 'https',
        hostKeyFingerprint: '',
        expiresAtMs: 0n,
      }),
      revokeSshSession: () => ({ revoked: true }),
      // Ignore inbound frames; just blast a large, verifiable byte stream back.
      forwardTcp: async function* () {
        for (let i = 0; i < CHUNKS; i++) {
          yield { payload: { case: 'data' as const, value: new Uint8Array(CHUNK).fill(i & 0xff) } };
        }
      },
    });

    const handle = await sandbox.forward('sb', { targetPort: 9000 });
    const received = await new Promise<Buffer>((resolve, reject) => {
      const socket = net.connect(handle.localPort, handle.localHost);
      const buf: Buffer[] = [];
      let total = 0;
      socket.on('connect', () => socket.write('go'));
      socket.on('data', (d) => {
        buf.push(d);
        total += d.length;
        // Simulate a slow consumer: pause, then resume on the next tick. This
        // keeps the OS/Node buffer near-full so writes return false and the
        // relay must await 'drain'.
        socket.pause();
        setTimeout(() => socket.resume(), 0);
        if (total >= CHUNKS * CHUNK) resolve(Buffer.concat(buf));
      });
      socket.on('error', reject);
    });

    expect(received.length).toBe(CHUNKS * CHUNK);
    // Verify order + integrity: chunk i is filled with (i & 0xff).
    for (let i = 0; i < CHUNKS; i++) {
      expect(received[i * CHUNK]).toBe(i & 0xff);
      expect(received[i * CHUNK + CHUNK - 1]).toBe(i & 0xff);
    }

    await handle.close();
    await handle.closed;
  });

  // Fix #7: the accepted socket must have an 'error' handler before
  // forwardConnection awaits createSshSession, or a peer reset in that window
  // emits an unhandled 'error' and crashes the process.
  it('survives a forwarded socket that resets during the session-mint window', async () => {
    let releaseSession: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      releaseSession = resolve;
    });
    const sandbox = client({
      getSandbox: () => readySandbox('sb', 'sb-id-reset'),
      createSshSession: async () => {
        // Hold the RPC open so the accepted socket sits in the pre-handler window.
        await gate;
        return {
          sandboxId: 'sb-id-reset',
          token: 'reset-tok',
          gatewayHost: 'gw',
          gatewayPort: 443,
          gatewayScheme: 'https',
          hostKeyFingerprint: '',
          expiresAtMs: 0n,
        };
      },
      // biome-ignore lint/correctness/useYield: the socket is reset before any frame is relayed
      forwardTcp: async function* () {
        return;
      },
      revokeSshSession: () => ({ revoked: true }),
    });

    const handle = await sandbox.forward('sb', { targetPort: 9000 });
    await new Promise<void>((resolve) => {
      const socket = net.connect(handle.localPort, handle.localHost, () => {
        // Abort mid-mint; the server-side accepted socket may see an
        // ECONNRESET 'error' before forwardConnection attaches its handlers.
        socket.destroy(new Error('peer reset'));
        setTimeout(resolve, 30);
      });
      socket.on('error', () => {}); // ignore the client-side reset
    });

    releaseSession?.();
    // The listener still shuts down cleanly after the aborted connection.
    await handle.close();
    await handle.closed;
  });

  it('reports per-connection failures without taking down the listener', async () => {
    let report!: (error: unknown) => void;
    const reported = new Promise<unknown>((resolve) => {
      report = resolve;
    });
    const sandbox = client({
      getSandbox: () => readySandbox('sb', 'sb-id-error'),
      createSshSession: () => {
        throw new ConnectError('mint failed', Code.Internal);
      },
    });

    const handle = await sandbox.forward('sb', {
      targetPort: 9000,
      onConnectionError: (error) => {
        report(error);
        throw new Error('consumer callback failed');
      },
    });
    await new Promise<void>((resolve) => {
      const socket = net.connect(handle.localPort, handle.localHost, () => resolve());
      socket.on('error', () => {});
    });
    await expect(reported).resolves.toMatchObject({ code: 'rpc' });
    expect(handle.localPort).toBeGreaterThan(0);
    await expect(handle.close()).resolves.toBeUndefined();
  });

  it('close is idempotent and waits for active forward RPC cancellation', async () => {
    let streamStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      streamStarted = resolve;
    });
    let streamAborted = false;
    const sandbox = client({
      getSandbox: () => readySandbox('sb', 'sb-id-close'),
      createSshSession: () => ({
        sandboxId: 'sb-id-close',
        token: 'close-tok',
        gatewayHost: 'gw',
        gatewayPort: 443,
        gatewayScheme: 'https',
        hostKeyFingerprint: '',
        expiresAtMs: 0n,
      }),
      forwardTcp: async function* (_requests, ctx) {
        streamStarted();
        await new Promise<void>((resolve) => {
          ctx.signal.addEventListener(
            'abort',
            () => {
              streamAborted = true;
              resolve();
            },
            { once: true },
          );
        });
        throw new ConnectError('canceled', Code.Canceled);
      },
      revokeSshSession: () => ({ revoked: true }),
    });

    const handle = await sandbox.forward('sb', { targetPort: 9000 });
    const socket = net.connect(handle.localPort, handle.localHost);
    socket.on('error', () => {});
    await started;
    await Promise.all([handle.close(), handle.close(), handle.closed]);
    expect(streamAborted).toBe(true);
    socket.destroy();
  });
});

// The lowercase enum-name unions in client.ts are a hand-maintained mirror of
// the generated proto enums. This pins every hand-written literal to its
// generated member name (lowercased), so a proto enum change that slips past
// the exhaustive Record type is still caught here at runtime.
describe('enum name maps', () => {
  function numericMembers(genEnum: Record<string, unknown>): Array<[string, number]> {
    return Object.entries(genEnum).filter((e): e is [string, number] => typeof e[1] === 'number');
  }

  const cases: Array<[string, Record<string, unknown>, Record<number, string>]> = [
    ['SandboxPhase', SandboxPhase, PHASE_NAMES],
    ['ServiceStatus', ServiceStatus, STATUS_NAMES],
    ['SettingScope', SettingScope, SCOPE_NAMES],
    ['PolicySource', PolicySource, POLICY_SOURCE_NAMES],
  ];

  for (const [label, genEnum, names] of cases) {
    it(`${label} maps every generated member to its lowercased name`, () => {
      const members = numericMembers(genEnum);
      for (const [name, value] of members) {
        expect(names[value]).toBe(name.toLowerCase());
      }
      // No missing or extra map entries versus the generated enum.
      expect(Object.keys(names).length).toBe(members.length);
    });
  }
});

describe('raw escape hatch', () => {
  it('reaches uncurated RPCs and returns generated wire messages', async () => {
    const sandbox = client({
      getSandbox: () => readySandbox('sb', 'sb-id-1'),
      getGatewayConfig: () => ({ settings: {}, settingsRevision: 42n }),
    });

    // An RPC with no curated wrapper is still reachable through raw.
    const cfg = await sandbox.raw.getGatewayConfig({});
    expect(cfg.settingsRevision).toBe(42n);

    // raw returns the full generated message: the enum stays numeric, where the
    // curated get() would lowercase status.phase to 'ready'.
    const resp = await sandbox.raw.getSandbox({ name: 'sb' });
    expect(resp.sandbox?.status?.phase).toBe(SandboxPhase.READY);
    expect(resp.sandbox?.metadata?.name).toBe('sb');

    // The shared transport is exposed for building extra clients.
    expect(sandbox.transport).toBeDefined();
  });
});
