// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Replica routing over real gRPC/HTTP2, with a front proxy that answers routed
// calls the way Envoy does when the owner's route has no ready endpoints.

import * as http2 from 'node:http2';
import type { AddressInfo } from 'node:net';
import * as net from 'node:net';
import { Code, ConnectError, type ServiceImpl } from '@connectrpc/connect';
import { connectNodeAdapter, createGrpcTransport } from '@connectrpc/connect-node';
import { afterEach, describe, expect, it } from 'vitest';
import { SandboxClient } from './client.js';
import { OpenShell, SandboxPhase } from './gen/openshell_pb.js';
import { retryUnrouted } from './routing.js';

const enc = (s: string) => new TextEncoder().encode(s);
const closers: Array<() => void> = [];
afterEach(() => {
  for (const close of closers.splice(0)) close();
});

interface Gateway {
  sandbox: SandboxClient;
  wantedOwner: string[];
  // Replica header seen by the gateway on each streaming call ('' when unrouted).
  routes: string[];
  rejectedByProxy: number;
  interactiveFrames: string[];
}

async function gateway(opts: { owner?: string; rejectRouted?: boolean; execError?: ConnectError }): Promise<Gateway> {
  const g: Gateway = {
    sandbox: undefined as never,
    wantedOwner: [],
    routes: [],
    rejectedByProxy: 0,
    interactiveFrames: [],
  };
  const route = (header: Headers): void => {
    g.routes.push(header.get('x-openshell-replica') ?? '');
  };
  const impl: Partial<ServiceImpl<typeof OpenShell>> = {
    getSandbox: (_req, ctx) => {
      g.wantedOwner.push(ctx.requestHeader.get('x-openshell-want-owner') ?? '');
      if (opts.owner) ctx.responseHeader.set('x-openshell-owner', opts.owner);
      return { sandbox: { metadata: { id: 'sb-id', name: 'sb' }, status: { phase: SandboxPhase.READY } } };
    },
    execSandbox: async function* (_req, ctx) {
      route(ctx.requestHeader);
      if (opts.execError) throw opts.execError;
      yield { payload: { case: 'stdout', value: { data: enc('hi') } } };
      yield { payload: { case: 'exit', value: { exitCode: 0 } } };
    },
    // The first (empty) message flushes response headers, like the gateway does.
    execSandboxInteractive: async function* (requests, ctx) {
      route(ctx.requestHeader);
      yield { payload: { case: 'stdout', value: { data: new Uint8Array() } } };
      for await (const frame of requests) {
        g.interactiveFrames.push(frame.payload.case ?? '');
        if (frame.payload.case === 'stdin') {
          yield { payload: { case: 'stdout', value: { data: frame.payload.value } } };
          yield { payload: { case: 'exit', value: { exitCode: 0 } } };
          return;
        }
      }
    },
    createSshSession: () => ({
      sandboxId: 'sb-id',
      token: 'tok',
      gatewayHost: 'gw',
      gatewayPort: 443,
      gatewayScheme: 'https',
    }),
    revokeSshSession: () => ({ outcome: 1 }),
    forwardTcp: async function* (requests, ctx) {
      route(ctx.requestHeader);
      yield { payload: { case: 'data', value: new Uint8Array() } };
      for await (const frame of requests) {
        if (frame.payload.case === 'data') yield { payload: { case: 'data', value: frame.payload.value } };
      }
    },
  };
  const adapter = connectNodeAdapter({ routes: (router) => router.service(OpenShell, impl) });
  const server = http2.createServer((req, res) => {
    if (opts.rejectRouted && req.headers['x-openshell-replica']) {
      g.rejectedByProxy++;
      res.writeHead(200, { 'content-type': 'application/grpc', 'grpc-status': '14' });
      res.end();
      return;
    }
    adapter(req, res);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  closers.push(() => server.close());
  const { port } = server.address() as AddressInfo;
  g.sandbox = new SandboxClient(createGrpcTransport({ baseUrl: `http://127.0.0.1:${port}` }));
  return g;
}

// Run exec, an interactive exec that writes stdin right away, and one forwarded connection.
async function runAll(g: Gateway): Promise<string[]> {
  const exec = await g.sandbox.exec('sb', ['true']);

  const session = await g.sandbox.execInteractive('sb', ['cat']);
  session.write(Buffer.from('typed'));
  let typed = '';
  for await (const event of session.output) if (!('type' in event)) typed += event.data.toString();

  const handle = await g.sandbox.forward('sb', { targetPort: 9000 });
  const echoed = await new Promise<string>((resolve, reject) => {
    const socket = net.connect(handle.localPort, handle.localHost, () => socket.write('ping'));
    socket.on('data', (d) => {
      resolve(d.toString());
      socket.end();
    });
    socket.on('error', reject);
  });
  await handle.close();
  return [exec.stdout.toString(), typed, echoed];
}

describe('replica routing', () => {
  it('asks for the owner and routes exec, interactive exec and forward to it', async () => {
    const g = await gateway({ owner: 'openshell-1' });
    expect(await runAll(g)).toEqual(['hi', 'typed', 'ping']);
    expect(g.wantedOwner).toEqual(['1', '1', '1']);
    expect(g.routes).toEqual(['openshell-1', 'openshell-1', 'openshell-1']);
  });

  it('sends no hint when the gateway reports no owner', async () => {
    const g = await gateway({});
    expect(await runAll(g)).toEqual(['hi', 'typed', 'ping']);
    expect(g.routes).toEqual(['', '', '']);
  });

  it('retries once unrouted when the proxy rejects the owner route, without losing input', async () => {
    const g = await gateway({ owner: 'openshell-1', rejectRouted: true });
    expect(await runAll(g)).toEqual(['hi', 'typed', 'ping']);
    expect(g.rejectedByProxy).toBe(3);
    expect(g.routes).toEqual(['', '', '']);
    expect(g.interactiveFrames).toEqual(['start', 'stdin']);
  });

  it('does not retry a gateway error', async () => {
    const g = await gateway({
      owner: 'openshell-1',
      execError: new ConnectError('supervisor not connected', Code.Unavailable),
    });
    await expect(g.sandbox.exec('sb', ['true'])).rejects.toThrow('supervisor not connected');
    expect(g.routes).toEqual(['openshell-1']);
  });

  it('matches only the proxy no-endpoints answer', () => {
    expect(retryUnrouted(new ConnectError('', Code.Unavailable))).toBe(true);
    expect(retryUnrouted(new ConnectError('no healthy upstream', Code.Unavailable))).toBe(true);
    expect(retryUnrouted(new ConnectError('upstream connect error: connection failure', Code.Unavailable))).toBe(true);
    expect(retryUnrouted(new ConnectError('supervisor not connected', Code.Unavailable))).toBe(false);
    expect(retryUnrouted(new ConnectError('', Code.NotFound))).toBe(false);
    expect(retryUnrouted(new Error(''))).toBe(false);
  });
});
