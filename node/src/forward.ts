// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import * as net from "node:net";
import { Duplex } from "node:stream";
import type { ClientDuplexStream } from "@grpc/grpc-js";
import { Client as SshClient } from "ssh2";
import type { TcpForwardFrame, TcpForwardInit } from "./_proto/openshell";
import { SandboxClient, SandboxError } from "./sandbox";

interface ForwardState {
  localPort: number;
  remotePort: number;
  server: net.Server;
  sshConn: SshClient;
}

/**
 * Manages port-forward tunnels into sandbox processes.
 *
 * Each forward opens a ForwardTcp gRPC bidirectional stream, speaks SSH over it
 * via ssh2, then exposes a local TCP port that tunnels to the requested sandbox
 * port — matching the pattern used by openshell_control_plane/app/ssh_forward.py.
 */
export class ForwardManager {
  private readonly _client: SandboxClient;
  private readonly _forwards = new Map<string, ForwardState>();

  constructor(client: SandboxClient) {
    this._client = client;
  }

  async startForward(sandboxName: string, remotePort = 8080): Promise<number> {
    const existing = this._forwards.get(sandboxName);
    if (existing) return existing.localPort;

    // 1. Resolve sandbox ID
    const sandbox = await this._client.get(sandboxName);
    const sandboxId = sandbox.metadata?.id ?? "";
    if (!sandboxId) throw new SandboxError(`sandbox '${sandboxName}' has no id`);

    // 2. Short-lived SSH session token
    const session = await this._client.createSshSession(sandboxId);
    const resolvedId = session.sandboxId || sandboxId;

    // 3. Open ForwardTcp gRPC bidirectional stream
    const grpcStream = this._client.stub.forwardTcp();

    // 4. Wrap gRPC stream in a raw-byte Duplex for ssh2
    const init: TcpForwardInit = {
      sandboxId: resolvedId,
      serviceId: `ssh-proxy:${resolvedId}`,
      authorizationToken: session.token,
      target: { $case: "ssh", ssh: {} },
    };
    const tunnel = new GrpcTunnelStream(grpcStream, init);

    // 5. Connect ssh2 over the tunnel
    const sshConn = new SshClient();
    await new Promise<void>((resolve, reject) => {
      sshConn.on("ready", resolve);
      sshConn.on("error", reject);
      sshConn.connect({
        sock: tunnel,
        username: "sandbox",
        // Accept any host key — the session token is the auth mechanism
        algorithms: {
          serverHostKey: [
            "ssh-ed25519",
            "ecdsa-sha2-nistp256",
            "rsa-sha2-256",
            "rsa-sha2-512",
          ],
        },
      });
    });

    // 6. Local TCP server: each connection is port-forwarded through SSH
    const server = net.createServer((socket) => {
      sshConn.forwardOut("127.0.0.1", 0, "127.0.0.1", remotePort, (err: Error | undefined, stream) => {
        if (err != null) {
          socket.destroy(err);
          return;
        }
        socket.pipe(stream).pipe(socket);
      });
    });

    const localPort = await new Promise<number>((resolve, reject) => {
      server.listen(0, "127.0.0.1", () => {
        const addr = server.address() as net.AddressInfo;
        resolve(addr.port);
      });
      server.on("error", reject);
    });

    this._forwards.set(sandboxName, { localPort, remotePort, server, sshConn });
    return localPort;
  }

  async stopForward(sandboxName: string): Promise<boolean> {
    const state = this._forwards.get(sandboxName);
    if (!state) return false;
    this._forwards.delete(sandboxName);
    await new Promise<void>((resolve) => state.server.close(() => resolve()));
    state.sshConn.end();
    return true;
  }

  async stopAll(): Promise<void> {
    for (const name of [...this._forwards.keys()]) {
      await this.stopForward(name);
    }
  }

  getForwardPort(sandboxName: string): number | undefined {
    return this._forwards.get(sandboxName)?.localPort;
  }
}

/**
 * Duplex that bridges a ForwardTcp gRPC bidirectional stream to raw bytes.
 *
 * ssh2 writes raw SSH protocol bytes → we wrap them in TcpForwardFrame(data=…)
 * and send over gRPC.  Incoming TcpForwardFrame(data=…) from gRPC are pushed as
 * raw bytes into the Duplex's readable side for ssh2 to consume.
 */
class GrpcTunnelStream extends Duplex {
  private readonly _grpc: ClientDuplexStream<TcpForwardFrame, TcpForwardFrame>;
  private _grpcDone = false;

  constructor(
    grpc: ClientDuplexStream<TcpForwardFrame, TcpForwardFrame>,
    init: TcpForwardInit
  ) {
    super();
    this._grpc = grpc;

    // Send the init frame before any data
    grpc.write({ payload: { $case: "init", init } });

    grpc.on("data", (frame: TcpForwardFrame) => {
      if (frame.payload?.$case === "data") {
        this.push(frame.payload.data);
      }
    });

    grpc.on("end", () => {
      this._grpcDone = true;
      this.push(null);
    });

    grpc.on("error", (err) => this.destroy(err));

    this.on("close", () => {
      if (!this._grpcDone) grpc.end();
    });
  }

  // Called when the readable consumer wants more data — we push reactively on gRPC events
  override _read(_size: number): void {}

  override _write(
    chunk: Buffer,
    _encoding: BufferEncoding,
    callback: (err?: Error | null) => void
  ): void {
    this._grpc.write({ payload: { $case: "data", data: chunk } }, (err: Error | null | undefined) =>
      callback(err ?? null)
    );
  }

  override _final(callback: (err?: Error | null) => void): void {
    this._grpc.end();
    callback();
  }
}
