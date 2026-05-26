// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import type { ServiceError } from "@grpc/grpc-js";
import {
  ClusterInferenceConfig,
  GetClusterInferenceResponse,
  InferenceClient as InferenceStub,
  SetClusterInferenceResponse,
} from "./_proto/inference";
import { makeChannelCredentials } from "./tls";
import type { SandboxClient } from "./sandbox";
import { SandboxError } from "./sandbox";

export { ClusterInferenceConfig, SetClusterInferenceResponse };

export interface InferenceRouteClientOptions {
  routeName?: string;
}

export class InferenceRouteClient {
  private readonly _stub: InferenceStub;
  private readonly _routeName: string;

  constructor(
    grpcTarget: string,
    sandboxClient: SandboxClient,
    options: InferenceRouteClientOptions = {}
  ) {
    const creds = makeChannelCredentials(sandboxClient._tls);
    this._stub = new InferenceStub(grpcTarget, creds);
    this._routeName = options.routeName ?? "";
  }

  async setCluster(
    providerName: string,
    modelId: string,
    options: { noVerify?: boolean; timeoutSecs?: number } = {}
  ): Promise<SetClusterInferenceResponse> {
    return callUnary<SetClusterInferenceResponse>((cb) =>
      this._stub.setClusterInference(
        {
          providerName,
          modelId,
          routeName: this._routeName,
          verify: false,
          noVerify: options.noVerify ?? true,
          timeoutSecs: options.timeoutSecs ?? 0,
        },
        cb
      )
    );
  }

  async getCluster(): Promise<ClusterInferenceConfig | undefined> {
    const res = await callUnary<GetClusterInferenceResponse>((cb) =>
      this._stub.getClusterInference({ routeName: this._routeName }, cb)
    );
    if (!res.providerName) return undefined;
    return { providerName: res.providerName, modelId: res.modelId, timeoutSecs: res.timeoutSecs };
  }

  close(): void {
    this._stub.close();
  }
}

function callUnary<Res>(
  fn: (cb: (err: ServiceError | null, res: Res) => void) => unknown
): Promise<Res> {
  return new Promise((resolve, reject) => {
    fn((err, res) => {
      if (err) reject(new SandboxError(err.message, err));
      else resolve(res);
    });
  });
}
