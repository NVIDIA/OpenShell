// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import * as fs from "node:fs";
import * as grpc from "@grpc/grpc-js";

export interface TlsConfig {
  caPath: string;
  certPath: string;
  keyPath: string;
}

export function makeChannelCredentials(
  tls?: TlsConfig
): grpc.ChannelCredentials {
  if (!tls) {
    return grpc.credentials.createInsecure();
  }
  const ca = fs.readFileSync(tls.caPath);
  const cert = fs.readFileSync(tls.certPath);
  const key = fs.readFileSync(tls.keyPath);
  return grpc.credentials.createSsl(ca, key, cert);
}
