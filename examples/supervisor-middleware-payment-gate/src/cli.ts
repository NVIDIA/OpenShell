#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright (c) 2026 Axiru, Inc.
// SPDX-License-Identifier: Apache-2.0
import * as grpc from "@grpc/grpc-js";
import { buildServer } from "./server.js";

const bind = process.env.AXIRU_MW_BIND ?? "0.0.0.0:50052";
const server = buildServer({ apiKey: process.env.AXIRU_API_KEY, baseUrl: process.env.AXIRU_BASE_URL });
server.bindAsync(bind, grpc.ServerCredentials.createInsecure(), (err, port) => {
  if (err) {
    console.error(err);
    process.exit(1);
  }
  console.error(`axiru openshell middleware listening on ${bind} (port ${port})`);
});
