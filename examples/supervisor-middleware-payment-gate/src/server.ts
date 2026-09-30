// SPDX-FileCopyrightText: Copyright (c) 2026 Axiru, Inc.
// SPDX-License-Identifier: Apache-2.0
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import { Gate, DEFAULT_REFUND_POLICY } from "./gate.js";
import { evaluateHttp, policyFromConfig } from "./middleware.js";

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const PROTO_DIR = join(here, "..", "proto");

export function buildServer(opts: { apiKey?: string; baseUrl?: string } = {}): grpc.Server {
  const def = protoLoader.loadSync(join(PROTO_DIR, "supervisor_middleware.proto"), {
    keepCase: true,
    longs: Number,
    enums: String,
    defaults: true,
    includeDirs: [PROTO_DIR, join(dirname(require.resolve("@grpc/proto-loader/package.json")), "..", "protobufjs")],
  });
  const pkg = grpc.loadPackageDefinition(def) as any;
  const svc = pkg.openshell.middleware.v1.SupervisorMiddleware.service;

  let gate = new Gate({ apiKey: opts.apiKey, baseUrl: opts.baseUrl, policy: DEFAULT_REFUND_POLICY });
  const server = new grpc.Server();

  server.addService(svc, {
    Describe: (_call: any, cb: any) =>
      cb(null, {
        name: "axiru-payment-gate",
        service_version: "0.1.0",
        expected_audience: "axiru-payment-gate",
        bindings: [
          { operation: "SUPERVISOR_MIDDLEWARE_OPERATION_HTTP_REQUEST", phase: "SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS", max_payload_bytes: 262144, request_timeout: { seconds: 2, nanos: 0 } },
        ],
        extension: { protocol_version: { major: 1, minor: 0 }, implementation_name: "axiru-openshell-middleware", implementation_version: "0.1.0" },
      }),
    ValidateConfig: (call: any, cb: any) => {
      try {
        const cfg = structToObject(call.request.config);
        gate = new Gate({ apiKey: opts.apiKey ?? (cfg.axiru_api_key as string | undefined), baseUrl: opts.baseUrl, policy: policyFromConfig(cfg, DEFAULT_REFUND_POLICY) });
        cb(null, { valid: true, reason: "" });
      } catch (e) {
        cb(null, { valid: false, reason: String(e) });
      }
    },
    EvaluateHttpRequest: async (call: any, cb: any) => {
      const r = call.request;
      const headers: Record<string, string> = {};
      for (const h of r.headers ?? []) headers[h.name] = h.value;
      try {
        const out = await evaluateHttp({ gate }, {
          method: r.target?.method ?? "",
          host: r.target?.host ?? "",
          path: r.target?.path ?? "",
          headers,
          body: Buffer.from(r.body ?? []).toString("utf8"),
          sandboxId: r.context?.sandbox_id || r.context?.sandbox || "sandbox",
        });
        cb(null, { decision: out.decision, reason: out.reason, reason_code: out.reason_code, has_body: false, header_mutations: out.header_mutations, findings: out.findings, metadata: out.metadata });
      } catch (e) {
        // Fail closed: the sandbox policy also sets on_error: fail_closed, this is belt and braces.
        cb(null, { decision: "DECISION_DENY", reason: `axiru middleware error: ${String(e)}`, reason_code: "AXIRU_ERROR", has_body: false, header_mutations: [], findings: [], metadata: {} });
      }
    },
    EvaluateWebSocketSession: (call: any) => {
      call.on("data", () => call.write({}));
      call.on("end", () => call.end());
    },
  });
  return server;
}

function structToObject(s: any): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries((s?.fields ?? {}) as Record<string, any>)) out[k] = valueOf(v);
  return out;
}
function valueOf(v: any): unknown {
  if (!v) return undefined;
  if (v.kind === "numberValue" || v.numberValue !== undefined) return v.numberValue;
  if (v.kind === "stringValue" || v.stringValue !== undefined) return v.stringValue;
  if (v.kind === "boolValue" || v.boolValue !== undefined) return v.boolValue;
  if (v.listValue) return (v.listValue.values ?? []).map(valueOf);
  if (v.structValue) return structToObject(v.structValue);
  return undefined;
}
