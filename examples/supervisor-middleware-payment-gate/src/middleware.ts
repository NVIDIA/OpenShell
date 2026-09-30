// SPDX-FileCopyrightText: Copyright (c) 2026 Axiru, Inc.
// SPDX-License-Identifier: Apache-2.0
import { Gate } from "./gate.js";
import type { Decision, Policy } from "./gate.js";
import { parseStripeRequest } from "./stripe.js";

export interface MiddlewareDeps {
  gate: Gate;
  /** After this many denials from one sandbox in 24h, findings recommend quarantine. */
  quarantineAfterDenials?: number;
}

export interface EvalInput {
  method: string;
  host: string;
  path: string;
  headers: Record<string, string>;
  body: string;
  sandboxId: string;
}

export interface EvalOutput {
  decision: "DECISION_ALLOW" | "DECISION_DENY";
  reason: string;
  reason_code: string;
  header_mutations: Array<{ write: { name: string; value: string; on_existing: "EXISTING_HEADER_ACTION_OVERWRITE" } }>;
  findings: Array<{ type: string; label: string; count: number; confidence: string; severity: string }>;
  metadata: Record<string, string>;
  axiru?: Decision;
}

const denials = new Map<string, number[]>();

/** Pure-ish core of the middleware, separated from gRPC so it can be unit tested. */
export async function evaluateHttp(deps: MiddlewareDeps, input: EvalInput): Promise<EvalOutput> {
  const pass: EvalOutput = { decision: "DECISION_ALLOW", reason: "not a money-moving call", reason_code: "PASSTHROUGH", header_mutations: [], findings: [], metadata: {} };
  if (!/(^|\.)stripe\.com$/i.test(input.host)) return pass;
  const parsed = parseStripeRequest(input.method, input.path, lower(input.headers), input.body, input.sandboxId);
  if (!parsed) return pass;

  if (parsed.amountUnspecified) {
    return deny(deps, input.sandboxId, "AMOUNT_UNSPECIFIED", `Stripe ${parsed.endpoint} without an explicit amount is a full refund. Specify amount so policy can evaluate it.`);
  }

  const d = await deps.gate.check(parsed.intent);
  const metadata = {
    "axiru.decision_id": d.decision_id,
    "axiru.verdict": d.verdict,
    "axiru.policy": `${d.policy_id}@${d.policy_version}`,
    "axiru.fingerprint": d.fingerprint,
    "axiru.reason_codes": d.reason_codes.join(","),
  };
  if (d.verdict === "allow") {
    return {
      decision: "DECISION_ALLOW",
      reason: d.rationale,
      reason_code: "AXIRU_ALLOW",
      // Pin Stripe's own idempotency to the decision, so a retry cannot become a second refund.
      header_mutations: [{ write: { name: "Idempotency-Key", value: d.decision_id, on_existing: "EXISTING_HEADER_ACTION_OVERWRITE" } }],
      findings: [{ type: "axiru.decision", label: "allow", count: 1, confidence: "certain", severity: "info" }],
      metadata,
      axiru: d,
    };
  }
  const out = deny(deps, input.sandboxId, d.verdict === "hold" ? "AXIRU_HOLD" : "AXIRU_DENY", d.rationale);
  out.metadata = { ...out.metadata, ...metadata };
  out.axiru = d;
  return out;
}

function deny(deps: MiddlewareDeps, sandboxId: string, code: string, reason: string): EvalOutput {
  const cutoff = Date.now() - 86_400_000;
  const list = (denials.get(sandboxId) ?? []).filter((t) => t > cutoff);
  list.push(Date.now());
  denials.set(sandboxId, list);
  const limit = deps.quarantineAfterDenials ?? 3;
  const findings = [{ type: "axiru.decision", label: code.toLowerCase(), count: 1, confidence: "certain", severity: code === "AXIRU_HOLD" ? "medium" : "high" }];
  const metadata: Record<string, string> = { "axiru.denials_24h": String(list.length) };
  if (list.length >= limit) {
    // The signal Sentry or an operator can act on. OpenShell records findings and metadata in the gateway audit log.
    findings.push({ type: "axiru.quarantine_recommended", label: `${list.length} denied money moves in 24h`, count: list.length, confidence: "certain", severity: "critical" });
    metadata["axiru.quarantine_recommended"] = "true";
  }
  return { decision: "DECISION_DENY", reason, reason_code: code, header_mutations: [], findings, metadata };
}

function lower(h: Record<string, string>): Record<string, string> {
  return Object.fromEntries(Object.entries(h).map(([k, v]) => [k.toLowerCase(), v]));
}

export function policyFromConfig(config: Record<string, unknown> | undefined, base: Policy): Policy {
  if (!config) return base;
  const n = (k: string) => (typeof config[k] === "number" ? (config[k] as number) : undefined);
  return {
    ...base,
    policy_id: (config.policy_id as string) ?? base.policy_id,
    per_transfer_ceiling_minor: n("per_transfer_ceiling_minor") ?? base.per_transfer_ceiling_minor,
    hold_above_minor: n("hold_above_minor") ?? base.hold_above_minor,
    daily_cap_per_agent_minor: n("daily_cap_per_agent_minor") ?? base.daily_cap_per_agent_minor,
    duplicate_window_days: n("duplicate_window_days") ?? base.duplicate_window_days,
    counterparty_allowlist: Array.isArray(config.counterparty_allowlist) ? (config.counterparty_allowlist as string[]) : base.counterparty_allowlist,
  };
}
