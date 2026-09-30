// SPDX-FileCopyrightText: Copyright (c) 2026 Axiru, Inc.
// SPDX-License-Identifier: Apache-2.0
import type { PaymentAction, PaymentIntent } from "./gate.js";

/**
 * Turn a raw Stripe API request into a PaymentIntent the gate can evaluate.
 * Stripe's API is form-encoded. Only money-moving endpoints are mapped; everything
 * else returns null and passes through untouched.
 */
export interface ParsedStripeCall {
  intent: PaymentIntent;
  endpoint: string;
  /** Stripe treats a refund with no amount as a full refund. The gate cannot size it, so the middleware denies and asks for an explicit amount. */
  amountUnspecified: boolean;
}

const MONEY_ENDPOINTS: Array<{ re: RegExp; action: PaymentAction; counterpartyKey: string[] }> = [
  { re: /^\/v1\/refunds$/, action: "refund", counterpartyKey: ["charge", "payment_intent"] },
  { re: /^\/v1\/charges\/([^/]+)\/refunds$/, action: "refund", counterpartyKey: [] },
  { re: /^\/v1\/transfers$/, action: "transfer", counterpartyKey: ["destination"] },
  { re: /^\/v1\/payouts$/, action: "payout", counterpartyKey: ["destination"] },
  { re: /^\/v1\/customers\/([^/]+)\/balance_transactions$/, action: "credit", counterpartyKey: [] },
  { re: /^\/v1\/disputes\/([^/]+)$/, action: "dispute", counterpartyKey: [] },
  { re: /^\/v1\/issuing\/authorizations\/([^/]+)\/approve$/, action: "purchase", counterpartyKey: [] },
];

export function parseForm(body: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const pair of body.split("&")) {
    if (!pair) continue;
    const [k, v = ""] = pair.split("=");
    out[decodeURIComponent(k.replace(/\+/g, " "))] = decodeURIComponent(v.replace(/\+/g, " "));
  }
  return out;
}

export function parseStripeRequest(method: string, path: string, headers: Record<string, string>, bodyText: string, sandboxId: string): ParsedStripeCall | null {
  if (method.toUpperCase() !== "POST") return null;
  const cleanPath = path.split("?")[0];
  for (const m of MONEY_ENDPOINTS) {
    const match = cleanPath.match(m.re);
    if (!match) continue;
    const form = headers["content-type"]?.includes("json") ? (JSON.parse(bodyText || "{}") as Record<string, string>) : parseForm(bodyText);
    const amountRaw = form.amount ?? form.amount_cents;
    const amount = amountRaw !== undefined ? Number(amountRaw) : NaN;
    const chargeId = match[1] ?? form.charge ?? form.payment_intent;
    const counterparty = m.counterpartyKey.map((k) => form[k]).find(Boolean) ?? chargeId ?? form.customer ?? match[1] ?? "unknown";
    const idem = headers["idempotency-key"];
    const intent: PaymentIntent = {
      intent_id: idem ? `stripe_${idem}` : `stripe_${sandboxId}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      agent_id: sandboxId,
      action: m.action,
      amount_minor: Number.isFinite(amount) && amount > 0 ? Math.trunc(amount) : 1,
      currency: (form.currency ?? "usd").toUpperCase(),
      counterparty: String(counterparty),
      rail: "stripe",
      reason: form["metadata[reason]"] ?? form.reason ?? form.description,
      customer_id: form.customer,
      original_charge: chargeId ? { id: String(chargeId), amount_minor: Number.MAX_SAFE_INTEGER } : undefined,
      context: { platform: "openshell", path: cleanPath },
    };
    return { intent, endpoint: cleanPath, amountUnspecified: !(Number.isFinite(amount) && amount > 0) };
  }
  return null;
}
