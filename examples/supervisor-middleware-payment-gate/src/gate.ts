// SPDX-FileCopyrightText: Copyright (c) 2026 Axiru, Inc.
// SPDX-License-Identifier: Apache-2.0
import { createHash } from "node:crypto";
/** A request to move money, submitted by an agent before the payment tool runs. */
export interface PaymentIntent {
  /** Stable id supplied by the caller. Used for idempotency and receipts. */
  intent_id: string;
  /** Which agent is asking. */
  agent_id: string;
  /** refund | credit | payout | transfer | purchase | dispute */
  action: PaymentAction;
  /** Minor units (cents). Integers only. */
  amount_minor: number;
  /** ISO 4217, upper case. */
  currency: string;
  /** Who receives the money: a merchant, vendor id, wallet, or customer id. */
  counterparty: string;
  /** stripe | x402 | usdc | card | link | other */
  rail: string;
  /** Free text from the agent. Never an input to the decision. Stored on the receipt. */
  reason?: string;
  /** For refunds: the original charge id and its amount, so the gate can enforce refund <= charge. */
  original_charge?: { id: string; amount_minor: number };
  /** For refunds and credits: the customer the money goes back to. */
  customer_id?: string;
  /** Platform context. Not an input to the decision. */
  context?: Record<string, unknown>;
}

export type PaymentAction = "refund" | "credit" | "payout" | "transfer" | "purchase" | "dispute";

export interface Policy {
  policy_id: string;
  version: string;
  /** Deny any single intent above this amount (minor units). */
  per_transfer_ceiling_minor?: number;
  /** Hold for a human above this amount (minor units). */
  hold_above_minor?: number;
  /** Deny once an agent's allowed total in a rolling 24h window would exceed this (minor units). */
  daily_cap_per_agent_minor?: number;
  /** If set, counterparties not in this list are denied. Case-insensitive exact match. */
  counterparty_allowlist?: string[];
  /** Deny a second refund or credit to the same customer for the same charge inside this window. */
  duplicate_window_days?: number;
  /** Hold once a customer has received this many refunds or credits inside velocity_window_days. */
  velocity_max_per_customer?: number;
  velocity_window_days?: number;
  /** Refunds may never exceed the original charge, cumulatively. Default true. */
  refund_cannot_exceed_charge?: boolean;
  /** Actions that always hold for a person, regardless of amount. Default: dispute. */
  always_hold_actions?: PaymentAction[];
  /** Optional business hours in UTC. Outside them, hold. */
  business_hours_utc?: { start_hour: number; end_hour: number };
}

export type Verdict = "allow" | "hold" | "deny";

export type ReasonCode =
  | "AMOUNT_EXCEEDS_TRANSFER_CEILING"
  | "AMOUNT_EXCEEDS_DAILY_CAP"
  | "COUNTERPARTY_NOT_ALLOWLISTED"
  | "DUPLICATE_WITHIN_WINDOW"
  | "REFUND_EXCEEDS_CHARGE"
  | "VELOCITY_EXCEEDED"
  | "HOLD_ABOVE_THRESHOLD"
  | "ACTION_REQUIRES_HUMAN"
  | "OUTSIDE_BUSINESS_HOURS"
  | "INVALID_INTENT"
  | "WITHIN_POLICY";

/** What the gate already knows: prior decisions the rules need to count. */
export interface LedgerContext {
  /** Prior allowed intents. The gate only needs amount, agent, customer, charge, and time. */
  prior: PriorDecision[];
}

export interface PriorDecision {
  intent_id: string;
  agent_id: string;
  action: PaymentAction;
  amount_minor: number;
  currency: string;
  customer_id?: string;
  original_charge_id?: string;
  verdict: Verdict;
  /** ISO timestamp. */
  at: string;
}

export interface Decision {
  decision_id: string;
  intent_id: string;
  verdict: Verdict;
  reason_codes: ReasonCode[];
  /** One sentence a person can read. Built from the codes, not from the agent's text. */
  rationale: string;
  policy_id: string;
  policy_version: string;
  /** ISO timestamp handed in by the caller. The evaluator never reads the wall clock. */
  evaluated_at: string;
  /** SHA-256 over the canonical decision record. */
  fingerprint: string;
  /** Fingerprint of the previous decision in this session, or 64 zeros. */
  prev_fingerprint: string;
}

const ZERO = "0".repeat(64);
const DAY_MS = 86_400_000;

/** Canonical JSON: sorted keys, no whitespace. Same input, same bytes, same hash. */
export function canonical(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}
function sortKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === "object") {
    return Object.keys(v as Record<string, unknown>)
      .sort()
      .reduce<Record<string, unknown>>((acc, k) => {
        acc[k] = sortKeys((v as Record<string, unknown>)[k]);
        return acc;
      }, {});
  }
  return v;
}
export function sha256Hex(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

function validate(intent: PaymentIntent): ReasonCode | null {
  if (!intent.intent_id || !intent.agent_id || !intent.counterparty) return "INVALID_INTENT";
  if (!Number.isInteger(intent.amount_minor) || intent.amount_minor <= 0) return "INVALID_INTENT";
  if (!/^[A-Z]{3,5}$/.test(intent.currency)) return "INVALID_INTENT";
  return null;
}

/**
 * The gate. A pure function: policy, intent, prior decisions, and a timestamp in;
 * a verdict, reason codes, and a fingerprint out. No I/O, no clock, no model.
 * Deny beats hold beats allow. Every applicable code is returned, not just the first.
 */
export function evaluate(
  policy: Policy,
  intent: PaymentIntent,
  ledger: LedgerContext,
  nowIso: string,
  prevFingerprint: string = ZERO,
): Decision {
  const codes: ReasonCode[] = [];
  const invalid = validate(intent);
  if (invalid) codes.push(invalid);

  const now = Date.parse(nowIso);
  const sameCurrency = (p: { currency: string }) => p.currency === intent.currency;
  const within = (at: string, days: number) => now - Date.parse(at) <= days * DAY_MS && Date.parse(at) <= now;

  if (!invalid) {
    // 1. Ceiling
    if (policy.per_transfer_ceiling_minor !== undefined && intent.amount_minor > policy.per_transfer_ceiling_minor) {
      codes.push("AMOUNT_EXCEEDS_TRANSFER_CEILING");
    }

    // 2. Counterparty allowlist
    if (policy.counterparty_allowlist && policy.counterparty_allowlist.length > 0) {
      const ok = policy.counterparty_allowlist.some((c) => c.toLowerCase() === intent.counterparty.toLowerCase());
      if (!ok) codes.push("COUNTERPARTY_NOT_ALLOWLISTED");
    }

    // 3. Daily cap per agent (allowed intents in the last 24h plus this one)
    if (policy.daily_cap_per_agent_minor !== undefined) {
      const spent = ledger.prior
        .filter((p) => p.agent_id === intent.agent_id && p.verdict === "allow" && sameCurrency(p) && within(p.at, 1))
        .reduce((s, p) => s + p.amount_minor, 0);
      if (spent + intent.amount_minor > policy.daily_cap_per_agent_minor) codes.push("AMOUNT_EXCEEDS_DAILY_CAP");
    }

    const isReturnOfMoney = intent.action === "refund" || intent.action === "credit";

    // 4. Duplicate window: same customer, same charge, already refunded inside the window
    if (isReturnOfMoney && policy.duplicate_window_days !== undefined && intent.original_charge && intent.customer_id) {
      const chargeId = intent.original_charge.id;
      const dup = ledger.prior.some(
        (p) =>
          p.verdict === "allow" &&
          (p.action === "refund" || p.action === "credit") &&
          p.customer_id === intent.customer_id &&
          p.original_charge_id === chargeId &&
          within(p.at, policy.duplicate_window_days!),
      );
      if (dup) codes.push("DUPLICATE_WITHIN_WINDOW");
    }

    // 5. Cumulative refunds never exceed the charge
    if (isReturnOfMoney && intent.original_charge && (policy.refund_cannot_exceed_charge ?? true)) {
      const already = ledger.prior
        .filter((p) => p.verdict === "allow" && p.original_charge_id === intent.original_charge!.id && sameCurrency(p))
        .reduce((s, p) => s + p.amount_minor, 0);
      if (already + intent.amount_minor > intent.original_charge.amount_minor) codes.push("REFUND_EXCEEDS_CHARGE");
    }

    // 6. Per-customer velocity
    if (isReturnOfMoney && policy.velocity_max_per_customer !== undefined && intent.customer_id) {
      const days = policy.velocity_window_days ?? 30;
      const count = ledger.prior.filter(
        (p) => p.verdict === "allow" && (p.action === "refund" || p.action === "credit") && p.customer_id === intent.customer_id && within(p.at, days),
      ).length;
      if (count + 1 > policy.velocity_max_per_customer) codes.push("VELOCITY_EXCEEDED");
    }

    // 7. Actions that always need a person
    const alwaysHold = policy.always_hold_actions ?? ["dispute"];
    if (alwaysHold.includes(intent.action)) codes.push("ACTION_REQUIRES_HUMAN");

    // 8. Hold threshold
    if (policy.hold_above_minor !== undefined && intent.amount_minor > policy.hold_above_minor) {
      codes.push("HOLD_ABOVE_THRESHOLD");
    }

    // 9. Business hours (UTC)
    if (policy.business_hours_utc) {
      const h = new Date(now).getUTCHours();
      const { start_hour, end_hour } = policy.business_hours_utc;
      const inside = start_hour <= end_hour ? h >= start_hour && h < end_hour : h >= start_hour || h < end_hour;
      if (!inside) codes.push("OUTSIDE_BUSINESS_HOURS");
    }
  }

  const DENY: ReasonCode[] = [
    "INVALID_INTENT",
    "AMOUNT_EXCEEDS_TRANSFER_CEILING",
    "AMOUNT_EXCEEDS_DAILY_CAP",
    "COUNTERPARTY_NOT_ALLOWLISTED",
    "DUPLICATE_WITHIN_WINDOW",
    "REFUND_EXCEEDS_CHARGE",
  ];
  let verdict: Verdict = "allow";
  if (codes.some((c) => DENY.includes(c))) verdict = "deny";
  else if (codes.length > 0) verdict = "hold";
  if (codes.length === 0) codes.push("WITHIN_POLICY");

  const rationale = buildRationale(verdict, codes, intent, policy);
  const record = {
    intent_id: intent.intent_id,
    verdict,
    reason_codes: codes,
    policy_id: policy.policy_id,
    policy_version: policy.version,
    evaluated_at: nowIso,
    prev_fingerprint: prevFingerprint,
    intent: { agent_id: intent.agent_id, action: intent.action, amount_minor: intent.amount_minor, currency: intent.currency, counterparty: intent.counterparty, rail: intent.rail },
  };
  const fingerprint = sha256Hex(canonical(record));
  return {
    decision_id: `dec_${fingerprint.slice(0, 16)}`,
    intent_id: intent.intent_id,
    verdict,
    reason_codes: codes,
    rationale,
    policy_id: policy.policy_id,
    policy_version: policy.version,
    evaluated_at: nowIso,
    fingerprint,
    prev_fingerprint: prevFingerprint,
  };
}

function money(minor: number, ccy: string): string {
  return `${(minor / 100).toFixed(2)} ${ccy}`;
}

function buildRationale(verdict: Verdict, codes: ReasonCode[], i: PaymentIntent, p: Policy): string {
  const parts: string[] = [];
  for (const c of codes) {
    switch (c) {
      case "AMOUNT_EXCEEDS_TRANSFER_CEILING":
        parts.push(`amount ${money(i.amount_minor, i.currency)} exceeds per-transfer ceiling ${money(p.per_transfer_ceiling_minor!, i.currency)}`);
        break;
      case "AMOUNT_EXCEEDS_DAILY_CAP":
        parts.push(`agent ${i.agent_id} would exceed daily cap ${money(p.daily_cap_per_agent_minor!, i.currency)}`);
        break;
      case "COUNTERPARTY_NOT_ALLOWLISTED":
        parts.push(`counterparty ${i.counterparty} is not on the allowlist`);
        break;
      case "DUPLICATE_WITHIN_WINDOW":
        parts.push(`a ${i.action} to customer ${i.customer_id} for charge ${i.original_charge?.id} already ran inside ${p.duplicate_window_days} days`);
        break;
      case "REFUND_EXCEEDS_CHARGE":
        parts.push(`total refunds on charge ${i.original_charge?.id} would exceed the original ${money(i.original_charge!.amount_minor, i.currency)}`);
        break;
      case "VELOCITY_EXCEEDED":
        parts.push(`customer ${i.customer_id} has reached ${p.velocity_max_per_customer} refunds in ${p.velocity_window_days ?? 30} days`);
        break;
      case "ACTION_REQUIRES_HUMAN":
        parts.push(`${i.action} always requires a person`);
        break;
      case "HOLD_ABOVE_THRESHOLD":
        parts.push(`amount ${money(i.amount_minor, i.currency)} is above the hold threshold ${money(p.hold_above_minor!, i.currency)}`);
        break;
      case "OUTSIDE_BUSINESS_HOURS":
        parts.push(`outside business hours`);
        break;
      case "INVALID_INTENT":
        parts.push(`intent is missing required fields or has a non-positive amount`);
        break;
      case "WITHIN_POLICY":
        parts.push(`within policy ${p.policy_id} v${p.version}`);
        break;
    }
  }
  const head = verdict === "allow" ? "Allowed" : verdict === "hold" ? "Held for a person" : "Denied";
  return `${head}: ${parts.join("; ")}.`;
}
export interface GateOptions {
  /** If set, decisions are requested from the hosted Axiru API. Otherwise the local evaluator runs. */
  apiKey?: string;
  /** Defaults to https://www.axiru.com/api/v1 */
  baseUrl?: string;
  /** Policy used by the local evaluator. Required when there is no API key. */
  policy?: Policy;
  /** Clock injection for tests. */
  now?: () => string;
  /** fetch injection for tests. */
  fetchImpl?: typeof fetch;
}

/** Sensible defaults for a support agent with refund authority. Override per deployment. */
export const DEFAULT_REFUND_POLICY: Policy = {
  policy_id: "refund-default",
  version: "1.0.0",
  per_transfer_ceiling_minor: 50_000,
  hold_above_minor: 10_000,
  daily_cap_per_agent_minor: 100_000,
  duplicate_window_days: 30,
  velocity_max_per_customer: 3,
  velocity_window_days: 30,
  refund_cannot_exceed_charge: true,
  always_hold_actions: ["dispute", "payout", "transfer"],
};

/**
 * Gate = evaluator + session ledger + optional hosted API.
 * Every platform adapter in this repo talks to this one class.
 */
export class Gate {
  private readonly prior: PriorDecision[] = [];
  private readonly decisions: Decision[] = [];
  private lastFingerprint = "0".repeat(64);
  private readonly opts: Required<Pick<GateOptions, "baseUrl" | "now" | "fetchImpl">> & GateOptions;

  constructor(opts: GateOptions = {}) {
    this.opts = {
      ...opts,
      baseUrl: opts.baseUrl ?? "https://www.axiru.com/api/v1",
      now: opts.now ?? (() => new Date().toISOString()),
      fetchImpl: opts.fetchImpl ?? fetch,
    };
    if (!opts.apiKey && !opts.policy) this.opts.policy = DEFAULT_REFUND_POLICY;
  }

  get policy(): Policy | undefined {
    return this.opts.policy;
  }

  /** Feed prior decisions from your own store so windows and caps count correctly across restarts. */
  seed(prior: PriorDecision[]): void {
    this.prior.push(...prior);
  }

  ledger(): readonly Decision[] {
    return this.decisions;
  }

  async check(intent: PaymentIntent): Promise<Decision> {
    const existing = this.decisions.find((d) => d.intent_id === intent.intent_id);
    if (existing) return existing; // idempotent: same intent id, same decision

    const decision = this.opts.apiKey ? await this.remote(intent) : this.local(intent);
    this.decisions.push(decision);
    this.lastFingerprint = decision.fingerprint;
    this.prior.push({
      intent_id: intent.intent_id,
      agent_id: intent.agent_id,
      action: intent.action,
      amount_minor: intent.amount_minor,
      currency: intent.currency,
      customer_id: intent.customer_id,
      original_charge_id: intent.original_charge?.id,
      verdict: decision.verdict,
      at: decision.evaluated_at,
    });
    return decision;
  }

  private local(intent: PaymentIntent): Decision {
    const ctx: LedgerContext = { prior: this.prior };
    return evaluate(this.opts.policy!, intent, ctx, this.opts.now(), this.lastFingerprint);
  }

  private async remote(intent: PaymentIntent): Promise<Decision> {
    const res = await this.opts.fetchImpl(`${this.opts.baseUrl}/decisions`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${this.opts.apiKey}` },
      body: JSON.stringify({
        intent_id: intent.intent_id,
        agent_id: intent.agent_id,
        action: intent.action,
        amount_cents: intent.amount_minor,
        currency: intent.currency.toLowerCase(),
        counterparty: intent.counterparty,
        rail: intent.rail,
        customer_id: intent.customer_id,
        stripe_charge_id: intent.original_charge?.id,
        original_amount_cents: intent.original_charge?.amount_minor,
        reason: intent.reason,
        context: intent.context,
      }),
    });
    if (!res.ok) {
      // Fail closed. A gate that cannot reach its policy does not say yes.
      const now = this.opts.now();
      return {
        decision_id: `dec_unavailable_${Date.parse(now)}`,
        intent_id: intent.intent_id,
        verdict: "hold",
        reason_codes: ["ACTION_REQUIRES_HUMAN"],
        rationale: `Held for a person: policy service returned HTTP ${res.status}; the gate fails closed.`,
        policy_id: "remote",
        policy_version: "unknown",
        evaluated_at: now,
        fingerprint: "",
        prev_fingerprint: this.lastFingerprint,
      };
    }
    const body = (await res.json()) as Partial<Decision> & { status?: string; decision_id?: string };
    const verdict = (body.verdict ?? mapStatus(body.status)) as Decision["verdict"];
    return {
      decision_id: body.decision_id ?? `dec_${Date.parse(this.opts.now())}`,
      intent_id: intent.intent_id,
      verdict,
      reason_codes: body.reason_codes ?? ["WITHIN_POLICY"],
      rationale: body.rationale ?? "",
      policy_id: body.policy_id ?? "remote",
      policy_version: body.policy_version ?? "unknown",
      evaluated_at: body.evaluated_at ?? this.opts.now(),
      fingerprint: body.fingerprint ?? "",
      prev_fingerprint: body.prev_fingerprint ?? this.lastFingerprint,
    };
  }
}

function mapStatus(s?: string): Decision["verdict"] {
  if (s === "allowed" || s === "allow") return "allow";
  if (s === "blocked" || s === "deny" || s === "denied") return "deny";
  return "hold";
}
