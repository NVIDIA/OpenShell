import { describe, expect, it } from "vitest";
import { Gate, DEFAULT_REFUND_POLICY } from "../src/gate.js";
import { evaluateHttp } from "../src/middleware.js";
import { parseStripeRequest } from "../src/stripe.js";

const H = { "content-type": "application/x-www-form-urlencoded" };
const deps = () => ({ gate: new Gate({ policy: { ...DEFAULT_REFUND_POLICY, counterparty_allowlist: undefined } }) });

describe("stripe parser", () => {
  it("maps POST /v1/refunds to a refund intent", () => {
    const p = parseStripeRequest("POST", "/v1/refunds", H, "charge=ch_123&amount=8000&metadata[reason]=customer+request", "sb1");
    expect(p?.intent.action).toBe("refund");
    expect(p?.intent.amount_minor).toBe(8000);
    expect(p?.intent.original_charge?.id).toBe("ch_123");
    expect(p?.intent.reason).toBe("customer request");
  });
  it("ignores reads and non-money endpoints", () => {
    expect(parseStripeRequest("GET", "/v1/charges/ch_1", H, "", "sb1")).toBeNull();
    expect(parseStripeRequest("POST", "/v1/customers", H, "email=a%40b.com", "sb1")).toBeNull();
  });
});

describe("middleware", () => {
  it("passes non-Stripe hosts through", async () => {
    const o = await evaluateHttp(deps(), { method: "POST", host: "api.github.com", path: "/repos", headers: H, body: "", sandboxId: "sb1" });
    expect(o.decision).toBe("DECISION_ALLOW");
    expect(o.reason_code).toBe("PASSTHROUGH");
  });
  it("allows an in-policy refund and pins the idempotency key to the decision", async () => {
    const o = await evaluateHttp(deps(), { method: "POST", host: "api.stripe.com", path: "/v1/refunds", headers: H, body: "charge=ch_1&amount=8000&customer=cus_1", sandboxId: "sb1" });
    expect(o.decision).toBe("DECISION_ALLOW");
    expect(o.header_mutations[0].write.name).toBe("Idempotency-Key");
    expect(o.header_mutations[0].write.value).toBe(o.axiru!.decision_id);
  });
  it("denies a second refund on the same charge inside the window", async () => {
    const d = deps();
    await evaluateHttp(d, { method: "POST", host: "api.stripe.com", path: "/v1/refunds", headers: H, body: "charge=ch_1&amount=3000&customer=cus_1", sandboxId: "sb1" });
    const o = await evaluateHttp(d, { method: "POST", host: "api.stripe.com", path: "/v1/refunds", headers: H, body: "charge=ch_1&amount=3000&customer=cus_1", sandboxId: "sb1" });
    expect(o.decision).toBe("DECISION_DENY");
    expect(o.metadata["axiru.reason_codes"]).toContain("DUPLICATE_WITHIN_WINDOW");
  });
  it("denies a refund with no amount (full refund) and asks for one", async () => {
    const o = await evaluateHttp(deps(), { method: "POST", host: "api.stripe.com", path: "/v1/refunds", headers: H, body: "charge=ch_9", sandboxId: "sb1" });
    expect(o.decision).toBe("DECISION_DENY");
    expect(o.reason_code).toBe("AMOUNT_UNSPECIFIED");
  });
  it("denies a transfer above the ceiling and recommends quarantine after repeated denials", async () => {
    const d = deps();
    let o;
    for (let i = 0; i < 3; i++) {
      o = await evaluateHttp(d, { method: "POST", host: "api.stripe.com", path: "/v1/transfers", headers: H, body: `amount=25000000&currency=usd&destination=acct_x${i}`, sandboxId: "sb-rogue" });
    }
    expect(o!.decision).toBe("DECISION_DENY");
    expect(o!.metadata["axiru.quarantine_recommended"]).toBe("true");
    expect(o!.findings.some((f) => f.type === "axiru.quarantine_recommended")).toBe(true);
  });
});
