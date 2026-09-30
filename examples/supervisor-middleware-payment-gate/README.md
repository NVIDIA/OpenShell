<!--
SPDX-FileCopyrightText: Copyright (c) 2026 Axiru, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# Supervisor Middleware Payment Gate

> [!WARNING]
> Supervisor middleware is a research preview. Its policy and service contracts may change without compatibility guarantees. Use it only to prototype and evaluate middleware integrations.

This example is a supervisor middleware for sandboxes whose agents hold Stripe credentials. OpenShell network policy decides whether the sandbox may reach `api.stripe.com` at all. This middleware decides whether a specific money-moving call should happen.

It parses refunds, customer credits, transfers, payouts, dispute updates, and issuing approvals out of the Stripe request body, evaluates a deterministic policy (per-transfer ceiling, hold threshold, daily cap per sandbox, duplicate window for the same customer and charge, optional counterparty allowlist), and returns `DECISION_ALLOW` or `DECISION_DENY` in the `PRE_CREDENTIALS` phase. Reads and non-money endpoints pass through.

On allow it writes a Stripe `Idempotency-Key` bound to the decision id, so a retry of the same decision cannot become a second refund. On deny it returns a reason code and a one-sentence rationale. A refund with no `amount` is a full refund in Stripe's API; the middleware denies it and asks for an explicit amount. After three denials from one sandbox in 24 hours it adds a `quarantine_recommended` finding with severity `critical`. Any internal error is a deny, and `policy.yaml` sets `on_error: fail_closed`.

The evaluator is a pure function: policy, intent, prior decisions, and a timestamp in; verdict, reason codes, and a SHA-256 fingerprint out. There is no model in the decision path and the agent's free-text reason is recorded but never evaluated, so the decision cannot be talked into anything by a prompt. Same inputs, same fingerprint.

Why a payment gate belongs here: most agent money losses have no attacker. A parsing bug that refunds a whole balance, a duplicate refund after a retry that looked like a failure, a loop of small refunds. The sandbox boundary sees the host; it does not see the amount. This example adds the amount.

## Prerequisites

Node.js 20 or later on the host for the middleware service. For the smoke run, the same prerequisites as the content guard example: `cargo`, `curl`, `jq`, `mise`, Docker or Podman, and the repository's mise tools.

## Run the service

```shell
cd examples/supervisor-middleware-payment-gate
npm install && npm run build
AXIRU_MW_BIND=0.0.0.0:50052 npm start
```

Bind to all host interfaces so a local containerized gateway and sandbox supervisor can reach it.

Add the service registration to your local gateway TOML (see `gateway.toml.snippet`):

```toml
[[openshell.supervisor.middleware]]
name = "axiru-payment-gate"
grpc_endpoint = "http://host.openshell.internal:50052"
allow_insecure_transport = true
max_payload_bytes = 262144
timeout = "2s"
```

Create a sandbox with the included policy:

```shell
openshell sandbox create --name support-agent --policy examples/supervisor-middleware-payment-gate/policy.yaml
```

The policy allows only the listed Stripe money-moving endpoints and reads, routes every allowed call through the middleware, and fails closed. Adjust the thresholds under `network_middlewares.axiru-payment-gate.config` (values are minor units, so `50000` is 500.00 USD) and list the binaries your agent actually uses.

## Try it from inside the sandbox

Inside the sandbox, with a Stripe test key available to the agent:

```shell
# In policy: 45.00 USD refund, first one on this charge. Expect a normal Stripe response.
curl -s https://api.stripe.com/v1/refunds -u "$STRIPE_KEY": -d charge=ch_test_1 -d amount=4500 -d customer=cus_test_1

# Same charge, same customer, inside the 30-day duplicate window. Expect the gateway to deny with reason_code AXIRU_DENY.
curl -s https://api.stripe.com/v1/refunds -u "$STRIPE_KEY": -d charge=ch_test_1 -d amount=4500 -d customer=cus_test_1

# 250,000.00 USD transfer. Expect a deny with AMOUNT_EXCEEDS_TRANSFER_CEILING in the audit log metadata.
curl -s https://api.stripe.com/v1/transfers -u "$STRIPE_KEY": -d amount=25000000 -d currency=usd -d destination=acct_test_x
```

Every evaluation lands in the gateway audit log with `axiru.decision_id`, `axiru.verdict`, `axiru.policy`, `axiru.fingerprint`, and `axiru.reason_codes` metadata, and a finding of type `axiru.decision`.

## Tests

```shell
npm test
```

Covers the Stripe parser, pass-through for non-Stripe hosts, allow with idempotency pinning, duplicate denial inside the window, denial of an unspecified amount, and the quarantine signal after repeated denials.

## Layout

- `src/gate.ts`: types, the pure evaluator, and a small `Gate` class with a session ledger and optional hosted mode.
- `src/stripe.ts`: maps Stripe API requests to payment intents.
- `src/middleware.ts`: the evaluation logic, separated from gRPC so it can be unit tested.
- `src/server.ts`, `src/cli.ts`: the `openshell.middleware.v1.SupervisorMiddleware` gRPC service.
- `proto/`: vendored from this repository's `proto/` directory at the commit this example was added.
- `policy.yaml`: reference sandbox policy.

## Limits

The local evaluator cannot see the original charge amount from a refund request, so the cumulative rule "refunds never exceed the charge" is only enforced when the middleware runs in hosted mode (set `AXIRU_API_KEY`) or when a Stripe read is placed in front of it. Only Stripe is mapped; adding a rail is one regex and one field mapping in `src/stripe.ts`. This example handles form-encoded and JSON request bodies for the listed endpoints and is not a general payments proxy.

A maintained version of this middleware, plus the same gate as an MCP server and as plugins for other agent runtimes, lives at https://github.com/AxiruAI/axiru-gate.
