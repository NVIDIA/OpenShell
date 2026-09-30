Title: Add supervisor middleware example: payment gate for agents that move money

Branch: examples/supervisor-middleware-payment-gate

Commit message (sign with -s from the Axiru GitHub identity):

    examples: add supervisor middleware payment gate

    Adds a self-contained supervisor middleware example for sandboxes whose
    agents hold Stripe credentials. Network policy decides whether the
    sandbox may reach api.stripe.com; this middleware decides whether a
    specific money-moving call should happen, in the PRE_CREDENTIALS phase.

    It parses refunds, credits, transfers, payouts, dispute updates and
    issuing approvals from the request body and evaluates a deterministic
    policy: per-transfer ceiling, hold threshold, daily cap per sandbox,
    duplicate window, optional counterparty allowlist. On allow it writes a
    Stripe Idempotency-Key bound to the decision id so a retry cannot become
    a second refund. On repeated denials it emits a quarantine_recommended
    finding. It fails closed. Protos are vendored from proto/ at this commit.

    Signed-off-by: Axiru <hello@axiru.com>

PR description:

This example shows a supervisor middleware for agents that hold Stripe credentials. OpenShell already controls whether the sandbox may reach api.stripe.com. This middleware decides whether a specific money-moving call should happen: it parses refunds, credits, transfers, and payouts from the request body, evaluates a deterministic policy (per-transfer ceiling, hold threshold, daily cap per sandbox, duplicate window, counterparty allowlist), and returns DECISION_ALLOW or DECISION_DENY in the PRE_CREDENTIALS phase. On allow it writes a Stripe Idempotency-Key tied to the decision so a retry cannot become a second refund. On repeated denials it emits a quarantine_recommended finding. It fails closed.

It is included because payment tools are where an agent mistake becomes a loss with no attacker involved (a parsing error that refunds the whole balance, a duplicate refund after a retry), and the sandbox boundary alone does not see the amount. The evaluator is a pure function with no model in the decision path, so decisions replay bit for bit.

The example is self-contained (Node.js, two runtime dependencies for gRPC) and mirrors the layout of supervisor-middleware-content-guard. Tests cover the parser, pass-through, allow with idempotency pinning, duplicate denial, unspecified amount, and the quarantine signal. Protos are vendored from proto/ at this commit.

Checklist before opening:
- Read CONTRIBUTING.md and STYLEGUIDE.md; add SPDX headers to src files if maintainers require them on examples (README already has one).
- Run the local gateway smoke path from the content guard README with this service on port 50052 and this policy.yaml; paste the gateway log lines for one allow and one deny into the PR.
- Commit with -s from the Axiru account. Do not sign with a personal name until after 19 Oct 2026.
- Open the PR from a fork under the AxiruAI org.
