<!-- SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Maximum Policy Envelope Spike

This spike tests whether OpenShell can compare a candidate policy against a
security-approved maximum policy and reject any candidate that allows more than
the maximum.

Core check:

```text
exists x:
  candidate_allows(x)
  AND NOT maximum_allows(x)
```

Rust normalizes schema-level OpenShell policy semantics, such as access presets
and unsupported field detection. Z3 owns the action variables (`binary`, `host`,
`port`, `layer`, `method`, and `path`) and checks whether any symbolic action is
allowed by the candidate but not by the maximum. Host, path, and binary globs
compile to Z3 regular-expression constraints. If the solver finds such an `x`,
the candidate exceeds the maximum. If no such `x` exists, the candidate is within
the modeled maximum. If either policy uses a surface the spike does not model
yet, the check fails closed as `Unsupported`.

The first modeled action layers are:

```text
L4:        binary, host, port
REST:      binary, host, port, method, path
WebSocket: binary, host, port, method, path
```

An L4 endpoint is broader than inspected protocols: it covers raw L4, REST, and
WebSocket actions on the same binary/host/port. REST and WebSocket endpoints
cover only their own inspected action layer.

## Demo 1: Narrow Candidate Within Maximum

Maximum:

```yaml
version: 1
network_policies:
  github:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/OpenShell/issues/*
    binaries:
      - path: /usr/bin/gh
```

Candidate:

```yaml
version: 1
network_policies:
  github:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/OpenShell/issues/123
    binaries:
      - path: /usr/bin/gh
```

Result:

```text
WithinMax
```

Why: the candidate narrows the approved path from one issue path glob to one
specific issue.

## Demo 2: Broad Path Proposal Exceeds Maximum

Maximum:

```yaml
rules:
  - allow:
      method: GET
      path: /repos/NVIDIA/OpenShell/issues/*
```

Candidate:

```yaml
rules:
  - allow:
      method: GET
      path: /repos/NVIDIA/**
```

Result:

```text
ExceedsMax {
  binary: "/usr/bin/gh",
  host: "api.github.com",
  port: 443,
  protocol: "rest",
  method: "GET",
  path: "/repos/NVIDIA/",
  reason: "candidate allows an action outside the maximum policy"
}
```

Why: the candidate allows requests outside the approved issue path. The
counterexample is a concrete model selected by Z3: a request the broader
candidate would allow but the maximum would not.

## Demo 3: Method Escalation Exceeds Maximum

Maximum:

```yaml
rules:
  - allow:
      method: GET
      path: /repos/NVIDIA/**
```

Candidate:

```yaml
rules:
  - allow:
      method: POST
      path: /repos/NVIDIA/OpenShell/issues
```

Result:

```text
ExceedsMax {
  method: "POST",
  ...
}
```

Why: the candidate adds a mutating HTTP method outside the maximum's approved
read-only method.

## Demo 4: Host, Binary, and Port Broadening

These candidate changes all exceed a narrower maximum:

```text
host: api.github.com       -> *.github.com
binary: /usr/bin/gh        -> /usr/bin/*
port: 443                  -> [443, 8443]
```

Why: each change creates at least one action that the maximum does not allow.

## Demo 5: L4, REST, And WebSocket Layering

An L4 maximum covers a narrower REST candidate on the same binary/host/port:

```yaml
maximum:
  endpoints:
    - host: api.github.com
      port: 443

candidate:
  endpoints:
    - host: api.github.com
      port: 443
      protocol: rest
      enforcement: enforce
      access: read-write
```

Result:

```text
WithinMax
```

A REST maximum does not cover a raw L4 candidate:

```text
ExceedsMax {
  protocol: "l4",
  host: "api.github.com",
  port: 443,
  ...
}
```

Why: raw L4 egress is broader and less inspected than an enforced REST or
WebSocket surface.

WebSocket endpoints are modeled as their own inspected layer with `GET` and
`WEBSOCKET_TEXT` actions. `read-only` WebSocket access covers the opening
`GET`, not text send authority. Credential rewrite flags fail closed until the
prover has an explicit authority check for introducing credential injection.

## Demo 6: Credentialed L4 Is A Separate High-Risk Check

The spike also includes a separate check for uninspected credentialed L4 reach:

```text
exists x:
  policy_allows(x)
  AND x.layer = L4
  AND credential_target_matches(x.host)
```

This is intentionally separate from maximum containment. It lets product policy
decide whether credentialed L4 should be explicitly allowed, auto-denied, or
sent to human review without changing the meaning of the signed maximum.

## Demo 7: Unsupported Surfaces Fail Closed

Maximum:

```yaml
access: full
deny_rules:
  - method: POST
    path: /admin/**
```

Result:

```text
Unsupported {
  reason: "maximum policy rule 'github' uses deny_rules, which policy envelope checks do not model yet"
}
```

Why: deny rules change containment semantics. Until the prover models allow plus
deny precedence, the check must not approve these cases.

Other surfaces currently fail closed:

```text
query constraints
GraphQL operation and field constraints
MCP tool/resource constraints
CIDR-only allowed_ips
endpoint path scoping
credential rewrite flags
```

## Narrowness Companion

The maximum-policy check answers whether a candidate stays under a
security-approved ceiling. That is the immediate enterprise gate. The related
narrowness question is different:

```text
How much broader is this candidate than the current policy?
```

A first useful shape is to reuse the same symbolic model and score the proposed
delta:

```text
delta = candidate_allows(x) AND NOT current_allows(x)
score(delta) <= budget
```

The current spike includes a first narrowness check. Z3 proves whether each
modeled candidate grant adds any action outside the current policy:

```text
exists x:
  candidate_grant_allows(x)
  AND NOT current_policy_allows(x)
```

Rust then scores the shape of each delta grant. This is deliberately coarse for
the spike:

```text
exact new grant:        +1
single path wildcard:   +2
host/binary wildcard:   +3
recursive glob (**):    +6
L7-to-L4 broadening:    +8
```

A conservative budget can allow one exact grant, including an exact L4
host/port grant, while rejecting recursive globs and L7-to-L4 broadening:

```rust
NarrownessBudget {
    max_delta_grants: 1,
    max_total_score: 1,
    allow_recursive_globs: false,
}
```

Credentialed raw L4 is handled by the separate credentialed-L4 check above. A
production auto-approval gate can combine that result with this budget, for
example by assigning a high score or requiring human review when raw L4 reaches
a credential target.

## Demo 8: One Exact Path Fits A Narrow Budget

Current:

```yaml
rules:
  - allow:
      method: GET
      path: /repos/NVIDIA/OpenShell/issues/123
```

Candidate:

```yaml
rules:
  - allow:
      method: GET
      path: /repos/NVIDIA/OpenShell/issues/123
  - allow:
      method: GET
      path: /repos/NVIDIA/OpenShell/issues/456
```

Result:

```text
WithinBudget {
  total_score: 1,
  delta_grants: [
    {
      method: "GET",
      path: "/repos/NVIDIA/OpenShell/issues/456",
      reasons: [NewGrant]
    }
  ]
}
```

Why: the candidate adds one exact modeled grant. The grant allows both `GET` and
runtime-implied `HEAD`, but the budget counts the source grant once.

## Demo 9: Exact L4 Versus L7-To-L4 Broadening

An exact L4 grant to a new normal host is still one exact grant:

```yaml
candidate:
  endpoints:
    - host: files.pythonhosted.org
      port: 443
```

Result:

```text
WithinBudget {
  total_score: 1,
  reasons: [NewGrant]
}
```

If the current policy already has inspected REST/WebSocket access for the same
authority and the candidate asks for raw L4, the same exact host/port becomes a
larger jump:

```yaml
current:
  endpoints:
    - host: api.github.com
      port: 443
      protocol: rest
      enforcement: enforce
      access: full

candidate:
  endpoints:
    - host: api.github.com
      port: 443
```

Result:

```text
ExceedsBudget {
  total_score: 9,
  reasons: [NewGrant, L7ToL4Broadening]
}
```

Why: the candidate is not just adding a host. It is replacing inspected
method/path reasoning with raw host/port authority for a service the current
policy already modeled at L7.

## Demo 10: Lazy Recursive Path Exceeds A Narrow Budget

Current:

```yaml
rules:
  - allow:
      method: GET
      path: /repos/NVIDIA/OpenShell/issues/123
```

Candidate:

```yaml
rules:
  - allow:
      method: GET
      path: /repos/NVIDIA/**
```

Result:

```text
ExceedsBudget {
  total_score: 7,
  delta_grants: [
    {
      method: "GET",
      path: "/repos/NVIDIA/**",
      reasons: [NewGrant, RecursivePathGlob]
    }
  ]
}
```

Why: the candidate still fits under a maximum policy if that maximum is broad
enough, but it is not a narrow update over the current policy. This is the
mechanism that can pressure agents away from requesting lazy `**` access.

This spike should not over-design the product surface yet. The useful next proof
is validating whether this budget shape is useful enough for policy proposal
auto-approval, or whether we need richer semantic categories before productizing
it.

## Current Test Command

```shell
mise exec -- cargo test -p openshell-prover
```

Coverage includes:

```text
REST method/path/host/binary/port containment
L4 versus REST/WebSocket layer containment
WebSocket text-send and read-only behavior
credentialed raw L4 detection
fail-closed unsupported deny/query/GraphQL/MCP/CIDR/rewrite surfaces
exact, wildcard, recursive-glob, L4, and WebSocket narrowness deltas
representative provider-shaped accept/reject cases
```

## Readout

This validates the product shape for L4, REST, and WebSocket maximum-policy
envelopes, narrowness budgets, and uninspected credentialed L4 detection with
symbolic Z3 counterexample queries. Deny rules, MCP, GraphQL, query constraints,
and CIDR can land as follow-on modeled surfaces once the containment and delta
mechanics are proven useful.
