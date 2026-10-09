# Cedar policy engine

`openshell-policy-cedar` loads and evaluates sandbox policies authored in
[Cedar](https://www.cedarpolicy.com/). A policy is either YAML or Cedar for the
life of a sandbox. A non-empty `SandboxPolicy.cedar_policy_source`, authored as
a `.cedar` file, selects Cedar. It is mutually exclusive with
`network_policies` and filesystem paths. Middleware is configuration rather
than policy, so a Cedar sandbox gets it from a separate middleware file
(`--middleware`), carried in `network_middlewares`.

`CedarEngine` validates the policy text in strict mode against the canonical
schema in `openshell-policy-cedar-schema`. It then derives three artifacts that
Cedar does not decide at request time: Landlock grants, which endpoints the
proxy inspects per request, and policy DNS eligibility. It accepts only policy
shapes whose meaning those artifacts can enforce exactly. The CLI, the gateway,
and the supervisor reject everything else. Cedar evaluation errors fail the
request instead of skipping the erroring policy.

Policy DNS eligibility comes from `NetworkConnect` permit scopes, and from
`when` conditions that require both `resource.host` and `resource.port`. A host
condition can be an exact string, or a delimited glob such as
`resource.host like("*.example.com", ".")` that follows the YAML wildcard host
rules. The glob is converted from Cedar's pattern elements, not its source
text, so policy DNS matches exactly the hosts Cedar's delimited `like` admits.
A glob never counts as an exactly named host, so it cannot resolve to a
private address.

Delimited `like` is not yet in a Cedar release. This branch depends on the
experimental `extended-like-wip` branch of `lianah/cedar`, pinned by commit,
with a matching `allow-git` exception in `deny.toml`.

## Integration

- `openshell-policy` validates Cedar sources behind its default `cedar`
  feature. Crates that never see Cedar policies disable the feature.
- The gateway rejects format switches on update, Cedar global policies, and
  removal of a Cedar-derived Landlock grant on a live sandbox.
- Providers attached to a Cedar sandbox supply credentials but grant no access.
  Provider composition puts their rules in `provider_credential_rules` instead
  of `network_policies`. For a connection Cedar allows, each matching provider
  endpoint contributes its credential settings. The same fail-closed credential
  guard as YAML refuses an uninspected connection to a credentialed endpoint.
- In `openshell-supervisor-network`, `PolicyEngine` is either the OPA engine or
  `CedarOnlyEngine`, and it is the only engine that network decision points
  receive. A Cedar sandbox keeps an OPA engine with no network policies for
  middleware and per-tunnel plumbing. Inspected tunnels are pinned to Cedar's
  policy generation and delegate L7 decisions to Cedar.
- The supervisor chooses the engine once at startup. On reload it rejects a
  format switch and stages the Cedar policy before the plumbing engine reloads.
  The staged policy is committed inside the plumbing commit, so a rejected
  policy leaves both engines on the previous revision. A rejected revision
  quarantines or retains the Cedar engine according to
  `policy_validation_failure_mode`, as for YAML.
- `@protocol` selects `rest` (default), `json-rpc`, `mcp`, or `graphql`. The
  supervisor fills the protocol's `HttpRequest` context fields from the
  relay's parsed request: one evaluation per JSON-RPC or MCP call (the relay
  splits batches), and one per GraphQL operation, denying the request if any
  is denied. Cedar MCP endpoints get the same default MCP revision as YAML.
  `sql` is rejected because the relay does not inspect SQL. The supervisor
  uppercases the request method, and denies JSON-RPC calls and response
  frames not sent with `POST` before evaluation, matching YAML.
- `openshell-supervisor-network`'s `cedar_parity_tests` run paired YAML and
  Cedar policies for REST, JSON-RPC, MCP, and GraphQL through both engines'
  per-tunnel evaluation, and fail when decisions differ outside a recorded
  list of known differences.
- `@enforcement("audit")` marks an `HttpRequest`-only policy as audit-only.
  An endpoint whose policies are all audit-only gets `enforcement: audit` in its
  L7 config, so the relay logs and forwards denials as it does for YAML. On an
  enforced endpoint, audit-only policies are staged: `CedarEngine` decides with
  the enforced policies, and reports a staged decision only when adding the
  audit-only policies would change it. Comparing decisions, not evaluating the
  audit-only policies alone, matters because Cedar denies by default. The
  supervisor logs staged decisions as `cedar_audit` events.
- Cedar-derived Landlock grants pass the same path checks as YAML paths and get
  the same baseline enrichment.

`cedar-policy` enables `serde_json`'s `preserve_order` feature in every binary
that links it. Code that relies on sorted JSON object keys must sort them
explicitly.
