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
- Cedar-derived Landlock grants pass the same path checks as YAML paths and get
  the same baseline enrichment.

`cedar-policy` enables `serde_json`'s `preserve_order` feature in every binary
that links it. Code that relies on sorted JSON object keys must sort them
explicitly.
