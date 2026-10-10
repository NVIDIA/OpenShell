# Cedar policy engine

`openshell-policy-cedar` loads and evaluates sandbox policies authored in
[Cedar](https://www.cedarpolicy.com/). A policy is either YAML or Cedar for the
life of a sandbox. A non-empty `SandboxPolicy.cedar_policy_source`, authored as
a `.cedar` file, selects Cedar. It is mutually exclusive with
`network_policies` and filesystem paths. Middleware and endpoint settings are
configuration rather than policy, so a Cedar sandbox gets them from a separate
middleware file (`--middleware`), carried in `network_middlewares` and
`endpoint_settings`.

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

`@transport("tcp")` on a `NetworkConnect` permit marks its endpoint as native
transparent TCP, the Cedar form of YAML `protocol: tcp`. `dns_endpoints` keeps
one record per host and `NetworkTransport`, so a host with native TCP and
other ports has two. Analysis applies the YAML rules for such endpoints: the
permit must name a DNS host (not an IP literal) and a port, in its scope or
conditions; and no inspected endpoint or non-TCP `NetworkConnect` endpoint may
overlap it on a host and port, which YAML's endpoint ambiguity check rejects.
Host globs are compared for overlap by searching for a host both match.

`NetworkConnect` has an optional `destination_ip` (`ipaddr`) context field,
the Cedar form of YAML `allowed_ips`. Analysis accepts it in a permit only as
top-level `when` conjuncts that are `context has destination_ip` or an `||`
of `context.destination_ip.isInRange(ip("..."))` tests, so each permit's
ranges are known exactly (conjuncts intersect). Ranges overlapping
loopback, link-local, or unspecified addresses are rejected, as is any
policy reading `destination_ip` whose action scope is not exactly
`NetworkConnect`. `CedarEngine::authorize_network` decides a request
without `destination_ip` against `unresolved_policies` (permits stripped of
their address conjuncts, forbids that read it left out), and with it against
every enforced policy. For an allow it reports each determining permit's
ranges, whether one has none, and whether one names the host and port
exactly. `dns_endpoints` keeps one record per host, transport, and range
set, carrying the ranges as `allowed_ips`.

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
  Token-grant owners, which the gateway stamps on provider endpoints, are
  admitted only for a request Cedar allows and the owner's own provider
  endpoint admits under its own rules. The supervisor evaluates that second
  check with the YAML Rego rule over the provider rules, so owner selection
  matches YAML exactly and provider rules can only remove owners.
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
- `@path` attaches `HttpRequest` policies to one path pattern of their
  endpoint, with the YAML endpoint `path` grammar. Analysis keys inspection
  by host, port, and path; policies without `@path` declare the path-less
  inspection. Protocols must agree per path, and two equally specific paths
  that can match one request must inspect it the same way, since the relay
  could not order them. The supervisor emits one endpoint config per path,
  and evaluates each request with the inspection of the config the relay
  selects for it (most specific matching path), denying a request no path
  matches as the relay does. `@path` selects inspection only: every policy
  applies to every request on its endpoint, so policies spell out path
  conditions. `resource.protocol` is the routed path's protocol. Provider
  endpoints and path-scoped endpoint settings take the inspection of the
  Cedar path declared as their own path, or else the one the relay would
  select for that path's text.
- `@protocol` selects `rest` (default), `json-rpc`, `mcp`, `graphql`,
  `websocket`, or `websocket-graphql`. Both WebSocket protocols produce a
  `websocket` endpoint config; `websocket-graphql` also sets
  `websocket_graphql_policy`, which a YAML endpoint derives from its GraphQL
  rules, so the relay classifies client messages as GraphQL over WebSocket.
  The relay evaluates the upgrade as a `GET` and each client message as a
  `WEBSOCKET_TEXT` request on the upgrade path, with the GraphQL fields for
  `websocket-graphql`. The
  supervisor fills the protocol's `HttpRequest` context fields from the
  relay's parsed request: one evaluation per JSON-RPC or MCP call (the relay
  splits batches), and one per GraphQL operation, denying the request if any
  is denied. Cedar MCP endpoints get the same default MCP revision as YAML
  unless an endpoint setting lists revisions.
  `sql` is rejected because the relay does not inspect SQL. The supervisor
  uppercases the request method, and denies JSON-RPC calls and response
  frames not sent with `POST` before evaluation, matching YAML.
- `HttpRequest`'s `context.query` is a per-request `Sandbox::HttpQuery`
  entity whose `String` tags hold the query parameters, decoded by the
  relay's request parser as for the Rego input. `CedarEngine::evaluate_l7`
  evaluates a request once per combination of its repeated values, and
  allows it only if no evaluation is denied and one `permit` (by policy id)
  is among the determining policies of every evaluation. That reproduces
  YAML query matchers: an allow rule matches every value of each key, and a
  deny rule fires on one matching value per key. Analysis collects the tag
  keys policies name literally; other keys are left out of the entity, so
  their values do not multiply evaluations, unless a policy computes a key.
  More than `MAX_QUERY_COMBINATIONS` (64) combinations is an error, which
  the supervisor turns into a denial with that reason. Audit endpoints and
  staged audit-only policies use the same combined decision.
- `CedarOnlyEngine` attaches a `CedarDestination` to each allowed
  connection's `EgressAuthorization`. It replaces the YAML destination modes
  below the host gateway aliases: every resolved address must avoid the
  always-blocked ranges, lie in the ranges of every allowing permit that has
  them, and pass a Cedar evaluation with `destination_ip` set; a private
  address also needs a permit that names the host exactly or only ranged
  permits. Control-plane ports are blocked unless only public-only permits
  allow the connection. These rules admit no address that YAML would reject
  whichever overlapping endpoint it consulted first. CONNECT and forward
  HTTP check every address; transparent TCP keeps the pinned policy DNS
  addresses that pass. For a host gateway alias, Cedar must also allow the
  pinned gateway address. Provider endpoints' `allowed_ips` only narrow:
  each matching provider endpoint's ranges must also admit every address,
  and block control-plane ports, but never count toward admitting a private
  address. They do not apply to a host gateway alias, as in YAML. Host-less
  provider endpoints match nothing.
- `CedarOnlyEngine` publishes the DNS records under the policy name `cedar`,
  indexed by position, with `protocol: tcp` on native TCP records. For an
  allowed connection, `EgressAuthorization::matched_endpoints` lists the
  records covering its host and port with the same indices, so the
  transparent TCP listener can correlate the decision with the policy DNS
  mapping the workload dialed, as it does for YAML.
- `openshell-supervisor-network`'s `cedar_parity_tests` run paired YAML and
  Cedar policies through both engines and fail when outcomes differ outside a
  recorded list of known differences. They compare per-request decisions,
  connection decisions, exactly declared hosts, the selected inspection,
  policy DNS eligibility, admitted token-grant owners, endpoint config
  settings, TLS mode, deny reasons, policy DNS records and the records a
  connection matched, staged transparent TCP opens, and whole relay exchanges
  and WebSocket sessions, and include ports of every existing YAML decision test that
  Cedar can express.
- `SandboxPolicy.endpoint_settings` holds endpoint configuration that is not
  access control: `tls: skip`, `allow_encoded_slash`, body limits, MCP
  revisions and `strict_tool_names`, and the GraphQL persisted-query
  registry. Each entry selects endpoints by host or host glob, ports, and an
  optional path, with the YAML endpoint field names; `openshell-policy`
  validates entries and rejects access and credential fields, and rejects the
  section on YAML policies. For a connection Cedar allows, the supervisor
  merges matching entries into the endpoint configs: a path-less entry into
  every config, and a path-scoped entry into a config for that path, added
  with Cedar's inspection so the relay's most-specific-path selection picks
  it. Protocol options apply only where Cedar selects that protocol, and
  `tls: skip` also applies to connections Cedar does not inspect. Before Cedar
  evaluates a hash-only GraphQL persisted query, the supervisor replaces it
  with its registry entry (hash first, then saved-query id) from the selected
  config, and denies it when it is unregistered or `persisted_queries` is not
  `allow_registered`, as the Rego rules do. The settings are part of the
  reload inputs, so changing them advances the policy generation.
- Both network actions have `binary_aliases: Set<String>`, the Cedar form of
  YAML's symlink expansion of binary paths. Analysis collects the literal
  paths policies test with `context.binary_aliases.contains`, `containsAny`,
  or `containsAll` (`CedarEngine::binary_alias_paths`), and rejects any other
  use of the set or of the whole `context` record, and paths that are not
  absolute or contain `*`. `CedarOnlyEngine` resolves each path with the
  YAML resolver through `/proc/<pid>/root` when the entrypoint process is
  known (`resolve_binary_symlinks`), and again on every reload (`stage` with
  the pid), as a YAML reload resolves its binary paths again. A
  request's aliases are the paths whose resolved target equals its binary or
  an ancestor, or glob-matches one when the target contains `*`, exactly as
  the Rego rules match the entry YAML adds for the target. So a binary
  condition `binary_path == B || ancestors.contains(B) ||
  binary_aliases.contains(B)` matches where the YAML binary `B` matches, in a
  `permit` or a `forbid`. Provider rule binaries used to select token-grant
  owners are resolved the same way.
- `@enforcement("audit")` marks an `HttpRequest`-only policy as audit-only.
  Enforcement is computed per inspected path. A path whose policies are all
  audit-only gets `enforcement: audit` in its L7 config, so the relay logs and forwards denials as it does for YAML. On an
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
