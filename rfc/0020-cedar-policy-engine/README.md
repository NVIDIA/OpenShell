---
authors:
  - "@vishwa-raman"
state: review
links:
  - https://github.com/NVIDIA/OpenShell/issues/4411
  - https://github.com/NVIDIA/OpenShell/issues/4474
  - https://github.com/NVIDIA/OpenShell/issues/4610
  - https://github.com/NVIDIA/OpenShell/pull/4564
---

# RFC 0020 - Cedar as an Alternate Sandbox Policy Language

## Summary

A sandbox policy can be written in [Cedar](https://www.cedarpolicy.com/)
instead of YAML. You choose the format once per sandbox: a `.cedar` file
makes it a Cedar sandbox; anything else stays YAML, unchanged and still
evaluated by Rego. A Cedar sandbox is decided by Cedar alone: which outbound
connections a process may open, which requests it may make on an inspected
connection, and which filesystem paths it may read or write. OpenShell
accepts only Cedar policies it can enforce exactly as written and rejects the
rest when they are submitted. Settings that configure inspection rather than
grant access, such as middleware and MCP revisions, move into a separate
`--middleware` file.

The reason is expressiveness that stays analyzable: authors can write
conditions the YAML structure never anticipated, and every policy remains
open to the kind of decidable analysis the policy prover gives YAML today
(see [Motivation](#motivation)). An implementation exists (see
[Implementation plan](#implementation-plan)).

## Motivation

A sandbox policy today is a YAML document with a fixed structure: filesystem
paths, process identity, and network rules that pair binaries with endpoints
and attach request rules to each endpoint. The Rego evaluator
(`sandbox-policy.rego`) gives that structure its meaning, and the
[policy prover](https://github.com/NVIDIA/OpenShell/blob/main/docs/how-it-works/policies/prover.mdx)
gives it analysis: an SMT encoding of the YAML model that answers "does this
candidate stay within this boundary" and "does this proposal add only safe
access", with a counterexample request when either answer is no. That capability is
real, it gates auto-approval of agent-authored proposals, and it stays.

The limit is the structure itself. Every policy has to be one of the shapes
the schema anticipates. Policies that depend on conditions outside those
shapes cannot be written at all: authorization conditions that combine
attributes of the caller, the resource, and the request in ways no single
field encodes, or temporal conditions such as access that is valid only after
an approval or only within a window. Each time such a need appears, the only
way to meet it inside YAML is a new field, new Rego to evaluate it, and a new
prover model to analyze it, and the three have to be kept in agreement by
hand. The prover today models filesystem, process, Landlock, L4 connections,
and REST rules, and reports `unsupported` for GraphQL, MCP, JSON-RPC,
WebSocket, query parameters, and audit endpoints: the model trails the
evaluator feature by feature.

The direct way to add expressiveness is to let authors write Rego. That gives
arbitrary conditions at the cost of analysis. Rego is a general-purpose
language, OpenShell cannot control what authors write, and there is no
decidable procedure that answers inclusion or reachability questions about an
arbitrary Rego program. The prover's guarantees would end where user-written
Rego begins.

Cedar sits between the two. A Cedar policy is a condition over a principal,
an action, a resource, and a request context, validated against a schema, so
authors can express conditions the YAML structure never anticipated. The
language is decidable by construction: no loops, recursion, or user-defined
functions; every evaluation terminates; and its symbolic compiler reduces any
policy set to SMT with an encoding proved sound and complete in Lean.
Analysis therefore applies to whatever an author writes, not only to the
shapes a hand-built model covers, and it applies to the policy that is
enforced, because the compiler and the evaluator share one specified
semantics. That is also why a Cedar sandbox enforces the Cedar text itself:
a policy derived from YAML by translation would move the question to the
translator.

Cedar is also the base for temporal policies.
[Dogwood](https://github.com/dogwood-policy/dogwood) extends Cedar with
`when temporal { ... }` conditions over the history of events the authorizer
has seen ("permit this call only if the same principal was approved within
the last hour", "deny after a logout until the next login") and with
information providers, values computed on demand that a condition may
consult. It lowers to Cedar and evaluates with the Cedar engine. Adopting
Cedar as a sandbox policy language is the step that makes those policies
reachable later without another change of language.

This RFC does not restate Cedar; see:

- The language guide and reference: [docs.cedarpolicy.com](https://docs.cedarpolicy.com/),
  in particular [policy syntax](https://docs.cedarpolicy.com/policies/syntax-policy.html)
  and [operators](https://docs.cedarpolicy.com/policies/syntax-operators.html),
  which covers `like`, `in`, `contains`, `containsAll`, and `containsAny`.
- The design paper, "Cedar: A New Language for Expressive, Fast, Safe, and
  Analyzable Authorization" ([doi:10.1145/3649835](https://doi.org/10.1145/3649835)).
- The implementation, [cedar-policy/cedar](https://github.com/cedar-policy/cedar),
  and its Lean model, [cedar-policy/cedar-spec](https://github.com/cedar-policy/cedar-spec).

## Non-goals

- Changing the YAML path. It remains the default and behaves as before.
- Translating YAML to Cedar automatically, or running both engines on one
  sandbox.
- Letting providers grant access on Cedar sandboxes. They supply credentials
  only; this can be revisited.
- SQL policy. OpenShell does not inspect SQL traffic for either format.
- Syscall policy. Seccomp filtering is a fixed runtime control for both
  formats, not authored policy.
- Changes to upstream Cedar. The language features OpenShell needs are
  developed with the Cedar team in `ai-openshell/cedar`, OpenShell's Cedar in
  its CNCF workspace, and proposed upstream separately.
- Temporal or history-dependent policies. This RFC adopts Cedar; a
  Dogwood-based proposal for temporal policies would build on it later.
- Changing the policy prover's YAML model. Extending analysis to Cedar
  sandboxes is tracked under Open questions.

## Proposal

### What changes for a policy author

| | YAML today | Cedar |
|---|---|---|
| Policy file | `.yaml`, `.yml`, or any other extension | `.cedar` (any case) |
| Create | `openshell sandbox create --policy p.yaml` | `openshell sandbox create --policy p.cedar [--middleware m.yaml]` |
| Replace on a live sandbox | `openshell policy set` | `openshell policy set` with the whole policy |
| Incremental edits | `openshell policy update`, policy advisor proposals | Not available; replace the whole policy |
| Middleware | `network_middlewares:` in the policy | `network_middlewares:` in the `--middleware` file |
| Inspection settings (`tls: skip`, MCP revisions, body limits, persisted queries) | Fields on the endpoint | `endpoint_settings:` in the `--middleware` file |
| `process:` section | Set in the policy | `process:` in the `--middleware` file, same schema and validation |
| `landlock:` section | Set in the policy | No Cedar form; defaults apply |
| Attached providers | Grant access to their endpoints and supply credentials | Supply credentials only; your policy must allow the endpoints |
| Gateway-wide configuration applied to every sandbox (`openshell policy set --global`), policy templates | Supported | YAML only |
| Format of a sandbox | — | Fixed for its lifetime; recreate to switch |
| Gateway and runtime versions | Any | Both must support Cedar; the CLI and SDKs refuse to send a Cedar policy to a gateway that does not advertise it, and the gateway withholds a Cedar policy from a runtime that cannot interpret it |
| View the policy | `openshell policy get` | `openshell policy get` prints the Cedar text, then middleware and endpoint settings; `--full` adds provider credential rules |

Validation happens three times with the same checks: in the CLI before the
file is sent, at the gateway, and in the supervisor. A policy OpenShell cannot
enforce exactly is rejected with the reason, never loaded with part of its
meaning dropped. Rejected revisions on a live sandbox follow the gateway's
`policy_validation_failure_mode`, as for YAML.

### How a YAML policy maps to Cedar

A YAML `network_policies` rule bundles three decisions into one object: the
binaries that may connect, the endpoints they may connect to, and the request
rules applied once a connection is inspected. Cedar separates them into
statements on three actions, all in the `Sandbox` namespace with a
`Sandbox::Process` principal:

| YAML | Cedar action | Resource | Decided |
|---|---|---|---|
| `filesystem_policy.read_only` | `ReadFile` | `Sandbox::FilesystemPath` | Once, at sandbox start, as Landlock grants |
| `filesystem_policy.read_write` | `ReadFile` and `WriteFile` | `Sandbox::FilesystemPath` | Once, at sandbox start |
| `binaries` × `endpoints` (`host`, `port`, `allowed_ips`, `protocol: tcp`) | `NetworkConnect` | `Sandbox::NetworkEndpoint::"host:port"` | Per connection, before any request is read |
| `rules`, `deny_rules`, `access`, `protocol`, `enforcement`, `path` | `HttpRequest` | `Sandbox::NetworkEndpoint::"host:port"` | Per request on an inspected connection |

The YAML endpoint fields that select *how* a request is parsed become
annotations on `HttpRequest` policies rather than conditions: `@protocol`
(`rest`, `json-rpc`, `mcp`, `graphql`, `websocket`, `websocket-graphql`),
`@path` (a per-path protocol and enforcement for one host and port),
`@enforcement("audit")`, and, on `NetworkConnect`, `@transport("tcp")`. Field
by field:

| YAML | Cedar |
|---|---|
| `host: api.github.com`, `port: 443` | `resource == Sandbox::NetworkEndpoint::"api.github.com:443"` |
| `host: "*.example.com"` | `resource is Sandbox::NetworkEndpoint` with `resource.host like("*.example.com", ".") && resource.port == 443` |
| `binaries: [{path: /usr/bin/curl}]` | `context.binary_path == "/usr/bin/curl" \|\| context.ancestors.contains("/usr/bin/curl") \|\| context.binary_aliases.contains("/usr/bin/curl")` |
| `binaries: [{path: "/usr/lib/node_modules/@openai/**"}]` | `context.binary_globs.contains("/usr/lib/node_modules/@openai/**")` (the globs that match the calling binary or an ancestor, computed per request) |
| `allowed_ips: [10.0.0.0/8]` | `context has destination_ip && context.destination_ip.isInRange(ip("10.0.0.0/8"))` |
| `protocol: tcp` | `@transport("tcp")` on the `NetworkConnect` permit |
| `access: read-only` | `["GET", "HEAD", "OPTIONS"].contains(context.method)` on `HttpRequest` |
| `rules: [{allow: {method: GET, path: /repos/**}}]` | `permit` on `HttpRequest` with `context.method == "GET" && context.path like("/repos/**", "/")` |
| `deny_rules: [{method: "*", path: "/repos/*/*/rulesets"}]` | `forbid` on `HttpRequest` with `context.path like("/repos/*/*/rulesets", "/")` |
| `query: {platform: {any: ["linux-*"]}}` | `context.query.hasTag("platform") && context.query.getTag("platform") like("linux-*", ".")` |
| `protocol: mcp`, `tool: {any: [search_web]}` | `@protocol("mcp")`, `context.jsonrpc_method == "tools/call" && context.mcp_tool == "search_web"` |
| `protocol: graphql`, `operation_type: mutation`, `fields: [createIssue]` | `@protocol("graphql")`, `context.graphql_operation_type == "mutation" && ["createIssue"].containsAll(context.graphql_fields)` |
| `enforcement: audit` (or no `enforcement`, which YAML defaults to audit) | `@enforcement("audit")` on each `HttpRequest` policy for the endpoint |
| `protocol: rest`, `enforcement: enforce` | The defaults; naming the endpoint in any `HttpRequest` policy makes it inspected |
| `include_workdir: true` | No form; list the workdir (for example `/sandbox`) explicitly |
| `process:` | `process:` in the `--middleware` file |
| `version: 1`, `landlock:` | No form |

Two rules of thumb carry most translations:

1. **Every endpoint needs a `NetworkConnect` permit, and every endpoint you
   want inspected needs at least one `HttpRequest` policy that names it, exactly
   or with a host glob.** A
   `NetworkConnect` permit on its own gives an uninspected connection, like a
   YAML endpoint with no `rules` and no `access`.
2. **Cedar denies by default and `forbid` always wins.** A YAML allow rule
   becomes a `permit`; a YAML deny rule becomes a `forbid`. Each YAML allow
   rule should be its own `permit`, because two rules joined with `||` in one
   permit can together allow a request neither allows alone (this matters for
   repeated query parameters).

Globs use Cedar's delimited `like`: `expr like("pattern", "delimiter")`. With
a delimiter, `*` matches within one segment and `**` across segments, the
same rules as YAML. Use `"."` for hosts, `"/"` for paths, and `"."` for query
values and MCP tool names. Without a delimiter, Cedar's own `like` lets `*`
cross segments, so `context.path like "/repos/*"` would also match
`/repos/a/b/c`.

### Tutorial: translating a YAML policy

This walks through the quickstart policy, which lets `curl` read the GitHub
REST API, then adds the rule forms the other examples in the repository use.
Each example and e2e directory with a YAML policy has a Cedar version beside
it, and its scripts accept `POLICY_FORMAT=cedar`.

#### Step 1: filesystem

```yaml
filesystem_policy:
  include_workdir: true
  read_only: [/bin, /usr, /lib, /proc, /dev/urandom, /app, /etc, /var/log]
  read_write: [/sandbox, /tmp, /dev/null]
landlock:
  compatibility: best_effort
```

```cedar
@id("filesystem/read_write")
permit (
    principal is Sandbox::Process,
    action in [Sandbox::Action::"ReadFile", Sandbox::Action::"WriteFile"],
    resource is Sandbox::FilesystemPath
)
when {
    resource in Sandbox::FilesystemPath::"/sandbox"
    || resource in Sandbox::FilesystemPath::"/tmp"
    || resource in Sandbox::FilesystemPath::"/dev/null"
};

@id("filesystem/read_only")
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"ReadFile",
    resource is Sandbox::FilesystemPath
)
when {
    resource in Sandbox::FilesystemPath::"/bin"
    || resource in Sandbox::FilesystemPath::"/usr"
    || resource in Sandbox::FilesystemPath::"/lib"
    || resource in Sandbox::FilesystemPath::"/proc"
    || resource in Sandbox::FilesystemPath::"/dev/urandom"
    || resource in Sandbox::FilesystemPath::"/app"
    || resource in Sandbox::FilesystemPath::"/etc"
    || resource in Sandbox::FilesystemPath::"/var/log"
};
```

`principal is Sandbox::Process` can be shortened to `principal`: a sandbox
has one principal type, so the line is the same on every policy. `resource in`
grants the subtree, as Landlock does; `resource ==` is rejected. There is no `include_workdir`, so the workdir is listed. `landlock`
has no Cedar form and uses its default. As in YAML, the supervisor adds its
baseline runtime paths when the policy can permit a network connection, and a
live update can add paths but not remove them. File policies must be plain
subtree permits: a file `forbid`, a condition other than `||`-joined
`resource in` tests, or a principal constraint is rejected, because Landlock
cannot express it, and a permit that lists only `WriteFile` is rejected, since
a Landlock write grant includes read; list both actions.

#### Step 2: the connection

```yaml
network_policies:
  github_api:
    name: github-api-readonly
    endpoints:
      - host: api.github.com
        port: 443
    binaries:
      - { path: /usr/bin/curl }
```

```cedar
@id("github_api/connect")
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"NetworkConnect",
    resource == Sandbox::NetworkEndpoint::"api.github.com:443"
)
when {
    context.binary_path == "/usr/bin/curl"
    || context.ancestors.contains("/usr/bin/curl")
    || context.binary_aliases.contains("/usr/bin/curl")
};
```

`@id` is an optional label. Logs, deny reasons, and the parity harness name a
policy by its `@id` when it has one, and by Cedar's positional id
(`policy0`, `policy1`, ...) otherwise. The `rule/purpose` form used here,
`github_api/connect`, is a convention that records which YAML rule a
statement came from; it is not syntax.

A YAML binary path matches the binary itself, any ancestor process, and a
symlink to it, so the Cedar condition tests all three. `context.binary_path`
is the kernel-resolved executable (`/usr/bin/python3.12`, not
`/usr/bin/python3`); `context.binary_aliases` holds the literal paths your
policies name that resolve to the calling binary or an ancestor, filled in
once the entrypoint process is known and again on each reload. A YAML binary
glob is matched against the binary and its ancestors by the supervisor, not by
Cedar: `context.binary_globs` holds the glob patterns your policies name that
match the calling binary or an ancestor, so
`context.binary_globs.contains("/usr/lib/node_modules/@openai/**")` means what
the YAML glob means while Cedar still sees literal set membership.

Naming the endpoint in the scope also makes `api.github.com` resolvable
through policy DNS, as listing it in YAML does. A host that only appears in a
`when` condition is eligible when the condition requires both `resource.host`
(exact or delimited glob) and `resource.port`, or names the endpoint with
`resource.host_port == "host:port"`; any other form fails closed.

#### Step 3: per-request rules

```yaml
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-only
```

```cedar
@id("github_api/read-only")
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"HttpRequest",
    resource == Sandbox::NetworkEndpoint::"api.github.com:443"
)
when {
    (context.binary_path == "/usr/bin/curl"
     || context.ancestors.contains("/usr/bin/curl")
     || context.binary_aliases.contains("/usr/bin/curl"))
    && ["GET", "HEAD", "OPTIONS"].contains(context.method)
};
```

The one YAML rule has become two permits because it makes two decisions at
two different moments: Step 2 decides the connection before any request is
read, and this step decides each request inside it. They cannot share one
permit with `action in [NetworkConnect, HttpRequest]`, because the method
condition would also run at connect time, where `method` is always empty,
and the connection would never be allowed.

`protocol: rest` and `enforcement: enforce` are the defaults, so no
annotation is needed. The `read-only` preset is spelled out: Cedar has no
presets, and a `GET` condition does not also allow `HEAD` as it does in YAML.
`context.method` is always uppercase. The binary condition is repeated
because YAML applies the rule's binaries to its request rules too.

Adding this policy is what makes the proxy inspect connections to
`api.github.com:443`. Without it, Step 2 alone would relay them without
per-request checks.

#### Wildcard hosts

```yaml
endpoints:
  - host: "*.example.com"
    port: 443
```

```cedar
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"NetworkConnect",
    resource is Sandbox::NetworkEndpoint
)
when {
    resource.host like("*.example.com", ".")
    && resource.port == 443
    && context.binary_path == "/usr/bin/curl"
};
```

The host moves from the scope into the condition because a scope literal
names one entity and Cedar compares entity ids literally; a `*` in a scope
literal is rejected. The glob follows the YAML wildcard host rules, so policy
DNS resolves the same hosts. Request rules work on wildcard hosts too: an
`HttpRequest` policy with the same `resource.host like(...) && resource.port
== 443` conditions inspects every matching host, as a YAML wildcard endpoint
with rules does. Exact and glob entries that select one host combine their
paths, and conflicting inspection on an equally specific path is rejected at
load, as YAML rejects overlapping endpoints. A host selector, exact or glob,
is limited to 253 bytes, the length of a DNS name; a longer one is rejected
at load.

#### Path rules and deny rules

```yaml
rules:
  - allow:
      method: GET
      path: /repos/**
  - allow:
      method: GET
      path: /api/v1/download
      query:
        platform:
          any: ["linux-*", "darwin-*"]
deny_rules:
  - method: "*"
    path: "/repos/*/*/rulesets"
```

```cedar
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"HttpRequest",
    resource == Sandbox::NetworkEndpoint::"api.github.com:443"
)
when { context.method == "GET" && context.path like("/repos/**", "/") };

permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"HttpRequest",
    resource == Sandbox::NetworkEndpoint::"api.github.com:443"
)
when {
    context.method == "GET" && context.path == "/api/v1/download"
    && context.query.hasTag("platform")
    && (context.query.getTag("platform") like("linux-*", ".")
        || context.query.getTag("platform") like("darwin-*", "."))
};

forbid (
    principal is Sandbox::Process,
    action == Sandbox::Action::"HttpRequest",
    resource == Sandbox::NetworkEndpoint::"api.github.com:443"
)
when { context.path like("/repos/*/*/rulesets", "/") };
```

`context.query` holds the decoded query parameters as tags; test presence with
`hasTag` before `getTag`. When a key repeats (`?tag=a&tag=b`), OpenShell
evaluates the request once per combination of values and allows it only if no
evaluation is denied and one `permit` allows every evaluation, which is what
YAML's allow and deny matchers do. More than 4,096 combinations of the values
of the keys that deciding policies read is denied; keys that only staged
policies read do not count (see [Audit mode](#audit-mode)).

#### MCP

```yaml
endpoints:
  - host: mcp.example.com
    port: 443
    protocol: mcp
    enforcement: enforce
    mcp:
      versions: ["2025-11-25"]
      allow_all_known_mcp_methods: true
    rules:
      - allow:
          tool:
            any: [search_web, read_document]
```

```cedar
@protocol("mcp")
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"HttpRequest",
    resource == Sandbox::NetworkEndpoint::"mcp.example.com:443"
)
when {
    context.mcp_method_class == "available"
    && !context.jsonrpc_response
    && (context.jsonrpc_method != "tools/call"
        || ["search_web", "read_document"].contains(context.mcp_tool))
};

@protocol("mcp")
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"HttpRequest",
    resource == Sandbox::NetworkEndpoint::"mcp.example.com:443"
)
when {
    (context.method == "GET" && context.jsonrpc_receive_stream)
    || context.jsonrpc_response
};
```

```yaml
# middleware.yaml, passed with --middleware
endpoint_settings:
  - host: mcp.example.com
    port: 443
    mcp:
      versions: ["2025-11-25"]
```

Each JSON-RPC call is evaluated on its own (batches are split), with
`jsonrpc_method`, `mcp_tool`, and `mcp_method_class` (`available` for a core
method of the selected revision, `extension` otherwise). Two things YAML does
implicitly are explicit here: the server-to-client receive stream and client
response frames need their own permit, and the accepted MCP revisions are an
endpoint setting rather than part of the policy. Calls not sent with `POST`
are denied before evaluation, as in YAML. A Cedar MCP endpoint reports
endpoint status (`openshell sandbox get`) as a YAML one does, under the
identity of its configured selector: the host or host glob, port, and path of
the `@protocol("mcp")` policy, or of the provider or `endpoint_settings` entry
that selects it, never the host a request happened to use.

#### GraphQL

```yaml
endpoints:
  - host: api.github.com
    port: 443
    path: /graphql
    protocol: graphql
    rules:
      - allow:
          operation_type: query
      - allow:
          operation_type: mutation
          fields: [createIssue]
    deny_rules:
      - operation_type: mutation
        fields: [deleteRepository]
```

```cedar
@path("/graphql")
@protocol("graphql")
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"HttpRequest",
    resource == Sandbox::NetworkEndpoint::"api.github.com:443"
)
when {
    context.path == "/graphql"
    && (context.graphql_operation_type == "query"
        || (context.graphql_operation_type == "mutation"
            && context.graphql_fields.containsAny(["createIssue"])
            && ["createIssue"].containsAll(context.graphql_fields)))
};

@path("/graphql")
@protocol("graphql")
forbid (
    principal is Sandbox::Process,
    action == Sandbox::Action::"HttpRequest",
    resource == Sandbox::NetworkEndpoint::"api.github.com:443"
)
when {
    context.path == "/graphql"
    && context.graphql_operation_type == "mutation"
    && context.graphql_fields.contains("deleteRepository")
};
```

A YAML allow rule requires every top-level field to match, so the permit uses
`containsAll` over the request's fields (and `containsAny` to reject an empty
set); a deny rule fires on one matching field, so the forbid uses `contains`.
Each operation in a request is evaluated separately and one denial denies the
request. Field globs (`fields: ["create*"]`) have no Cedar form; exact names
do.

The path appears twice on purpose. `@path("/graphql")` is metadata for the
relay: it gives that path its own protocol, as a YAML endpoint with `path`
does for one host and port, and it does not limit which policies apply. Every
policy for the endpoint is evaluated for every request on it, so the
condition repeats the path to scope the permit, as a YAML rule is scoped by
its endpoint's `path`. A GraphQL path is
authoritative for the requests it parses, as a YAML GraphQL endpoint is: a
permit of another path that neither reads a GraphQL field nor tests
`resource.protocol` does not allow operations parsed on this path.

#### Native TCP and address ranges

```yaml
network_policies:
  redis:
    endpoints:
      - host: redis.openshell.demo
        port: 6379
        protocol: tcp
        allowed_ips: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]
    binaries:
      - { path: "/**" }
```

```cedar
@id("redis/connect")
@transport("tcp")
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"NetworkConnect",
    resource == Sandbox::NetworkEndpoint::"redis.openshell.demo:6379"
)
when {
    context.binary_path like("/**", "/")
    && context has destination_ip
    && (context.destination_ip.isInRange(ip("10.0.0.0/8"))
        || context.destination_ip.isInRange(ip("172.16.0.0/12"))
        || context.destination_ip.isInRange(ip("192.168.0.0/16")))
};
```

`@transport("tcp")` is `protocol: tcp`: plain L4 traffic through policy DNS,
never inspected. A host and port must be native TCP for every policy or for
none, so beside a native TCP permit, a `NetworkConnect` permit whose host
cannot be derived (a port-only condition, an undelimited glob, a TLD glob)
is rejected, since it could cover the same endpoint. `context.destination_ip` is `allowed_ips`. It is optional
because it is absent until the host resolves, which is why the condition
tests `context has destination_ip` first. A connection is decided before the
host resolves, with the address condition assumed to hold, and again for each
resolved address, all of which must pass. Write the
address condition as top-level `when` conjuncts (`context has destination_ip`
and an `||` of `isInRange` tests) so OpenShell can read the ranges exactly;
other forms are rejected. A `forbid` may read the address in any form: it is
evaluated before resolution with the address absent, so its other conditions
still apply, and again for each resolved address. Loopback, link-local, and unspecified addresses
stay blocked regardless of policy, and a host matched by a glob may not
resolve to a private address unless a permit names it exactly or restricts
its addresses, as in YAML.

#### Audit mode

```yaml
endpoints:
  - host: httpbin.org
    port: 443
    protocol: rest
    rules:
      - allow: { method: POST, path: /anything }
```

```cedar
@enforcement("audit")
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"HttpRequest",
    resource == Sandbox::NetworkEndpoint::"httpbin.org:443"
)
when { context.method == "POST" && context.path == "/anything" };
```

A YAML endpoint with no `enforcement` is in audit mode: denied requests are
logged and forwarded. Cedar's default is enforce, so each `HttpRequest`
policy for such an endpoint carries `@enforcement("audit")`. An audit policy
has YAML's audit-endpoint semantics: it decides requests on every path of its
endpoint, and a path whose deciding policies are all audit runs in audit mode,
where the routed path's mode decides whether a denial blocks even when the
denying policy is an enforced one on another path. Because one audit policy
with a new `@path` is enough to put that path in audit mode, the CLI and the
supervisor warn when an audit-only path sits beside enforced policies on the
same host and port.

A *staged* policy is different: `@enforcement("staged")` marks a policy that
never takes part in a decision and never changes a path's mode. OpenShell
compares the decision with and without it and logs each request whose
decision it would change, so a new `forbid` can be observed before it is
enforced. The comparison cannot alter the enforced decision: the query keys a
staged policy reads do not count toward the 4,096-combination limit of the
deciding policies, the comparison has its own budget, and an evaluation error
or an exceeded budget in the comparison skips it and keeps the enforced
result (the same error in a deciding policy still fails the request closed):

```cedar
@enforcement("staged")
@id("no-webhook-changes")
forbid (
    principal is Sandbox::Process,
    action == Sandbox::Action::"HttpRequest",
    resource == Sandbox::NetworkEndpoint::"api.github.com:443"
)
when { context.path like("/repos/*/*/hooks/**", "/") };
```

#### Middleware

```yaml
# policy.yaml
network_middlewares:
  regex-redactor:
    name: Redact API tokens
    middleware: openshell/regex
    order: 10
    config: { mode: redact }
    on_error: fail_closed
    endpoints:
      include: ["api.github.com"]
```

The section moves unchanged into the `--middleware` file:

```shell
openshell sandbox create --policy ./policy.cedar --middleware ./middleware.yaml -- claude
openshell policy set <name> --policy ./policy.cedar --middleware ./middleware.yaml --wait
```

The same file carries `endpoint_settings`: `tls: skip`,
`allow_encoded_slash`, JSON-RPC and MCP body limits, `mcp.versions` and
`mcp.strict_tool_names`, and the GraphQL persisted-query registry. Each entry
selects endpoints with the YAML fields (`host`, `port` or `ports`, optional
`path`) and may set only configuration fields; access fields (`rules`,
`access`, `protocol`, `allowed_ips`, `binaries`, ...) and credential fields
are rejected. Settings apply only on connections the Cedar policy allows.

#### Providers

Attached providers still inject credentials and token grants, but on a Cedar
sandbox they grant no access. Write a `NetworkConnect` permit and an
`HttpRequest` policy for each credentialed endpoint; a credentialed endpoint
that is not inspected is refused, as in YAML. A provider's `allowed_ips` only
narrow the addresses its connections may reach. A token grant applies to a
request only when your policy allows it and the provider's own rules admit
it, which OpenShell checks by compiling the provider rules to Cedar; provider
rules can withhold a token, never grant a request.

### What does not carry over

Each of these is reported when the policy is submitted or denied at request
time, never silently relaxed:

- GraphQL field globs. Exact names work (binary globs over ancestors are
  covered by `context.binary_globs`).
- `**` touching other characters in a glob, which YAML reads as `*`; write
  `*`, or `**` as a whole segment.
- `GET` implying `HEAD`; list `HEAD`.
- Implicit MCP receive streams and response frames; permit them.
- A generic `WEBSOCKET_TEXT` permit on a GraphQL-over-WebSocket path; YAML
  rejects the rule and Cedar rejects the permit.
- Conditional or `forbid` filesystem rules; Landlock is a flat allow-list.
- The `landlock:` section; defaults apply.
- `openshell policy update`, policy templates, policy advisor proposals, and
  the gateway-wide configuration set with `openshell policy set --global`.
- `protocol: sql`; neither format inspects SQL.

### Parity with YAML

The parity harness in `openshell-supervisor-network` pairs each YAML test
policy with a Cedar policy written to mean the same thing and runs both
through their engines with the calls the proxy makes, comparing decisions,
selected inspection, policy DNS eligibility and records, admitted token-grant
owners, endpoint settings, address admission, and whole relay exchanges.

Of the unit tests in that crate, 260 test a YAML policy decision. 258
have a Cedar equivalent in the harness. The remaining two need a Cedar
language change (a binary glob matched against ancestors) or test data the
YAML loader rejects. On Linux the harness runs 2,911 cases, counting the
rows generated per example and per glob pattern: 2,906 agree, and 5 are
recorded differences that the harness fails on if the engines start to
agree (the harness prints this tally, so the numbers are reproducible). An
evaluation error on either side fails a case unless the case allows it, and
where Cedar now rejects a policy shape at load the harness asserts the
rejection. Porting found two places Cedar was more permissive than YAML and
one where it was stricter; all three are fixed and covered.

The five recorded differences are deliberate, and Cedar is the stricter side
in each: `HEAD` under a `GET` rule (list `HEAD`); MCP revisions carried in the
settings file rather than the policy; more than 4,096 query value
combinations; and two private-address cases that YAML admits through
first-matching-endpoint order or through provider rules granting access,
which the design rejects. Everything a literal translation used to allow
beyond YAML is now either expressed exactly (`context.binary_globs`,
wildcard-host inspection, audit semantics, GraphQL path authority) or
rejected at load (`**` touching other characters, a generic message permit on
a GraphQL-over-WebSocket path).

### Why two network actions, and only two

YAML's one `endpoints` list hides two decisions the proxy makes at two
moments, and Cedar names them. `NetworkConnect` is decided when a process
opens a connection, when only the destination, the calling binary and its
ancestors, and, after DNS, the resolved address are known. `HttpRequest` is
decided per message inside a connection the proxy has allowed and chosen to
inspect, once a method, path, or body exists. One action for both would
either decide the connection on request fields that cannot be filled yet or
re-decide the connection on every request. (In the Rust crate, `NetworkRequest`
and `L7Request` are the inputs to these two actions; the first is not a
broader form of the second.)

`HttpRequest` is one action rather than one per protocol because everything
the relay inspects arrives over HTTP: REST calls, JSON-RPC and MCP calls in
`POST` bodies, and GraphQL operations in bodies, query strings, or WebSocket
frames. Its context is the union of the protocols' fields, with the ones that
do not apply left empty, so an author writes one kind of request rule, one
`forbid` on an endpoint covers every protocol on it, and a new protocol adds
context fields and an `@protocol` value rather than a new action. `@protocol`
tells the relay how to parse; `resource.protocol` lets a policy pin itself to
one parsing when an endpoint has several paths, and a GraphQL path is
authoritative for the requests it parses, as in YAML.

### Architectural decisions

These are the choices that shaped the implementation and the reasons for
them.

**Cedar is the enforced policy, not a model of one.** There is no
translation from YAML and no second engine checking Cedar's answers, so the
policy the analysis tools read is the policy that runs.
`SandboxPolicy.cedar_policy_source` carries the text, and a non-empty value
is what makes a sandbox a Cedar sandbox.

**One engine per sandbox, chosen once.** In the supervisor, every network
decision point (CONNECT, forward proxy, transparent connections, policy DNS,
the credential guard, relay setup, middleware selection) receives a
`PolicyEngine` that is either `Opa` or `Cedar`. A Cedar sandbox never
constructs an OPA engine and evaluates no Rego. This keeps the decision path
singular, makes "which engine decided" a fact the OCSF events can record, and
means a Rego change cannot affect a Cedar sandbox or the reverse. The data
both engines hand to the proxy (endpoint configs, policy DNS records,
middleware configs) is typed Rust; the Rego engine converts its output into
those types at one boundary, and nothing from the Rego library appears on the
Cedar path. A format switch on a live sandbox is rejected because the engine
is fixed at startup. Limits that belong to the sandbox rather than to an
engine, such as the WebSocket message-assembly budget, are shared by every
tunnel of either engine and survive reloads.

**Accept only what can be enforced exactly.** Cedar decides `NetworkConnect`
and `HttpRequest` at request time, but Landlock grants, which endpoints the
proxy inspects and how, policy DNS eligibility, and address ranges are
applied by other components that read the policy once. `CedarEngine` derives
those artifacts by analyzing the policy text at load, and rejects any policy
whose meaning the artifacts could not reproduce: a conditional file permit, a
`destination_ip` test in a form whose ranges cannot be read, an `HttpRequest`
policy with no endpoint in its scope. The alternative, loading the policy and
enforcing an approximation, would make the analyzed policy and the enforced
behavior differ, which is the problem this RFC exists to remove. The analysis
itself is bounded by its input: host selectors are limited to a DNS name's
length, literal hosts are compared directly, and host-glob overlap is checked
in space linear in the pattern length, so the largest policy the gateway
accepts cannot exhaust its memory at validation.

**Policy and configuration are separate files.** Middleware and endpoint
settings do not grant or deny anything; they configure how allowed traffic is
handled. Keeping them out of the `.cedar` file keeps the Cedar text pure
access control, which is what the analysis tools reason about, and lets the
same `network_middlewares` format serve both policy languages. The cost is a
second file for sandboxes that need them. `endpoint_settings` reuses the YAML
`NetworkEndpoint` message, and its validation classifies every field of that
message explicitly, so a field added to `NetworkEndpoint` later fails the build
until it is classified rather than being accepted as a setting.

**Providers supply credentials, never access.** On YAML sandboxes the gateway
composes attached providers' rules into `network_policies`, so attaching a
provider opens its endpoints. Doing the same on a Cedar sandbox would make a
YAML rule set a co-decider, reintroducing a translated policy into the
decision path. Instead the gateway delivers provider rules in a separate,
gateway-managed field, Cedar alone decides access, and provider rules are
compiled to Cedar only to select token-grant owners, where they can withhold
a token but never admit a request Cedar denied.

**Inspection mode is metadata, so it is an annotation.** YAML's `protocol`,
`enforcement`, `path`, and `protocol: tcp` fields describe how the relay
should treat traffic, not whether to allow it. Cedar annotations
(`@protocol`, `@path`, `@enforcement`, `@transport`) carry that metadata
without adding conditions, so `permit`/`forbid` semantics stay exactly
Cedar's and the analysis tools see nothing they do not understand.

**Segment-aware globs are a Cedar language change, not a workaround.** YAML
hosts and paths use `*` within a segment and `**` across. OpenShell could have
matched globs itself and passed booleans into Cedar, but then those
conditions would be opaque to Cedar's analysis. Delimited `like` was instead
added to Cedar by the Cedar team, with parser, validator, evaluator,
symbolic-compiler, and Lean specification support, in `ai-openshell/cedar`,
  and is proposed upstream as cedar-policy/rfcs#115. OpenShell depends on its
  own Cedar by design, so this is not a schedule dependency on upstream.

**Additive storage.** The three new `SandboxPolicy` fields
(`cedar_policy_source`, `provider_credential_rules`, `endpoint_settings`) are
additive, so gateway storage, revision history, and policy hashing are
unchanged and stored YAML policies decode exactly as before.

**Cedar support is negotiated, never assumed.** Additive fields cut both
ways: a gateway without Cedar support would decode a Cedar policy as an empty
YAML policy, accept it, and let attached providers open their endpoints,
whatever the Cedar text forbids. Two flags close that gap, following the
`supports_stable_placeholder` precedent. `HealthResponse.supports_cedar_policy`
tells a client whether the gateway interprets Cedar; the CLI and the Rust,
Python, Go, and TypeScript SDKs check it and refuse to send a Cedar policy to
a gateway that does not advertise it, before any sandbox is created or policy
changed. `GetSandboxConfigRequest.supports_cedar_policy` tells the gateway
whether the sandbox runtime fetching a configuration interprets Cedar; a
Cedar policy requested without it is answered with `Unimplemented` rather
than an empty policy, so an older runtime cannot start a Cedar sandbox open.

**Decisions before and after DNS.** A connection is authorized before the
destination resolves, so address conditions are evaluated twice: once with
`destination_ip` absent, treating address conjuncts as satisfied, and again
per resolved address against the full policy. Policy DNS filters answers the
same way, so a workload never learns an address the policy would reject.

**Reloads commit atomically or not at all.** On reload the supervisor stages
the Cedar policy and validates it with the checks YAML gets, including
middleware and endpoint settings. Only then does it advance the middleware
generation, activate the policy (closing inspected tunnels pinned to the old
generation), install provider credentials, and publish the middleware. A
rejected revision leaves all four on the previous revision, and a change to
middleware alone keeps Cedar's generation so it does not close tunnels.

## Implementation plan

The proposal is implemented on `vishwa/cedar-openshell`, under review as
[pull request #4565](https://github.com/NVIDIA/OpenShell/pull/4565). It
contains the schema and engine crates (`openshell-policy-cedar-schema`,
`openshell-policy-cedar`), the proto fields and capability flags, CLI,
gateway, and supervisor integration, the `PolicyEngine` enum, the middleware
file with `endpoint_settings`, credentials-only providers with token-grant
admission, the `cedar` feature flag on `openshell-policy`, Cedar fields and
capability checks in the Rust, Python, Go, and TypeScript SDKs, the parity
harness, the `e2e/cedar` suite and its CI matrix entry, Cedar versions of
every example and e2e policy, the Cedar policies documentation page, the
crate README, and the public `openshell-cli` and `generate-sandbox-policy`
skills.

A panel review of the pull request found six defects and one documentation
gap, each since fixed with a regression test: host-glob overlap analysis
that could allocate memory quadratic in selector length; no capability
negotiation, so an older gateway read a Cedar policy as empty YAML; a
`resource.protocol` check that also matched other `resource` attributes and
let a REST permit decide GraphQL requests; a per-tunnel rather than
sandbox-wide WebSocket budget; staged policies that could change an enforced
decision through the query budget or an evaluation error; Cedar MCP endpoints
missing from endpoint status; and public skills that round-tripped every
policy through YAML. The review also recommended splitting the change into
four pull requests (shared runtime refactor, standalone engine, feature
integration, remaining examples); that is a maintainers' decision and is
listed below.

Remaining steps:

- Decide whether to land the pull request whole or split it as the review
  recommends.
- Keep `ai-openshell/cedar` moving with the Cedar team: track delimited
  `like` upstream (cedar-policy/rfcs#115) and bump the pin as features land.
- Rename the Rust input types of `openshell-policy-cedar` after the schema
  actions (`NetworkRequest` to a `NetworkConnect` request type, `L7Request`
  to an `HttpRequest` one), so the code stops inviting the question answered
  above.
- Extend `e2e/cedar` to endpoint settings, `@path`, WebSocket, query
  parameters, native TCP, `destination_ip`, and `binary_aliases`, which
  today are covered by unit and parity tests.
- Decide the open questions below that affect the schema before the RFC is
  accepted, since schema changes after release are breaking for Cedar
  authors.
- Extend the policy prover's boundary and proposal checks to Cedar sandboxes
  through Cedar's symbolic compiler, so a Cedar policy gets at least the
  checks a YAML policy gets today. `openshell-prover check` reads YAML only.

Verification so far: unit tests and `clippy -D warnings` pass on macOS and
Linux with `openshell-policy` built with and without `cedar`; pre-commit,
`cargo deny`, the docs build, and the Go, TypeScript, and Python SDK checks
pass; `mise run e2e:cedar` passes its 39 checks against a Docker gateway,
including a provider attached through the gateway (attachment alone grants
no access, an explicit permit injects the credential, a denied request never
reaches the upstream, and a rotated credential reaches it); the parity
harness passes (2,911 cases on Linux, 2,906 agreeing, 5 recorded
differences; the 13 symlink cases are ignored on macOS); the
example parity module passes (166 tests); and the quickstart, content guard,
and MCP conformance examples run end to end in both formats. Mixed versions
are covered by unit tests: a Cedar policy sent to a gateway without support
is refused by the CLI and each SDK, and a Cedar configuration fetched by a
runtime without support is refused by the gateway. On the pull request, CI
ran the `cedar` and `mcp-cedar` end-to-end suites, the Docker, Podman,
Kubernetes, and VM matrices, and the Windows MSVC lane, all passing. Not yet
verified against a live gateway: native TCP, WebSocket, address ranges, and
symlinked binaries beyond what the parity harness covers.

## Risks

- **OpenShell's own Cedar.** `ai-openshell/cedar` is a fork OpenShell
  maintains and iterates on with the Cedar team, so features such as
  delimited `like` can change shape as they are refined (upstream proposal:
  [cedar-policy/rfcs#115](https://github.com/cedar-policy/rfcs/pull/115)),
  and the git pin is a standing supply-chain exception the project owns
  rather than a temporary one.
- **Policies that read differently.** The Cedar forms of YAML's implicit
  behaviors (`HEAD` under `GET`, MCP streams, audit versus staged, binary
  globs through `context.binary_globs`) are explicit in the policy text, and
  a reviewer who assumes YAML semantics can miss them; shapes that would mean
  more than their YAML reading are rejected at load.
- **Expressiveness.** Filesystem rules are unconditional subtree grants;
  every `HttpRequest` policy names its endpoint or its host glob; GraphQL
  field globs cannot be written; MCP streams need explicit permits; address
  conditions must be top-level conjuncts; host selectors are limited to 253
  bytes; query evaluation is capped at 4,096 combinations. Each fails closed
  and is reported.
- **Mixed versions.** Cedar needs the gateway and the sandbox runtime
  upgraded together. The CLI and SDKs refuse a gateway that does not
  advertise Cedar support, and the gateway refuses a runtime that does not,
  so the failure is a refused command or a sandbox that does not start, never
  a sandbox running with less than its policy. Operators upgrading a fleet
  see Cedar sandboxes fail on runtimes that are still old.
- **Providers do not open access.** Authors used to attaching a provider and
  getting its endpoints must now write the permits. Forgetting the
  `HttpRequest` policy for a credentialed endpoint refuses the connection.
- **Two-phase address checks.** An upstream proxy that connects by hostname
  (`proxy_connect_by_hostname`) re-resolves the host, so address conditions
  do not bind the address it uses. YAML `allowed_ips` has the same limit.
- **Fixed identity and no `process` section.** Cedar requests carry user and
  group `sandbox`, so identity conditions are always true, and the compute
  driver selects the runtime identity.
- **Build effects.** `cedar-policy` enables `serde_json`'s `preserve_order`
  in every binary that links it, so code assuming sorted JSON keys must sort
  explicitly; the boundary digest already does. Linking Cedar also grew
  `SandboxPolicy` enough that some gateway futures needed boxing.

## Alternatives

- **Keep YAML only.** Expressiveness stays bounded by the schema, and every
  new field needs matching Rego and a matching prover model, as the
  Motivation describes.
- **Expose Rego to policy authors.** Arbitrary conditions, but no decidable
  analysis of what authors write.
- **Translate YAML to Cedar.** Gaps between the languages would silently
  narrow or widen access for policies that hit them, and the translator
  would need verifying.
- **Run both engines and require agreement.** The same policy written twice,
  double evaluation, and the enforced decision still partly Rego.
- **Evaluate globs outside Cedar.** Keeps a released Cedar, but the glob
  conditions become opaque to Cedar's analysis, which defeats the purpose.
- **Cedar in supervisor middleware or gateway interceptors.** Middleware
  runs after the network decision and interceptors transform gRPC at the
  gateway; neither can own CONNECT authorization or Landlock grants, so
  either would be a second layer on top of YAML rather than a replacement.

## Prior art

- The policy prover established that OpenShell wants policy analysis with
  counterexamples, and that auto-approval can be gated on it.
- The YAML `protocol`, `enforcement`, `path`, and `tcp` endpoint fields are
  the precedent for `@protocol`, `@enforcement`, `@path`, and `@transport`:
  inspection mode as authored metadata, not allow or deny logic.
- YAML wildcard hosts and path globs set the segment rules that delimited
  `like` reproduces, with the host matcher policy DNS already uses.

## Open questions

- A gateway-wide YAML policy (`openshell policy set --global`) cannot be
  applied to a running Cedar sandbox, because a sandbox never switches format.
  Under `fail_closed` the Cedar sandbox is quarantined; under
  `retain_last_valid` it keeps its own policy. Should the supervisor quarantine
  regardless of the failure mode, since the operator asked for the global
  policy to win, and should the gateway warn when Cedar sandboxes exist?
- Should `@protocol` become an attribute of `NetworkEndpoint` instead of an
  annotation?
- Can Cedar add a narrow "any member matches" form over sets? It would cover
  GraphQL field globs, and would let `context.binary_globs` (a set the
  supervisor computes) become a plain condition. The Cedar team tracks this as
  cedar-policy/cedar#2512 and considers it a large change, since Cedar has no
  loops and the SMT side depends on an experimental cvc5 feature. They
  suggest a faster route: evaluate such bounded conditions outside Cedar and
  tell the analyzer how the resulting booleans relate
  ([cedar-policy/cedar#2511](https://github.com/cedar-policy/cedar/issues/2511)).
  That trades some analyzability for coverage, and needs a decision.
- Should Cedar MCP endpoints allow receive streams and response frames
  without explicit permits, as YAML does?
- Should policy load reject undelimited `like` on `resource.host` and
  `context.path`, to prevent accidental cross-segment globs?
- Should the sandbox's `process` identity be passed into Cedar requests?
- Provider rules are already compiled into Cedar to select token-grant
  owners. Should those generated policies be able to grant access, and should
  `policy get --full` show them so authors can analyze them?
- Which analyses should run on Cedar sandboxes, and where: the prover's
  boundary and proposal checks through `cedar symcc`, in the prover CLI, at
  the gateway, or both?
- Which temporal policies do sandboxes need first (approval-gated calls,
  rate limits, session windows), and how would Dogwood's event history be fed
  from supervisor decisions and OCSF events?
- What would make Cedar the default rather than an opt-in?

## References

1. Cedar language documentation: [docs.cedarpolicy.com](https://docs.cedarpolicy.com/);
   project site [cedarpolicy.com](https://www.cedarpolicy.com/); language
   change proposals [github.com/cedar-policy/rfcs](https://github.com/cedar-policy/rfcs).
2. J. W. Cutler et al. "Cedar: A New Language for Expressive, Fast, Safe,
   and Analyzable Authorization." *Proc. ACM Program. Lang.* 8, OOPSLA1
   (2024). [doi:10.1145/3649835](https://doi.org/10.1145/3649835).
3. C. Disselkoen et al. "How We Built Cedar: A Verification-Guided
   Approach." *FSE 2024 Companion*.
   [doi:10.1145/3663529.3663854](https://doi.org/10.1145/3663529.3663854).
4. E. Torlak. "SymCert: Verifying SMT-Based Policy Analyses." *FMCAD 2026*.
   [Paper](https://www.amazon.science/publications/symcert-verifying-smt-based-policy-analyses).
5. Cedar implementation, including `cedar symcc`:
   [github.com/cedar-policy/cedar](https://github.com/cedar-policy/cedar).
   Lean formalization and differential testing:
   [github.com/cedar-policy/cedar-spec](https://github.com/cedar-policy/cedar-spec).
6. Delimited `like` used by this proposal:
   [ai-openshell/cedar](https://github.com/ai-openshell/cedar) and its Lean
   specification [ai-openshell/cedar-spec](https://github.com/ai-openshell/cedar-spec).
   The Cedar team's RFC for the feature:
   [cedar-policy/rfcs#115](https://github.com/cedar-policy/rfcs/pull/115);
   the set-quantifier request:
   [cedar-policy/cedar#2512](https://github.com/cedar-policy/cedar/issues/2512).
7. OpenShell user documentation for this feature, on the implementation
   branch `vishwa/cedar-openshell`: `docs/how-it-works/policies/cedar.mdx`;
   implementation overview: `crates/openshell-policy-cedar/README.md`.
8. OpenShell policy prover: `docs/how-it-works/policies/prover.mdx` and
   `crates/openshell-prover`.
9. Dogwood, temporal policies and information providers on Cedar:
   [github.com/dogwood-policy/dogwood](https://github.com/dogwood-policy/dogwood).
