---
authors:
  - "@derekwaynecarr"
state: draft
links:
  - https://github.com/NVIDIA/OpenShell/issues/1977
---

# RFC 0011 - Multi-Player Support

## Summary

This RFC proposes adding multi-user support to OpenShell. Today, sandboxes and
providers are gateway-global with no ownership tracking or isolation between
users. This proposal introduces workspaces as hard isolation boundaries, an
expanded role model (Platform Admin, Workspace Admin, User), workspace-scoped
access, per-workspace quota enforcement, and audit trail enhancements. The Sandbox Supervisor remains a separate principal type
with sandbox-scoped authentication distinct from the user role model. A
`default` workspace preserves backwards compatibility for single-player
deployments.

## Motivation

OpenShell is currently a single-player experience. Every authenticated user sees
every sandbox and every provider. There is no concept of resource ownership,
tenant isolation, or delegated administration. This blocks several adoption
scenarios:

- **Enterprise teams** cannot share a gateway without seeing each other's
  sandboxes, credentials, and activity. There is no way to scope visibility
  or enforce per-team resource limits.

- **CI/CD and agent orchestration** workflows need machine identities with
  workspace-scoped access. Today the only option is full-privilege OIDC tokens
  or mTLS certs with no role granularity beyond admin/user. Workspaces provide
  the scoping boundary for these identities.

- **Compliance and incident response** teams need audit trails that attribute
  every sandbox and control-plane action to a specific principal. The existing
  OCSF infrastructure logs sandbox-level events but does not consistently tag
  them with the creating principal.

- **Cost attribution** is impossible without ownership metadata. Operators cannot
  answer "which team is consuming how many active sandboxes."

The existing codebase provides a foundation: OIDC authentication, a principal
model (User/Sandbox/Anon), two-tier RBAC, OCSF event infrastructure, and labels
on `ObjectMeta`. The gap is the isolation, ownership, and governance layer on
top.

Leaving the current design unchanged limits OpenShell to single-operator,
single-team deployments, which constrains adoption and forces organizations
to run one gateway per team.

## Non-goals

- **Cross-gateway federation.** This RFC scopes multi-player to a single gateway.
  Multi-gateway federation (e.g., routing users to regional gateways) is a
  separate concern.
- **Fine-grained ABAC or policy language.** The role model uses coarse-grained
  roles with workspace scoping, not attribute-based access control or a policy
  DSL like OPA/Rego for authorization decisions.
- **UI/dashboard for user management.** This RFC covers the API and data model.
  Administrative UIs are a follow-on.
- **Billing integration.** Principal attribution on resources enables cost
  attribution; integration with billing systems is out of scope.
- **Sandbox-to-sandbox networking isolation.** Network isolation between
  workspaces at the container/pod level is out of scope; this RFC addresses
  control-plane isolation only.
- **Multi-provider OIDC.** This RFC assumes a single configured OIDC provider.
  Supporting multiple OIDC providers (e.g., corporate SSO for humans and
  GitHub Actions for CI/CD simultaneously) requires issuer-based token routing,
  provider-qualified subject formats in membership records, and authenticator
  chain changes. These are valuable extensions but are not required for the
  core workspace and role model. A follow-on RFC can add multi-provider support
  without changing the workspace or membership abstractions.

## Proposal

### System Roles

The role model expands from the current two-tier (admin/user) to three user
roles:

| Role | Description |
|------|-------------|
| **Platform Admin** | Runtime role with full visibility across all workspaces. Creates workspaces, assigns Workspace Admins, and sets gateway-wide default policies. |
| **Workspace Admin** | Manages users, providers, policies, and quotas within a single workspace. Cannot change gateway infra or access other workspaces. |
| **User** | Creates sandboxes and accesses all sandboxes within assigned workspaces. Uses credentials available in those workspaces. Default role for OIDC-authenticated principals, both human and machine. |

### Sandbox Supervisor

The Sandbox Supervisor is not a user role — it is a separate principal type
with its own authentication and authorization path. User roles are properties
of a `Principal::User` and are resolved via OIDC claims or workspace membership
records. The Sandbox Supervisor authenticates as a `Principal::Sandbox` via a
gateway-minted JWT whose subject is bound to a single sandbox UUID.

The supervisor is scoped to a single sandbox, analogous to a Kubernetes kubelet
identity. It authenticates via a gateway-minted JWT or bootstrap certificate
and is restricted to RPCs that operate on its own sandbox. Authorization is
enforced by a static method allowlist (`is_sandbox_callable`) at the router
layer and per-handler scope guards (`ensure_sandbox_principal_scope`) that
verify the JWT's sandbox UUID matches the request target. The supervisor never
goes through the RBAC role check or workspace membership lookup.

The supervisor learns its workspace from the `GetSandboxConfigResponse.workspace`
field returned by its first settings poll. It caches this value and passes it
in subsequent workspace-scoped RPCs (policy sync, policy analysis, draft
policy queries). This avoids server-side special-casing for sandbox principals
while keeping the supervisor's JWT scoped to a single sandbox UUID.

### Role-to-RPC Access Matrix

Access is grouped by domain. Within each domain, the access level (none, read,
read-write) applies to all RPCs in that group unless noted otherwise. All user
roles are scoped to their workspace except Platform Admin, which operates
cross-workspace. The Sandbox Supervisor column is included for completeness —
it uses a separate authentication and authorization path (see Sandbox
Supervisor section above).

| Domain | Platform Admin | Workspace Admin | User | Sandbox Supervisor |
|--------|---------------|-----------------|------|--------------------|
| Workspace lifecycle (`Create`, `Get`, `List`, `Delete`) | read-write | read (own) | read (own) | none |
| Workspace membership (`Add`, `Remove`, `List`) | read-write | read-write (own ws, no admin assign) | none | none |
| Sandbox lifecycle (`Create`, `Get`, `List`, `Delete`) | read-write | read-write (own ws) | read-write (own ws) | read (own sandbox) |
| Sandbox data-plane (`Exec`, `ForwardTcp`, `CreateSshSession`, `RelayStream`) | full | full (own ws) | full (own ws) | none |
| Sandbox observability (`GetSandboxLogs`, `ListSandboxPolicies`, `GetSandboxPolicyStatus`) | read | read (own ws) | read (own ws) | own sandbox |
| Provider management (`Create`, `Get`, `List`, `Update`, `Delete`) | read-write | read-write (own ws) | read (no creds) | none |
| Provider attachment (`Attach`, `Detach`, `ListSandboxProviders`) | read-write | read-write (own ws) | read (own ws) | none |
| Services (`Expose`, `Get`, `List`, `Delete`) | read-write | read-write (own ws) | read-write (own ws) | none |
| Gateway config (`GetGatewayConfig`, `UpdateConfig`) | read-write | none | none | none |
| Policy drafts (`SubmitPolicyAnalysis`, `Approve`, etc.) | read-write | read-write (own ws) | none | none |
| Supervisor path (`ConnectSupervisor`, `IssueSandboxToken`, `RefreshSandboxToken`, `GetSandboxProviderEnvironment`, `PushSandboxLogs`, `ReportPolicyStatus`) | none | none | none | own sandbox |

**Control-plane audit log.** Every mutating gRPC call emits an OCSF
`ApiActivity` event recording the principal, action, target resource, and
timestamp. These events are emitted through the existing OCSF infrastructure
and exported as structured JSONL for consumption by external systems (see
Audit Trail section below).

### Workspaces

A workspace is a first-class resource and a hard isolation boundary. Sandboxes,
providers, and policies within a workspace are invisible to other workspaces.
Every resource belongs to exactly one workspace. A `default` workspace exists
for single-player backwards compatibility. Workspace creation is admin-only:
Platform Admins create workspaces and assign Workspace Admins. Self-service
workspace creation can be added later as a gateway configuration option.

The `Workspace` resource uses standard `ObjectMeta` (the `workspace` field in
its own `ObjectMeta` is unused, following the same convention as Kubernetes
Namespace objects). Workspace-level configuration — quota limits, policy
overrides, and Workspace Admin role bindings — are properties on the Workspace
resource. The gateway exposes `CreateWorkspace`, `GetWorkspace`,
`ListWorkspaces`, and `DeleteWorkspace` RPCs, gated to Platform Admins.
Sandbox and provider create operations validate that the referenced workspace
exists, rejecting unknown workspace values.

`DeleteWorkspace` uses a two-phase graceful deletion protocol inspired by
Kubernetes namespace deletion. A workspace has two lifecycle phases: **Active**
(default) and **Terminating**.

1. **Mark Terminating.** When `DeleteWorkspace` is called, the workspace is
   atomically marked Terminating via a CAS write that sets
   `ObjectMeta.deletion_timestamp_ms` and `WorkspaceStatus.phase =
   TERMINATING`. This is non-reversible — once Terminating, the workspace
   cannot return to Active.

2. **Reject new resources.** `resolve_workspace` returns the workspace's
   termination state. Create-path handlers (`CreateSandbox`,
   `CreateProvider`, `ExposeService`, `SetInferenceRoute`,
   `AddWorkspaceMember`, etc.) call `ensure_active()` and reject operations
   on Terminating workspaces with `FAILED_PRECONDITION`. Read and delete
   operations continue to work so administrators can clean up.

3. **Scan for blockers.** After marking Terminating, the handler scans for
   remaining workspace-scoped resources. If any exist, the call returns
   `FAILED_PRECONDITION` listing them. The workspace stays Terminating;
   the administrator cleans up resources and retries.

4. **Complete deletion.** If no blocking resources remain, membership records
   are cleaned up and the workspace is deleted.

The Terminating phase closes the TOCTOU race in the original design: without
it, a concurrent `CreateSandbox` could commit a new resource between the
blocker scan and the delete, orphaning the sandbox. By marking Terminating
first, concurrent creates are rejected during the scan window.

Re-entry is idempotent: calling `DeleteWorkspace` on an already-Terminating
workspace skips the CAS write and proceeds directly to the blocker scan.

The `default` workspace cannot be deleted. Gateway startup fails if the
`default` workspace cannot be created or verified — this is a fatal error, not
a best-effort operation.

Workspace membership is capped at 1000 members per workspace.
`AddWorkspaceMember` rejects additions that would exceed this limit with a
resource-exhausted error. This cap bounds the cleanup cost during workspace
deletion and ensures the member listing used for cleanup is exhaustive.

`ObjectMeta` gains a `workspace` field referencing a Workspace by name. Within
a workspace, organizational grouping (teams, projects, cost centers) uses the
existing label system with well-known key conventions (e.g.,
`openshell.dev/team=infra`, `openshell.dev/project=alpha`) rather than
additional dedicated fields. This:

- Gives a clear security boundary (workspace) without over-modeling
  organizational hierarchy.
- Allows multiple overlapping groupings within a workspace via labels.
- Keeps the proto surface minimal: `workspace` and `deletion_timestamp_ms` are
  the only new fields on `ObjectMeta`. The `deletion_timestamp_ms` field is set
  when graceful deletion begins (0 = not deleting) and serves as the
  authoritative source of truth for termination state.

#### Workspace use cases

- **Credential segmentation within a team.** Each user gets their own workspace
  on a shared gateway, keeping their API keys (e.g., per-user Claude or Codex
  keys) isolated from other users. This eliminates the need for a separate
  gateway per user while preserving credential isolation.

- **Shared coding sessions.** All workspace members can access any sandbox in
  the workspace, enabling pair programming and collaborative debugging without
  additional access grants.

- **CI/CD and automation.** A workspace scopes sandbox lifecycle to a specific
  pipeline or project. Machine workloads authenticate via the configured OIDC
  provider and are added as workspace members with the appropriate role.

- **Agent harness integration.** A single OpenShell gateway can be partitioned
  into discrete workspaces so that multiple agent harness instances (e.g.,
  OpenClaw) can procure sandboxes from the same gateway with proper isolation.
  This removes the requirement for a one-to-one association between an agent
  harness instance and an OpenShell gateway instance.

#### Future work: server-initiated workspace cleanup

The current graceful deletion requires the administrator to manually remove all
workspace-scoped resources before deletion completes. A future enhancement
could add a background GC controller that automatically deletes resources when
a workspace enters the Terminating phase:

- The administrator calls `DeleteWorkspace` once; the server handles cleanup
  asynchronously (sandboxes first, then providers, profiles, services, etc.).
- `DeleteWorkspace` could return immediately with a status indicating cleanup
  is in progress, or block until complete with a configurable timeout.
- The GC controller would respect resource-specific ordering constraints (e.g.,
  detach providers before deleting sandboxes) and retry transient failures.

This is deferred to Phase 2. For now, administrators must manually clean up
resources before deletion completes.

### Ownership and Access Control

Access control is based on workspace membership. Principal attribution (who
created or modified a resource) is handled by the control-plane audit log, not
by fields on the resource itself.

#### Role assignment

Roles fall into two categories:

- **Global roles** (Platform Admin) are assigned externally via OIDC claims in
  the identity provider (e.g., an `openshell-platform-admin` role in the JWT).
  This role is a property of the principal, not of any workspace, and grants
  cross-workspace access. The gateway evaluates it from the authenticated
  token at request time.

- **Workspace-scoped roles** (Workspace Admin, User) are assigned internally
  via workspace membership records stored in the gateway's durable object
  store. These roles are properties of a principal's relationship to a
  specific workspace.

The authorization layer combines both: the gateway first evaluates global roles
from the JWT, then resolves workspace-scoped roles from membership records for
the target workspace. A request to a workspace-scoped RPC is authorized if the
principal has the Platform Admin global role or a
workspace membership with a sufficient role.

Workspace membership is managed through three RPCs:

- `AddWorkspaceMember(workspace, principal_subject, role)` — Platform Admins
  can assign any workspace-scoped role. Workspace Admins can add Users to
  their own workspace but cannot assign the Workspace Admin role.
- `RemoveWorkspaceMember(workspace, principal_subject)` — same access pattern.
- `ListWorkspaceMembers(workspace)` — Platform Admins can list any workspace;
  Workspace Admins can list their own.

Principal subjects are the OIDC `sub` claim from the configured identity
provider. The gateway does not maintain a user directory — membership
references OIDC subjects that are resolved at authentication time. Membership
records are persisted in the durable object store, indexed by both workspace
and principal subject for efficient lookup.

A principal's request to any workspace-scoped RPC is rejected if they are not a
member of the target workspace. Platform Admins bypass membership checks —
their role grants cross-workspace access by definition.

#### Resource-level access

Within a workspace, access varies by resource type:

- **Sandboxes.** All workspace members can list, get, exec into, and access any
  sandbox in their workspace. Credential isolation happens at the workspace
  boundary — within a workspace, all members share the same trust domain and
  the same provider credentials, so there is no security benefit to restricting
  sandbox access by owner. Platform Admins can list across workspaces using
  `all_workspaces = true` on list RPCs (see Cross-Workspace List Operations
  below).

- **Providers.** Users can list and reference providers by name within their
  workspace but cannot create, update, or delete them, and cannot see raw
  credential material. Workspace Admins manage provider lifecycle within their
  workspace. `ListProviders` is scoped to the caller's workspace.

- **Services.** Services are child resources of sandboxes, keyed by sandbox
  name. They carry the parent sandbox's workspace in their `ObjectMeta` for
  consistent filtering, but the workspace is always inherited from the sandbox,
  never set independently. All workspace members can expose, list, and delete
  services on any sandbox in their workspace.

- **Provider profiles.** Provider profiles are type definitions that describe
  what a provider type needs (credentials, endpoints, filesystem paths).
  Profiles have two-tier scoping: platform-scoped profiles are managed by
  Platform Admins and visible to all workspaces; workspace-scoped profiles
  are managed by Workspace Admins and visible only within their workspace.
  The same profile ID can exist at both platform and workspace scope — the
  workspace profile shadows the platform profile for workspace-scoped
  operations, with the platform profile as the fallback when no workspace
  override exists. This lets Platform Admins publish org-wide defaults that
  Workspace Admins can customize per-workspace without affecting other
  workspaces.

  Each profile carries two metadata fields in list/get responses: **source**
  (provenance — `builtin`, `user`, or `interceptor/{name}`) and **scope**
  (visibility — `platform`, `workspace`, or empty for sources like builtins
  and interceptors that are not user-scoped). These fields are set by the
  gateway and ignored on import payloads. Built-in profiles (claude-code,
  github, nvidia, etc.) are visible in all scopes.

  `ListProviderProfiles` returns all profiles visible in the requested
  context: workspace-scoped listings include workspace custom profiles,
  platform custom profiles, and builtins. When a workspace profile shadows
  a platform profile, both appear in the listing with distinct scope values
  so the user can see the override relationship. Platform-scoped listings
  (`--global`) include only platform custom profiles and builtins.

  Import, update, and delete operations target either platform scope or
  workspace scope explicitly. Importing a profile at workspace scope when a
  platform profile with the same ID exists produces a warning diagnostic
  indicating the shadow relationship.

- **Policies.** Users cannot modify policies directly. Sandbox policy is
  derived from attached provider profiles (see Policy Scoping below).
  Workspace Admins control policy indirectly by managing which providers are
  available in the workspace. `ListSandboxPolicies` is scoped to the caller's
  workspace.

#### Sandbox access within a workspace

All workspace members have full access to all sandboxes in the workspace. There
is no per-sandbox sharing mechanism within a workspace — the workspace boundary
is the access control surface. Cross-workspace sandbox sharing is deferred to
future work (see Future Work section).

### Policy Scoping

Sandbox policy is derived from the providers attached to the sandbox. There is
no separate workspace-level policy to author or maintain — the providers a
Workspace Admin makes available in the workspace define what sandboxes in that
workspace can do.

| Layer | Scope | Set by | Purpose |
|-------|-------|--------|---------|
| Gateway default | All sandboxes | Platform Admin | Enforcement modes (Landlock) and gateway-wide network deny rules |
| Provider profiles | Per sandbox | Workspace Admin (provider lifecycle) / User (provider attachment) | Network endpoints, filesystem paths, environment variables |

Each provider carries a profile describing the endpoints and filesystem paths
it requires. When a user attaches providers to a sandbox, the gateway computes
the effective policy as the union of the attached provider profiles, layered on
top of the gateway default. The gateway returns a single resolved
`SandboxPolicy` at `GetSandboxConfig` time — the sandbox sees a flat policy,
not the composition.

Provider types fall into two categories:

- **Credential providers** (Anthropic, OpenAI, GitHub) — inject secrets and add
  the provider's network endpoints to the sandbox policy.
- **Endpoint providers** — add network endpoints only, no secrets. Used for
  internal services (Git servers, artifact registries, custom APIs) that
  sandboxes need to reach but that don't require credential injection.

Both types use the same provider abstraction. The Workspace Admin's policy
decision reduces to: "which providers does this workspace have?" The User's
sandbox-level policy decision is: "which of those providers does my sandbox
use?"

The gateway default (enforcement modes, deny rules) remains the floor and
cannot be overridden by provider profiles. Deny rules at the gateway level
override provider profile allows.

**Migration.** Existing global policies map to the gateway default. Existing
per-sandbox policies continue to work through the policy advisor flow, which
generates policy from attached providers. The `restrictive_default_policy()`
fallback applies when no providers are attached — identical to current behavior.

### Authorization Enforcement

The gateway's existing authorization pattern — compile-time per-method
metadata, middleware authentication, and per-handler guards — extends to
workspace-scoped enforcement without architectural changes.

**Proto-driven method metadata.** Authorization rules are declared as custom
options on each proto RPC method, making the proto definition the single
source of truth for the API contract and its access control:

```proto
import "google/protobuf/descriptor.proto";

message AuthorizationRule {
  string auth_mode = 1;       // "bearer", "sandbox", "dual", "unauthenticated"
  string workspace_role = 2;  // "user", "admin"
  string global_role = 3;     // "platform_admin"
}

extend google.protobuf.MethodOptions {
  AuthorizationRule authorization = 50000;
}
```

Each RPC carries its authorization requirement:

```proto
service OpenShell {
  rpc CreateSandbox(CreateSandboxRequest) returns (CreateSandboxResponse) {
    option (authorization) = { auth_mode: "bearer", workspace_role: "user" };
  }
  rpc CreateProvider(CreateProviderRequest) returns (CreateProviderResponse) {
    option (authorization) = { auth_mode: "bearer", workspace_role: "admin" };
  }
  rpc CreateWorkspace(CreateWorkspaceRequest) returns (CreateWorkspaceResponse) {
    option (authorization) = { auth_mode: "bearer", global_role: "platform_admin" };
  }
  rpc ConnectSupervisor(stream SupervisorMessage) returns (stream GatewayMessage) {
    option (authorization) = { auth_mode: "sandbox" };
  }
}
```

The gateway already compiles a `FileDescriptorSet` at build time and embeds
it in the binary (`openshell_core::FILE_DESCRIPTOR_SET`). Adding
`prost_reflect::DescriptorPool` allows the runtime to resolve custom
extensions natively — no build.rs code generation, no external tooling:

```rust
static DESCRIPTOR_POOL: LazyLock<DescriptorPool> = LazyLock::new(|| {
    DescriptorPool::decode(openshell_core::FILE_DESCRIPTOR_SET)
        .expect("decode descriptor pool")
});
```

At startup the middleware walks the pool's methods, reads the
`(authorization)` extension from each `MethodDescriptor::options()`, and
builds the lookup table keyed by gRPC method path. This replaces the current
`#[rpc_authz]` proc macro and per-service `AUTH_METADATA` tables — the proto
definition becomes the single source of truth for both the API contract and
its access control. The middleware calls the same `method_authz::lookup()`
function at request dispatch time; only the source of the table changes.

The existing exhaustiveness tests switch from `prost_types::FileDescriptorSet`
to `DescriptorPool` and assert that every method in the pool carries a valid
`(authorization)` option, catching missing annotations at `cargo test` time.

This follows the pattern established by `google.api.http` annotations for
REST gateway generation: the proto carries the metadata, the descriptor pool
resolves it, and the runtime consumes it directly.

**Workspace on every scoped request.** Since resource names are
unique-within-workspace, every workspace-scoped RPC includes the workspace in
its request message. A `WorkspaceScoped` trait implemented on each request type
provides uniform access:

```rust
trait WorkspaceScoped {
    fn workspace(&self) -> &str;
}
```

**Single authorization path.** A shared `authorize_workspace` function replaces
per-handler authorization boilerplate. It extracts the principal from request
extensions, checks for Platform Admin global role bypass, resolves
workspace membership from the durable store, and verifies the membership role
meets the method's declared minimum:

```rust
let principal = authorize_workspace(
    &request, WorkspaceRole::User, &self.membership,
)?;
```

Every workspace-scoped handler uses this one-line call. The middleware layer
is unchanged: it authenticates the caller, inserts the principal into request
extensions, and the handler resolves workspace authorization.

### Authorization Boundaries (Kubernetes Deployments)

In Kubernetes deployments, authorization operates at two layers. Kubernetes
RBAC governs control-plane operations: who can create, delete, or manage
sandbox custom resources and other objects in a Kubernetes namespace. The
gateway's role model governs data-plane operations: who can exec into a
running sandbox, stream relay output, or view audit logs.
These are runtime authorization decisions through the gateway's gRPC endpoints
where Kubernetes RBAC has no reach.

Both layers are needed in Kubernetes deployments with clear boundaries between
them. For non-Kubernetes drivers (Docker, Podman, VM), the gateway's role model
is the sole authorization mechanism.

### Provider Credential Scoping

Providers belong to a workspace. A User can only attach providers available in
their workspace when creating a sandbox. No role sees raw credential material
through the API; all roles reference providers by
name. The sandbox supervisor resolves credentials at runtime through an internal
trusted path, not through role-level permissions.

### Authentication

The gateway authenticates principals via its existing OIDC provider. The
workspace and role model does not change the authentication mechanism — it
layers authorization on top of the authenticated identity.

When OIDC is configured, the gateway validates the Bearer token, extracts the
`sub` claim as the principal subject, and evaluates global roles from JWT
claims (e.g., Platform Admin). Workspace-scoped roles are resolved from
membership records keyed by the principal's `sub` claim.

When OIDC is not configured, every request is treated as a Platform Admin
principal. The full workspace model remains available — workspaces can be
created, members added, resources scoped — but no authentication or
authorization checks are enforced. This preserves the current single-player
experience and allows operators to adopt workspaces for organizational
structure before enabling authentication.

### Audit Trail

Multi-player introduces multiple principals acting on shared infrastructure.
The audit trail must attribute every action to a specific principal so that
security teams, compliance reviewers, and operators can answer "who did what,
when, and in which workspace" without needing a gateway role to do so.

OpenShell already has an OCSF event infrastructure with two output layers:
a shorthand formatter for human-readable logs and a JSONL formatter for
structured machine consumption. Multi-player extends this infrastructure
with principal and workspace attribution on every event.

**Control-plane events.** Every mutating gRPC call (`CreateSandbox`,
`DeleteSandbox`, `CreateProvider`, `UpdatePolicy`, `AddWorkspaceMember`)
emits an OCSF event with the authenticated principal's subject, the target
workspace, the action, the target resource, and a timestamp. `ApiActivity`
is a new OCSF event class that must be added to the `openshell-ocsf` crate.
`ConfigStateChange` covers policy and configuration mutations. These events
are emitted through the existing OCSF infrastructure — no separate audit
storage or query API is required.

**Sandbox-level events.** Sandbox activity (network decisions, process
lifecycle, SSH sessions) is already emitted as OCSF events by the sandbox
supervisor. Multi-player adds the creating principal's subject to these
events so security teams can trace sandbox behavior back to the human or
machine principal that created it.

**Log forwarding.** The gateway writes OCSF events as structured JSONL to
a configurable output (file, stdout). Operators forward this JSONL to their
SIEM or log aggregation system (Splunk, Elastic, Datadog, CloudWatch) using
standard log shipping tools (Fluentd, Vector, Filebeat). The JSONL format
follows OCSF v1.7.0 schema conventions, making it directly ingestible by
SIEM platforms that support OCSF.

This model follows the Kubernetes pattern: the API server writes audit events
to a log backend, and external tooling handles aggregation, retention, and
querying. Audit consumers do not need a gateway role — they access audit data
through their organization's log infrastructure. Queries like "who created
sandbox X" or "what did user Y do between T1 and T2" are answered in the SIEM,
not through a gateway API.

### Resource Governance

- **Per-workspace quotas.** Max concurrent sandboxes, max GPU allocations, max
  sandbox lifetime per workspace. Enforced at the gateway before sandbox
  creation. Quota limits are hard — sandbox creation is rejected when a quota
  is exceeded. Quotas are framed as DoS and abuse protection for the control
  and data plane, not as a chargeback mechanism. Quota limits are properties on the
  workspace data model; detailed schema design is deferred to implementation.

### Kubernetes Compute Driver: Workspace Mapping

OpenShell workspaces are a gateway-level concept. The gateway populates the
workspace on each `DriverSandbox` passed to the compute driver. Drivers consume
the workspace to map it to the appropriate infrastructure-level isolation (K8s
namespace, Docker label, etc.) but do not define or manage workspaces
themselves. When the Kubernetes compute driver renders sandboxes onto a cluster,
it must map each OpenShell workspace to a Kubernetes namespace. The driver
supports two modes, configured per deployment:

**Managed mode** (default) — the driver creates and deletes Kubernetes
namespaces on demand. The Kubernetes namespace name is derived from the gateway
identifier and the OpenShell workspace:
`openshell-{gateway-id}-{workspace-name}`. For example, if the gateway
identifier is `prod` and the OpenShell workspace is `team-ml`, the Kubernetes
namespace is `openshell-prod-team-ml`.

The gateway identifier prefix ensures that multiple gateways can operate on a
common Kubernetes cluster without namespace collisions. Each gateway owns its
own set of Kubernetes namespaces and can independently create, watch, and delete
them. The gateway identifier is already part of the gateway's bootstrap
configuration.

When an OpenShell workspace is deleted and all sandboxes have been removed, the
driver deletes the corresponding Kubernetes namespace.

Managed mode requires a `ClusterRole` with namespace create/delete permissions.
The Helm chart includes conditional `ClusterRole` and `ClusterRoleBinding`
templates that are enabled by default. Workspace names must be validated at
creation time to ensure the resulting Kubernetes namespace name is DNS-1123
compliant (lowercase alphanumeric and hyphens, max 63 characters total
including the `openshell-{gateway-id}-` prefix). The gateway rejects workspace
names that would produce invalid or colliding Kubernetes namespace names.

**Operator mode** — an alternative for environments where the gateway should not
create Kubernetes namespaces. The OpenShell workspace name maps one-to-one to a
Kubernetes namespace of the same name. If a sandbox belongs to OpenShell
workspace `team-ml`, the driver renders it into the Kubernetes namespace
`team-ml`. No mapping configuration is required. The Kubernetes namespaces must
be pre-provisioned — the driver has no permission to create or delete them.
If the target Kubernetes namespace does not exist, the driver lets the
Kubernetes API reject the request and surfaces the error — no pre-validation,
which avoids TOCTOU races.

This direct identity mapping enables the OpenShell gateway to operate as a
natural Kubernetes-style operator: it receives a desired state (sandbox in
workspace X) and renders it into the corresponding cluster namespace. Platform
teams manage Kubernetes namespaces through their existing tooling (kubectl,
GitOps, Terraform) and OpenShell follows.

```toml
[openshell.drivers.kubernetes]
workspace_mode = "operator"  # opt-in; default is "managed"
```

**Watcher strategy.** Today the Kubernetes driver watches a single Kubernetes
namespace via `Api::namespaced_with()`. With multiple workspaces, the driver
shifts to a cluster-wide list/watch filtered by OpenShell labels (e.g.,
`openshell.dev/managed-by=gateway`). This follows the standard Kubernetes
operator pattern for multi-namespace controllers. A per-namespace watcher
approach does not scale — it requires O(n) API connections and complicates
dynamic workspace addition/removal. The cluster-wide watch requires a
`ClusterRole` granting list/watch across Kubernetes namespaces (applicable to
both operator and managed modes).

#### Shared-namespace resource naming

Before namespace-per-workspace support lands, the Kubernetes driver operates
in shared-namespace mode: all workspaces render sandboxes into the same
Kubernetes namespace. The gateway populates `DriverSandbox.workspace` on
every sandbox dispatched to the compute driver. The driver uses this field to
construct collision-safe Kubernetes resource names and to label and annotate
the resulting objects.

**Resource names.** Kubernetes resource names follow the format
`{workspace}--{name}`. Two sandboxes named `work` in workspaces `alpha` and
`beta` produce distinct resources `alpha--work` and `beta--work`. The
workspace prefix is always present — there is no bare-name fallback.

**Labels.** Each sandbox object carries labels for selector-based lookup:

| Label | Value | Purpose |
|-------|-------|---------|
| `openshell.ai/sandbox-id` | sandbox UUID | Get/delete by ID |
| `openshell.ai/sandbox-name` | bare sandbox name | Lookup by (workspace, name) tuple |
| `openshell.ai/sandbox-workspace` | workspace name | Lookup by (workspace, name) tuple |
| `openshell.ai/managed-by` | `openshell-gateway` | Scope cluster-wide watches |

**Annotations.** Annotations store authoritative sandbox metadata for
reconstructing `DriverSandbox` from a Kubernetes object. The annotation keys
mirror the label keys (`openshell.ai/sandbox-id`, `openshell.ai/sandbox-name`,
`openshell.ai/sandbox-workspace`). On read, the driver checks annotations
first, then falls back to labels for backwards compatibility with objects
created before annotations were added. If neither source provides a workspace,
the driver returns an error — it never falls back to an empty workspace.

**Label-based lookup.** Get and delete operations use label selectors instead
of Kubernetes resource name lookup. `get_sandbox(sandbox_id)` lists by
`openshell.ai/sandbox-id={uuid}`. `delete_sandbox(sandbox_id)` lists by the
same label to discover the Kubernetes resource name, then issues the delete.
This decouples the API contract (sandbox UUID) from the Kubernetes resource
name (which encodes the workspace).

When namespace-per-workspace mode is implemented (Phase 3–4), the driver will
use the workspace to select the target Kubernetes namespace instead of encoding
it in the resource name. The label-based lookup and annotation patterns
established here carry over unchanged.

**Docker and Podman drivers.** The Docker driver's `sandbox_namespace` label
provides a foundation for workspace mapping, but the driver currently uses a
single configured namespace rather than per-sandbox values. The driver contract
must be updated so that workspace flows through `DriverSandbox` and the driver
applies it as the container label filter. The same applies to Podman and other
local drivers — workspace isolation is enforced at the gateway level and does
not require Kubernetes.

### Compute Driver Trust Model

The `ComputeDriver` gRPC service is a gateway-internal contract between the
gateway and its compute backend. Drivers can be in-process (Docker, Podman) or
out-of-process (VM driver subprocess, remote Kubernetes driver). The trust model
for this channel is:

**The driver is a trusted backend.** The gateway is the sole caller of the
driver service. The driver does not enforce workspace isolation — it operates on
`DriverSandbox` messages keyed by `(id, name, namespace)` and has no concept of
workspaces. Workspace is a gateway-level tenancy boundary that the gateway
resolves before dispatching to the driver. The driver trusts the gateway to have
already authenticated the user, authorized the operation, and resolved the
workspace-to-namespace mapping.

**Gateway-to-driver authentication.** For in-process drivers, no authentication
is needed — the driver runs in the gateway process. For out-of-process drivers,
the gateway authenticates to the driver via mTLS or a shared credential
configured at deployment time. This is a service-to-service trust boundary, not
a user-facing one. The `RemoteComputeDriver` connects over a gRPC channel; the
channel's transport security governs the trust.

**Multi-gateway deployments.** When multiple gateways share a compute backend
(e.g., a shared Kubernetes cluster), each gateway independently manages its own
workspace set and namespace mappings. The driver has no mechanism to enforce
cross-gateway workspace isolation — it sees containers/pods from all gateways
indiscriminately. Isolation between gateways relies on the deterministic
namespace naming convention (`openshell-{gateway-id}-{workspace-name}`) ensuring
non-overlapping Kubernetes namespaces, and on OpenShell labels that scope
list/watch results to a specific gateway's resources.

**The driver does not need workspace-scoped RPCs.** The `ComputeDriver` service
contract remains workspace-unaware. `CreateSandbox` receives a `DriverSandbox`
with the resolved Kubernetes namespace (or Docker label). `ListSandboxes` returns
all platform-observed sandboxes — the gateway correlates them back to workspaces.
Adding workspace awareness to the driver contract would violate the separation
between the gateway's tenancy model and the driver's infrastructure model.

### Cross-Workspace Infrastructure Operations

Several gateway-internal operations must query workspace-scoped resources across
all workspaces. These operations run as the gateway process itself — they are
not user-initiated gRPC calls and do not go through the authentication or
workspace authorization path. The gateway is the actor.

**Affected operations:**

- **Sandbox reconciliation** (`reconcile_store_with_backend`). The reconciler
  periodically compares all stored sandbox records against the compute driver's
  inventory to detect orphans (store records with no driver-side resource) and
  ghost resources (driver resources with no store record). The driver's
  `ListSandboxes` returns all platform-observed sandboxes regardless of
  workspace — the driver has no workspace concept. The gateway must query all
  stored sandboxes across all workspaces to produce the full set for comparison.

- **Startup resume** (`resume_persisted_sandboxes`). On gateway startup, the
  resume path iterates all stored sandboxes whose phase indicates they should
  be running and asks the driver to resume each one. This must cover all
  workspaces.

- **Provider credential refresh** (`refresh_provider_credential`). A background
  worker iterates `StoredProviderCredentialRefreshState` records to refresh
  expiring credentials. These refresh state records are globally scoped (not
  workspace-scoped), but the worker must look up the corresponding `Provider`
  resource, which is workspace-scoped. With multiple workspaces, the same
  provider name can exist in different workspaces, so the refresh state must
  carry the provider's workspace to resolve the correct one unambiguously.

**Store-level cross-workspace query.** The persistence layer gains a
`list_by_type(object_type, limit, offset)` method that omits the workspace
filter. This is distinct from the workspace-scoped `list(object_type, workspace,
limit, offset)` used by gRPC handlers. The cross-workspace query is used only
by internal infrastructure operations — it is not exposed through any gRPC RPC
directly.

**Workspace resolution on driver watch events.** When the driver reports a
sandbox that does not exist in the store (a watch event for a sandbox the
gateway has no record of), the gateway creates a new store record. The workspace
for this record is resolved by reverse-mapping the `DriverSandbox.namespace`
field through the workspace-to-namespace configuration:

- **Managed mode**: the gateway parses the Kubernetes namespace name
  (`openshell-{gateway-id}-{workspace-name}`) to extract the workspace.
- **Operator mode**: the gateway looks up which workspace maps to the reported
  Kubernetes namespace via the identity mapping.
- **Docker/Podman**: the gateway reads the workspace from the container label.

If no mapping matches, the sandbox is assigned to the `default` workspace. This
is a best-effort fallback for cases like manually created containers or
resources from a prior gateway configuration.

### Cross-Workspace List Operations

Platform Admins need the ability to list resources across all workspaces,
analogous to `kubectl get pods --all-namespaces`. This is an explicit opt-in
on list RPCs, not the default behavior.

**RPC mechanism.** Workspace-scoped list RPCs (`ListSandboxes`,
`ListProviders`, `ListServices`) gain an `all_workspaces` boolean field. When
`all_workspaces = true`, the handler bypasses workspace scoping and returns
results from all workspaces. The caller must have the Platform Admin global role;
workspace-scoped roles cannot set `all_workspaces`. Results include the
`workspace` field in each resource's `ObjectMeta` so the caller can distinguish
provenance.

This is distinct from passing an empty workspace string. Empty workspace is
resolved to `"default"` by the gateway's `resolve_workspace()` logic for
backwards compatibility — it does not mean "all workspaces."

**Store query.** The `all_workspaces` handler path uses the same
`list_by_type(object_type, limit, offset)` store method as the internal
infrastructure operations. The authorization gate (Platform Admin check) is
enforced at the gRPC handler level, not at the store level — the store method
itself is access-control-unaware.

**CLI surface.** The `--all-workspaces` flag is available on list commands for
Platform Admins:

```shell
openshell sandbox list --all-workspaces
openshell provider list --all-workspaces
openshell service list --all-workspaces
```

### Enterprise Deployment: Multi-Consumer Gateway

A common enterprise deployment pattern — particularly in regulated industries
like financial services and defense — involves one or two data centers, each
running a handful of Kubernetes clusters. In this environment, organizations
want to minimize the number of OpenShell gateways they need to reason about.
Workspaces enable a single gateway per compute region to serve multiple
independent sandbox consumers with proper isolation between them.

**Multiple consumers, one gateway.** In a single enterprise OpenShell
deployment, many independent consumers procure sandboxes on demand — agent
harnesses, CI/CD pipelines, internal tooling, and interactive users. Using
OpenClaw as an example agent-harness consumer that needs to procure sandboxes
on demand, an OpenClaw instance adds a single `workspace` field to its
OpenShell plugin config:

```json5
// OpenClaw plugin config — workspace scopes all sandbox operations
{
  plugins: {
    entries: {
      openshell: {
        enabled: true,
        config: {
          from: "openclaw",
          mode: "remote",
          gateway: "prod",
          gatewayEndpoint: "https://openshell.internal:8443",
          workspace: "team-capital-markets",
        },
      },
    },
  },
}
```

The plugin passes `--workspace` to every `openshell` CLI invocation (`sandbox
get`, `sandbox create`, `sandbox list`). The rest of the OpenClaw integration
— sandbox lifecycle, SSH transport, workspace sync — is unchanged.

OpenClaw sandboxes for tool execution and agent sessions are provisioned within
the assigned workspace. Other consumers — a different OpenClaw instance for
another department, a separate agent harness, or a CI pipeline — each operate
in their own workspace on the same gateway. Sandbox list operations are
workspace-scoped: a consumer sees only its own sandboxes, never sandboxes
belonging to other consumers.

This is not OpenShell absorbing multiplayer concerns from its consumers.
OpenClaw and other agent harnesses own their own multi-user models. The
requirement on the OpenShell side is narrower: a single gateway must support
1:N partitioning so that each consumer's sandboxes are properly isolated from
every other consumer's sandboxes, without requiring a dedicated gateway per
consumer.

**Kubernetes-level isolation chain.** When the gateway renders sandboxes onto
the cluster, each workspace maps to a discrete Kubernetes namespace. This
enables the Kubernetes isolation stack when the cluster is configured for it:

- **Network policy** can partition traffic between Kubernetes namespaces,
  preventing cross-workspace network access between sandboxes (requires a CNI
  that enforces NetworkPolicy).
- **UID/GID range allocation** (as enforced on platforms like OpenShift) assigns
  each Kubernetes namespace a unique UID/GID range. Every sandbox process runs
  under a UID that is unique to its workspace's namespace.
- **SELinux labeling** (on OpenShift and similarly configured platforms) assigns
  each Kubernetes namespace a unique SELinux label (MCS category). Kernel-level
  mandatory access control constrains processes to their namespace's domain.

These are platform prerequisites, not features provisioned by OpenShell. The
workspace-to-namespace mapping provides the structure; the cluster must be
configured to enforce isolation at each layer.

**Sandbox escape threat model.** Container breakout is the dominant concern in
regulated environments. The workspace-to-Kubernetes-namespace mapping means
that even in the event of a sandbox escape, the attacker's process carries the
UID/GID and SELinux label of the originating workspace's Kubernetes namespace.
On platforms that enforce these boundaries at the node level, a compromised
process is constrained by:

- Kubernetes RBAC and secrets scoped to the originating namespace.
- UID/GID range enforcement preventing access to other namespaces' resources.
- SELinux MCS labels preventing cross-namespace process and file access.

The combination of gateway-level workspace isolation (control plane) and
Kubernetes namespace isolation (data plane) produces defense in depth: even if
one layer is compromised, the other constrains the blast radius to a single
workspace.

### CLI Surface

All sandbox and provider commands accept an optional `--workspace` flag that
scopes operations to a specific workspace. When omitted, the CLI defaults to
the `default` workspace, preserving the single-player experience.

The workspace can also be set via the `OPENSHELL_WORKSPACE` environment
variable. The explicit `--workspace` flag takes precedence over the environment
variable.

```shell
openshell sandbox create --workspace team-ml --name my-sandbox
openshell sandbox list --workspace team-ml
openshell provider list --workspace team-ml
```

#### Cross-workspace listing

Platform Admins can list resources across all workspaces using the
`--all-workspaces` flag. This is mutually exclusive with `--workspace`. Output
includes the workspace in each row so the admin can distinguish provenance.

```shell
openshell sandbox list --all-workspaces
openshell provider list --all-workspaces
openshell service list --all-workspaces
```

#### Provider profile scope flag

Provider profiles use two-tier scoping (see Resource-level access above).
Because `--workspace` defaults to the `default` workspace, a separate
`--global` flag distinguishes platform-scoped operations from workspace-scoped
ones. The two flags are mutually exclusive.

| Flag | Scope | Who | Behavior |
|------|-------|-----|----------|
| *(neither)* | Workspace (`default`) | Workspace Admin | Operates on workspace-scoped profiles; list returns all visible profiles (workspace + platform + built-in) |
| `--workspace team-ml` | Workspace (`team-ml`) | Workspace Admin | Same, targeting a specific workspace |
| `--global` | Platform | Platform Admin | Operates on platform-scoped profiles; list returns platform custom + built-in only |

```shell
# Platform Admin imports an org-wide custom profile (platform-scoped)
openshell provider profile import --global -f internal-gitlab.yaml

# Workspace Admin imports a team-specific override (workspace-scoped)
openshell provider profile import --workspace team-ml -f internal-gitlab.yaml

# All visible profiles: workspace custom + platform custom + built-in
# When the same ID exists at both scopes, both appear with distinct SCOPE values
openshell provider list-profiles --workspace team-ml
```

Example output showing source and scope columns:

```
Available Provider Profiles:

  INFERENCE
    ID                     SCOPE       SOURCE     NAME                               ENDPOINTS
    anthropic              platform    user       Anthropic                          1  inference
    anthropic              workspace   user       Anthropic (custom endpoints)       3  inference
    openai                             builtin    OpenAI                             1  inference

  OTHER
    ID                     SCOPE       SOURCE                    NAME                               ENDPOINTS
    gov-api                            interceptor/governance    Governance API                     1
```

Providers reference profiles by type. The `--global-profile` flag on
`provider create` controls which scope the provider resolves its profile from.
When a workspace profile shadows a platform profile, a provider without
`--global-profile` uses the workspace version:

```shell
# Uses the workspace "anthropic" profile (shadows platform)
openshell provider create --type anthropic --name my-anthropic

# Explicitly uses the platform profile
openshell provider create --type anthropic --name my-anthropic --global-profile
```

### Python SDK Surface

The Python SDK requires `workspace` as an explicit keyword-only argument on
all workspace-scoped operations (`create()`, `get()`, `delete()`, `list()`,
etc.). Unlike the CLI, the SDK does not default to `"default"` — programmatic
callers must always specify the target workspace. This is a deliberate design
choice: agents and automation scripts should be explicit about which workspace
they operate on, and a silent default could mask workspace-routing bugs.
Passing `workspace=None` to `list()` uses `all_workspaces=True` for
cross-workspace queries.

## Implementation plan

The implementation builds on the existing authentication, RBAC, and OCSF
foundations. The work can be phased to deliver value incrementally:

- **Phase 1: Workspace and membership model.** Add the `Workspace` resource
  with standard `ObjectMeta` and `CreateWorkspace`, `GetWorkspace`,
  `ListWorkspaces`, `DeleteWorkspace` RPCs gated to Platform Admins. Add
  `workspace` field to `ObjectMeta` for Sandbox and Provider resources,
  validated against existing workspaces on create. All workspace-scoped
  resources inherit workspace from their parent sandbox or workspace context:
  services, SSH sessions, policy revisions, policy drafts, settings, provider
  refresh state, inference routes, audit records, and log/watch streams.
  Provider profiles use two-tier scoping with workspace shadowing: the same
  profile ID can exist at both platform and workspace scope. Workspace profiles
  shadow platform profiles for workspace-scoped operations; the platform
  profile is the fallback when no workspace override exists. The
  `EffectiveProviderProfileCatalog` stores layered entries per profile ID —
  an effective profile (workspace if present, otherwise platform) and an
  optional platform fallback for the shadowed entry.
  `ListProviderProfiles` returns all profiles visible in the requested context
  with `source` (provenance: `builtin`, `user`, `interceptor/{name}`) and
  `scope` (visibility: `platform`, `workspace`, or empty for non-scoped
  sources) metadata on each entry. When a workspace profile shadows a
  platform profile, both appear in the listing with distinct scope values.
  Built-in and interceptor profile IDs are reserved — user-managed profiles
  cannot shadow them at any scope. Shadowing only applies between
  user-managed scopes (workspace over platform). Builtins and
  interceptor-provided profiles remain scope-agnostic.
  Add `UpdateProviderProfiles` RPC for
  in-place updates to existing custom profiles, with optimistic concurrency
  control via a `resource_version` field on `ProviderProfile` — updates must
  supply the current version to prevent stale overwrites.
  The `Provider` datamodel message gains a
  `profile_workspace` field that binds a provider to a specific workspace's
  profile scope — when set, the provider resolves profiles from that workspace
  rather than the platform scope, enabling workspace-scoped provider
  configuration without duplicating the provider record itself.
  Implement workspace-scoped
  storage and filtering in gRPC handlers. Add the membership store with `(workspace, principal_subject) →
  role` records and `AddWorkspaceMember`, `RemoveWorkspaceMember`,
  `ListWorkspaceMembers` RPCs. Create the `default` workspace on gateway
  startup for backwards compatibility. Sandbox name uniqueness shifts from
  globally unique to unique-within-workspace. The current global uniqueness
  constraint `(object_type, name)` shifts to `(object_type, workspace, name)`.
  Existing resources are backfilled to the `default` workspace during
  migration. Service endpoint hostnames always include workspace
  (`{workspace}--{sandbox}--{service}.{base-domain}`), including the `default`
  workspace. Always including the workspace eliminates hostname parsing
  ambiguity — with a variable number of `--`-delimited segments, the parser
  cannot distinguish `{sandbox}--{service}` from `{workspace}--{sandbox}`
  without knowing whether the default workspace was omitted. The consistent
  three-segment format makes parsing unambiguous: two segments is
  `{workspace}--{sandbox}`, three is `{workspace}--{sandbox}--{service}`.
  This is a breaking change: existing two-segment hostnames
  (`{sandbox}--{service}.{domain}`) will fail to parse after the upgrade.
  Backward compatibility is desirable but not a hard requirement
  at this stage — existing users must recreate service endpoints when upgrading.
  Add a cross-workspace `list_by_type(object_type, limit, offset)` store method
  for internal infrastructure operations (reconciler, resume, provider refresh)
  that need to query workspace-scoped resources across all workspaces. Thread
  workspace through `StoredProviderCredentialRefreshState` so the provider
  refresh worker can unambiguously resolve workspace-scoped providers — with
  multiple workspaces, `provider_name` alone is insufficient because different
  workspaces can have same-named providers. Add `all_workspaces` field to
  workspace-scoped list RPCs for Platform Admin cross-workspace visibility.
  Add `ObjectWorkspace::requires_workspace()` trait method and validation in
  store write helpers (`put_message`, `put_scoped_message`) that returns an
  error when a workspace-scoped resource is persisted with an empty workspace.
  Rename inference RPCs from `SetClusterInference`/`GetClusterInference` to
  `SetInferenceRoute`/`GetInferenceRoute` (and `ClusterInferenceConfig` to
  `InferenceRouteConfig`) to reflect that inference routes are now
  workspace-scoped rather than cluster-global.
  **Additional breaking changes:** The Docker/Podman container label key
  changes from `openshell.sandbox_namespace` to `openshell.workspace` —
  existing containers will not be discovered after the upgrade; delete all
  sandboxes before upgrading. SSH config host aliases change from
  `openshell-{sandbox}` to `openshell-{sandbox}.{workspace}` — existing
  SSH configs must be regenerated after the upgrade.

- **Phase 2: Expanded role model and authorization enforcement.** Extend the
  RBAC system from two-tier (admin/user) to three user roles (Platform Admin,
  Workspace Admin, User). Add proto-driven authorization metadata via custom
  method options and `prost_reflect::DescriptorPool`. Implement
  `authorize_workspace()` and `WorkspaceScoped` trait for workspace-scoped
  access guards in gRPC handlers. Replace the `#[rpc_authz]` proc macro with
  descriptor pool-based lookup. Add Workspace Admin role with per-workspace
  management capabilities.

- **Phase 3: Kubernetes driver — managed mode (default).** The driver creates
  Kubernetes namespaces on demand using the naming convention
  `openshell-{gateway-id}-{workspace-name}`. The watcher shifts from
  single-namespace `Api::namespaced_with()` to cluster-wide list/watch with
  OpenShell label filtering. Once all sandboxes in a workspace are deleted,
  the driver deletes the corresponding Kubernetes namespace. Helm chart adds
  `ClusterRole` and `ClusterRoleBinding` for namespace create/delete and
  multi-namespace list/watch permissions (enabled by default). Includes
  idempotent create with retry to handle races. The reconciler and watch
  event handler use the cross-workspace `list_by_type` store query (from
  Phase 1) to compare driver inventory against all stored sandboxes. When
  the driver reports a sandbox not in the store, the gateway resolves its
  workspace by reverse-mapping `DriverSandbox.namespace` through the
  workspace-to-namespace configuration (parsing the managed-mode naming
  convention or looking up the operator-mode identity mapping).

- **Phase 4: Kubernetes driver — operator mode.** Alternative mode where the
  OpenShell workspace name maps one-to-one to a pre-existing Kubernetes
  namespace. The driver accepts per-sandbox workspaces from the gateway
  (populated via `driver_sandbox_from_public()`) and renders sandboxes into the
  corresponding Kubernetes namespace. No namespace create/delete permissions
  required. Opt-in via `workspace_mode = "operator"` in the driver config.
  Shares the cluster-wide watcher infrastructure from Phase 3.

- **Phase 5: Audit trail enhancements.** Add `ApiActivity` OCSF event type for
  control-plane mutations. Tag all sandbox activity events with the
  authenticated principal's subject and workspace. Extend OCSF JSONL export
  with principal and workspace attribution fields.

- **Phase 6: Quota enforcement.** Implement per-workspace quota checks at the
  gateway. Add quota configuration surface for Platform Admins and Workspace
  Admins. Quota limits are stored as workspace properties and usage counters
  are tracked in the existing durable object store.

Phases 1 and 2 are sequential prerequisites — Phase 2 depends on Phase 1.
Phase 4 depends on Phase 3 (shared watcher infrastructure). Phases 3, 5, and 6
can be reordered relative to each other based on priority. Phases 5 and 6
depend only on Phase 1.

## Risks

- **Migration complexity.** Existing deployments have no workspace concept. The
  `default` workspace provides backwards compatibility, but platform teams with
  established workflows may need to re-organize resources when adopting
  workspaces. Migration tooling and documentation will be needed.

- **Proto surface growth.** Adding `workspace` and role-related fields to the
  proto increases the API surface that must be maintained across versions. The
  design intentionally keeps new proto fields minimal (`workspace` on
  `ObjectMeta`) and uses labels for soft grouping to limit this.

- **RBAC complexity.** Three roles with workspace scoping is significantly more
  complex than the current two-tier model. Misconfiguration could lead to
  privilege escalation or overly restrictive access. Clear defaults, validation,
  and documentation are essential.

- **Performance at scale.** Workspace-scoped filtering and quota enforcement add
  per-request overhead. For deployments with many workspaces and users, the
  filtering and quota checks must be efficient. Indexing strategies need
  consideration during implementation.

- **Quota enforcement races.** Concurrent sandbox creation within a workspace
  could race against quota limits. The quota check and sandbox creation must be
  atomic or use optimistic concurrency control with retry.

- **Kubernetes ClusterRole requirements.** Both operator and managed modes require
  a `ClusterRole` for cluster-wide list/watch. Managed mode additionally
  requires namespace create/delete permissions. Some clusters restrict these
  grants. The Helm chart must make these conditional and clearly documented.

- **Managed mode race conditions.** Kubernetes namespace creation is async.
  Sandbox creation may race against it. The naming convention
  (`openshell-{gateway-id}-{workspace-name}`) is deterministic, so concurrent
  creates from the same gateway are idempotent.

- **In-flight sandboxes during workspace deletion.** Workspace deletion is
  rejected if active sandboxes exist. Once all sandboxes are removed, the
  driver deletes the corresponding Kubernetes namespace.

- **Multi-gateway coordination.** The `openshell-{gateway-id}-{workspace-name}`
  naming convention partitions Kubernetes namespaces by gateway, so multiple
  gateways can share a cluster without collisions. However, this means each
  gateway manages its own workspace set independently — cross-gateway workspace
  visibility requires external coordination.

- **Cross-workspace store query authorization.** The `list_by_type` store method
  has no access-control gate — it is a persistence-layer primitive. Authorization
  for cross-workspace queries is enforced at the gRPC handler level (Platform
  Admin check for `all_workspaces` on list RPCs) and by code-level access
  control for internal operations (only the reconciler, resume, and refresh
  worker call it). This relies on internal code discipline rather than an
  enforced store-level boundary. A future extension could add a store-level
  caller identity parameter if defense-in-depth is desired.

- **Remote compute driver channel security.** The `RemoteComputeDriver` gRPC
  channel does not currently enforce authentication. For deployments where the
  driver runs as a separate service (rather than a co-located subprocess), the
  channel should use mTLS or a shared credential. Without transport security,
  any network-adjacent process could impersonate the gateway to the driver.

## Future Work

### Cross-workspace sandbox sharing

This design treats the workspace as the access control boundary — all workspace
members have full access to all sandboxes in the workspace, and there is no
per-sandbox sharing mechanism within a workspace.

A future extension could allow sharing a sandbox with a principal who is not a
member of the workspace. The motivating use case: a platform team runs a
"shared-tools" workspace containing sandboxes with internal services (a test
database, a mock API, a reference environment). Engineers in other workspaces
need exec access to specific sandboxes in shared-tools without becoming full
members of that workspace — full membership would grant them access to all
sandboxes and providers in shared-tools, which is broader than needed.

This would require a scoped access grant that gives the target principal access
to a specific sandbox without conferring workspace membership. The grant would
need to be auditable, revocable, and limited to the specific sandbox — not a
general workspace bypass. Design considerations include whether the sharee can
list other resources in the workspace, how provider credential exposure is
handled (the sandbox environment may already have credentials injected), and
whether the grant survives sandbox recreation.

### Built-in profile visibility scoping

Built-in profiles (claude-code, github, nvidia, etc.) are currently included
in both workspace-scoped and platform-scoped profile listings. This is
convenient but may be misleading — a Workspace Admin seeing built-in profiles
in their workspace listing might assume they can modify or override them at
the workspace level.

A future change could restrict built-in profiles to the platform-scoped
listing only (`--global`). Workspace-scoped listings would show only custom
profiles that have been explicitly imported into that workspace. This would
make the listing semantics cleaner: workspace scope shows what the Workspace
Admin has configured, platform scope shows what the Platform Admin and the
system provide. The trade-off is discoverability — new users listing profiles
in their workspace would see nothing until a Workspace Admin imports profiles,
which could be confusing for single-player deployments.

### Workspace-scoped settings

Runtime settings (`providers_v2_enabled`, `ocsf_json_enabled`,
`agent_policy_proposals_enabled`, `proposal_approval_mode`) currently use
two-tier resolution: a gateway-global value overrides per-sandbox values.
A Workspace Admin who wants to enable agent policy proposals or set auto-
approval mode for their workspace must ask a Platform Admin to set it
globally, or configure it on each sandbox individually.

A workspace-scoped settings tier would sit between gateway-global and
per-sandbox: gateway-global > workspace > sandbox. This would let Workspace
Admins control operational knobs for their workspace without Platform Admin
involvement and without per-sandbox configuration burden. The resolution
chain would check gateway-global first (Platform Admin override), then
workspace (Workspace Admin default for the workspace), then sandbox
(per-sandbox override), then the built-in default.

Design considerations:

- Some settings are inherently gateway-wide feature flags
  (`providers_v2_enabled`) and may not make sense at workspace scope. The
  settings registry could gain a `scopes` field indicating which tiers a
  setting participates in.
- The `UpdateConfig` RPC currently distinguishes `global: true` from
  sandbox-targeted updates. A workspace tier would need a third targeting
  mode in the request, or workspace settings could use a separate RPC.
- Settings resolution already loads both global and sandbox settings on every
  `GetSandboxConfig` call. Adding a workspace tier adds one more store read
  per config fetch. Caching or batching may be needed at scale.

### Machine identity via OIDC workload identity

CI/CD pipelines, agent harnesses, and other machine workloads could
authenticate to the gateway using OIDC workload identity tokens issued by
their platform (GitHub Actions, GitLab CI, GCP, AWS). The gateway would
validate these tokens and resolve the token's `sub` claim to a workspace
membership, following the same `authorize_workspace` path as human principals.
No stored API keys or service account secrets would be required.

The most common deployment — human users authenticating via corporate SSO
and machine workloads authenticating via CI/CD platform OIDC — requires
multi-provider OIDC support (see Non-goals). The workspace and membership
model introduced in this RFC is designed to support workload identity without
changes: a machine workload's OIDC subject is added as a workspace member
with the User role, and the standard authorization path applies.

### SandboxStatus portability

`SandboxStatus` exposes platform-specific coordinates (`sandbox_name`,
`agent_pod`, `agent_fd`, `sandbox_fd`) that are informational and
display-oriented today. These fields are always accessed in the context of a
parent `Sandbox` record that carries the workspace, so they do not need
workspace context themselves.

As workspace-to-namespace mapping modes evolve (shared namespace, dedicated
namespace per workspace, operator mode with pre-provisioned namespaces),
revisit whether these fields remain portable or need to become abstract and
self-describing regardless of the active mapping method. In particular:

- `sandbox_name` currently holds the bare user-facing name. In shared-namespace
  mode the Kubernetes resource name differs (`{workspace}--{name}`), but the
  status field intentionally carries the bare name for display. If
  namespace-per-workspace mode is added, this distinction may become moot.
- `agent_pod` is operationally critical — it correlates supervisor connections
  to specific pods. Its value is Kubernetes-specific and may need an
  abstraction layer for non-Kubernetes drivers.
- `agent_fd` and `sandbox_fd` are currently unused by consumers. Evaluate
  whether to remove them rather than carry them forward.

## Alternatives

### Flat label-based tenancy (no workspaces)

Use labels alone for all isolation, without a first-class workspace concept.
Users would filter by label, and access control would use label selectors.

This was rejected because labels are a soft grouping mechanism with no
enforcement guarantee. A mislabeled resource would be visible across tenant
boundaries. Hard isolation requires a first-class field that the system enforces
at every access point, not a convention that depends on correct labeling.

### One gateway per team

Instead of multi-tenancy, deploy separate gateways per team. This provides
complete isolation by default.

This was rejected because it creates operational overhead (N gateways to
manage), prevents resource sharing across teams, and makes cross-team
collaboration impossible. It also pushes the multi-tenancy problem to the
infrastructure layer without solving it. In practice, even within a single
team, individual members typically have private per-user API keys for services
like Claude or Codex that they cannot share with teammates. This pushes
team-level deployments toward per-user gateways, compounding the operational
cost. The multi-player proposal mitigates this by giving each user their own
workspace on a shared gateway for credential isolation, while allowing teams
to share workspaces for collaboration where appropriate.

### OPA/Rego for authorization

Use a policy language like OPA/Rego for fine-grained authorization decisions
instead of role-based access control.

This was considered but deferred. The current need is coarse-grained role-based
isolation, not attribute-based policy evaluation. OPA/Rego authorization could
be layered on top of the workspace and role model in a future RFC if
fine-grained policies are needed.

## Prior art

- **Kubernetes namespaces and RBAC.** The workspace model draws from Kubernetes
  conventions: hard isolation boundaries, labels for soft grouping, and RBAC
  with role bindings scoped to boundaries. The term "workspace" is intentionally
  distinct from "Kubernetes namespace" to avoid conflation — an OpenShell
  workspace may map to a Kubernetes namespace, but the concepts are independent.

- **GitHub organizations and teams.** GitHub's model of organizations
  (workspaces) with teams (label-based grouping) and per-repo role assignments
  informed the separation between hard boundaries and soft grouping.

- **AWS IAM.** AWS's account-level isolation with IAM roles and policies within
  accounts informed the quota and credential scoping model. The lesson is that
  hard account boundaries with delegated administration scales better than
  flat permission models.

## Appendix: End-to-End Workspace Lifecycle

This walkthrough traces a workspace from creation through sandbox teardown,
showing the authorization check at each step.

**1. Platform Admin creates a workspace.**

```text
CreateWorkspace { name: "team-ml" }
→ global_role = "platform_admin" → pass
→ persist Workspace { name: "team-ml" }
```

**2. Platform Admin adds a Workspace Admin.**

```text
AddWorkspaceMember { workspace: "team-ml", subject: "bob@corp.example.com", role: WORKSPACE_ADMIN }
→ global_role = "platform_admin" → bypass membership check → pass
→ persist membership ("team-ml", "bob@corp.example.com", Admin)
```

**3. Workspace Admin adds a User.**

```text
AddWorkspaceMember { workspace: "team-ml", subject: "alice@corp.example.com", role: USER }
→ authorize_workspace("team-ml", WorkspaceRole::Admin)
→ lookup ("team-ml", "bob@corp.example.com") → Admin → pass
→ validate: Workspace Admins cannot assign the Admin role → USER is allowed
→ persist membership ("team-ml", "alice@corp.example.com", User)
```

**4. Workspace Admin adds a provider.**

```text
CreateProvider { workspace: "team-ml", name: "claude-key", type: "claude", credentials: {...} }
→ authorize_workspace("team-ml", WorkspaceRole::Admin) → pass
→ persist Provider { workspace: "team-ml", name: "claude-key" }
```

**5. User creates a sandbox.**

```text
CreateSandbox { workspace: "team-ml", name: "my-sandbox", providers: ["claude-key"] }
→ authorize_workspace("team-ml", WorkspaceRole::User)
→ lookup ("team-ml", "alice@corp.example.com") → User → pass
→ validate provider "claude-key" exists in "team-ml" → yes
→ resolve effective policy: gateway default + provider profiles for ["claude-key"]
→ persist Sandbox { workspace: "team-ml", name: "my-sandbox" }
→ dispatch to driver (K8s managed → namespace "openshell-prod-team-ml")
```

**6. User deletes the sandbox.**

```text
DeleteSandbox { workspace: "team-ml", name: "my-sandbox" }
→ authorize_workspace("team-ml", WorkspaceRole::User) → pass
→ drain and delete sandbox
→ dispatch delete to driver
```

Membership records are stored in the durable object store as a
`(workspace, principal_subject) → role` mapping, separate from the Workspace
resource itself. This follows the Kubernetes pattern where RoleBindings are
independent resources, not properties of the Namespace object.

### Sandbox Supervisor Lifecycle

The sandbox supervisor uses a separate authentication path from user roles.
This walkthrough continues from step 5 above, showing how the supervisor
bootstraps and operates scoped to a single sandbox.

**7. Gateway mints a sandbox JWT at creation time.**

```text
CreateSandbox → persist sandbox (uuid-a) → mint JWT:
JWT { sub: "spiffe://openshell/sandbox/uuid-a", sandbox_id: "uuid-a" }
→ token injected into container/pod via compute driver
```

**8. Supervisor connects to the gateway.**

```text
ConnectSupervisor (bidirectional stream)
Auth: Bearer <sandbox-jwt>
→ SandboxJwtAuthenticator → Principal::Sandbox { sandbox_id: "uuid-a" }
→ router: is_sandbox_callable("ConnectSupervisor") → yes
→ supervisor sends SupervisorHello { sandbox_id: "uuid-a" }
→ ensure_sandbox_principal_scope: JWT sandbox_id == hello sandbox_id → pass
→ register session, send SessionAccepted, notify driver: sandbox ready
```

**9. Supervisor fetches provider credentials.**

```text
GetSandboxProviderEnvironment { sandbox_id: "uuid-a" }
→ enforce_sandbox_scope: JWT sandbox_id == request sandbox_id → pass
→ gateway resolves providers for sandbox uuid-a (workspace-internal lookup)
→ return { ANTHROPIC_API_KEY: "sk-...", ... }
```

**10. Cross-sandbox and cross-principal access is rejected.**

```text
Supervisor-A → GetSandboxProviderEnvironment { sandbox_id: "uuid-b" }
→ enforce_sandbox_scope: "uuid-a" != "uuid-b" → PERMISSION_DENIED

Supervisor-A → ListSandboxes { workspace: "team-ml" }
→ router: is_sandbox_callable("ListSandboxes") → false → PERMISSION_DENIED
```

**11. Supervisor learns its workspace from the config response.**

```text
GetSandboxConfig { sandbox_id: "uuid-a" }
→ response includes workspace: "team-ml"
→ supervisor caches workspace for subsequent RPCs
```

The supervisor discovers its workspace from the `workspace` field in
`GetSandboxConfigResponse`, returned by its first settings poll. It caches
this value and uses it for workspace-scoped RPCs such as `UpdateConfig`
(policy sync), `SubmitPolicyAnalysis`, and `GetDraftPolicy`. The supervisor's
authorization surface remains a single sandbox UUID — the workspace is used
only to scope resource lookups, not for access control.
