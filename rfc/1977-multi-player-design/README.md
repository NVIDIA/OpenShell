---
authors:
  - "@derekwaynecarr"
state: draft
links:
  - https://github.com/NVIDIA/OpenShell/issues/1977
---

# RFC 1977 - Multi-Player Support

## Summary

This RFC proposes adding multi-user support to OpenShell. Today, sandboxes and
providers are gateway-global with no ownership tracking or isolation between
users. This proposal introduces namespaces as hard isolation boundaries, an
expanded role model (Platform Admin, Namespace Admin, Operator, User, Service
Account), owner-scoped access guards, per-namespace and per-user quota
enforcement, and audit trail enhancements. A `default` namespace preserves
backwards compatibility for single-player deployments.

## Motivation

OpenShell is currently a single-player experience. Every authenticated user sees
every sandbox and every provider. There is no concept of resource ownership,
tenant isolation, or delegated administration. This blocks several adoption
scenarios:

- **Enterprise teams** cannot share a gateway without seeing each other's
  sandboxes, credentials, and activity. There is no way to scope visibility or
  enforce per-team resource limits.

- **CI/CD and agent orchestration** workflows need machine identities (service
  accounts) with scoped, rotatable credentials. Today the only option is
  full-privilege OIDC tokens or mTLS certs with no role granularity beyond
  admin/user.

- **Compliance and incident response** teams need audit trails that attribute
  every sandbox and control-plane action to a specific principal. The existing
  OCSF infrastructure logs sandbox-level events but does not consistently tag
  them with the creating principal.

- **Cost attribution** is impossible without ownership metadata. Operators cannot
  answer "which team consumed how many GPU-hours last month."

The existing codebase provides a foundation: OIDC authentication, a principal
model (User/Sandbox/Anon), two-tier RBAC, OCSF event infrastructure, and labels
on `ObjectMeta`. The gap is the isolation, ownership, and governance layer on
top.

Leaving the current design unchanged limits OpenShell to single-operator,
single-team deployments, which constrains adoption and forces organizations to
run one gateway per team.

## Non-goals

- **Cross-gateway federation.** This RFC scopes multi-player to a single gateway.
  Multi-gateway federation (e.g., routing users to regional gateways) is a
  separate concern.
- **Fine-grained ABAC or policy language.** The role model uses coarse-grained
  roles with namespace scoping, not attribute-based access control or a policy
  DSL like OPA/Rego for authorization decisions.
- **UI/dashboard for user management.** This RFC covers the API and data model.
  Administrative UIs are a follow-on.
- **Billing integration.** Cost attribution metadata is in scope; integration
  with billing systems is not.
- **Sandbox-to-sandbox networking isolation.** Network isolation between
  namespaces at the container/pod level is out of scope; this RFC addresses
  control-plane isolation only.

## Proposal

### System Roles

The role model expands from the current two-tier (admin/user) to five roles:

| Role | Description |
|------|-------------|
| **Platform Admin** | Manages gateway configuration, auth providers, compute drivers, and quotas. Full visibility across all namespaces. |
| **Namespace Admin** | Manages users, providers, policies, and quotas within a single namespace. Cannot change gateway infra or access other namespaces. |
| **Operator** | Read-only view of all sandboxes and audit logs across namespaces for monitoring, incident response, and compliance. Cannot create or modify sandboxes. |
| **User** | Creates and manages their own sandboxes within assigned namespaces. Uses credentials available in those namespaces. Default role for OIDC-authenticated humans. |
| **Service Account** | Machine identity for CI/CD, automation, or agent-to-agent orchestration. Scoped to a namespace with explicit grants. |

### Namespaces

A namespace is a hard isolation boundary. Sandboxes, providers, and policies
within a namespace are invisible to other namespaces. Every resource belongs to
exactly one namespace. A `default` namespace exists for single-player backwards
compatibility.

This is a first-class field in `ObjectMeta` alongside `created_by`. Within a
namespace, organizational grouping (teams, projects, cost centers) uses the
existing label system with well-known key conventions (e.g.,
`openshell.dev/team=infra`, `openshell.dev/project=alpha`) rather than
additional dedicated fields. This:

- Gives a clear security boundary (namespace) without over-modeling
  organizational hierarchy.
- Allows multiple overlapping groupings within a namespace via labels.
- Reuses Kubernetes-style patterns that users already understand.
- Keeps the proto surface minimal: `namespace` and `created_by` are the only
  new fields.

### Ownership and Access Control

Every sandbox gets a `created_by` field in `ObjectMeta` populated from the
authenticated principal's subject. Access control is owner-scoped within
namespaces:

- **Users** can only exec into, delete, or view sandboxes they own within their
  namespace.
- **Namespace Admins** can manage any sandbox in their namespace.
- **Platform Admins** can manage everything.
- **Operators** can view everything (read-only).
- `ListSandboxes` filters to owned sandboxes within the caller's namespace by
  default; Namespace Admins see all sandboxes in their namespace; Platform
  Admins and Operators can list across namespaces.

A User can share a sandbox with another user within the same namespace
(read-only or exec access) without making it globally visible. Platform Admins
can grant targeted cross-namespace access for specific use cases (e.g., a shared
services namespace).

### Policy Assignment

Platform Admins set gateway-wide default policies. Namespace Admins can tighten
(but not loosen) policies for their namespace. Users cannot modify policies.
This ensures a minimum security baseline while allowing per-namespace
customization.

### Provider Credential Scoping

Providers belong to a namespace. A User can only attach providers available in
their namespace when creating a sandbox. Users cannot see raw credential
material; they reference providers by name. Namespace Admins grant specific
provider credentials to users or service accounts within their namespace.

### Authentication

- **Multi-provider OIDC.** Support multiple OIDC providers (corporate SSO,
  GitHub, Google) mapped to internal identities. The authenticator chain already
  supports this; the gap is identity federation and mapping to the expanded role
  model.
- **API key authentication.** For service accounts and CI/CD. Long-lived keys
  scoped to a namespace and role, stored hashed, rotatable.
- **mTLS for service-to-service.** Already partially supported via
  `MtlsAuthConfig`. Extend to map cert OU/CN to roles.

### Audit Trail

- **Control-plane audit log.** Every mutating gRPC call (`CreateSandbox`,
  `DeleteSandbox`, `CreateProvider`, `UpdatePolicy`) emits an OCSF
  `ConfigStateChange` or `ApiActivity` event with the authenticated principal,
  action, target resource, and timestamp. Builds on the existing OCSF
  infrastructure.
- **Session attribution.** Sandbox activity (network, process, SSH events)
  tagged with the creating principal's subject, so security teams can trace
  sandbox behavior back to a human or service account.
- **Audit log export.** Structured OCSF JSONL shipped to SIEM/log aggregation.
  Operators can query "who created sandbox X" or "what did user Y do between T1
  and T2."

### Resource Governance

- **Per-namespace quotas.** Max concurrent sandboxes, max GPU allocations, max
  sandbox lifetime per namespace. Enforced at the gateway before sandbox
  creation.
- **Cost attribution.** Sandbox resource consumption tagged with owner,
  namespace, and labels for chargeback.

### Kubernetes Compute Driver: Namespace Mapping

OpenShell namespaces are a logical concept. When the Kubernetes compute driver
renders sandboxes onto a cluster, it must map each OpenShell namespace to a
Kubernetes namespace. The driver supports two modes, configured per deployment:

**Managed mode** (default) — the driver creates and deletes Kubernetes
namespaces on demand. The Kubernetes namespace name is derived from the gateway
identifier and the OpenShell namespace:
`openshell-{gateway-id}-{namespace-name}`. For example, if the gateway
identifier is `prod` and the OpenShell namespace is `team-ml`, the Kubernetes
namespace is `openshell-prod-team-ml`.

The gateway identifier prefix ensures that multiple gateways can operate on a
common Kubernetes cluster without namespace collisions. Each gateway owns its
own set of Kubernetes namespaces and can independently create, watch, and delete
them. The gateway identifier is already part of the gateway's bootstrap
configuration.

When an OpenShell namespace is deleted, the driver deletes the corresponding
Kubernetes namespace after draining all sandboxes.

Managed mode requires a `ClusterRole` with namespace create/delete permissions.
The Helm chart includes conditional `ClusterRole` and `ClusterRoleBinding`
templates that are enabled by default.

**Operator mode** — an alternative for environments where the gateway should not
create Kubernetes namespaces. The OpenShell namespace name maps one-to-one to a
Kubernetes namespace of the same name. If a sandbox belongs to OpenShell
namespace `team-ml`, the driver renders it into the Kubernetes namespace
`team-ml`. No mapping configuration is required. The Kubernetes namespaces must
be pre-provisioned — the driver has no permission to create or delete them.

This direct identity mapping enables the OpenShell gateway to operate as a
natural Kubernetes-style operator: it receives a desired state (sandbox in
namespace X) and renders it into the corresponding cluster namespace. Operators
manage Kubernetes namespaces through their existing tooling (kubectl, GitOps,
Terraform) and OpenShell follows.

```toml
[openshell.drivers.kubernetes]
namespace_mode = "operator"  # opt-in; default is "managed"
```

**Watcher strategy.** Today the Kubernetes driver watches a single namespace via
`Api::namespaced_with()`. With multiple namespaces, the driver shifts to a
cluster-wide list/watch filtered by OpenShell labels (e.g.,
`openshell.dev/managed-by=gateway`). This follows the standard Kubernetes
operator pattern for multi-namespace controllers. A per-namespace watcher
approach does not scale — it requires O(n) API connections and complicates
dynamic namespace addition/removal. The cluster-wide watch requires a
`ClusterRole` granting list/watch across namespaces (applicable to both operator
and managed modes).

**Docker driver.** The Docker driver's existing `sandbox_namespace` label
naturally maps to the OpenShell namespace value with no additional API concepts
to manage.

### Service Account Workflows

- **CI/CD sandbox creation.** A service account creates sandboxes on behalf of a
  pipeline within its namespace, labeled for the target project, with limited
  lifetime and no interactive access.
- **Agent orchestration.** One agent's service account creates sandboxes for
  sub-agents, each getting their own sandbox principal. The parent service
  account retains visibility.

## Implementation plan

The implementation builds on the existing authentication, RBAC, and OCSF
foundations. The work can be phased to deliver value incrementally:

- **Phase 1: Namespace and ownership model.** Add `namespace` and `created_by`
  fields to `ObjectMeta` in the proto. Implement namespace-scoped storage and
  filtering in gRPC handlers. Create the `default` namespace for backwards
  compatibility. Sandbox name uniqueness shifts from globally unique to
  unique-within-namespace. Existing sandboxes are backfilled into the `default`
  namespace. All existing single-player behavior continues unchanged.

- **Phase 2: Kubernetes driver — managed mode (default).** The driver creates
  Kubernetes namespaces on demand using the naming convention
  `openshell-{gateway-id}-{namespace-name}`. The watcher shifts from
  single-namespace `Api::namespaced_with()` to cluster-wide list/watch with
  OpenShell label filtering. Namespace cascade delete drains sandboxes before
  removing the Kubernetes namespace. Helm chart adds `ClusterRole` and
  `ClusterRoleBinding` for namespace create/delete and multi-namespace
  list/watch permissions (enabled by default). Includes idempotent create with
  retry to handle races.

- **Phase 3: Kubernetes driver — operator mode.** Alternative mode where the
  OpenShell namespace name maps one-to-one to a pre-existing Kubernetes
  namespace. The driver accepts per-sandbox namespaces from the gateway
  (populated via `driver_sandbox_from_public()`) and renders sandboxes into the
  corresponding Kubernetes namespace. No namespace create/delete permissions
  required. Opt-in via `namespace_mode = "operator"` in the driver config.

- **Phase 4: Expanded role model.** Extend the RBAC system from two-tier
  (admin/user) to five roles. Implement owner-scoped access guards in gRPC
  handlers. Add Namespace Admin role with per-namespace management capabilities.
  Add Operator role with read-only cross-namespace access.

- **Phase 5: Provider credential scoping.** Scope provider resources to
  namespaces. Add credential delegation from Namespace Admins to users and
  service accounts. Enforce provider visibility restrictions in sandbox creation.

- **Phase 6: API key authentication and service accounts.** Implement API key
  authenticator with hashed key storage, namespace-scoped keys, and rotation.
  Add service account principal type with explicit grants.

- **Phase 7: Audit trail enhancements.** Add `ApiActivity` OCSF event type for
  control-plane mutations. Tag all sandbox activity events with the creating
  principal's subject. Extend OCSF JSONL export with attribution fields.

- **Phase 8: Collaboration.** Implement sandbox sharing within namespaces.
  Add cross-namespace access grants for Platform Admins. Implement label-scoped
  sandbox listing.

- **Phase 9: Quota enforcement.** Implement per-namespace quota checks at the
  gateway. Add quota configuration surface for Platform Admins and Namespace
  Admins.

Each phase is independently shippable and testable. Phase 1 is the prerequisite
for all subsequent phases but does not require any of them. Phases 2-9 can be
reordered based on priority.

## Risks

- **Migration complexity.** Existing deployments have no namespace concept. The
  `default` namespace provides backwards compatibility, but operators with
  established workflows may need to re-organize resources when adopting
  namespaces. Migration tooling and documentation will be needed.

- **Proto surface growth.** Adding `namespace`, `created_by`, and role-related
  fields to the proto increases the API surface that must be maintained across
  versions. The design intentionally keeps the new proto fields minimal
  (namespace + created_by) and uses labels for soft grouping to limit this.

- **RBAC complexity.** Five roles with namespace scoping is significantly more
  complex than the current two-tier model. Misconfiguration could lead to
  privilege escalation or overly restrictive access. Clear defaults, validation,
  and documentation are essential.

- **Performance at scale.** Namespace-scoped filtering and quota enforcement add
  per-request overhead. For deployments with many namespaces and users, the
  filtering and quota checks must be efficient. Indexing strategies need
  consideration during implementation.

- **Quota enforcement races.** Concurrent sandbox creation within a namespace
  could race against quota limits. The quota check and sandbox creation must be
  atomic or use optimistic concurrency control with retry.

- **Kubernetes ClusterRole requirements.** Both operator and managed modes require
  a `ClusterRole` for cluster-wide list/watch. Managed mode additionally
  requires namespace create/delete permissions. Some clusters restrict these
  grants. The Helm chart must make these conditional and clearly documented.

- **Managed mode race conditions.** Kubernetes namespace creation is async.
  Sandbox creation may race against it. The naming convention
  (`openshell-{gateway-id}-{namespace-name}`) is deterministic, so concurrent
  creates from the same gateway are idempotent.

- **In-flight sandboxes during namespace deletion.** Deleting a namespace with
  active sandboxes requires a decision: block deletion until drained (safe,
  explicit), cascade delete all sandboxes, or mark as deleting and drain
  gracefully. The initial implementation should block deletion if active
  sandboxes exist.

- **Multi-gateway coordination.** The `openshell-{gateway-id}-{namespace-name}`
  naming convention partitions Kubernetes namespaces by gateway, so multiple
  gateways can share a cluster without collisions. However, this means each
  gateway manages its own namespace set independently — cross-gateway namespace
  visibility requires external coordination.

## Alternatives

### Flat label-based tenancy (no namespaces)

Use labels alone for all isolation, without a first-class namespace concept.
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
cost. The multi-player proposal mitigates this by letting team members in a
shared department use per-user credentials within a common gateway deployment,
collaborate on sandboxes where appropriate, and avoid multiplying platform
infrastructure.

### OPA/Rego for authorization

Use a policy language like OPA/Rego for fine-grained authorization decisions
instead of role-based access control.

This was considered but deferred. The current need is coarse-grained role-based
isolation, not attribute-based policy evaluation. OPA/Rego authorization could
be layered on top of the namespace and role model in a future RFC if
fine-grained policies are needed.

## Prior art

- **Kubernetes namespaces and RBAC.** The namespace model directly follows
  Kubernetes conventions: namespaces as hard isolation boundaries, labels for
  soft grouping, and RBAC with role bindings scoped to namespaces. OpenShell
  users familiar with Kubernetes will find the model intuitive.

- **GitHub organizations and teams.** GitHub's model of organizations
  (namespaces) with teams (label-based grouping) and per-repo role assignments
  informed the separation between hard boundaries and soft grouping.

- **AWS IAM.** AWS's account-level isolation with IAM roles and policies within
  accounts informed the quota and credential scoping model. The lesson is that
  hard account boundaries with delegated administration scales better than
  flat permission models.

## Open questions

- Should namespace creation be self-service (any authenticated user can create
  a namespace) or admin-only (Platform Admins create namespaces and assign
  Namespace Admins)?

- What is the identity mapping strategy for multi-provider OIDC? If a user
  authenticates via both corporate SSO and GitHub, how are those identities
  linked to a single internal principal?

- Should per-namespace quota limits be hard (reject sandbox creation) or soft
  (warn but allow, with alerting)?

- How should sandbox sharing permissions interact with policy tightening? If a
  Namespace Admin tightens a policy, does it retroactively affect shared
  sandboxes that were created under the looser policy?

- What is the storage backend for API keys and quota state? The gateway
  currently does not have a durable store beyond configuration files.

- Which resources beyond sandboxes are namespace-scoped? Sandboxes are the
  primary namespaced resource. Should settings, policies, and provider configs
  also be namespace-scoped from the start, or should they remain global and be
  extended later as the organizational model matures?

- In operator mode, should the driver validate that the target Kubernetes
  namespace exists before accepting a sandbox create, or should it let the
  Kubernetes API reject the request and surface the error?
