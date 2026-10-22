# Review areas and topics

Draft for community review. All names below are suggestions, not confirmed volunteers. No automatic requests, notifications, or new approval requirements are enabled by this draft.

Related work: [review routing and membership workflow (#4839)](https://github.com/NVIDIA/OpenShell/issues/4839).

## Purpose

Help authors and tools invite the right people to review OpenShell changes. Areas identify components and system boundaries with coordinating ownership. Topics identify expertise that can apply across several areas. An issue or PR can involve several topics.

These definitions follow the group's reviewed areas/topics proposal. This file is the proposed repository registry; the initial roster and format remain open for review.

## Join, change, or leave a roster

Open a PR editing the relevant membership tables below. Include your GitHub handle, role, status, and review scope. Explain the change in the PR description. A reviewed and merged PR is the sign-up mechanism for every role.

For the initial proposal, comment on the forthcoming registry PR to suggest additions, removals, or scope corrections. A proposed person's agreement is needed before their entry becomes confirmed. Contributions linked below are evidence for discussion, not proof of willingness or complete subject-matter coverage.

Subscriber entries require the individual's opt-in. No subscribers have been enrolled in this draft.

## Roles and coverage

| Role | Participation | Repository privilege |
| --- | --- | --- |
| maintainer | Available for review and approval in the recorded scope. | Maintain or admin. |
| reviewer | Available for selected review requests in the recorded scope. | Write. |
| subscriber | Receives relevant-work notifications and can contribute feedback without a review obligation. | Read, including public access. |

Roles follow repository privileges. Aligning today's privileges and the CNCF organization's permissions is outside this proposal. Suggested maintainer entries are drawn from [MAINTAINERS.md](MAINTAINERS.md); this registry does not grant repository access or change the existing maintainer approval check.

Target at least two confirmed maintainers covering every area and topic. Suggestions do not count as confirmed coverage. Scope limitations matter: two names do not establish two-person coverage of every specialty. All categories currently need confirmation; compliance and MCP also need additional maintainer nominations.

## Proposed routing behavior

Every ready-for-review PR has exactly one primary area for coordination and zero or more relevant topics. There is no hard topic limit; apply topics that merit specialist review. Other materially affected areas still contribute reviewers even when they are not the primary area.

Select a non-author maintainer from the primary area and relevant reviewers for the topics and secondary-area impact. Reuse people who cover several categories, distribute requests among eligible volunteers, and allow human reassignment. Notify opted-in subscribers separately and deduplicate notifications across categories.

Routing must use confirmed membership from the trusted merged registry. A PR changing this file cannot use its proposed membership to authorize its own review. Selection and notifications are follow-up work in #4839; they do not make every roster member a required approver.

## Registry format

Each category has a level-three heading containing its exact label, a scope description, and a membership table with these fixed columns:

| Column | Meaning |
| --- | --- |
| GitHub | One GitHub login, written as an @mention. |
| Role | `maintainer`, `reviewer`, or `subscriber`. |
| Status | `suggested` or `confirmed`. Only confirmed entries may receive automated requests or notifications. |
| Scope | The person's review scope or notification interests. |
| Basis | Optional contribution evidence for a suggestion, or `Self-nominated` for a volunteer. |

Use one row per person in a category. A maintainer or reviewer can cover several categories, but should not also have a subscriber row in the same category. Remove an entry through a reviewed PR to withdraw, or change it to subscriber when the person wants notifications without review requests.

## Areas

Areas are OpenShell-specific components or system boundaries. They represent the division of labor across the project. Keep the number of areas small enough to support named leads and reporting during community calls.

### area:build

CI/CD workflows, release pipelines, build targets, packaging, and artifact publication.

| GitHub | Role | Status | Scope | Basis |
| --- | --- | --- | --- | --- |
| @matthewgrossman | maintainer | suggested | Release pipelines and packaging | [#4754](https://github.com/NVIDIA/OpenShell/pull/4754) |
| @SDAChess | maintainer | suggested | Build tooling and compatibility checks | [#4611](https://github.com/NVIDIA/OpenShell/pull/4611) |

### area:drivers

Infrastructure orchestration, including compute scheduling, secret management, runtime integrations (GPU, Docker, virtual machines, Kata Containers, and Kubernetes), deployment topologies, and pause/resume lifecycle operations. Includes host OS and architecture support (including amd64 and arm64), backend-specific isolation (including Windows AppContainer and isolation sessions), and compatibility.

| GitHub | Role | Status | Scope | Basis |
| --- | --- | --- | --- | --- |
| @elezar | maintainer | suggested | Compute capabilities and backend integration | [#3010](https://github.com/NVIDIA/OpenShell/pull/3010) |
| @drew | maintainer | suggested | Compute-driver and supervisor integration | [#4656](https://github.com/NVIDIA/OpenShell/pull/4656) |
| @mrunalp | maintainer | suggested | Kubernetes compute driver | [#4527](https://github.com/NVIDIA/OpenShell/pull/4527) |

### area:runtime

Sandbox execution, isolation, process supervision, policy enforcement, network proxying, middleware, volumes, and (agent) memory. Includes shared isolation primitives such as Linux namespaces, seccomp and Landlock, and process/executable identity.

Provider discovery and configuration, profiles, sandbox attachments, provider-contributed policy, credential resolution and delivery, refresh and rotation, and provider lifecycle management.

| GitHub | Role | Status | Scope | Basis |
| --- | --- | --- | --- | --- |
| @drew | maintainer | suggested | Isolation, workload execution, and supervisor lifecycle | [#4106](https://github.com/NVIDIA/OpenShell/pull/4106) |
| @TaylorMutch | maintainer | suggested | Sandbox and supervisor integration | [#4823](https://github.com/NVIDIA/OpenShell/pull/4823) |
| @shiju-nv | reviewer | suggested | Provider credentials and protocol inspection | [#4152](https://github.com/NVIDIA/OpenShell/pull/4152) |

### area:enterprise

Authentication, multitenancy, gateway interceptors, FIPS compliance, and other enterprise requirements.

| GitHub | Role | Status | Scope | Basis |
| --- | --- | --- | --- | --- |
| @sjenning | maintainer | suggested | Extension contracts and provider authorization | [#4357](https://github.com/NVIDIA/OpenShell/pull/4357) |
| @derekwaynecarr | maintainer | suggested | Service authorization | [#3796](https://github.com/NVIDIA/OpenShell/pull/3796) |

### area:platform

SDKs, CLIs, API machinery, gateway infrastructure, persistence (eg postgres, sqlite support), configuration (gateway.toml), and gateway-side sandbox and session management.

| GitHub | Role | Status | Scope | Basis |
| --- | --- | --- | --- | --- |
| @pimlock | maintainer | suggested | Gateway configuration and supervisor sessions | [#4320](https://github.com/NVIDIA/OpenShell/pull/4320) |
| @TaylorMutch | maintainer | suggested | CLI and Rust SDK integration | [#4817](https://github.com/NVIDIA/OpenShell/pull/4817) |

## Topics

Topics connect contributors with work matching their expertise or interests. They describe technical concerns across areas rather than separate component ownership.

### topic:api

Public API contracts, gRPC and protobuf definitions, SDK interfaces, versioning, compatibility, API ergonomics, design patterns, component and communication standards.

| GitHub | Role | Status | Scope | Basis |
| --- | --- | --- | --- | --- |
| @drew | maintainer | suggested | Public API entities and references | [#3272](https://github.com/NVIDIA/OpenShell/pull/3272) |
| @mrunalp | maintainer | suggested | Workspace selectors and mutation contracts | [#3321](https://github.com/NVIDIA/OpenShell/pull/3321) |

### topic:architecture

Cross-cutting system design, component boundaries, data and control flow, architectural decisions, and RFC-level concerns.

| GitHub | Role | Status | Scope | Basis |
| --- | --- | --- | --- | --- |
| @drew | maintainer | suggested | Runtime and compute-driver boundaries | [#4106](https://github.com/NVIDIA/OpenShell/pull/4106) |
| @mrunalp | maintainer | suggested | Gateway mutation architecture | [#3321](https://github.com/NVIDIA/OpenShell/pull/3321) |

### topic:authnz

Authentication, authorization, credential protection, policy integrity/signed policiesIncludes identity verification, login and session handling, OIDC integration, bearer-token validation, access permissions, and authorization across tenant and workspace boundaries.

| GitHub | Role | Status | Scope | Basis |
| --- | --- | --- | --- | --- |
| @sjenning | maintainer | suggested | Provider authorization and extension negotiation | [#4357](https://github.com/NVIDIA/OpenShell/pull/4357) |
| @krishicks | maintainer | suggested | Gateway and sandbox authentication | [#4762](https://github.com/NVIDIA/OpenShell/pull/4762) |

### topic:compliance

FIPS, regulatory alignment, auditability, and standardization requirements.

| GitHub | Role | Status | Scope | Basis |
| --- | --- | --- | --- | --- |
| @johntmyers | maintainer | suggested | Repository license and compliance text; FIPS coverage needs nomination | [#3467](https://github.com/NVIDIA/OpenShell/pull/3467) |

### topic:documentation

Architecture documentation, README maintenance, project website updates, and automated documentation generation.

| GitHub | Role | Status | Scope | Basis |
| --- | --- | --- | --- | --- |
| @krishicks | maintainer | suggested | Observability documentation | [#4560](https://github.com/NVIDIA/OpenShell/pull/4560) |
| @drew | maintainer | suggested | Deployment and contributor-facing documentation | [#4622](https://github.com/NVIDIA/OpenShell/pull/4622) |

### topic:dx

Ensure OpenShell is easy to contribute to for humans and agents.

| GitHub | Role | Status | Scope | Basis |
| --- | --- | --- | --- | --- |
| @elezar | maintainer | suggested | Contributor triage and workflow tooling | [#4534](https://github.com/NVIDIA/OpenShell/pull/4534) |
| @johntmyers | maintainer | suggested | Agent review and contributor workflows | [#4309](https://github.com/NVIDIA/OpenShell/pull/4309) |

### topic:gpu

GPU scheduling, Kubernetes Dynamic Resource Allocation (DRA), Container Device Interface (CDI) configuration, Multi-Instance GPU (MIG) support, and hardware-accelerated runtime integration.

| GitHub | Role | Status | Scope | Basis |
| --- | --- | --- | --- | --- |
| @elezar | maintainer | suggested | Device capabilities and compute integration | [#3010](https://github.com/NVIDIA/OpenShell/pull/3010) |
| @alangou | maintainer | suggested | CDI device identity and validation | [#4306](https://github.com/NVIDIA/OpenShell/pull/4306) |

### topic:kubernetes

Kubernetes operator development, custom resource definitions (CRDs), deployment controllers, and native integration with Kubernetes APIs.

| GitHub | Role | Status | Scope | Basis |
| --- | --- | --- | --- | --- |
| @mrunalp | maintainer | suggested | Kubernetes compute-driver behavior | [#4527](https://github.com/NVIDIA/OpenShell/pull/4527) |
| @drew | maintainer | suggested | Shared supervisor deployment | [#4695](https://github.com/NVIDIA/OpenShell/pull/4695) |

### topic:mcp

Model Context Protocol (MCP) support, server and client implementations, and standard integration.

| GitHub | Role | Status | Scope | Basis |
| --- | --- | --- | --- | --- |
| @johntmyers | maintainer | suggested | Network enforcement integration; MCP-specific coverage needs confirmation | [#2723](https://github.com/NVIDIA/OpenShell/pull/2723) |
| @shiju-nv | reviewer | suggested | MCP protocol and revision enforcement | [#3850](https://github.com/NVIDIA/OpenShell/pull/3850) |

### topic:networking

General network transport, connectivity, and proxy behavior not covered by the more specialized L7 category.

| GitHub | Role | Status | Scope | Basis |
| --- | --- | --- | --- | --- |
| @johntmyers | maintainer | suggested | Proxy egress and transparent TCP | [#2723](https://github.com/NVIDIA/OpenShell/pull/2723) |
| @alangou | maintainer | suggested | DNS and hostname policy enforcement | [#4602](https://github.com/NVIDIA/OpenShell/pull/4602) |
| @shiju-nv | reviewer | suggested | HTTP and application-protocol inspection | [#3753](https://github.com/NVIDIA/OpenShell/pull/3753) |

### topic:observability

Logging, metrics, tracing, telemetry, dashboards, event correlation, and the collection or export of operational data from gateways and sandboxes.

| GitHub | Role | Status | Scope | Basis |
| --- | --- | --- | --- | --- |
| @krishicks | maintainer | suggested | OCSF and OpenTelemetry | [#4545](https://github.com/NVIDIA/OpenShell/pull/4545) |
| @matthewgrossman | maintainer | suggested | Tracing correctness and log handling | [#4212](https://github.com/NVIDIA/OpenShell/pull/4212) |

### topic:operability

Deployment and configuration of OpenShell installations, upgrades, backup and restore, disaster recovery, operational diagnostics, and maintenance of running installations.

| GitHub | Role | Status | Scope | Basis |
| --- | --- | --- | --- | --- |
| @pimlock | maintainer | suggested | Gateway configuration and Kubernetes reconciliation | [#4676](https://github.com/NVIDIA/OpenShell/pull/4676) |
| @TaylorMutch | maintainer | suggested | HA gateway operation | [#1868](https://github.com/NVIDIA/OpenShell/pull/1868) |

### topic:performance

Startup time, latency, throughput, resource overhead, scalability, and benchmarking. Includes rate limiting.

| GitHub | Role | Status | Scope | Basis |
| --- | --- | --- | --- | --- |
| @matthewgrossman | maintainer | suggested | Gateway and supervisor overhead | [#4619](https://github.com/NVIDIA/OpenShell/pull/4619) |
| @drew | maintainer | suggested | Sandbox process lifecycle overhead | [#3757](https://github.com/NVIDIA/OpenShell/pull/3757) |

### topic:policy

Policy authoring, validation, proving, distribution, enforcement, and policy ergonomics across runtimes and APIs. Includes policy hardening.

| GitHub | Role | Status | Scope | Basis |
| --- | --- | --- | --- | --- |
| @alangou | maintainer | suggested | Policy matching and proof correctness | [#4326](https://github.com/NVIDIA/OpenShell/pull/4326) |
| @pimlock | maintainer | suggested | Policy authoring and rule proposals | [#3707](https://github.com/NVIDIA/OpenShell/pull/3707) |
| @shiju-nv | reviewer | suggested | Provider and application-protocol policy | [#3850](https://github.com/NVIDIA/OpenShell/pull/3850) |

### topic:reliability

High availability, failure recovery, retries, graceful degradation, fault tolerance, and operational resilience. Includes correctness across restarts.

| GitHub | Role | Status | Scope | Basis |
| --- | --- | --- | --- | --- |
| @TaylorMutch | maintainer | suggested | HA gateway behavior | [#1868](https://github.com/NVIDIA/OpenShell/pull/1868) |
| @pimlock | maintainer | suggested | Gateway reconciliation and lifecycle | [#4676](https://github.com/NVIDIA/OpenShell/pull/4676) |

### topic:sdk

Software Development Kit (SDK) creation, maintenance, language bindings, and distribution.

| GitHub | Role | Status | Scope | Basis |
| --- | --- | --- | --- | --- |
| @TaylorMutch | maintainer | suggested | Rust SDK and CLI integration | [#4817](https://github.com/NVIDIA/OpenShell/pull/4817) |
| @SDAChess | maintainer | suggested | TypeScript SDK | [#4495](https://github.com/NVIDIA/OpenShell/pull/4495) |
| @maxdubrinsky | reviewer | suggested | Python SDK and credential-driver bindings | [#4760](https://github.com/NVIDIA/OpenShell/pull/4760) |

### topic:security

Vulnerability management, static/dynamic analysis, FSR (Functional Security Requirement) implementation, and security auditing. Includes bypass detection, abuse prevention, and vulnerability remediation.

| GitHub | Role | Status | Scope | Basis |
| --- | --- | --- | --- | --- |
| @alangou | maintainer | suggested | Security scanning and policy validation | [#4203](https://github.com/NVIDIA/OpenShell/pull/4203) |
| @johntmyers | maintainer | suggested | Security regression review | [#4338](https://github.com/NVIDIA/OpenShell/pull/4338) |

### topic:testing

Unit, integration, regression, conformance, and end-to-end testing, including test infrastructure, coverage gaps, flaky tests, and environment-specific test failures.

| GitHub | Role | Status | Scope | Basis |
| --- | --- | --- | --- | --- |
| @matthewgrossman | maintainer | suggested | Conformance and tracing tests | [#4521](https://github.com/NVIDIA/OpenShell/pull/4521) |
| @SDAChess | maintainer | suggested | Test infrastructure and compatibility checks | [#4488](https://github.com/NVIDIA/OpenShell/pull/4488) |
