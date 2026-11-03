# Review areas and topics

## Areas

Areas are OpenShell-specific components or system boundaries. They represent the division of labor across the project. Keep the number of areas small enough to support named leads and reporting during community calls.

### area:build

CI/CD workflows, release pipelines, build targets, packaging, and artifact publication.

| Name | GitHub ID | Company/Organization |
| --- | --- | --- |
| Matthew Grossman | [@matthewgrossman](https://github.com/matthewgrossman) | NVIDIA |
| Simon Scatton | [@SDAChess](https://github.com/SDAChess) | NVIDIA |
| Jim Meyer | [@purp](https://github.com/purp) | NVIDIA |
| Taylor Mutch | [@TaylorMutch](https://github.com/TaylorMutch) | NVIDIA |

### area:drivers

Infrastructure orchestration, including compute scheduling, secret management, runtime integrations (GPU, Docker, Podman, virtual machines, Kata Containers, and Kubernetes), deployment topologies, and pause/resume lifecycle operations. Includes host OS and architecture support (including amd64 and arm64), backend-specific isolation (including Windows AppContainer and isolation sessions), and compatibility.

| Name | GitHub ID | Company/Organization |
| --- | --- | --- |
| Evan Lezar | [@elezar](https://github.com/elezar) | NVIDIA |
| Drew Newberry | [@drew](https://github.com/drew) | NVIDIA |
| Mrunal Patel | [@mrunalp](https://github.com/mrunalp) | Red Hat |
| Divesh Chowdary | [@FrostGod](https://github.com/FrostGod) | NVIDIA |
| Russell Bryant | [@russellb](https://github.com/russellb) | Red Hat |

### area:runtime

Sandbox execution, isolation, process supervision, policy enforcement, network proxying, middleware, volumes, and (agent) memory. Includes shared isolation primitives such as Linux namespaces, seccomp and Landlock, and process/executable identity.

Provider discovery and configuration, profiles, sandbox attachments, provider-contributed policy, credential resolution and delivery, refresh and rotation, and provider lifecycle management.

| Name | GitHub ID | Company/Organization |
| --- | --- | --- |
| Drew Newberry | [@drew](https://github.com/drew) | NVIDIA |
| Taylor Mutch | [@TaylorMutch](https://github.com/TaylorMutch) | NVIDIA |
| Shiju | [@shiju-nv](https://github.com/shiju-nv) | NVIDIA |
| Jim Meyer | [@purp](https://github.com/purp) | NVIDIA |

### area:enterprise

Authentication, multitenancy, gateway interceptors, FIPS compliance, and other enterprise requirements.

| Name | GitHub ID | Company/Organization |
| --- | --- | --- |
| Seth Jennings | [@sjenning](https://github.com/sjenning) | Red Hat |
| Derek Carr | [@derekwaynecarr](https://github.com/derekwaynecarr) | Red Hat |
| Akram Ben Aissi | [@akram](https://github.com/akram) | Red Hat |

### area:platform

SDKs, CLIs, API machinery, gateway infrastructure, persistence (eg postgres, sqlite support), configuration (gateway.toml), and gateway-side sandbox and session management.

| Name | GitHub ID | Company/Organization |
| --- | --- | --- |
| Piotr Mlocek | [@pimlock](https://github.com/pimlock) | NVIDIA |
| Taylor Mutch | [@TaylorMutch](https://github.com/TaylorMutch) | NVIDIA |
| Divesh Chowdary | [@FrostGod](https://github.com/FrostGod) | NVIDIA |

## Topics

Topics connect contributors with work matching their expertise or interests. They describe technical concerns across areas rather than separate component ownership.

### topic:api

Public API contracts, gRPC and protobuf definitions, SDK interfaces, versioning, compatibility, API ergonomics, design patterns, component and communication standards.

| Name | GitHub ID | Company/Organization |
| --- | --- | --- |
| Drew Newberry | [@drew](https://github.com/drew) | NVIDIA |
| Mrunal Patel | [@mrunalp](https://github.com/mrunalp) | Red Hat |

### topic:architecture

Cross-cutting system design, component boundaries, data and control flow, architectural decisions, and RFC-level concerns.

| Name | GitHub ID | Company/Organization |
| --- | --- | --- |
| Drew Newberry | [@drew](https://github.com/drew) | NVIDIA |
| Mrunal Patel | [@mrunalp](https://github.com/mrunalp) | Red Hat |

### topic:authnz

Authentication, authorization, credential protection, policy integrity/signed policies. Includes identity verification, login and session handling, OIDC integration, bearer-token validation, access permissions, and authorization across tenant and workspace boundaries.

| Name | GitHub ID | Company/Organization |
| --- | --- | --- |
| Seth Jennings | [@sjenning](https://github.com/sjenning) | Red Hat |
| Kris Hicks | [@krishicks](https://github.com/krishicks) | NVIDIA |
| Gordon Sim | [@grs](https://github.com/grs) | Red Hat |

### topic:compliance

FIPS, regulatory alignment, auditability, and standardization requirements.

| Name | GitHub ID | Company/Organization |
| --- | --- | --- |
| John T. Myers | [@johntmyers](https://github.com/johntmyers) | NVIDIA |
| Jim Meyer | [@purp](https://github.com/purp) | NVIDIA |

### topic:documentation

Architecture documentation, README maintenance, project website updates, and automated documentation generation.

| Name | GitHub ID | Company/Organization |
| --- | --- | --- |
| Kris Hicks | [@krishicks](https://github.com/krishicks) | NVIDIA |
| Drew Newberry | [@drew](https://github.com/drew) | NVIDIA |
| Piotr Mlocek | [@pimlock](https://github.com/pimlock) | NVIDIA |

### topic:dx

Ensure OpenShell is easy to contribute to for humans and agents.

| Name | GitHub ID | Company/Organization |
| --- | --- | --- |
| Evan Lezar | [@elezar](https://github.com/elezar) | NVIDIA |
| John T. Myers | [@johntmyers](https://github.com/johntmyers) | NVIDIA |
| Jim Meyer | [@purp](https://github.com/purp) | NVIDIA |
| Kris Hicks | [@krishicks](https://github.com/krishicks) | NVIDIA |
| Piotr Mlocek | [@pimlock](https://github.com/pimlock) | NVIDIA |

### topic:extensions

Extension APIs and integration points, including consistency, general-purpose design, and support for external use cases.

| Name | GitHub ID | Company/Organization |
| --- | --- | --- |
| Piotr Mlocek | [@pimlock](https://github.com/pimlock) | NVIDIA |
| Matthew Grossman | [@matthewgrossman](https://github.com/matthewgrossman) | NVIDIA |
| Drew Newberry | [@drew](https://github.com/drew) | NVIDIA |
| Artem Lytvyn | [@letv1nnn](https://github.com/letv1nnn) | Independent |

### topic:gpu

GPU scheduling, Kubernetes Dynamic Resource Allocation (DRA), Container Device Interface (CDI) configuration, Multi-Instance GPU (MIG) support, and hardware-accelerated runtime integration.

| Name | GitHub ID | Company/Organization |
| --- | --- | --- |
| Evan Lezar | [@elezar](https://github.com/elezar) | NVIDIA |
| Adrien Langou | [@alangou](https://github.com/alangou) | NVIDIA |

### topic:kubernetes

Kubernetes operator development, custom resource definitions (CRDs), deployment controllers, and native integration with Kubernetes APIs.

| Name | GitHub ID | Company/Organization |
| --- | --- | --- |
| Mrunal Patel | [@mrunalp](https://github.com/mrunalp) | Red Hat |
| Drew Newberry | [@drew](https://github.com/drew) | NVIDIA |
| Divesh Chowdary | [@FrostGod](https://github.com/FrostGod) | NVIDIA |
| Kris Hicks | [@krishicks](https://github.com/krishicks) | NVIDIA |
| Taylor Mutch | [@TaylorMutch](https://github.com/TaylorMutch) | NVIDIA |
| Krzysztof Malczuk | [@2000krysztof](https://github.com/2000krysztof) | Red Hat |
| Mark Campbell | [@Bobbins228](https://github.com/Bobbins228) | Red Hat |
| Jorge Garcia Oncins | [@jgarciao](https://github.com/jgarciao) | Red Hat |
| Ignas Baranauskas | [@Ygnas](https://github.com/Ygnas) | Red Hat |

### topic:mcp

Model Context Protocol (MCP) support, server and client implementations, and standard integration.

| Name | GitHub ID | Company/Organization |
| --- | --- | --- |
| John T. Myers | [@johntmyers](https://github.com/johntmyers) | NVIDIA |
| Shiju | [@shiju-nv](https://github.com/shiju-nv) | NVIDIA |

### topic:networking

General network transport, connectivity, and proxy behavior not covered by the more specialized L7 category.

| Name | GitHub ID | Company/Organization |
| --- | --- | --- |
| John T. Myers | [@johntmyers](https://github.com/johntmyers) | NVIDIA |
| Adrien Langou | [@alangou](https://github.com/alangou) | NVIDIA |
| Shiju | [@shiju-nv](https://github.com/shiju-nv) | NVIDIA |
| Divesh Chowdary | [@FrostGod](https://github.com/FrostGod) | NVIDIA |
| Russell Bryant | [@russellb](https://github.com/russellb) | Red Hat |

### topic:observability

Logging, metrics, tracing, telemetry, dashboards, event correlation, and the collection or export of operational data from gateways and sandboxes.

| Name | GitHub ID | Company/Organization |
| --- | --- | --- |
| Kris Hicks | [@krishicks](https://github.com/krishicks) | NVIDIA |
| Matthew Grossman | [@matthewgrossman](https://github.com/matthewgrossman) | NVIDIA |
| Taylor Mutch | [@TaylorMutch](https://github.com/TaylorMutch) | NVIDIA |
| Artem Lytvyn | [@letv1nnn](https://github.com/letv1nnn) | Independent |
| Roland Huss | [@rhuss](https://github.com/rhuss) | Red Hat |
| Gaizka Menendez | [@gmenher](https://github.com/gmenher) | Red Hat |

### topic:operability

Deployment and configuration of OpenShell installations, upgrades, backup and restore, disaster recovery, operational diagnostics, and maintenance of running installations.

| Name | GitHub ID | Company/Organization |
| --- | --- | --- |
| Piotr Mlocek | [@pimlock](https://github.com/pimlock) | NVIDIA |
| Taylor Mutch | [@TaylorMutch](https://github.com/TaylorMutch) | NVIDIA |
| Jim Meyer | [@purp](https://github.com/purp) | NVIDIA |

### topic:performance

Startup time, latency, throughput, resource overhead, scalability, and benchmarking. Includes rate limiting.

| Name | GitHub ID | Company/Organization |
| --- | --- | --- |
| Matthew Grossman | [@matthewgrossman](https://github.com/matthewgrossman) | NVIDIA |
| Divesh Chowdary | [@FrostGod](https://github.com/FrostGod) | NVIDIA |
| Drew Newberry | [@drew](https://github.com/drew) | NVIDIA |
| Jim Meyer | [@purp](https://github.com/purp) | NVIDIA |

### topic:policy

Policy authoring, validation, proving, distribution, enforcement, and policy ergonomics across runtimes and APIs. Includes policy hardening.

| Name | GitHub ID | Company/Organization |
| --- | --- | --- |
| Adrien Langou | [@alangou](https://github.com/alangou) | NVIDIA |
| Piotr Mlocek | [@pimlock](https://github.com/pimlock) | NVIDIA |
| Shiju | [@shiju-nv](https://github.com/shiju-nv) | NVIDIA |
| John T. Myers | [@johntmyers](https://github.com/johntmyers) | NVIDIA |

### topic:reliability

High availability, failure recovery, retries, graceful degradation, fault tolerance, and operational resilience. Includes correctness across restarts.

| Name | GitHub ID | Company/Organization |
| --- | --- | --- |
| Taylor Mutch | [@TaylorMutch](https://github.com/TaylorMutch) | NVIDIA |
| Piotr Mlocek | [@pimlock](https://github.com/pimlock) | NVIDIA |
| Jim Meyer | [@purp](https://github.com/purp) | NVIDIA |
| Divesh Chowdary | [@FrostGod](https://github.com/FrostGod) | NVIDIA |

### topic:sdk

Software Development Kit (SDK) creation, maintenance, language bindings, and distribution.

| Name | GitHub ID | Company/Organization |
| --- | --- | --- |
| Taylor Mutch | [@TaylorMutch](https://github.com/TaylorMutch) | NVIDIA |
| Simon Scatton | [@SDAChess](https://github.com/SDAChess) | NVIDIA |
| Max Dubrinsky | [@maxdubrinsky](https://github.com/maxdubrinsky) | Gretel |
| Krzysztof Malczuk | [@2000krysztof](https://github.com/2000krysztof) | Red Hat |

### topic:security

Vulnerability management, static/dynamic analysis, FSR (Functional Security Requirement) implementation, and security auditing. Includes bypass detection, abuse prevention, and vulnerability remediation.

| Name | GitHub ID | Company/Organization |
| --- | --- | --- |
| Adrien Langou | [@alangou](https://github.com/alangou) | NVIDIA |
| John T. Myers | [@johntmyers](https://github.com/johntmyers) | NVIDIA |
| Jim Meyer | [@purp](https://github.com/purp) | NVIDIA |
| Simon Scatton | [@SDAChess](https://github.com/SDAChess) | NVIDIA |
| Krzysztof Malczuk | [@2000krysztof](https://github.com/2000krysztof) | Red Hat |
| Christian Zaccaria | [@ChristianZaccaria](https://github.com/ChristianZaccaria) | Red Hat |
| Russell Bryant | [@russellb](https://github.com/russellb) | Red Hat |

### topic:testing

Unit, integration, regression, conformance, and end-to-end testing, including test infrastructure, coverage gaps, flaky tests, and environment-specific test failures.

| Name | GitHub ID | Company/Organization |
| --- | --- | --- |
| Matthew Grossman | [@matthewgrossman](https://github.com/matthewgrossman) | NVIDIA |
| Simon Scatton | [@SDAChess](https://github.com/SDAChess) | NVIDIA |
| Evan Lezar | [@elezar](https://github.com/elezar) | NVIDIA |
| Mark Campbell | [@Bobbins228](https://github.com/Bobbins228) | Red Hat |
| Jorge Garcia Oncins | [@jgarciao](https://github.com/jgarciao) | Red Hat |
| Gaizka Menendez | [@gmenher](https://github.com/gmenher) | Red Hat |

### topic:ux

CLI command interface and flags, help text, error messages and exit codes, human readable outputs, TUI, and first run path to working sandbox.

| Name | GitHub ID | Company/Organization |
| --- | --- | --- |
| Roland Huss | [@rhuss](https://github.com/rhuss) | Red Hat |
| Artem Lytvyn | [@letv1nnn](https://github.com/letv1nnn) | Independent |
