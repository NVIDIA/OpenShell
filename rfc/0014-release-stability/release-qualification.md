# RFC 0014 Supplement - Release Qualification

A pre-release is eligible for stable publication only after its artifacts pass
every required [conformance test](#conformance-tests) and
[upgrade test](#upgrade-tests), its
[breaking API change review](#breaking-api-change-review), and its
[security review](#security-review).

## Conformance tests

Conformance tests run for different OpenShell driver, gateway, and host
configurations. Each workflow installs the pre-release in one representative
environment and verifies the supported OpenShell behavior for that
configuration.

For each driver, the suite:

1. Installs the pre-release artifacts and starts the gateway and selected runtime.
2. Verifies gateway health, version reporting, TLS, authentication, and
   authorization.
3. Creates a sandbox, connects to it, executes commands, and exercises stop,
   restart, and restore behavior where supported.
4. Exercises filesystem, process, network, credential, and inference policy
   enforcement, including expected denial behavior.
5. Verifies the configured compute driver, credential driver, interceptor, and
   middleware contracts, including capability discovery, validation, errors,
   restart reconciliation, and cleanup.
6. Deletes the sandbox and confirms that runtime, network, credential, and
   persisted resources are removed.

Conformance passes only when every driver workflow completes without an
undeclared skip or retry-dependent result. A configuration may opt out of a
specific conformance test when it does not support the capability under test.
The opt-out and unsupported capability must be declared in the test
configuration before qualification runs; any other skip fails qualification.
A workflow may exercise relevant GPU, authentication, credential-driver,
interceptor, middleware, and client/server skew variants as subcases without
creating separate workflows. Unsupported capabilities must return documented
errors rather than fail silently.

Each workflow uses one representative environment for the configuration under test. It
may run multiple capability subcases inside that environment without creating
additional workflows.

### Configurations to test

The goal is to provide test coverage for each documented driver, topology, and environment configuration.

| ID | Compute driver | Representative environment | Gateway configuration |
| --- | --- | --- | --- |
| C01 | Docker | Ubuntu x86_64 with Docker 28.0.4 | Local gateway; TLS and sandbox mTLS; credentials; CDI GPU when stable |
| C02 | Podman | Fedora x86_64 with Podman 5.x rootless | Local gateway; TLS and sandbox mTLS; credentials; CDI GPU when stable |
| C03 | MicroVM | Linux x86_64 with KVM and IOMMU | Local gateway; libkrun CPU; TLS and sandbox mTLS; QEMU/VFIO GPU when stable |
| C04 | Kubernetes | Kubernetes 1.29 | Sidecar, three replicas; external PostgreSQL; Kubernetes Secrets; TLS and OIDC; GPU when stable |
| C05 | Kubernetes | Kubernetes 1.29 | Combined, three replicas; external PostgreSQL; Kubernetes Secrets; TLS and OIDC; GPU when stable |
| C06 | Docker | Fedora x86_64 with Docker 28.0.4 and SELinux enforcing | Local gateway; TLS and sandbox mTLS; credentials |
| C07 | Kubernetes | Supported OpenShift release | Combined, three replicas; external PostgreSQL; Kubernetes Secrets; TLS and OIDC |

## Upgrade tests

Upgrade tests run once per supported product installation package. They verify
that users can move from every supported source release to the pre-release
without reinstalling or losing supported state.

For each installation package, the suite:

1. Installs the source release and creates representative gateways, sandboxes,
   policies, providers, credentials, and persisted state.
2. Exercises the source installation to establish a known-good baseline.
3. Performs the documented in-place upgrade using the pre-release
   artifacts.
4. Verifies schema and state migrations, gateway health, existing resources,
   policy behavior, and new sandbox creation.
5. Runs a post-upgrade smoke test that verifies existing resources and creates
   and deletes a new sandbox.
6. Exercises rollback when rollback is part of the supported upgrade contract.

### Configurations to test

| ID | Installation package | Representative environment | Drivers | Upgrade path |
| --- | --- | --- | --- | --- |
| U01 | Homebrew formula | macOS on Apple Silicon | MicroVM | Previous stable formula to pre-release formula |
| U02 | DEB through APT | Ubuntu x86_64 | Docker | Previous stable repository package to pre-release package |
| U03 | RPM | Fedora x86_64 | Podman | Previous stable repository package to pre-release package |
| U04 | Snap | Ubuntu x86_64 | Docker | Previous stable revision to pre-release revision |
| U05 | Windows MSI through WinGet | Windows x86_64 | Docker Desktop | Previous stable MSI to pre-release MSI |
| U06 | Helm chart | Kubernetes 1.29 | Kubernetes | Previous stable chart and images to pre-release chart and image digests |

## Breaking API change review

Breaking API change review runs once per pre-release. It compares its
stable protobuf and public SDK interfaces with the latest stable baseline and
any additional baseline required by the N-1 maintenance promise. The review:

1. Runs protobuf compatibility checks against the supported descriptor
   baselines.
2. Runs language-specific compatibility checks for generated and hand-written
   SDK or configuration interfaces. An agent may assess this using a breaking
   API detection skill.

Breaking API change review passes when no unaddressed breaking change affects a
stable API baseline and every intentional minor-release break satisfies the
versioning and migration requirements.

## Security review

Security review runs once per pre-release and will:

1. Produce vulnerability, dependency, container, and infrastructure scan
   results for the pre-release artifacts.
2. Run an agent-based security scanner, such as Codex Security, against changes
   since the previous stable release.

Security review passes when no unresolved critical or high-severity finding
affects a supported configuration.
