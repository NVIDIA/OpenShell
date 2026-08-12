# RFC 0014 Supplement - Release Qualification

A release candidate is eligible for stable release only after its published
artifacts pass every required [conformance](#conformance) and
[upgrade](#upgrade) workflow, its
[breaking API change review](#breaking-api-change-review), and its
[security review](#security-review).

## Conformance

Conformance runs for different OpenShell driver and host configurations.
Kubernetes runs once per supported gateway topology. Each workflow installs the
candidate in one representative environment and verifies the supported
OpenShell behavior for that driver and topology.

For each driver, the suite:

1. Installs the candidate artifacts and starts the gateway and selected runtime.
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
unexpected skip or retry-dependent result. A workflow may exercise relevant
GPU, authentication, credential-driver, interceptor, middleware, and
client/server skew variants as subcases without creating separate workflows.
Unsupported capabilities must return documented errors rather than fail
silently.

Each workflow uses one representative environment for the compute driver. It
may run multiple capability subcases inside that environment without creating
additional workflows. Kubernetes uses a separate blocking workflow for each
supported gateway topology.

### Configurations to test

| ID | Compute driver | Representative environment | Gateway configuration |
| --- | --- | --- | --- |
| C01 | Docker | Ubuntu x86_64 with Docker 28.0.4 | Local gateway; TLS and sandbox mTLS; credentials; CDI GPU when stable |
| C02 | Podman | Fedora x86_64 with Podman 5.x rootless and SELinux enforcing | Local gateway; TLS and sandbox mTLS; credentials; CDI GPU when stable |
| C03 | MicroVM | Linux x86_64 with KVM and IOMMU | Local gateway; libkrun CPU; TLS and sandbox mTLS; QEMU/VFIO GPU when stable |
| C04 | Kubernetes | Kubernetes 1.29 | Sidecar, three replicas; external PostgreSQL; Kubernetes Secrets; TLS and OIDC; GPU when stable |
| C05 | Kubernetes | Kubernetes 1.29 | Combined, three replicas; external PostgreSQL; Kubernetes Secrets; TLS and OIDC; GPU when stable |

C02 must pass without disabling SELinux or weakening the host SELinux policy.

## Upgrade

Upgrade runs once per supported product installation package. It verifies that
users can move from every supported source release to the candidate without
reinstalling or losing supported state.

For each installation package, the suite:

1. Installs the source release and creates representative gateways, sandboxes,
   policies, providers, credentials, and persisted state.
2. Exercises the source installation to establish a known-good baseline.
3. Performs the documented in-place upgrade using the published candidate
   artifacts.
4. Verifies schema and state migrations, gateway health, existing resources,
   policy behavior, and new sandbox creation.
5. Runs a post-upgrade smoke test that verifies existing resources and creates
   and deletes a new sandbox.
6. Exercises rollback when rollback is part of the supported upgrade contract.

### Configurations to test

| ID | Installation package | Representative environment | Drivers | Upgrade path |
| --- | --- | --- | --- | --- |
| U01 | Homebrew formula | macOS on Apple Silicon | MicroVM | Previous stable formula to candidate formula |
| U02 | DEB through APT | Ubuntu x86_64 | Docker | Previous stable repository package to candidate package |
| U03 | RPM | Fedora x86_64 | Podman | Previous stable repository package to candidate package |
| U04 | Snap | Ubuntu x86_64 | Docker | Previous stable revision to candidate revision |
| U05 | Windows MSI through WinGet | Windows x86_64 | Docker Desktop | Previous stable MSI to candidate MSI |
| U06 | Helm chart | Kubernetes 1.29 | Kubernetes | Previous stable chart and images to candidate chart and image digests |

## Breaking API change review

Breaking API change review runs once per candidate. It compares the candidate's
stable protobuf and public SDK interfaces with the latest stable baseline and
any additional baseline required by the N-1 maintenance promise. The review:

1. Runs protobuf compatibility checks against the supported descriptor
   baselines.
2. Runs language-specific compatibility checks for generated and hand-written
   SDK interfaces.
3. Classifies each detected change as stable, experimental, or development-only
   and records the evidence in the qualification record.
4. Confirms that a patch release contains no breaking stable API change.
5. For an intentional breaking change in a minor release, confirms the required
   project version, protobuf package revision where applicable, migration
   guidance, release notes, and approval.

Breaking API change review passes when no unaddressed breaking change affects a
stable API baseline and every intentional minor-release break satisfies the
versioning and migration requirements.

## Security review

Security review runs once per candidate and covers the complete candidate
artifact set. A designated security approver:

1. Reviews vulnerability, dependency, container, and infrastructure scan
   results for the candidate artifacts.
2. Reviews changes since the previous stable release to authentication,
   authorization, policy enforcement, sandbox isolation, credentials, and the
   update trust boundary.
3. Confirms that required penetration testing is current for the affected trust
   boundaries.
4. Records the scope, evidence, findings, and disposition in the qualification
   record.

Security review passes when no unresolved critical or high-severity finding
affects a supported configuration. A medium-severity finding requires an
explicit documented disposition before release. Low and informational findings
remain tracked but do not block by default.
