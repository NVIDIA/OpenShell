---
authors:
  - "@drew"
  - "@SDAChess"
state: draft
links:
  - https://github.com/NVIDIA/OpenShell/issues/4425
---

# RFC 0019 - A Smaller Core and a Wider Tent

## Summary

Let's split OpenShell into a smaller core repository and a set of focused
repositories for platforms, packaging, SDKs, and provider integrations. The goal
is to make it easier for new maintainers to own a useful part of OpenShell while
keeping the core small enough to maintain well.

## Motivation

OpenShell covers a lot of ground. Someone who wants to maintain a Kubernetes
integration, a package, or an SDK shouldn't need to take on the whole project.
We want to widen the tent: give those contributors a clear home, ownership, and
room to move.

A smaller core lets its maintainers focus on the runtime and the contracts that
hold the ecosystem together. The surrounding repositories can build communities
with their own expertise, test infrastructure, and release responsibilities.

## Proposal

Organize OpenShell around a core repository and focused ecosystem repositories.
The `openshell` core owns the runtime, CLI, Rust SDK, shared interfaces, and
Kubernetes integration. Go, Python, and TypeScript each get an SDK repository.
The packages repository owns installation and distribution; Windows and desktop
repositories own their platform integrations. Each provider gets a repository
for its integration and tests. A `console` repository holds the frontend.

The core repository keeps the name `openshell`. All other repository names omit
the `openshell-` prefix.

The proposed repository structure is:

```text
OpenShell repositories
├── openshell             Gateway, supervisor, sandbox, CLI, Rust SDK, shared Rust interfaces, Kubernetes
├── sdk-go                Go SDK
├── sdk-python            Python SDK
├── sdk-typescript        TypeScript SDK
├── packages              install.sh, RPM, DEB, snap, Homebrew tap and formula
├── windows               MSI installer and MXC driver
├── desktop               Desktop drivers: macOS App Sandbox, Podman, Docker, VM
├── console               OpenShell frontend
├── providers-<provider>  One repository per provider integration
└── awesome-list          Curated OpenShell resources and examples
```

This gives maintainers a focused area to own while keeping the shared contracts
in core. Each repository is responsible for its releases and compatibility with
the core versions it supports.

### Core: `openshell`

- CLI, built for Linux, Windows, and macOS.
- Gateway, built for Linux, Windows, and macOS.
- Supervisor, built for Linux, Windows, and macOS.
- Linux sandbox runtime, with support for Linux isolation, gVisor, Kata, and
  Firecracker.
- Prover.
- Rust SDK, kept alongside the CLI as the reference client.
- Shared Rust interfaces used by components across repositories.
- Kubernetes compute driver, with support for gVisor, Kata, Firecracker, and runc.
- Helm chart and its publication.
- Kubernetes operator.
- A compute driver that assembles these components as processes on the host.
  On Linux, use `systemd-nspawn` for launch and isolation.
- Publication of binaries.

Kubernetes stays in core for this migration. After this RFC is implemented,
we will explore splitting the Helm chart, Kubernetes driver, and operator into
a separate repository.

### SDK repositories

Each other language SDK gets its own repository:

| Repository | Owns and publishes |
| --- | --- |
| `sdk-go` | Go SDK, with its own maintainers, tests, and releases. |
| `sdk-python` | Python SDK, with its own maintainers, tests, and releases. |
| `sdk-typescript` | TypeScript SDK, with its own maintainers, tests, and releases. |

The Rust SDK stays in core as the reference client used by the CLI. Keeping them
together lets changes to the gateway, SDK, and CLI be developed and tested in one
repository. Each other language SDK gets its own repository so maintainers can
own its language-specific tooling and release process.

Core remains the source of truth for the public protobuf definitions. SDK
repositories should generate bindings from a pinned, published version of those
definitions, document which core releases they support, and test against those
releases. Automation should propose updates when core publishes new definitions
so separate repositories do not depend on manual copying to stay in sync.

### Packaging and installation

| Repository | Owns and publishes |
| --- | --- |
| `packages` | The one-line `install.sh` installation path and Homebrew tap; publishes RPM, DEB, and snap packages and the `openshell.rb` formula. |

### Windows: `windows`

- MSI installer and its publication.
- MXC driver and its publication.

### Desktop: `desktop`

- macOS isolation through App Sandbox and container integration.
- Podman integration.
- Docker integration.
- Possible microVM support. Whether this belongs here, in core, or in a separate
  repository remains an open question.

### Console: `console`

The `console` repository holds the OpenShell frontend and owns its development,
tests, and releases. It consumes the public gateway API and documents which
core releases it supports.

### Provider repositories and ownership

Each provider gets its own `providers-<provider>` repository, such as
`providers-aws`, `providers-google`, `providers-oci`, or `providers-github`.
Each owns its provider integration and test infrastructure suited to that
integration.

Each repository should have named maintainers and own its tests and published
artifacts. Shared Rust interfaces live in core alongside the Rust SDK. Core
maintainers own these shared contracts; integration maintainers own how their
implementation uses them. We need clear compatibility expectations
so users can assemble a working OpenShell without guessing which versions fit.

## Implementation plan

Migrate in the following order, preserving history where practical:

1. **SDKs.** Move Go, Python, and TypeScript into their respective repositories.
   Keep the Rust SDK and shared Rust interfaces in core. Establish the pinned
   protobuf inputs, SDK release automation, and compatibility tests before
   retiring the existing SDK paths. Document any package or import path changes.
2. **Packages.** Move `install.sh`, RPM, DEB, and snap packaging, and the Homebrew
   tap and `openshell.rb` formula into `packages`. Validate installation and
   removal using artifacts from a pinned core release, including formula
   installation against published core binaries.
3. **Windows.** Move the MSI installer and MXC driver into `windows`.
   Establish builds, installer checks, and driver compatibility tests against
   core.
4. **Core.** Consolidate `openshell` around the CLI, gateway, supervisor, Linux
   sandbox runtime, prover, Rust SDK, shared Rust interfaces, host compute driver,
   and Kubernetes integration. Keep the Helm chart, Kubernetes driver, operator,
   chart publication, and deployment tests in core. Update core builds and
   releases to consume the extracted components where needed, and validate that
   the released pieces work together. Provider integrations remain in place
   until the next phase.
5. **Providers.** Break out provider integrations one at a time into
   `providers-<provider>`, with maintainers, releases, and test
   infrastructure appropriate to each integration.

Before each move, name the maintainers and identify dependencies on the shared
checkout. Each new repository owns its tests, release automation, contribution
guidance, and documented compatibility relationship with core. Update
installation paths, documentation, and contributor skills with each move, and
validate the replacement before retiring its old paths. Desktop migration timing
remains an open question.

Create `console` as the home for frontend development, with its own tests,
release automation, and documented compatibility with core. After this RFC is
implemented, explore a separate Kubernetes repository as follow-up work.

## Risks

More repositories mean more release and CI coordination. Changes that cross a
boundary may take longer, and an integration can fall behind core. Explicit
ownership, compatibility checks, and a gradual migration should help, but this
only works if the new repositories attract maintainers.

## Alternatives

We could keep the monorepo and delegate ownership through CODEOWNERS and focused
CI. That reduces migration work, but leaves everyone sharing the same repository
and release machinery. We could also split only packaging and integrations
first, then decide whether SDKs and platform drivers benefit from moving.

## Prior art

[RFC 0012](../0012-isolation-backend/README.md) separates compute orchestration,
supervision, and isolation behind contracts. Those boundaries give us a starting
point for deciding what can live outside core.

## Open questions

None
