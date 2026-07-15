---
authors:
  - "@rhuss"
state: draft
links:
  - https://github.com/NVIDIA/OpenShell/issues/2292
---

# RFC 0014 - SDK Acceptance Scorecard

## Summary

Define a tiered conformance framework for OpenShell language SDKs. Every SDK declares which API tier, auth level, and operational requirements it meets using a standard scorecard format. The scorecard gives contributors a clear target and reviewers a concrete checklist.

The primary deliverable is a scorecard document (`sdk/CONFORMANCE.md`) that serves as the living acceptance contract for current and future language SDKs.

## Motivation

OpenShell is expanding beyond its initial Python and TypeScript SDKs. The Go SDK (#2044, tracked in #2270) is the first new language contribution, and the community meeting on 2026-07-14 surfaced a gap: there are no formal acceptance criteria for what a language SDK must deliver to be considered conforming.

There is no operational framework for evaluating whether a specific SDK meets the bar. This leaves two groups without clear guidance:

- **SDK contributors** do not know what their PR must include to get merged. Without a defined bar, reviews devolve into subjective assessments of "completeness."
- **SDK reviewers** have no checklist to evaluate against. Each review becomes an ad-hoc assessment, inconsistent across languages and reviewers.

A binary "conforms or not" model does not fit reality. An SDK that covers sandbox management and command execution is useful even without SSH tunneling or OIDC flows. The project needs a layered model where contributors can land a Core-conforming SDK and incrementally grow toward Full conformance.

If we leave the current state unchanged, each new language SDK will negotiate its acceptance criteria from scratch, creating inconsistency across the SDK ecosystem and slowing community contributions.

## Non-goals

- Defining the SDK architecture or binding strategy per language.
- Specifying gRPC wire format or proto schema changes. SDKs wrap the existing proto contract.
- Mandating a specific test framework or linter tool. The RFC defines categories of quality checks, not which tool to use.
- Automated conformance test suites. The initial scorecard is self-declared by SDK authors. Automated verification is a follow-on effort.
- Browser or WASM SDK support.

## Proposal

### Conformance tiers

Three API conformance tiers, each building on the previous. A tier is met when all its required operations are implemented with tests and the operational requirements (Section 3) are satisfied.

#### Core

The minimum viable SDK. After a Core SDK is merged, consumers can manage sandboxes, run commands, transfer files, and check gateway health.

| Resource | Required capabilities |
|----------|---------------------|
| Sandbox | Create, retrieve, list, delete, watch for state changes, wait until ready |
| Exec | Run a command and collect output, stream command output incrementally |
| File | Upload a local file to a sandbox, download a file from a sandbox |
| Health | Check gateway health status |
| Errors | Typed error representation with status codes and helpers to distinguish error categories (not found, already exists, conflict, invalid argument) |
| Client | Top-level client with connection management and graceful shutdown |

#### Extended

Provider management, configuration, and policy. After an Extended SDK is merged, consumers can register AI providers, manage credentials, configure sandboxes, and work with network policies.

All Core capabilities, plus:

| Resource | Required capabilities |
|----------|---------------------|
| Provider | Create, retrieve, list, update, delete, ensure (create-or-update) |
| Profile | List, retrieve, import, update, lint/validate, delete |
| Config | Retrieve sandbox configuration, retrieve gateway configuration, apply configuration updates |
| Credential refresh | Query refresh status, configure refresh, trigger rotation, remove refresh configuration |
| Service | Expose a service endpoint, retrieve, list, delete |
| Policy | Retrieve draft policy, approve/reject individual chunks, bulk approve, clear drafts, query draft history, query policy status, list revisions, edit draft chunks, undo approvals |

#### Full

Network tunneling, interactive sessions, and advanced watch primitives. After a Full SDK is merged, consumers have access to the complete OpenShell API surface.

All Extended capabilities, plus:

| Resource | Required capabilities |
|----------|---------------------|
| SSH | Create session, revoke session, open bidirectional tunnel |
| TCP | Forward a connection to a sandbox port, bind a local port and tunnel accepted connections |
| Exec (interactive) | Bidirectional I/O with terminal resize support |
| Edge | Tunnel integration for edge API access |
| Watch | Event-driven watch interface with stop and reconnect semantics |

### Auth levels

Authentication is a separate axis from API conformance. An SDK can implement Core API tier with L3 auth, or Full API tier with only L1 auth. The two dimensions are independent.

#### L1 - Static auth

| Requirement | Description |
|-------------|-------------|
| Static token | Accept a pre-issued bearer token |
| No-auth | Support unauthenticated connections for local development |
| TLS configuration | Optional TLS cert/key/CA and insecure skip-verify |

#### L2 - Token lifecycle

All L1 requirements, plus:

| Requirement | Description |
|-------------|-------------|
| Refreshable token wrapper | Wrap a token source that auto-rotates expiring credentials |
| AuthProvider interface | Extensible interface for custom auth providers |
| Thread-safe refresh | Concurrent requests share a single token refresh, no thundering herd |

#### L3 - OIDC

All L2 requirements, plus:

| Requirement | Description |
|-------------|-------------|
| OpenID Connect discovery | Auto-discover endpoints from issuer URL |
| Device-code flow | Headless/CLI authentication without a browser on the SDK host |
| Authorization-code flow | Browser-based authentication with local redirect |
| Token persistence | Store and reload tokens across process restarts |
| Automatic refresh | Transparently refresh expired tokens using refresh tokens |

### Operational requirements

These requirements apply to every SDK regardless of API tier or auth level. They ensure that SDK code maintains quality and stays in sync with the upstream proto contract.

#### Linting

Each SDK must use a language-appropriate linter integrated into CI:

| Language | Expected tool | Notes |
|----------|--------------|-------|
| Go | `golangci-lint` | Project-standard config in SDK directory |
| Python | `ruff` | Or equivalent (pylint, flake8) |
| TypeScript | `eslint` | With project TypeScript config |

The specific tool and config are chosen by the SDK author, but CI must fail on lint violations.

#### Testing

| Requirement | Description |
|-------------|-------------|
| Unit tests | Every public API method has at least one test |
| Error path tests | Key error conditions (not found, invalid argument, conflict) are tested |
| Table-driven tests | Preferred where applicable (multiple inputs, same assertion pattern) |
| Integration tests | Behind a build tag or environment variable gate, runnable against a live gateway |
| Example tests | Compilable usage examples that also serve as documentation |

#### Proto sync

Each SDK must document and automate how it stays in sync with upstream proto definitions:

| Requirement | Description |
|-------------|-------------|
| Generation workflow | Documented steps to regenerate language bindings from `.proto` files |
| Freshness check | CI step that verifies generated code matches the current proto definitions |
| Version tracking | A file or marker indicating which proto version the SDK was generated from |

#### CI job

Every SDK must have a CI job in `.github/workflows/branch-checks.yml` (or equivalent) that runs on every PR touching the SDK's directory:

| Step | Description |
|------|-------------|
| Build | Compile the SDK |
| Lint | Run the language linter |
| Test | Run the full test suite (excluding integration tests) |
| Vet/Check | Language-specific static analysis (go vet, mypy, tsc) |
| Proto freshness | Verify generated proto code is up to date |

### Scorecard format

Each SDK must include a conformance scorecard in a standard format. The scorecard can live in the SDK's README or in a dedicated `CONFORMANCE.md` file.

```markdown
## Conformance

| Dimension | Level | Status | Notes |
|-----------|-------|--------|-------|
| API | Core | :white_check_mark: | |
| API | Extended | :white_check_mark: | |
| API | Full | :construction: | Missing: edge client |
| Auth | L1 - Static | :white_check_mark: | |
| Auth | L2 - Token lifecycle | :white_check_mark: | |
| Auth | L3 - OIDC | :white_check_mark: | |
| CI | Lint | :white_check_mark: | golangci-lint |
| CI | Test | :white_check_mark: | 368 tests |
| CI | Proto sync | :white_check_mark: | |
| CI | Vet/Check | :white_check_mark: | go vet |

Last updated: YYYY-MM-DD
```

Status values:
- :white_check_mark: Fully implemented and tested
- :construction: Partially implemented (explain in Notes)
- :x: Not implemented
- :calendar: Planned (link to tracking issue in Notes)

## Implementation plan

1. **Accept this RFC**: establish the conformance framework and scorecard format through the normal RFC review process.

2. **Create the scorecard document**: after acceptance, create `sdk/CONFORMANCE.md` as a top-level document that defines the tiers, auth levels, and operational requirements. Each SDK section within it contains the scorecard matrix.

3. **Retrofit existing SDKs**: evaluate the Python and TypeScript SDKs against the tiers and populate their scorecard entries. This is a documentation exercise, not a code change.

4. **Apply to the Go SDK**: the Go SDK PRs (#2270) already track conformance implicitly. Add the scorecard to the Go SDK's documentation PR (PR F).

5. **Future SDKs**: any new language SDK contribution must include a scorecard as part of its initial PR, declaring which tiers it targets.

## Risks

- **Over-specification**: defining too many requirements at the Core tier could discourage new SDK contributions. Mitigation: keep Core minimal (sandbox, exec, file, health) and let Extended/Full grow organically.

- **Scorecard staleness**: self-declared scorecards may fall out of date as SDKs evolve. Mitigation: CI could eventually verify the scorecard against actual test coverage, but automated verification is a non-goal for this RFC.

- **Tier boundary disputes**: contributors and reviewers may disagree about which operations belong in which tier. Mitigation: the tier definitions in this RFC are the authoritative source. Changes go through the RFC amendment process.

## Alternatives

### No formal conformance framework

Continue evaluating SDK contributions ad-hoc. Each SDK negotiates its own acceptance criteria with reviewers.

This is the current state. It works with two SDKs maintained by the core team, but breaks down with community contributions where expectations are implicit. The Go SDK experience demonstrated this directly.

### Binary conformance (pass/fail)

Define a single "conforming SDK" bar that requires the full API surface, all auth levels, and all operational requirements.

This sets the bar too high for initial contributions. A useful SDK that covers sandbox management and command execution would be blocked until SSH tunneling and OIDC are also implemented. The tiered model allows incremental delivery.

### Per-language acceptance criteria

Each language SDK defines its own acceptance criteria based on what makes sense for that ecosystem.

This creates inconsistency. Users and reviewers cannot compare SDKs without reading each one's custom criteria. A shared framework with language-specific operational details (which linter, which test framework) is the better balance.

## Prior art

- **Kubernetes conformance tests**: Kubernetes defines conformance profiles for distributions. Certified distributions must pass a conformance test suite. This RFC adopts the tiered model but starts with self-declared scorecards rather than automated tests.

- **OpenTelemetry SDK specification**: OpenTelemetry defines a language-neutral SDK specification that each language implementation must satisfy, with a compliance matrix per language. The scorecard format in this RFC is inspired by OpenTelemetry's approach.

- **gRPC ecosystem**: gRPC itself publishes language-specific implementation status matrices showing which features each language supports. The tiered model here follows a similar pattern.

## Open questions

- Where should the scorecard document live? Options: a single `sdk/CONFORMANCE.md` covering all languages, per-SDK files like `sdk/go/CONFORMANCE.md`, or a section in each SDK's README.

- Should a fake/mock client implementation be a Core requirement or Extended? The Go SDK includes a full fake client package, which is valuable for testing but adds significant code.

- How does SDK conformance interact with the beta/1.0 stability milestones? Should Core conformance be a prerequisite for including an SDK in a release?

- Should the scorecard eventually be machine-readable (e.g., a YAML file) to enable automated dashboard generation?
