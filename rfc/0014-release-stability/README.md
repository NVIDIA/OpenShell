---
authors:
  - "@drew"
state: review
links:
  - https://github.com/NVIDIA/OpenShell/pull/2148
  - https://github.com/NVIDIA/OpenShell/pull/2695
---

# RFC 0014 - Alpha Exit Criteria and Stable Release Policy

## Summary

The goal of this RFC is to define OpenShell's exit from alpha and establish a
predictable release cycle for production users and ecosystem developers.

We propose

- Development releases for every commit to `main`, nightly release candidates, and qualified stable releases every Tuesday.
- Preview and Stable API maturity, compatibility, and versioning
  rules, and maintenance for the latest and N-1 minor release lines.
- A release qualification pipeline covering conformance, upgrades,
  API changes, and security reviews across the supported release matrix.

## Motivation

The goal is to exit alpha without slowing OpenShell's development. Releases
should remain frequent and automated, and Preview APIs should be able to
evolve quickly enough to keep pace with the ecosystem. At the same time, users
need Stable interfaces they can confidently build on.

Starting with `0.1.0`, OpenShell provides both: a defined compatibility contract
for Stable interfaces and room to evolve Preview APIs and features.
Releases are suitable for production use within the published support matrix
only after passing conformance, upgrade, compatibility, artifact, and security
checks.

## Proposal

### Release cadence

Starting with `0.1.0`, OpenShell publishes stable tagged releases intended for production use within
the published support matrix. Stable releases occur every Tuesday and increment
the patch version, for example `0.1.1` followed by `0.1.2`. A stable tag is
published only when there are changes and every blocking qualification suite
passes.

OpenShell publishes a development release for every commit to `main`. Each
development release identifies its source commit and artifact manifest, and the
floating `dev` alias points to the newest one. Development releases enable all
development compilation flags and features.

OpenShell builds a release candidate nightly for the next expected stable
release when `main` has changed and normal CI passes. After `0.1.1`, candidates
are numbered `0.1.2-rc.1`, `0.1.2-rc.2`, and so on. A release candidate is promoted to a stable release tag as part of the weekly release pipeline once the candidate has passed qualification.

### Project version and compatibility contract

Version `0.1.0` begins OpenShell's supported compatibility contract. For
the `0.x` series:

- Patch releases may contain bug fixes and additive, backward-compatible
  functionality. They do not intentionally break a stable interface.
- An unavoidable breaking change to any stable interface starts a new minor
  release and resets the patch version, for example `0.1.x` to `0.2.0`.

### API and feature maturity

OpenShell designates public Protobuf definitions and their corresponding SDK
interfaces as Preview or Stable. Protobuf packages encode the designation in
their version name. SDKs use language-appropriate package, module, namespace,
or symbol naming to expose the same designation.

| Maturity | Protobuf naming | SDK naming | Compatibility |
| --- | --- | --- | --- |
| Preview | `v1preview` or `v1preview1` | Language-specific Preview package, module, namespace, or symbol | May change or be removed in any release |
| Stable | `v1` or `v2` | Default Stable package, module, namespace, or symbol | Covered by the release compatibility contract |

Every API and feature is Preview or Stable, regardless of whether it
appears in stable, release candidate, or development artifacts. Each SDK must
document its language-specific naming convention, and Preview interfaces must
not appear to be Stable.

Preview APIs are intended for public evaluation and rapid iteration. They may
change in place without a compatibility guarantee. Graduation adds a Stable
`v1` package instead of renaming the Preview package in place.

Unreleased features use named compile-time flags such as `unstable-<feature>`,
collected under a `dev` compilation flag. Development releases enable them; stable
releases and release candidates exclude them from service binaries, the CLI,
configuration, and documentation. For now, SDK distributions may include their
generated types and client methods when the SDK naming convention communicates
their maturity.

### Breaking changes and API versioning

If a breaking change affects a stable OpenShell surface, the release moves to
the next minor version. If the same change is incompatible with a Stable
protobuf contract, the protocol must move to a new major-versioned package,
for example `openshell.v1` to `openshell.v2`. The supported server retains the
old protocol for a defined maintenance window and supplies an explicit migration path.

A breaking Stable SDK interface must move to a corresponding versioned SDK
surface and retain the old interface for the same maintenance window. A
breaking CLI, configuration, policy, Helm, or state change requires a minor
project release even when no Protobuf package changes. Conversely, a breaking
Preview API change does not require a minor project release when it does not
break any Stable interface.

Breaking-change detection runs during code review and again during release
candidate qualification. Stable protobuf packages use Buf's `FILE` rules
against the latest stable baseline and any additional supported baseline needed
for the N-1 maintenance promise. Language-specific API checks or agent review
skills cover the public SDKs.

The following examples illustrate how these rules affect a release candidate:

| Example | Concrete change | Release treatment |
| --- | --- | --- |
| Breaking Stable Protobuf contract | `string policy = 7` to `PolicyReference policy = 7` | Blocks a patch RC and requires a minor OpenShell release. |
| Breaking Preview Python SDK method | `create_sandbox(timeout=30)` to `create_sandbox(deadline=...)` | May ship in any release with release notes and migration guidance. |
| Breaking stable policy document | `endpoints:` to `destinations:` | Blocks a patch RC unless both fields remain supported. |
| Breaking stable CLI contract | `--policy policy.yaml` to `--policy-file policy.yaml` | Requires retaining the old flag as an alias or shipping a minor release. |

### Release candidate qualification and stable release promotion

The release system separates candidate creation, qualification, and stable
publication:

```mermaid
flowchart LR
    A["Commit to main"] --> B["Dev release<br/>dev features enabled"]
    A --> C["Qualified main commit"]
    C --> D["Nightly RC build<br/>release feature set"]
    D --> E["RC qualification"]
    E -->|"pass"| F["Eligible Tuesday candidate"]
    E -->|"fail"| G["No stable release"]
    F --> H["Build or promote stable artifacts"]
    H --> I["Final artifact checks"]
    I -->|"pass"| J["Create tag and publish"]
    I -->|"fail"| G
```

Every release candidate produces a manifest containing its version,
full source commit, build inputs, artifact names and digests, SBOM and provenance
references, and qualification results. Qualification installs and exercises the
candidate artifacts wherever practical rather than substituting a source build.

Release qualification consists of four suites defined in the
[release qualification supplement](release-qualification.md):

- **Conformance** runs across supported driver and gateway configurations. It
  verifies core sandbox behavior, policy enforcement, and extension contracts.
- **Upgrade** runs once per supported installation package and verifies its
  upgrade path, state migration, post-upgrade health, and rollback where
  promised.
- **Breaking API change review** runs once per candidate and compares stable
  protobuf and SDK interfaces with every applicable compatibility baseline.
- **Security review** runs once per candidate and verifies security scan
  results, reviews changes to security-sensitive boundaries, and confirms that
  every finding has the required disposition.

The initial release targets are defined in the [build matrix](build-matrix.md),
and blocking coverage is defined in the
[release qualification supplement](release-qualification.md).

The weekly release selects the newest eligible release candidate and promotes it to the next stable release.

### Maintenance and backports

OpenShell maintains two release lines: the latest minor and N-1. Support
applies to the newest patch on each line. Users on an older patch update to the
new maintenance patch rather than receiving a separate fix for every historical
patch.

Maintenance releases contain critical reliability fixes and security fixes.
They do not backport features. A fix is developed on the appropriate primary
branch and backported to a `release/<major>.<minor>` branch when the older line
is affected. Each backport passes the compatibility, regression, packaging,
and supported upgrade qualification appropriate to that line.

For example, if `0.3.1` is current and a vulnerability also affects the 0.2
line, OpenShell publishes the next available `0.2.x` patch from the maintained
0.2 branch. A security release may occur immediately rather than waiting for
the next Tuesday release.

## Implementation plan

1. **Keep per-commit dev releases and build 0.1.0 RCs nightly.** Build every
   commit to `main` with all development features, and publish sequential
   `0.1.0-rc.N` candidates with the release feature set leading to 0.1.0.
2. **Make the necessary breaking API changes.** Use the pre-0.1.0 window to
   finalize Stable interfaces, move evolving APIs to Preview packages,
   and establish the compatibility baseline.
3. **Build qualification tests and release machinery.** Automate compatibility
   detection, conformance, upgrade, breaking API change review, security
   qualification, artifact validation, and release publication gates.
4. **Release 0.1.0.** Promote a qualified release candidate, publish the stable
   artifacts and support guidance, and begin the weekly release cadence.
