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

## Non-goals

- Moving everything at once or settling every migration detail here.
- Promising runtime support just because a component builds on a platform.
- Redesigning the driver interfaces or deciding every release policy.

## Proposal

These are the proposed homes and responsibilities:

| Repository | Owns and publishes |
| --- | --- |
| `openshell` | CLI, gateway, and supervisor builds for Linux, Windows, and macOS; Linux sandbox runtime with Linux, gVisor, Kata, and Firecracker support; prover; a compute driver that assembles these pieces as host processes. Publishes containers and binaries. |
| `openshell-desktop` | macOS isolation and container integration, Podman, Docker, and possibly microVM support. |
| `openshell-packages` | The one-line `install.sh` installation path and RPM, DEB, and Snap packages. |
| `openshell-homebrew` | The Homebrew tap and `openshell.rb` formula. |
| `openshell-windows` | MSI installer and MXC driver. |
| `openshell-kubernetes` | Helm chart, Kubernetes compute driver supporting gVisor, Kata, Firecracker, and runc, and an operator. Publishes the Helm chart. |
| `openshell-sdks` | Go, Python, Rust, and TypeScript SDKs. |
| `openshell-providers-<provider>` | One repository per provider, such as AWS, Google, OCI, or GitHub, with test infrastructure suited to that integration. |

Each repository should have named maintainers and own its tests and published
artifacts. Core maintainers own the shared contracts; integration maintainers
own how their implementation uses them. We need clear compatibility expectations
so users can assemble a working OpenShell without guessing which versions fit.

The platform and isolation entries above describe the proposed destination,
including future work. Moving code does not make those capabilities available.

## Implementation plan

1. Agree on the boundaries, find initial maintainers, and identify shared code
   and interfaces that currently depend on being in one checkout.
2. Move one focused component first, preserving history where practical. Give
   its new repository tests, release automation, contribution guidance, and a
   documented compatibility relationship with core.
3. Move the remaining components incrementally. Update installation paths,
   documentation, and contributor skills with each move, and validate that the
   released pieces still work together before retiring their old paths.

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

- What macOS isolation mechanism do we mean by "appcontainer" in the original
  outline, and what belongs alongside container support?
- Should microVM support live in desktop, core, or its own repository?
- How should the host compute driver launch and isolate processes? Is
  `systemd-spawn` intended to mean `systemd-nspawn`, and what do other platforms use?
- Where do shared Rust interfaces live, and how do we test compatibility and
  coordinate security fixes across repositories?
- Which component should move first, and who wants to maintain each new home?
