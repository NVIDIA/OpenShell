---
name: sync-agent-infra
description: Reconcile contributor skills, AGENTS.md, CONTRIBUTING.md, issue and PR templates, and workflow references after repository workflow changes.
metadata:
  internal: true
---

# Sync Agent Infrastructure

Keep contributor guidance consistent without copying procedural workflows into `AGENTS.md`. That file holds repository coding conventions and pointers; the relevant skills hold issue, PR, and maintenance procedures. `CONTRIBUTING.md` explains the human workflow.

## When to run

Run after adding, removing, or renaming a skill or crate; changing issue or PR conventions; changing development workflows; or modifying templates or agent cross references. Run before opening a PR that touches these areas.

## Maintenance map

| Change | Skills to inspect |
|---|---|
| Issues, triage, labels, or feature proposals | `create-github-issue`, `triage-issue`, `create-spike`, `build-from-issue` |
| PR template, vouch behavior, or review conventions | `create-github-pr`, `review-github-pr`, `build-from-issue` |
| Security assessment or remediation | `review-security-issue`, `fix-security-issue` |
| Published docs workflow | `update-docs-from-commits` |
| CLI commands, flags, defaults, or workflows | `openshell-cli` |
| Sandbox policy schema or enforcement | `generate-sandbox-policy`, `openshell-cli` |
| Gateway deployment, Helm, drivers, or health checks | `debug-openshell-cluster`, `helm-dev-environment` |
| Inference providers or native model endpoints | `debug-inference`, `openshell-cli` |
| TUI behavior | `tui-development` |
| Release artifacts or smoke coverage | `test-release-canary` |
| CI diagnostics | `watch-github-actions` |
| Gator supervision | `launch-openshell-gator` |
| SBOM workflow | `sbom` |
| RFC workflow | `create-rfc` |

Search both `skills/` and `.agents/skills/` for affected commands, fields, and components; the map is a starting point.

## Consistency check

1. Compare `skills/*/SKILL.md` and `.agents/skills/*/SKILL.md` with the inventories in `CONTRIBUTING.md`. Public skills must work outside a checkout and use installed CLI help and published documentation. Contributor skills must set `metadata.internal: true`. Confirm names are unique and local links resolve.
2. Compare `crates/` with the architecture table in `AGENTS.md`. Check the public and contributor skill rows.
3. Read the current GitHub labels and their descriptions, then check issue guidance for the general triage → validation → human acceptance process. Skills should mention the `state:*` namespace without enumerating exact labels, and should not depend on `agent:*` labels. A direct request authorizes only the requested phase; unattended work uses current state descriptions, maintainer assignments, and comments to establish the authorized phase.
4. Check issue templates, `create-github-issue`, `create-spike`, and `triage-issue` for the first-hand OpenShell User Story, OpenShell-only bug reproduction, notional UX examples, and consideration of applicable extension points.
5. Check the PR template, `create-github-pr`, `build-from-issue`, `fix-security-issue`, and `CONTRIBUTING.md`: every PR must close an existing issue covering its scope. Multi-PR work needs an issue per PR; a separate issue may track the overall effort.
6. Check `README.md`, `.github/ISSUE_TEMPLATE/`, `.github/workflows/`, `.agents/agents/`, and related skill cross references for stale workflow statements. Keep user-facing documentation changes minimal and avoid duplicated internal explanations.
7. Use `npx -y skills add . --list` from a disposable clean copy when skill discovery changes. It should expose public skills only; clean generated files afterward.

Fix contradictions, then repeat the affected checks. Report files changed and any remaining drift. Do not treat an old document's label list as a source of truth over current GitHub metadata.
