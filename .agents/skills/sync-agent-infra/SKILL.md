---
name: sync-agent-infra
description: Detect and fix drift across agent-first infrastructure files. Ensures skill inventories, workflow chains, architecture tables, issue/PR templates, and cross-references stay consistent when skills, crates, or workflows change. Run after adding, removing, or renaming skills or components. Trigger keywords - sync agent infra, sync skills, update agent docs, check agent consistency, agent infra drift, sync contributing, sync agents.
metadata:
  internal: true
---

# Sync Agent Infrastructure

Detect and fix drift across the agent-first infrastructure files. These files reference each other and must stay consistent:

| File | What it tracks |
|------|---------------|
| `AGENTS.md` | Project identity, workflow chains, architecture overview, issue/PR conventions, skill maintenance pointer |
| `CONTRIBUTING.md` | Skills table, workflow chains, "When to Open an Issue" guidance, skill references |
| `CONTRIBUTING.md` issue lifecycle section | Human-facing issue states, roadmap decisions, acceptance signals, and direct-versus-queued agent ownership |
| `README.md` | "Use OpenShell with Your Agent" and "Built With Agents" sections |
| `.github/ISSUE_TEMPLATE/bug_report.yml` | Skill name references in diagnostic guidance |
| `.github/ISSUE_TEMPLATE/feature_request.yml` | Skill name references in investigation guidance |
| `.github/ISSUE_TEMPLATE/config.yml` | Contact link text referencing skills |
| `.github/workflows/issue-triage.yml` | Comment text referencing skills |
| `.agents/skills/triage-issue/SKILL.md` | Skill name references in gate check and diagnosis steps |
| `skills/*/SKILL.md` | Standalone user instructions and links to documentation, included files, and related skills |
| `.agents/skills/create-github-pr/SKILL.md` | Pre-PR agent infrastructure check |
| `.agents/skills/review-github-pr/SKILL.md` | Review-time agent infrastructure check |
| `.agents/skills/build-from-issue/SKILL.md` | Label awareness and pre-commit agent infrastructure check |
| `.claude/agents/principal-engineer-reviewer.md` | Shared review-time agent infrastructure check |

## When to Run

- After adding, removing, renaming, or moving a skill in `skills/` or `.agents/skills/`
- After adding, removing, or renaming a crate in `crates/`
- After changing workflow chain relationships between skills
- After changing which product or development areas a skill covers
- After modifying issue or PR templates
- Before opening a PR that touches any of the above

## Skill Maintenance Map

Use this map when product behavior, commands, or development workflows change. It is a routing aid, not an exhaustive dependency list. Search both `skills/` and `.agents/skills/` for the changed command, field, component, or workflow before concluding that no other skill needs an update.

| Change area | Skills to review |
|---|---|
| CLI commands, flags, defaults, or workflows | `openshell-cli` |
| Sandbox policy schema, presets, or enforcement behavior | `generate-sandbox-policy`, `openshell-cli` |
| Supervisor middleware policy, registrations, runtime, or failure behavior | `generate-sandbox-policy`, `openshell-cli`, `debug-openshell-cluster` |
| Gateway deployment, Helm, runtime drivers, or health checks | `debug-openshell-cluster`, `helm-dev-environment` |
| Inference routing, providers, or `inference.local` behavior | `debug-inference`, `openshell-cli` |
| TUI architecture, navigation, data fetching, or UX | `tui-development` |
| Release artifacts or post-publish smoke coverage | `test-release-canary` |
| GitHub Actions workflows, required checks, or CI diagnostics | `watch-github-actions`; also `test-release-canary` for release smoke coverage |
| Gator harness, sandbox image, supervision, or model overrides | `launch-openshell-gator` |
| SBOM generation, dependency metadata, or license workflows | `sbom` |
| Issue templates, labels, contribution gates, or spike/build workflow | `triage-issue`, `create-spike`, `build-from-issue`, `create-github-issue` |
| PR template, review conventions, or vouch behavior | `create-github-pr`, `review-github-pr`, `build-from-issue` |
| Security review or remediation workflow | `review-security-issue`, `fix-security-issue` |
| RFC template, numbering, or lifecycle | `create-rfc` |
| Documentation structure, navigation, or doc-update workflow | `update-docs-from-commits` |
| Skills, crates, workflow chains, issue/PR templates, or agent cross-references | `sync-agent-infra` |

## Prerequisites

You must be in the OpenShell repository root.

## Step 1: Inventory Current State

Gather the source of truth for each category.

### Skills

List public and contributor skill directories separately:

```bash
ls -1 skills/
ls -1 .agents/skills/
```

The directories are canonical by audience: `skills/` contains public, installable user/operator skills and `.agents/skills/` contains internal contributor workflows. Every other file must agree with both inventories.

### Crates

List all crate directories:

```bash
ls -1 crates/
```

### Workflow Chains

The canonical workflow chains are defined in `AGENTS.md` under "## Workflow Chains". Read that section — it is the source of truth for skill pipelines.

### Labels

The canonical label set is used by skills and templates. The key labels are: `state:triage-needed`, `state:needs-info`, `state:validated`, `state:accepted`, `agent:plan-requested`, `agent:plan-ready`, `agent:implementation-requested`, `agent:in-progress`, `agent:pr-opened`, `roadmap`, `topic:security`, `good first issue`, `help wanted`, `spike`, and the relevant `area:*`, `topic:*`, `integration:*`, and `test:*` labels. Lifecycle and `agent:*` request labels gate unattended queue pickup. They do not prevent a direct user request: the agent warns about each missing or incomplete expected workflow label and continues with the requested phase without changing those labels.

## Step 2: Check Each File for Drift

For each file in the table above, check for the following inconsistencies:

### `CONTRIBUTING.md`

1. **Public skills table** — Every skill in `skills/` must appear in "Skills for Using OpenShell" and no contributor skill may appear there.
2. **Contributor skills table** — Every skill in `.agents/skills/` must appear in "Agent Skills for Contributors" and no public skill may appear there.
3. **Inventory paths** — No skill in either table should reference a directory that does not exist.
4. **Workflow chains** — Must match `AGENTS.md` workflow chains exactly.
5. **Skill references in prose** — Any named skill must exist in exactly one canonical skill directory.

### `AGENTS.md`

1. **Architecture overview** — Every crate in `crates/` must appear in the architecture table. The `python/`, `proto/`, `deploy/`, `.agents/` rows must also be present.
2. **Skill layout** — The architecture table must contain separate `skills/` and `.agents/skills/` rows with accurate audience descriptions.
3. **Workflow chains** — Verify each skill named in a chain exists in exactly one of the two skill directories.
4. **Issue/PR conventions** — Verify referenced skills (`create-github-issue`, `create-github-pr`, `build-from-issue`) exist.
5. **Skill maintenance pointer** — Verify it still points to `sync-agent-infra` and does not duplicate the maintenance map from this skill.

### Issue Lifecycle Documentation

1. **`CONTRIBUTING.md` issue lifecycle section** — State, roadmap, acceptance-signal, and agent-workflow meanings must match `AGENTS.md`.
2. **Invocation modes** — Lifecycle and `agent:*` request labels must gate unattended queue pickup without blocking a direct user request to a specific agent.
3. **Direct-mode warnings** — Guidance must require the agent to warn about each missing or incomplete expected workflow label, continue with the requested phase, and leave labels unchanged.

### `README.md`

1. **Public installation guidance** — The README must distinguish `skills/` from `.agents/skills/`, include `npx skills add NVIDIA/OpenShell`, and list only canonical public skills as installable.
2. **"Built With Agents"** — Contributor skill names must exist under `.agents/skills/`. Workflow descriptions should be consistent with `AGENTS.md` chains.

### Issue Templates

1. **`bug_report.yml`** — Must collect a User Story, Problem Statement, Impact / Why This Matters, Acceptance Criteria, Reproduction Steps, and Environment. Logs are optional and bug-specific; reporter diagnostics must not be required.
2. **`feature_request.yml`** — Must collect a User Story, Problem Statement, Impact / Why This Matters, Proposed Design, Acceptance Criteria, and Alternatives Considered. The design describes workflow and observable behavior without prescribing internal implementation; agent investigation is optional.
3. **`config.yml`** — Skill category descriptions in contact links should be accurate.

### Issue Triage Workflow

1. **`issue-triage.yml`** — Skill names in the redirect comment must exist.

### Skill Cross-References

1. **`triage-issue`** — Skills referenced in gate check and diagnosis steps must exist.
2. **`openshell-cli`** — Companion skills table entries must exist in one canonical location.
3. **`build-from-issue`** — Label names must match the project's label taxonomy. Lifecycle and request labels must gate unattended queue pickup, while direct requests warn on workflow discrepancies and continue.
4. **`create-spike`** — Reference to `build-from-issue` as next step must be accurate.
5. **`review-security-issue`** / **`fix-security-issue`** — Cross-references between the two must be accurate.
6. **PR creation and review checks** — The `create-github-pr`, `review-github-pr`, `build-from-issue`, and `principal-engineer-reviewer` references to `sync-agent-infra` must exist and use trigger conditions aligned with this skill.

### Skill Layout, Metadata, and Portability

1. **Placement** — The four public skills (`openshell-cli`, `generate-sandbox-policy`, `debug-inference`, and `debug-openshell-cluster`) must live only in `skills/`. Every other repository skill must live only in `.agents/skills/`.
2. **Internal metadata** — Every `.agents/skills/*/SKILL.md` must set `metadata.internal: true`. Public skills must not set internal metadata. Treat this as a discovery filter, not an access-control boundary.
3. **Unique names** — Parse the `name` field from every `SKILL.md` under both roots. Every name must be globally unique and match the documented inventory.
4. **Local references** — Every relative Markdown link and referenced file in a skill must resolve within that installed skill directory unless the reference is an explicit published URL.
5. **Canonical paths** — Contributor skills that name the source location of a public skill must use `skills/<name>/...`, never `.agents/skills/<name>/...`.
6. **Public portability** — Public skills must not require repository-relative files under `docs/`, `architecture/`, `crates/`, `deploy/`, or `.agents/`; source builds; `mise`; or repository E2E workflows. Use installed `openshell --help` for command syntax and Markdown endpoints under `https://docs.nvidia.com/openshell/latest/` (URLs ending in `.md`) for product documentation.
7. **No canonical documentation copies** — Review public reference files and large command/schema blocks. Remove material that merely copies CLI help, policy schemas, architecture docs, or published operational documentation; retain only skill-specific reasoning and worked interactions.
8. **Discovery** — Run `npx -y skills add . --list` from a clean checkout or disposable copy. It must list exactly the four public skills. Remove any generated lock file or installed directory after the check.

## Step 3: Report Drift

If any inconsistencies are found, report them in a structured format:

```markdown
## Agent Infrastructure Drift Report

### Skills Inventory
- PUBLIC ADDED (exists in skills/ but missing from CONTRIBUTING.md): <list>
- PUBLIC REMOVED (documented as public but missing from skills/): <list>
- CONTRIBUTOR ADDED (exists in .agents/skills/ but missing from CONTRIBUTING.md): <list>
- CONTRIBUTOR REMOVED (documented as contributor but missing from .agents/skills/): <list>
- METADATA/PATH/NAME ERRORS: <list>
- OK: <public count> public and <contributor count> contributor skills consistent

### Architecture Table
- ADDED (exists in crates/ but missing from AGENTS.md): <list>
- REMOVED (in AGENTS.md but missing from crates/): <list>
- OK: <count> components consistent

### Workflow Chains
- STALE: <chain name> references non-existent skill <skill>
- OK: <count> chains consistent

### Cross-References
- <file>:<line> references non-existent skill <skill>
- <file>:<line> references non-existent label <label>
- The skill maintenance map has a stale or missing change-area mapping: <details>
- OK: <count> references consistent
```

If no drift is found, report: "Agent infrastructure is consistent. No drift detected."

## Step 4: Fix Drift

If drift is found, fix it by updating the affected files:

1. **Added skill** — Add it to the CONTRIBUTING.md skills table in the appropriate category. If it participates in a workflow chain, update the chains in both `AGENTS.md` and `CONTRIBUTING.md`.
2. **Removed skill** — Remove it from all files. Check for references in templates and other skills.
3. **Renamed skill** — Update every reference across all files.
4. **Added crate** — Add a row to the AGENTS.md architecture table.
5. **Removed crate** — Remove the row from the AGENTS.md architecture table.
6. **Changed workflow chain** — Update chains in both `AGENTS.md` and `CONTRIBUTING.md`. Update the "Built With Agents" section in `README.md` if the change is user-visible.
7. **Changed skill coverage** — Update the skill maintenance map in this file and any affected cross-references or companion-skill tables.
8. **Audience or portability drift** — Move the skill to its canonical root, fix internal metadata, replace stale public-skill paths, repair local links, and replace copied product documentation with CLI self-discovery or published documentation links.

After fixing, re-run Step 2 to verify consistency.

## Step 5: Summarize Changes

Report what was fixed:

```markdown
## Changes Made
- Updated CONTRIBUTING.md skills table: added `<skill>`
- Updated AGENTS.md architecture table: removed `<crate>`
- Fixed cross-reference in `.agents/skills/triage-issue/SKILL.md`: `<old>` → `<new>`
```
