---
name: sync-agent-infra
description: Detect and fix drift across agent-first infrastructure files. Ensures skill inventories, workflow chains, architecture tables, issue/PR templates, and cross-references stay consistent when skills, crates, or workflows change. Run after adding, removing, or renaming skills or components. Trigger keywords - sync agent infra, sync skills, update agent docs, check agent consistency, agent infra drift, sync contributing, sync agents.
---

# Sync Agent Infrastructure

Detect and fix drift across the agent-first infrastructure files. These files reference each other and must stay consistent:

| File | What it tracks |
|------|---------------|
| `AGENTS.md` | Project identity, workflow chains, architecture overview, issue/PR conventions |
| `CONTRIBUTING.md` | Skills table, workflow chains, "When to Open an Issue" guidance, skill references |
| `README.md` | "Built With Agents" section, "Explore with your agent" skill references |
| `.github/ISSUE_TEMPLATE/bug_report.yml` | Skill name references in diagnostic guidance |
| `.github/ISSUE_TEMPLATE/feature_request.yml` | Skill name references in investigation guidance |
| `.github/ISSUE_TEMPLATE/config.yml` | Contact link text referencing skills |
| `.github/workflows/issue-triage.yml` | Comment text referencing skills |
| `.agents/skills/triage-issue/SKILL.md` | Skill name references in gate check and diagnosis steps |
| `.agents/skills/openshell-cli/SKILL.md` | Companion skills table |
| `.agents/skills/build-from-issue/SKILL.md` | `state:triage-needed` label awareness |

## When to Run

- After adding, removing, or renaming a skill in `.agents/skills/`
- After adding, removing, or renaming a crate in `crates/`
- After changing workflow chain relationships between skills
- After modifying issue or PR templates
- Before opening a PR that touches any of the above

## Prerequisites

You must be in the OpenShell repository root.

## Step 1: Inventory Current State

Gather the source of truth for each category.

### Skills

List all skill directories:

```bash
ls -1 .agents/skills/
```

This is the canonical skill list. Every other file must agree with it.

### Crates

List all crate directories:

```bash
ls -1 crates/
```

### Workflow Chains

The canonical workflow chains are defined in `AGENTS.md` under "## Workflow Chains". Read that section — it is the source of truth for skill pipelines.

### Labels

The canonical label set is used by skills and templates. The key labels are: `state:agent-ready`, `state:review-ready`, `state:in-progress`, `state:pr-opened`, `state:triage-needed`, `topic:security`, `good first issue`, `spike`, and the relevant `area:*`, `topic:*`, `integration:*`, and `test:*` labels.

## Step 2: Check Each File for Drift

For each file in the table above, check for the following inconsistencies:

### `CONTRIBUTING.md`

1. **Skills table** — Every skill in `.agents/skills/` must appear in the "Agent Skills for Contributors" table. No skill in the table should reference a directory that doesn't exist.
2. **Workflow chains** — Must match `AGENTS.md` workflow chains exactly.
3. **Skill references in prose** — Any skill mentioned by name in "Before You Open an Issue", "When to Open an Issue", or "When NOT to Open an Issue" must exist in `.agents/skills/`.

### `AGENTS.md`

1. **Architecture overview** — Every crate in `crates/` must appear in the architecture table. The `python/`, `proto/`, `deploy/`, `.agents/` rows must also be present.
2. **Workflow chains** — Verify each skill named in a chain exists in `.agents/skills/`.
3. **Issue/PR conventions** — Verify referenced skills (`create-github-issue`, `create-github-pr`, `build-from-issue`) exist.

### `README.md`

1. **"Explore with your agent"** — Skill names referenced must exist in `.agents/skills/`.
2. **"Built With Agents"** — Skill names referenced must exist. Workflow descriptions should be consistent with `AGENTS.md` chains.

### Issue Templates

1. **`bug_report.yml`** — Skill names in the Agent Diagnostic guidance and checklist must exist.
2. **`feature_request.yml`** — Skill names in the Agent Investigation guidance must exist.
3. **`config.yml`** — Skill category descriptions in contact links should be accurate.

### Issue Triage Workflow

1. **`issue-triage.yml`** — Skill names in the redirect comment must exist.

### Skill Cross-References

1. **`triage-issue`** — Skills referenced in gate check and diagnosis steps must exist.
2. **`openshell-cli`** — Companion skills table entries must exist.
3. **`build-from-issue`** — Label names must match the project's label taxonomy.
4. **`create-spike`** — Reference to `build-from-issue` as next step must be accurate.
5. **`review-security-issue`** / **`fix-security-issue`** — Cross-references between the two must be accurate.

## Step 3: Report Drift

If any inconsistencies are found, report them in a structured format:

```markdown
## Agent Infrastructure Drift Report

### Skills Inventory
- ADDED (exists in .agents/skills/ but missing from CONTRIBUTING.md): <list>
- REMOVED (in CONTRIBUTING.md but missing from .agents/skills/): <list>
- OK: <count> skills consistent

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

After fixing, re-run Step 2 to verify consistency.

## Step 5: Summarize Changes

Report what was fixed:

```markdown
## Changes Made
- Updated CONTRIBUTING.md skills table: added `<skill>`
- Updated AGENTS.md architecture table: removed `<crate>`
- Fixed cross-reference in `.agents/skills/triage-issue/SKILL.md`: `<old>` → `<new>`
```
