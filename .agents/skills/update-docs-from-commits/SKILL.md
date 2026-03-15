---
name: update-docs-from-commits
description: Scan recent git commits for changes that affect user-facing behavior, then draft or update the corresponding documentation pages. Use when docs have fallen behind code changes, after a batch of features lands, or when preparing a release. Trigger keywords - update docs, draft docs, docs from commits, sync docs, catch up docs, doc debt, docs behind, docs drift.
---

# Update Docs from Commits

Scan recent git history for commits that affect user-facing behavior and draft documentation updates for each.

## Prerequisites

- You must be in the OpenShell git repository.
- The `docs/` directory must exist with the current doc set.
- Read `docs/CONTRIBUTING.md` before writing any content. It contains the style guide and formatting rules.

## When to Use

- After a batch of features or fixes has landed and docs may be stale.
- Before a release, to catch any doc gaps.
- When a contributor asks "what docs need updating?"

## Step 1: Identify Relevant Commits

Determine the commit range. The user may provide one explicitly (e.g., "since v0.2.0" or "last 30 commits"). If not, default to commits since the head of the main branch.

```bash
# Commits since a tag
git log v0.2.0..HEAD --oneline --no-merges

# Or last 50 commits
git log -50 --oneline --no-merges
```

Filter to commits that are likely to affect docs. Look for these signals:

1. **Commit type**: `feat`, `fix`, `refactor`, `perf` commits often change behavior. `docs` commits are already doc changes. `chore`, `ci`, `test` commits rarely need doc updates.
2. **Files changed**: Changes to `crates/openshell-cli/`, `python/`, `proto/`, `deploy/`, or policy-related code are high-signal.
3. **Ignore**: Changes limited to `tests/`, `e2e/`, `.github/`, `tasks/`, or internal-only modules.

```bash
# Show files changed per commit to assess impact
git log v0.2.0..HEAD --oneline --no-merges --name-only
```

## Step 2: Map Commits to Doc Pages

For each relevant commit, determine which doc page(s) it affects. Use this mapping as a starting point:

| Code area | Likely doc page(s) |
|---|---|
| `crates/openshell-cli/` (gateway commands) | `docs/sandboxes/manage-gateways.md` |
| `crates/openshell-cli/` (sandbox commands) | `docs/sandboxes/manage-sandboxes.md` |
| `crates/openshell-cli/` (provider commands) | `docs/sandboxes/manage-providers.md` |
| `crates/openshell-cli/` (new top-level command) | May need a new page or `docs/reference/` entry |
| `crates/openshell-proxy/` or policy code | `docs/sandboxes/policies.md`, `docs/reference/policy-schema.md` |
| `crates/openshell-inference/` | `docs/inference/configure.md` |
| `python/` (SDK changes) | `docs/reference/` or `docs/get-started/quickstart.md` |
| `proto/` (API changes) | `docs/reference/` |
| `deploy/` (Dockerfile, Helm) | `docs/sandboxes/manage-gateways.md`, `docs/about/architecture.md` |
| Community sandbox definitions | `docs/sandboxes/community-sandboxes.md` |

If a commit does not map to any existing page but introduces a user-visible concept, flag it as needing a new page.

## Step 3: Read the Commit Details

For each commit that needs a doc update, read the full diff to understand the change:

```bash
git show <commit-hash> --stat
git show <commit-hash>
```

Extract:

- What changed (new flag, renamed command, changed default, new feature).
- Why it changed (from the commit message body, linked issue, or PR description).
- Any breaking changes or migration steps.

## Step 4: Read the Current Doc Page

Before editing, read the full target doc page to understand its current content and structure:

```bash
# Read the file
```

Identify where the new content should go. Follow the page's existing structure.

## Step 5: Draft the Update

Write the doc update following the rules in `docs/CONTRIBUTING.md`. Key reminders:

- **Active voice, present tense, second person.**
- **No unnecessary bold.** Reserve bold for UI labels and parameter names.
- **No em dashes** unless used sparingly. Prefer commas or separate sentences.
- **Start sections with an introductory sentence** that orients the reader.
- **No superlatives.** Say what the feature does, not how great it is.
- **Code examples use `console` language** with `$` prompt prefix.
- **Include the SPDX header** if creating a new page.
- **Match existing frontmatter format** if creating a new page.
- **Always write NVIDIA in all caps.** Wrong: Nvidia, nvidia.
- **Always capitalize OpenShell correctly.** Wrong: openshell, Openshell, openShell.
- **Do not number section titles.** Wrong: "Section 1: Deploy a Gateway" or "Step 3: Verify." Use plain descriptive titles.
- **No colons in titles.** Wrong: "Gateways: Deploy and Manage." Write "Deploy and Manage Gateways" instead.
- **Use colons only to introduce a list.** Do not use colons as general-purpose punctuation between clauses.

When updating an existing page:

- Add content in the logical place within the existing structure.
- Do not reorganize sections unless the change requires it.
- Update any cross-references or "Next Steps" links if relevant.

When creating a new page:

- Follow the frontmatter template from `docs/CONTRIBUTING.md`.
- Add the page to the appropriate `toctree` in `docs/index.md`.

## Step 6: Present the Results

After drafting all updates, present a summary to the user:

```
## Doc Updates from Commits

### Updated pages
- `docs/sandboxes/manage-gateways.md`: Added `--gpu` flag documentation (from commit abc1234).
- `docs/reference/policy-schema.md`: Updated network policy schema for new `tls_inspect` field (from commit def5678).

### New pages needed
- None (or list any new pages created).

### Commits with no doc impact
- `chore(deps): bump tokio` (abc1234) — internal dependency, no user-facing change.
- `test(e2e): add gateway timeout test` (def5678) — test-only change.
```

## Step 7: Build and Verify

After making changes, build the docs locally:

```bash
mise run docs
```

Check for:

- Build warnings or errors.
- Broken cross-references.
- Correct rendering of new content.

## Tips

- When in doubt about whether a commit needs a doc update, check if the commit message references a CLI flag, config option, or user-visible behavior.
- Group related commits that touch the same doc page into a single update rather than making multiple small edits.
- If a commit is a breaking change, add a note at the top of the relevant section using a `:::{warning}` admonition.
- PRs that are purely internal refactors with no behavior change do not need doc updates, even if they touch high-signal directories.

## Example Usage

User says: "Catch up the docs for everything merged since v0.2.0."

1. Run `git log v0.2.0..HEAD --oneline --no-merges --name-only`.
2. Filter to `feat`, `fix`, `refactor`, `perf` commits touching user-facing code.
3. Map each to a doc page.
4. Read the commit diffs and current doc pages.
5. Draft updates following the style guide.
6. Present the summary.
7. Build with `mise run docs` to verify.
