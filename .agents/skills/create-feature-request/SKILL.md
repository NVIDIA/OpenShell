---
name: create-feature-request
description: Create a numbered OpenShell feature request document from a user's feature idea, populate it from the information provided, ask focused follow-up questions, and leave the user with a draft to complete. Use when the user says things like "create a feature request to do XYZ", "start a feature request doc", "draft a feature proposal", or "create a product proposal".
---

# Create Feature Request

Create a repo-backed feature request document from the user's feature idea. The
feature request is a product proposal, not an implementation plan.

The skill's job is to start and improve the draft. The user owns completing the
document before asking for review.

## Core Flow

```text
User asks: "create a feature request to do XYZ"
  |
  +-- Copy the feature request template into the next numbered folder
  |
  +-- Populate the new README with information the user already provided
  |
  +-- Ask focused follow-up questions about missing product context
  |
  +-- Update the doc with the user's answers
  |
  +-- Ask the user to complete any remaining TODOs
```

Do not create a GitHub issue, open a PR, mark the document complete, or change
the state from `draft` unless the user explicitly asks for that later.

## Step 1: Create The Draft

Feature requests live under `feature-requests/NNNN-short-slug/`.

Find the next available number by inspecting existing folders:

```bash
find feature-requests -maxdepth 1 -type d -name '[0-9][0-9][0-9][0-9]-*' | sort
```

Choose the next zero-padded number. Create a short lowercase slug from the
feature title using product language, not implementation details.

Copy the template:

```bash
cp -r feature-requests/0000-template feature-requests/NNNN-short-slug
```

Then edit `feature-requests/NNNN-short-slug/README.md`.

Set the front matter:

```yaml
---
authors:
  - "@<author>"
state: draft
links:
  - (GitHub issue to be created after this feature request doc is complete and GitHub-visible)
  - (related discussions, RFCs, PRs, docs, or prior art)
---
```

Use the user's GitHub username when known. Otherwise use
`TODO(<author>): add GitHub username`.

## Step 2: Populate From User-Provided Information

Fill sections only when the user's request, notes, or existing draft provide
clear support. Do not invent product requirements.

Use `TODO(<author>): ...` placeholders for incomplete sections. Make each TODO
specific enough that the user knows what to add.

Good TODOs:

- `TODO(<author>): describe the target users for this feature.`
- `TODO(<author>): explain the current workaround and why it is insufficient.`
- `TODO(<author>): define success criteria maintainers can evaluate.`

Do not add code-level design, internal API structure, or implementation plans.
Feature requests stay focused on user problems, product requirements, scope,
non-goals, success criteria, risks, alternatives, and OpenShell fit.

## Step 3: Ask Follow-Up Questions

After the first draft is created, inspect the remaining TODOs and ask the user
for the highest-value missing information. Ask a small number of focused
questions rather than dumping the whole template back on the user.

Prefer questions about:

- the user problem,
- target users,
- desired outcome,
- current workaround,
- why OpenShell should own the capability,
- product scope and non-goals,
- availability and support expectations,
- success criteria,
- risks, tradeoffs, alternatives, and prior art.

When the user answers, update the feature request doc with the new information
and leave unresolved sections as visible `TODO(<author>)` placeholders.

## Step 4: Hand The Draft Back To The User

When the draft has been populated with the available information, report:

1. The created file path.
2. The sections that still need user input.
3. A clear instruction that the user should complete the remaining TODOs before
   asking for review, opening a PR, or creating a linked discussion issue.

Never present an agent-generated feature request as complete or approved. Core
maintainer approval is human-only.

## Output Shape

```markdown
Started feature request draft:
[README.md](/absolute/path/to/feature-requests/NNNN-short-slug/README.md:1)

I populated the sections supported by your request. Please review the draft and complete any remaining
TODOs before asking for feature request review.
```

## Relationship To Other Workflows

- Use this skill for substantial feature ideas that need a product
  proposal.
- Use GitHub Discussions for rough feature ideas that are not ready for a
  feature request document.
- Create a linked GitHub issue only after the feature request doc is complete
  and GitHub-visible.
- Use the RFC process only after maintainers review the completed feature
  request and ask for deeper technical design.
