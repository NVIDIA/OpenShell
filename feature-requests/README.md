# OpenShell Feature Requests

Feature requests are product proposals for OpenShell. They describe a user need,
why the capability belongs in OpenShell, what the product should do, and how
maintainers should evaluate success. They are intentionally lighter than RFCs:
feature requests decide **whether** a capability should exist and where it
belongs at the product level; RFCs decide **how** approved, technically involved
capabilities should be designed.

Use feature requests to create a durable record of product intent before
implementation begins.

## Feature requests vs other artifacts

OpenShell has several places where ideas and design information live. Use this
guide to pick the right one:

| Artifact | Purpose | When to use |
|----------|---------|-------------|
| **GitHub Discussion** | Gauge interest in a rough idea | You have an early thought and want feedback before writing a proposal |
| **GitHub issue** | Discuss a concrete feature request | You have a feature request draft or clear product ask and need a durable discussion record |
| **Feature request** | Define product requirements and decide whether OpenShell should own a capability | You know the user problem and want maintainers to evaluate scope, priority, and product fit |
| **Spike issue** (`create-spike`) | Investigate implementation feasibility for scoped work | You need codebase research before an RFC or implementation issue |
| **RFC** | Propose detailed technical design for an approved or likely feature | The change affects architecture, public contracts, multiple components, or requires broad technical consensus |
| **Architecture doc** (`architecture/`) | Document how things work today | Living reference material updated as the system evolves |

The key distinction: **feature requests are product requirements; RFCs are
technical design proposals.** A feature request may lead to an RFC, a spike, a
normal implementation issue, or rejection.

## When to use a feature request

Use a feature request when you want to propose:

- a new user-facing capability,
- a change to OpenShell's product behavior or supported workflows,
- a new environment-specific capability that users should be able to rely on,
- a new supported integration surface,
- a cross-platform behavior whose availability and support expectations need
  to be clear,
- a significant documentation or example initiative that changes how users
  adopt OpenShell.

Feature requests should be written from a user and product perspective. They
should explain the problem, target users, use cases, product scope, non-goals,
success criteria, and why OpenShell is the right layer for the capability.

## When not to use a feature request

Skip the feature request process for:

- bugs,
- small implementation tasks for already-approved behavior,
- routine refactors,
- dependency updates,
- documentation fixes that do not change product direction,
- detailed technical designs without an approved product need.

If the main question is "how should this be implemented?", start with an RFC or
a spike after the product need is clear.

## Best practices

Strong feature requests:

- start with a concrete user problem,
- identify who benefits and how often they encounter the problem,
- explain why the capability belongs in OpenShell rather than user config,
  external tooling, or a downstream fork,
- distinguish product requirements from implementation choices,
- describe where users should expect the feature to be available,
- define non-goals so the scope does not drift,
- describe observable success criteria,
- include current workarounds and why they are not enough,
- link related issues, discussions, RFCs, docs, and prior art,
- call out security, privacy, policy, or portability tradeoffs at the product
  level.

Avoid:

- proposing code structure, internal APIs, or detailed implementation plans,
- treating the feature request as a "please build this" ticket,
- bundling several unrelated features into one proposal,
- assuming every useful integration should be built in,
- skipping non-goals and tradeoffs.

## Availability and support expectations

Feature requests should explain where users should expect a capability to work.
This is a product question, not an implementation design question.

- Should every OpenShell user expect this capability to exist?
- Is it only meaningful in certain operating environments or deployment modes?
- Is it tied to a specific external service or integration?
- What should users be able to rely on consistently across environments?
- Can the user need be met by documenting an existing supported workflow?

If the answer requires detailed contracts, capability negotiation, or technical
design, link a follow-up RFC after the feature request is approved.

## Feature request metadata and state

Every feature request starts with YAML front matter:

```yaml
---
authors:
  - "@username"
state: draft
links:
  - https://github.com/NVIDIA/OpenShell/issues/123
  - https://github.com/NVIDIA/OpenShell/discussions/456
---
```

We track the following metadata:

- **authors**: The authors and owners of the feature request. Use GitHub
  usernames.
- **state**: The current lifecycle state.
- **links**: Related issues, discussions, RFCs, PRs, docs, or prior art.
- **superseded_by**: *(optional)* For feature requests in the `superseded`
  state, the feature request number that replaces this one.

A feature request can be in one of the following states:

| State | Description |
|-------|-------------|
| `draft` | The proposal is being written and is not ready for review. |
| `review` | Under active discussion in a linked GitHub issue and pull request. |
| `accepted` | Maintainers agree the feature belongs in OpenShell. |
| `rejected` | The feature was reviewed and declined. |
| `implemented` | The accepted feature has shipped or is otherwise complete. |
| `superseded` | Replaced by a newer feature request. |

Acceptance means the product direction is approved. It does not necessarily mean
the implementation is ready to begin; maintainers may still require an RFC,
spike, or smaller implementation issues.

## Lifecycle

### 1. Start with discussion when the idea is rough

If the problem or product fit is still uncertain, consider opening a GitHub
Discussion first. Early discussion helps validate the need, surface tradeoffs,
and find the right reviewers.

When the feature is concrete enough for product review, open a GitHub issue.
That issue is the durable discussion record for the feature request and should
be linked from the feature request front matter.

### 2. Reserve a feature request number

Look at the existing folders in this directory and choose the next available
number. If two authors choose the same number on separate branches, the later PR
should pick the next available number during review.

### 3. Create the feature request

Each feature request lives in its own folder:

```text
feature-requests/NNNN-my-feature/
    README.md
    (optional: supporting files)
```

Where `NNNN` is the feature request number, zero-padded to four digits, and
`my-feature` is a short descriptive name.

To start a new feature request, copy the template folder:

```shell
cp -r feature-requests/0000-template feature-requests/NNNN-my-feature
```

Fill in the metadata, include the linked GitHub issue, and keep the state as
`draft` while you are iterating.

### 4. Open a pull request

When the proposal is ready for review, update the state to `review` and open a
pull request. Link the GitHub issue, pull request, and any related discussions,
prior art, or RFCs in the front matter.

### 5. Iterate and decide

Maintainers and contributors review the product need, OpenShell fit, scope,
tradeoffs, priority, and availability expectations. The linked issue should
capture the product discussion; the pull request should carry the concrete doc
updates. The author should update the proposal as the discussion converges.

If accepted, update the state to `accepted`. If declined, update the state to
`rejected` and summarize why. If replaced by a newer proposal, update the state
to `superseded`.

### 6. Follow-up work

After acceptance, maintainers decide the next artifact:

- an RFC for detailed technical design,
- a spike issue for feasibility research,
- one or more implementation issues,
- documentation or example work,
- no immediate work if the feature is accepted but not prioritized.

When the feature is fully delivered, update the state to `implemented` and link
the relevant PRs, issues, docs, and RFCs.
