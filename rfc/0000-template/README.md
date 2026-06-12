---
authors:
  - "@your-github-username"
state: draft
links:
  - (related PRs or issues)
---

# RFC NNNN - Your Title Here

<!--
See rfc/README.md for the full RFC process and state definitions.
-->

## Summary

Provide a brief overview of the change in one or two paragraphs. Focus on what
the RFC proposes and the outcome it is intended to enable. Avoid diving into the
full background, implementation detail, or tradeoff analysis here.

A reader should be able to understand the intent of the RFC from this section
alone.

## Motivation

Explain why this change is necessary now. Describe the current problem, who it
affects, and the workflows that are not well served today.

Include enough context that anyone can follow the reasoning. Two to five
paragraphs is usually enough. Cross-cutting or historically loaded changes may
need more context, but prefer linking to relevant issues, prior RFCs,
architecture docs, design discussions, bug reports, or external references
instead of restating long background material.

Useful questions to answer:

- What is broken, missing, confusing, or unnecessarily difficult today?
- What constraints make this worth solving through an RFC instead of a smaller
  issue or pull request?
- What happens if we leave the current design unchanged?

## Non-goals

List the related problems, design options, or implementation details that this
RFC intentionally does not address. Be explicit about boundaries so reviewers
can focus on the decision at hand.

Non-goals are especially useful when the RFC is part of a larger roadmap. Call
out work that may happen later, work tracked by another issue or RFC, and
requirements that are deliberately excluded.

Most RFCs can cover non-goals in three to seven bullets, with one sentence each.
Add a short explanation only when a boundary would otherwise be easy to misread.

## Proposal

This should be the main design section: explain the intended outcome, API shape,
component boundaries, and any important invariants.

Organize the proposal into focused subsections when helpful. This is usually the
longest section, but most RFCs should fit in two to six subsections, with each
subsection roughly one to four paragraphs plus any needed diagrams or examples.

Include the high-value details reviewers need:

- Public interfaces such as APIs, CLI behavior, or configuration.
- Internal boundaries such as crate responsibilities or driver contracts.
- User experience and compatibility impacts.
- Security, privacy, and operational constraints.
- Diagrams or examples when they make the design easier to review.

## Implementation plan

Explain how the project gets from the current state to the proposed state.
Prefer concrete phases over a broad checklist when the work spans multiple
components.

Cover:

- Required implementation, documentation, test, and release steps.
- The intended order of changes and any temporary compatibility layers.
- How existing users and integrations move forward.
- How the change will be validated before and after release.
- Whether the RFC can be implemented incrementally, behind a flag, or as a
  breaking change.

A short overview paragraph plus three to eight bullets or phases is usually
enough. For phased work, keep each phase to one paragraph or a compact bullet
list.

## Risks

Explain why the project might choose not to adopt this proposal. Include costs
that go beyond implementation difficulty.

Consider:

- Compatibility risks and migration burden.
- Security, reliability, or performance risks.
- Complexity added to OpenShell's architecture or contributor workflow.
- New dependencies or support obligations.
- Failure modes and how operators or users would diagnose them.

Where possible, describe mitigations and remaining uncertainty separately.

Most RFCs should cover three to six risks, with one paragraph or bullet per
risk. Higher-risk proposals may need more detail, but keep the focus on risks
that could change the decision.

## Alternatives

Describe credible competing approaches that could solve the same problem,
and explain why the proposal was chosen instead. Include the impact of doing
nothing.

For each meaningful alternative, capture the tradeoff that matters most, such as
implementation complexity or compatibility. Alternatives should make the final
proposal easier to evaluate, not just list rejected ideas.

Most RFCs should cover one to four alternatives. If there are multiple
alternatives, use one subsection per alternative and keep each subsection to one
to three paragraphs.

## Prior art

Identify existing systems or previous OpenShell decisions that informed this
proposal. Explain the lesson that applies here.

Prior art may include upstream projects, standards, RFCs from this repository,
or operational experience from production systems.

Two to five references or examples is usually enough, with one paragraph each
explaining the relevant lesson.

## Open questions

List unresolved design questions and decisions that need reviewer input. Keep
this section current as the RFC evolves.

Each open question should be specific enough for a reviewer to answer or route
to the right owner. If an answer would change the proposal materially, call that
out.

This is usually a short bullet list. Keep each question to one or two sentences,
and remove questions as they are answered.
