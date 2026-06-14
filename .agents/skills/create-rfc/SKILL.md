---
name: create-rfc
description: Create OpenShell RFC proposals in rfc/ from a design request. Use when the user asks to write, draft, start, create, or update an RFC, Request for Comments, architecture proposal, API proposal, process proposal, or cross-cutting design proposal that should follow the OpenShell RFC process and template.
---

# Create RFC

## Workflow

Create RFCs by following `rfc/README.md` and `rfc/0000-template/README.md`.
Keep the template as the source of truth for section guidance.

1. Read `rfc/README.md` to confirm when an RFC is appropriate, how to choose the
   RFC number, and how the lifecycle works.
2. Read `rfc/0000-template/README.md` before drafting. Follow its section
   guidance, including scope, expected detail, and suggested section length.
3. Choose the next available `NNNN` from the existing `rfc/NNNN-*` directories
   unless the user provided a specific number.
4. Create `rfc/NNNN-short-title/README.md` by copying the template and replacing
   placeholders. Use a short hyphenated folder title.
5. Fill in front matter with the RFC author, `state: draft`, and any related
   links the user provided. If the author is unknown, use the requesting user's
   GitHub handle when available or leave the template placeholder.
6. Draft each section from the user's design context. Keep Summary concise,
   Motivation readable by anyone, Non-goals explicit, Proposal focused on what
   is being proposed, and Alternatives focused on credible competing approaches.
7. Preserve uncertainty in Open questions instead of silently deciding unknowns.
   If a missing decision blocks a coherent RFC, ask the user for that decision.
8. Check the completed RFC against the template once more before finishing.

## Writing Standards

- Prefer concrete design statements over placeholder language.
- Link to relevant issues, prior RFCs, and architecture docs when they provide
  needed context.
- Keep rejected or left-out designs in Alternatives, not Proposal.
- Use Mermaid diagrams for architecture or data flow when a diagram would make
  the proposal easier to review.
- Do not update `architecture/` or published docs just because an RFC was
  drafted. Those updates belong with implementation or with an accepted RFC when
  the user asks for them.

## Validation

Before handing the RFC back to the user:

- Verify the folder name and RFC number match the process in `rfc/README.md`.
- Verify every template section is present or intentionally marked as not
  applicable.
- Run a Markdown formatting or lint check only if the repo already provides one
  for Markdown-only changes.
