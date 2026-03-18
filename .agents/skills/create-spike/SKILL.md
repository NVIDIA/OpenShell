---
name: create-spike
description: Investigate a plain-language problem description by deeply exploring the codebase, then create a structured GitHub issue with technical findings. Prequel to build-from-issue — maps vague ideas to concrete, buildable issues. Trigger keywords - spike, investigate, explore, research issue, technical investigation, create spike, new spike, feasibility, codebase exploration.
---

# Create Spike

Investigate a problem, map it to the codebase, and produce a structured GitHub issue ready for `build-from-issue`.

A **spike** is an exploratory investigation. The user has a vague idea — a feature they want, a bug they've noticed, a performance concern — but hasn't mapped it to code, assessed feasibility, or structured it as a buildable issue. This skill does that mapping.

## Prerequisites

- The `gh` CLI must be authenticated (`gh auth status`)
- You must be in a git repository with a GitHub remote

## Workflow Overview

```
User describes a problem
  │
  ├─ Step 1: Gather the problem statement
  │   └─ Ask ONE round of clarifying questions if genuinely needed
  │
  ├─ Step 2: Deep codebase investigation via principal-engineer-reviewer
  │   └─ Map the problem to code, assess feasibility, identify risks
  │
  ├─ Step 3: Determine labels from the repo
  │
  ├─ Step 4: Create a GitHub issue with structured findings
  │
  └─ Step 5: Report to user with issue URL and next steps
```

## Step 1: Gather the Problem Statement

The user provides a problem description. This could be:

- A feature idea: "I want sandboxes to be able to reach private IPs"
- A bug report: "The retry logic in the proxy seems too aggressive"
- A performance concern: "Policy evaluation is slow for large rule sets"
- A refactoring goal: "The config parsing is scattered across too many modules"

Extract from the user's input:

1. **What** they want (the desired outcome or observed problem)
2. **Why** they want it (motivation, use case, or trigger)
3. **Constraints** they've mentioned (backwards compatibility, performance targets, etc.)

### Clarification policy

If the problem is too vague to determine which area of the codebase to investigate, ask **ONE** round of clarifying questions. Do not over-interrogate. Examples of when to ask:

- "Make things faster" — ask which component or operation is slow
- "Fix the networking" — ask what specific behavior is wrong

Examples of when NOT to ask:

- "The retry logic in the proxy is too aggressive" — clear enough, start investigating
- "Allow sandbox egress to private IP space" — clear enough, start investigating
- "The OPA policy evaluation needs caching" — clear enough, start investigating

## Step 2: Deep Codebase Investigation

This is the core of the skill. Use the Task tool with the `principal-engineer-reviewer` sub-agent to perform a thorough codebase investigation.

```
Task tool with subagent_type="principal-engineer-reviewer"
```

The prompt to the reviewer **must** instruct it to:

1. **Identify which components/subsystems are involved.** Don't just guess from names — read the code to confirm.

2. **Read the relevant source files thoroughly.** Not just grep for keywords — actually read and understand the logic. Follow the call chain from entry point through to the relevant behavior.

3. **Map the current architecture for the affected area.** How do the components interact? What's the data flow? Where are the boundaries?

4. **Identify the exact code paths that would need to change.** Provide file paths and line numbers. Name the functions, structs, and modules.

5. **Assess feasibility and complexity:**
   - **Low**: Isolated change, < 3 files, clear path forward
   - **Medium**: Multiple files/components, some design decisions, but well-scoped
   - **High**: Cross-cutting changes, architectural decisions needed, significant unknowns

6. **Identify risks, edge cases, and design decisions that need human input.** What could go wrong? What trade-offs exist? What decisions shouldn't be made by an agent?

7. **Check for existing patterns in the codebase that should be followed.** If there's a convention for how similar features are implemented, note it. The implementation should be consistent.

8. **Look at relevant tests to understand test coverage expectations.** What test patterns exist? What level of coverage is expected for this area?

9. **Check architecture docs** in the `architecture/` directory for relevant documentation about the affected subsystems.

10. **Determine the issue type:** `feat`, `fix`, `refactor`, `chore`, `perf`, or `docs`.

### What makes a good investigation prompt

Include in the prompt to the reviewer:

- The user's problem statement (verbatim or lightly paraphrased)
- Any constraints the user mentioned
- A clear instruction to return: component list, file references with line numbers, architecture summary, feasibility assessment, risks, and the issue type

### What to do with the results

The reviewer will return a detailed analysis. You'll use this to populate the issue body (Step 4). The issue should contain both the stakeholder-readable summary and the full technical investigation — everything in one place.

## Step 3: Determine Labels

Fetch the available labels from the repository:

```bash
gh label list --limit 100
```

Based on the investigation results, select appropriate labels:

- **Do not add issue type labels** — GitHub built-in issue types come from issue templates or manual follow-up, not labels
- **Include area labels** if they exist in the repo (e.g., `area:sandbox`, `area:proxy`, `area:policy`, `area:cli`)
- **Do not invent labels** — only use labels that already exist in the repo
- **Add `state:review-ready`** — the issue is ready for human review upon creation

## Step 4: Create the GitHub Issue

Create the issue with a structured body containing both the stakeholder-readable summary and the full technical investigation. The title should follow conventional commit format.

```bash
gh issue create \
  --title "<type>: <concise description of the problem/feature>" \
  --label "<area:component>" --label "state:review-ready" \
  --body "$(cat <<'EOF'
## Problem Statement

<What and why — refined from the user's description. 2-4 sentences. Written for stakeholders, not just engineers.>

## Technical Context

<What the investigation found about the current architecture in the affected area. How things work today and why a change is needed.>

## Affected Components

| Component | Key Files | Role |
|-----------|-----------|------|
| <component> | `<file1>`, `<file2>` | <what this component does in the context of this change> |
| ... | ... | ... |

## Technical Investigation

### Architecture Overview

<How the affected subsystems work today. Include data flow, component interactions, and relevant design decisions. Reference architecture docs if applicable.>

### Code References

| Location | Description |
|----------|-------------|
| `<file>:<line>` | <what this code does and why it's relevant> |
| `<file>:<line>` | <what this code does and why it's relevant> |
| ... | ... |

### Current Behavior

<What happens today in the code paths that would change. Be specific — name functions, trace the flow.>

### What Would Need to Change

<Detailed breakdown of modifications needed, organized by component. Include specific functions and structs, but stop short of writing an implementation plan — that's `build-from-issue`'s job.>

### Alternative Approaches Considered

<If the investigation surfaced multiple viable approaches, describe them and note trade-offs. Flag which decisions need human input.>

### Patterns to Follow

<Existing patterns in the codebase that the implementation should be consistent with. Reference specific examples.>

## Proposed Approach

<High-level strategy — NOT a full implementation plan. That's `build-from-issue`'s job. Describe the direction, not the steps. 3-6 sentences.>

## Scope Assessment

- **Complexity:** <Low / Medium / High>
- **Confidence:** <High — clear path / Medium — some unknowns / Low — needs discussion>
- **Estimated files to change:** <count>
- **Issue type:** `<feat|fix|refactor|chore|perf|docs>`

## Risks & Open Questions

- <risk or unknown that needs human judgment>
- <design decision that could go either way>
- ...

## Test Considerations

- <what testing strategy makes sense for this change>
- <which test levels are needed: unit, integration, e2e>
- <any test infrastructure that may need to be added>
- <what tests exist for the affected area today, what patterns should be followed, any test infrastructure gaps>

---
*Created by spike investigation. Use `build-from-issue` to plan and implement.*
EOF
)"
```

**Do NOT post a follow-up comment on the issue.** All findings must be contained in the issue body itself.

**Display the issue URL** so it's easily clickable:

```
Created issue [#<number>](https://github.com/OWNER/REPO/issues/<number>)
```

## Step 5: Report to User

After creating the issue, report:

1. The issue URL (as a clickable markdown link)
2. A 2-3 sentence summary of what was found
3. Key risks or decisions that need human attention
4. Next steps:

> Review the issue. Refine the proposed approach if needed, then use `build-from-issue` on the issue to create an implementation plan and build it.

## Design Principles

1. **Everything goes in the issue body.** Do NOT post follow-up comments. The issue body should contain both the stakeholder-readable summary and the full technical investigation, all in one place.

2. **Do NOT create an implementation plan.** The spike identifies the problem space and proposes a direction. The implementation plan is `build-from-issue`'s responsibility, created after human review of the spike.

3. **One round of clarification max.** Don't turn this into an interrogation. If the user provides enough to identify the area of the codebase, start investigating.

4. **The issue should save `build-from-issue` work.** When `build-from-issue` runs, it reads the issue body as input context. The technical investigation section should contain enough detail that its `principal-engineer-reviewer` can build on the investigation rather than starting from scratch.

5. **Cross-reference `build-from-issue`.** Mention it as the natural next step in the issue body footer.

## Useful Commands Reference

| Command | Description |
| --- | --- |
| `gh issue create --title "..." --body "..." --label "..."` | Create a new issue |
| `gh label list --limit 100` | List available labels in the repo |
| `gh issue edit <id> --add-label "..."` | Add labels to an issue |
| `gh issue view <id> --json number,title,body,state,labels` | Fetch issue metadata |

## Example Usage

### Feature spike

User says: "Allow sandbox egress to private IP space via networking policy"

1. Problem is clear — no clarification needed
2. Fire `principal-engineer-reviewer` to investigate:
   - Finds `is_internal_ip()` SSRF check in `proxy.rs` that blocks RFC 1918 addresses
   - Reads OPA policy evaluation pipeline in `opa.rs` and `crates/openshell-sandbox/data/sandbox-policy.rego`
   - Reads proto definitions in `sandbox.proto` for `NetworkEndpoint`
   - Maps the 4-layer defense model: netns, seccomp, OPA, SSRF check
   - Reads `architecture/security-policy.md` and `architecture/sandbox.md`
   - Identifies exact insertion points: policy field addition, SSRF check bypass path, OPA rule extension
   - Assesses: Medium complexity, High confidence, ~6 files
3. Fetch labels — select `area:sandbox`, `area:proxy`, `area:policy`, `state:review-ready`
4. Create issue: `feat: allow sandbox egress to private IP space via networking policy` — body includes both the summary and full investigation (code references, architecture context, alternative approaches)
5. Report: "Created issue #59. The investigation found that private IP blocking is enforced at the SSRF check layer in the proxy. The proposed approach adds a policy-level override. Review the issue and use `build-from-issue` when ready."

### Bug investigation spike

User says: "The proxy retry logic seems too aggressive — I'm seeing cascading failures under load"

1. Problem is clear enough — investigate retry behavior in the proxy
2. Fire `principal-engineer-reviewer`:
   - Finds retry configuration in proxy request handling
   - Reads the retry loop, backoff strategy, and timeout settings
   - Checks if there's circuit breaker logic
   - Maps the failure propagation path
   - Identifies that retries happen without backoff jitter, causing thundering herd
   - Assesses: Low complexity, High confidence, ~2 files
3. Fetch labels — select `area:proxy`, `state:review-ready`
4. Create issue: `fix: proxy retry logic causes cascading failures under load` — body includes both the summary and full investigation (retry code references, current behavior trace, comparison to standard backoff patterns)
5. Report: "Created issue #74. The proxy retries without jitter or circuit breaking, which amplifies failures under load. Straightforward fix. Review and use `build-from-issue` when ready."

### Performance/refactoring spike

User says: "Policy evaluation is getting slow — can we cache compiled OPA policies?"

1. Problem is clear — investigate OPA policy evaluation performance
2. Fire `principal-engineer-reviewer`:
   - Reads the OPA evaluation pipeline end to end
   - Measures where policies are loaded and compiled (per-request vs. cached)
   - Checks if there's an existing caching layer
   - Reads the policy reload/hot-swap mechanism
   - Identifies that policies are recompiled on every evaluation
   - Assesses: Medium complexity, Medium confidence (cache invalidation is a design decision), ~4 files
3. Fetch labels — select `area:policy`, `state:review-ready`
4. Create issue: `perf: cache compiled OPA policies to reduce evaluation latency` — body includes both the summary and full investigation (compilation hot path, per-request overhead, cache invalidation strategies with trade-offs)
5. Report: "Created issue #81. Policies are recompiled per-request with no caching. The main design decision is the cache invalidation strategy — flagged as an open question. Review and use `build-from-issue` when ready."
