---
authors:
  - "@your-github-username"
state: draft
links:
  - (GitHub issue where this feature request is discussed)
  - (related discussions, RFCs, PRs, docs, or prior art)
---

# Feature Request NNNN - Your Title Here

<!--
See feature-requests/README.md for the full feature request process and state
definitions.

Use this template to propose a new OpenShell feature from a product and user
requirements perspective.

This document should explain what users need, why the feature belongs in
OpenShell, how success will be evaluated, and whether the capability should be
available everywhere or only in specific environments.

Avoid detailed implementation design here. If maintainers approve the feature
request and the work needs deeper technical design, link an RFC in the
"Technical RFC" section below.
-->

## Summary

Briefly describe the feature and the user-visible outcome.

## User problem

What user problem does this solve? Who experiences it, how often, and what is
the impact today?

## Target users

Who is this for?

## Use cases

Describe the main workflows this feature should support.

Example:

> As a ...
> I want ...
> So that ...

## Why this belongs in OpenShell

Explain why OpenShell should own this capability instead of leaving it to user
configuration, documentation, an external tool, a downstream fork, or a
platform-specific workaround.

## Product scope

What should be included in this feature?

## Non-goals

What is intentionally out of scope?

## Suggested product surface

Where should users experience this capability?

- Built-in OpenShell behavior available across supported environments
- A capability exposed by one or more compute drivers
- A provider or external-service integration
- Sandbox policy or security configuration
- Inference routing configuration
- CLI, TUI, SDK, docs, or examples
- Not sure; maintainer guidance requested

## Availability and support expectations

Where should users expect this feature to work? Answer in terms of user
expectations and portability, not implementation details.

- Should every OpenShell user expect this feature to exist?
- Is the feature only meaningful in specific operating environments or
  deployment modes?
- Is this mainly about integrating with a specific external service?
- What should users be able to rely on consistently across environments?

## Requirements

List product requirements. These should describe observable behavior, not code
structure.

- The feature must ...
- The feature should ...
- The feature may ...

## User experience

Describe the expected user experience at a high level. Include example commands,
screens, settings, or docs only when they clarify the product behavior.

## Success criteria

How will maintainers know this feature worked? How can success be measured? 

## Priority and urgency

Why should this be done now? What happens if it is deferred?

## Risks and tradeoffs

What are the product risks?

Examples:

- increases OpenShell scope too much
- creates confusing overlap with an existing capability
- adds maintenance burden for drivers or providers
- creates inconsistent behavior across environments
- weakens security, privacy, or policy expectations

## Alternatives and workarounds

What can users do today? Why is that insufficient?

What other product approaches were considered?

## Related work and prior art

Link to related issues, discussions, docs, or examples in OpenShell and other
projects.

## Technical RFC

Link an RFC here if this feature is approved and needs detailed technical
design.

- RFC: TBD

## Contribution intent

Would you or your organization help move this forward?

- [ ] I can help define requirements
- [ ] I can test or validate the feature
- [ ] I can contribute implementation after the feature is approved
- [ ] I need maintainer guidance before committing to contribution
- [ ] I cannot contribute at this time

## Open questions

- ...
