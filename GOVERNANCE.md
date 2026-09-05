# OpenShell Project Governance

OpenShell is dedicated to creating safe, private, policy-governed runtimes for autonomous AI agents. This document explains how the project is governed.

## Values

OpenShell and its leadership embrace the following values:

- **Openness:** Communication and decision-making happen in the open and remain discoverable for future reference. As much as possible, discussions and work take place in public forums and repositories.
- **Fairness:** All stakeholders may provide feedback and submit contributions. The project considers contributions on their merits.
- **Community over product or company:** Sustaining and growing the community takes priority over shipping code or advancing one sponsor's organizational goals. Contributors participate as individuals.
- **Vendor neutrality:** No single organization controls project direction or decisions. Maintainer selection, roadmap priorities, and release decisions are based on the interests of the project rather than employer affiliation.
- **Inclusivity:** Different perspectives and skills make OpenShell better. The project provides a welcoming and respectful environment for participation.
- **Participation:** Responsibilities and privileges are earned through sustained participation, demonstrated judgment, and earned community trust.

## Contributor Ladder

OpenShell uses a contributor ladder to provide a path from participation to project leadership. Movement through the ladder reflects increasing trust, responsibility, and project-wide stewardship. Contributions may include code, documentation, design, testing, issue triage, reviews, release work, community support, and other work that advances the project.

### Contributor

A Contributor is anyone who participates constructively in the OpenShell community.

Contributors are responsible for:

- Following the project Code of Conduct and contribution guidelines.
- Taking responsibility for the correctness and provenance of their work, including work created with AI tools or agents.
- Engaging constructively with reviewers, users, and other contributors.

Contributors may:

- Participate in project discussions.
- Submit issues, designs, code, documentation, tests, and reviews.
- Help other contributors and users.

### Reviewer

A Reviewer is a trusted Contributor with demonstrated knowledge in one or more project areas. Reviewers help maintain quality and provide consistent, actionable feedback, but do not receive project-wide merge or voting rights by virtue of this role.

Reviewers are responsible for:

- Regularly reviewing contributions in their areas of knowledge.
- Reviewing for correctness, security, maintainability, tests, documentation, and consistency with project direction.
- Supporting new and occasional contributors and helping them improve useful contributions.
- Escalating decisions that require broader expertise or project-wide input.

A Reviewer demonstrates:

- A record of constructive, technically valuable reviews.
- A working knowledge of the relevant project areas and their operational context.
- Reliable collaboration and follow-through.
- Judgment exercised for the good of OpenShell, independent of employer, product, or team interests.

An existing Maintainer may nominate a Contributor to become a Reviewer. A simple majority vote of the Maintainers approves the nomination. Maintainers may grant the GitHub permissions needed for the Reviewer's responsibilities.

### Maintainer

Maintainers have project-wide write, merge, and voting privileges. They are collectively responsible for steering OpenShell in a positive direction and for managing project resources and contributor access. The current Maintainers are listed in [MAINTAINERS.md](MAINTAINERS.md).

Maintainer status is held by individual humans. AI agents, automated systems, service accounts, companies, and other organizations cannot be Maintainers or exercise Maintainer votes.

Maintainers are responsible for:

- Reviewing and merging contributions across the project.
- Protecting project quality, security, architectural coherence, and long-term maintainability.
- Participating in project-wide technical, governance, roadmap, and release decisions.
- Seeking review from the people most knowledgeable about affected areas.
- Mentoring Contributors, Reviewers, and prospective Maintainers.
- Supporting contributions that benefit the broader community, including work outside their employer's immediate priorities.
- Following through on regressions and other issues arising from decisions they approve.
- Representing OpenShell and its community responsibly.

Maintainers may:

- Approve and merge changes after applicable review and automated checks.
- Vote on project matters.
- Nominate Contributors for Reviewer or Maintainer roles.
- Represent OpenShell in public and communicate with the CNCF on behalf of the project.

The collective team of Maintainers is the Maintainer Council, the governing body for OpenShell.

## Becoming a Maintainer

Maintainer status reflects established trust and readiness to steward the whole project. Activity metrics are an eligibility floor, not a scorecard, an automatic promotion mechanism, or sufficient evidence of readiness.

A candidate must first meet all of the following minimum participation requirements:

- At least three months of sustained participation in OpenShell discussions, contributions, reviews, or other project work.
- At least three substantial pull requests merged into the project.
- Constructive reviews of at least five substantial pull requests.
- Demonstrated contribution to the general core product through reviews and feedback on third-party contributions beyond a feature, product, or project primarily needed by the candidate or their organization.

For these requirements, a substantial pull request is work that requires meaningful technical or project judgment. Mechanical changes, generated volume, lines changed, and a series of closely related pull requests do not by themselves demonstrate substance. Maintainers evaluate the scope, difficulty, quality, impact, and judgment shown by the work in context.

Meeting the minimum participation requirements only establishes eligibility. A candidate must also demonstrate:

- Deep understanding of OpenShell in one or more project areas, including how those areas interact with the broader platform.
- Sound technical and product judgment, including an ability to identify risk, evaluate tradeoffs, and preserve long-term maintainability.
- Consistently high-quality implementation or documentation work and technically useful reviews.
- Understanding of project architecture, contribution policies, testing, security expectations, review practices, and development workflows.
- Reliable collaboration, respectful communication, and follow-through.
- Support for new and occasional contributors.
- A community-first perspective and an ability to act independently of the candidate's employer, friends, team, product, or organizational priorities.
- Personal accountability for contributions and reviews, including the ability to explain, validate, and take responsibility for work produced with AI tools or agents.
- Direct participation in OpenShell community calls, sufficient for the community to know the person behind the contributions and for Maintainers to assess the candidate's understanding, judgment, communication, and accountability.

The use of AI or agents neither qualifies nor disqualifies a candidate. The Maintainer Council evaluates the candidate's demonstrated understanding, judgment, accountability, community participation, and the value they add to the project's human review and decision-making capacity. Raw contribution velocity, lines of code, and activity counts beyond the eligibility floor are not proxies for those qualities.

Community call attendance is qualitative evidence, not an attendance quota or substitute for the other requirements. Candidates who cannot reasonably attend the regular call because of time zone, accessibility, or similar constraints may arrange equivalent direct, synchronous participation with community members and Maintainers. Video participation is not required.

An existing Maintainer must nominate a candidate by sending a message to the [project mailing list](mailto:openshell-maintainers@ai-openshell.org). A simple majority vote of all active Maintainers approves the nomination. Nominations are evaluated without prejudice to employer or demographics and should consider the organizational diversity of the Maintainer Council.

Approved Maintainers receive the GitHub rights needed for the role, are added to [MAINTAINERS.md](MAINTAINERS.md), and are invited to Maintainer communication channels.

## Removing a Maintainer

A Maintainer may resign at any time when they can no longer fulfill the role.

A Maintainer may also be removed for inactivity, persistent failure to fulfill Maintainer responsibilities, a Code of Conduct violation, behavior detrimental to the project, or other cause. Inactivity means six months of very low or no project activity without a definite plan to resume active participation. Non-code project work counts as activity.

Removal requires a two-thirds vote of the remaining active Maintainers. A Maintainer whose removal is under consideration may participate in the discussion but does not vote on their own removal.

### Emeritus Maintainers

Depending on the circumstances of a resignation or removal, a Maintainer may move to Emeritus status. Emeritus Maintainers are recognized for past contributions and may be consulted on project matters, but they do not have voting rights or merge access. They are listed separately in [MAINTAINERS.md](MAINTAINERS.md).

An Emeritus Maintainer may return to active status through the standard Maintainer nomination and voting process, provided they meet the current requirements and can commit to active participation.

## Meetings and Communication

Project governance ordinarily takes place through public GitHub issues, discussions, and pull requests so decisions are visible and discoverable. Anyone interested in OpenShell may join the [OpenShell Community Google Group](https://groups.google.com/a/ai-openshell.org/g/openshell-community/about) to receive the community meeting invitation and view the community meeting agenda. Consequential decisions made during a meeting must be recorded in a public project artifact.

Maintainers may meet privately when handling security reports, Code of Conduct reports, personnel matters, or other sensitive information. All Maintainers must be invited except anyone whose participation would create a conflict of interest, including a Maintainer who is the subject of a report.

## CNCF Resources

Any Maintainer may propose a request for CNCF resources through the [project mailing list](mailto:openshell-maintainers@ai-openshell.org) or a project meeting. A simple majority vote of active Maintainers approves the request. The Maintainer Council may delegate CNCF coordination to a non-Maintainer community member and arrange the access needed for that work.

## Code of Conduct

OpenShell follows the [CNCF Code of Conduct](https://github.com/cncf/foundation/blob/main/code-of-conduct.md). The Maintainer Council handles reports privately and coordinates with the CNCF Code of Conduct Committee when appropriate. If a Maintainer is directly involved in a report, that Maintainer is excluded from its handling, and the remaining Maintainers designate at least two uninvolved Maintainers to coordinate the response.

## Security Response

Security reports are handled according to the project [security policy](SECURITY.md). The Maintainer Council appoints or recognizes the people responsible for coordinating security responses and reviews the response process and membership at least annually.

## Voting

OpenShell uses [lazy consensus](https://community.apache.org/committers/decisionMaking.html#lazy-consensus) for most decisions: a proposal proceeds when there is general agreement and no unresolved, reasoned objection. Maintainers should allow time appropriate to the impact and urgency of a decision so that affected contributors across time zones can participate.

Any Maintainer may call for a formal vote on the [project mailing list](mailto:openshell-maintainers@ai-openshell.org) or at a project meeting. Unless this document states otherwise, a proposal requires a simple majority of all active Maintainers to pass. A two-thirds vote requires support from at least two-thirds of all active Maintainers. Maintainers must disclose relevant conflicts of interest and recuse themselves when they cannot act solely in the project's interest.

## Evolving This Governance

The Maintainer Council should revisit this model as OpenShell grows. Signals that the project may need working groups, area-specific approvers, subproject governance, organization-balanced voting, or an elected steering body include:

- Decisions routinely stall because the Maintainer Council is too large or different project areas need delegated authority.
- Contributors cannot find a clear path to greater responsibility.
- One organization dominates project decisions or Maintainer membership.
- Subprojects develop distinct contributor communities or release cadences.

Such changes are a sign of project growth rather than governance failure.

## Modifying This Governance

Changes to this governance document and its supporting governance documents require a two-thirds vote of all active Maintainers.
