---
name: getting-started-with-openshell
description: Guide a prospective OpenShell contributor from first interest to hands-on use, and toward community involvement once they show real engagement. Use when someone asks how to get started, how to contribute, what to work on first, or how to get involved with OpenShell. Trigger keywords - getting started, get started, how do I contribute, first contribution, get involved, new contributor, onboarding, vouch request.
metadata:
  internal: true
---

# Getting Started with OpenShell

Help a prospective contributor turn interest into hands-on experience, then point them toward the community. OpenShell values contributors who use it and understand it. Someone shopping for any issue to implement is not ready to contribute yet. Your job is to guide them, not to do their onboarding for them.

## Ground rules

- Take no GitHub write actions. Do not comment on issues, claim or assign work, open PRs, or post a vouch request on the person's behalf.
- Ask one or two questions at a time and listen. Adapt to what they tell you; this is a conversation, not a form.
- Let them do the work. Explain commands and concepts, but have them run things and read the output themselves.
- Keep track of their answers and what they actually did. Phase 4 builds on that record, and nothing else.

## 1. Learn their interest

Use questions to choose what they should learn first, not to screen them. Ask:

- What do they want to do with OpenShell? Which agent do they run, and what should it be able, or unable, to do?
- What environment do they use: a laptop with Docker or Podman, Kubernetes, or a VM?
- What draws them to the project: security, policy, agent tooling, infrastructure, or something else?

Use the answers to pick the sandbox, policy, and background reading for phase 2. If they only want "something to work on," say plainly that the project looks for contributors who use OpenShell first, then continue to phase 2.

## 2. Build and learn

Guide them through hands-on use that matches their interest. Prefer the published docs at <https://docs.nvidia.com/openshell/latest/> for product concepts and `openshell --help` for command syntax.

1. Install OpenShell, or build it from source following Prerequisites and Getting Started in [CONTRIBUTING.md](../../../CONTRIBUTING.md#prerequisites).
2. Run their own agent in a sandbox with the [Run Your First Agent](https://docs.nvidia.com/openshell/latest/about/run-your-first-agent) guide.
3. Write or adjust a policy for their real use case. Have them trigger an allowed and a denied request.
4. Read the sandbox logs with `openshell logs <sandbox>` and find the OCSF events for those decisions. See [Accessing Logs](https://docs.nvidia.com/openshell/latest/observability/accessing-logs).
5. Point them to background for their area: the architecture table in [AGENTS.md](../../../AGENTS.md#architecture-overview), the relevant crate `README.md`, and related RFCs in [rfc/](../../../rfc/README.md).

Ask what surprised them, what was hard, and what they would change. Their answers are the start of a perspective worth bringing to the community.

## 3. Assess engagement

Look for evidence in the conversation and their workspace. Strong signals:

- A sandbox running a real workload, not only the hello-world example.
- A policy they wrote and can explain.
- Specific friction, a bug, or a missing feature they hit themselves.
- A clear area of interest they can connect to code, docs, or an RFC.

Weak signals: wanting any open issue, choosing issues by label or title alone, or being unable to describe what they did with OpenShell. With only weak signals, encourage more hands-on use from phase 2 and stop there. Do not suggest issues to claim or help with a vouch request.

## 4. Point toward involvement

When the evidence is strong, explain the path in [CONTRIBUTING.md](../../../CONTRIBUTING.md#first-time-contributors):

1. **Join the community.** Get an invite to CNCF Slack at <https://slack.cncf.io>, find the OpenShell channel, and introduce themselves with what they use OpenShell for and what they learned. Join the [OpenShell Community Google Group](https://groups.google.com/a/ai-openshell.org/g/openshell-community/about) to get the community call invitation and agenda, and attend a call. File bugs or feature requests from their own experience with the issue templates.
2. **Request a vouch.** Offer to help draft a [Vouch Request](https://github.com/NVIDIA/OpenShell/discussions/new?category=vouch-request). Build the draft only from their answers in phase 1 and what they did in phases 2 and 3: their use case, the sandbox and policy they ran, and the friction or interest they found. Do not add experience they did not describe or skills they did not show. Have them review the draft and rewrite it in their own voice, then post it themselves. Unvouched PRs are closed automatically.
3. **Find work.** Look for open [`good first issue`](https://github.com/NVIDIA/OpenShell/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) issues in their area. A PR from someone without write access must link an issue labeled `state:accepted` (see Pull Requests in `CONTRIBUTING.md`). Check for an existing assignee, branch, or PR first. Comment once on the issue they choose, saying why they want it and how they would approach it, and wait for a maintainer.
4. **Earn a contributor's badge.** Implement the first issue with an agent running inside an OpenShell sandbox, and include OCSF log excerpts from that session in the PR as evidence. Redact anything sensitive.

If no matching `good first issue` exists, suggest asking in Slack or on a community call where help is wanted, rather than picking an unrelated issue.
