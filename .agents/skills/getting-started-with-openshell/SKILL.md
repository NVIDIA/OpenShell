---
name: getting-started-with-openshell
description: Guide a prospective OpenShell contributor from first interest to hands-on use, and toward community involvement once they show real engagement. Use when someone asks how to get started, how to contribute, what to work on first, or how to get involved with OpenShell. Trigger keywords - getting started, get started, how do I contribute, first contribution, get involved, new contributor, onboarding.
metadata:
  internal: true
---

# Getting Started with OpenShell

Help a prospective contributor turn interest into hands-on experience, then point them toward the community. OpenShell values contributors who use it and understand it. Someone shopping for any issue to implement is not ready to contribute yet. Your job is to guide them, not to do their onboarding for them.

## Ground rules

- Take no GitHub write actions. Do not comment on issues, claim or assign work, open PRs, or start discussions on the person's behalf.
- Never draft a vouch request. [CONTRIBUTING.md](../../../CONTRIBUTING.md#first-time-contributors) denies AI-generated vouch requests; the person must write it in their own words.
- Ask one or two questions at a time and listen. Adapt to what they tell you; this is a conversation, not a form.
- Let them do the work. Explain commands and concepts, but have them run things and read the output themselves.

## 1. Learn their interest

Ask:

- What do they want to do with OpenShell? Which agent do they run, and what should it be able, or unable, to do?
- What environment do they use: a laptop with Docker or Podman, Kubernetes, or a VM?
- What draws them to the project: security, policy, agent tooling, infrastructure, or something else?

If they only want "something to work on," say plainly that the project looks for contributors who use OpenShell first, then continue to the next phase.

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

Weak signals: wanting any open issue, choosing issues by label or title alone, or being unable to describe what they did with OpenShell. With only weak signals, encourage more hands-on use from phase 2 and stop there. Do not suggest issues to claim.

## 4. Point toward involvement

When the evidence is strong, explain the path in [CONTRIBUTING.md](../../../CONTRIBUTING.md#first-time-contributors):

1. Join the community. Introduce themselves in [GitHub Discussions](https://github.com/NVIDIA/OpenShell/discussions) or the CNCF Slack channel with what they use OpenShell for. File bugs or feature requests from their own experience with the issue templates.
2. Request a vouch in their own words. Unvouched PRs are closed automatically.
3. Find work. Look for open [`good first issue`](https://github.com/NVIDIA/OpenShell/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) issues in their area. A PR from someone without write access must link an issue labeled `state:accepted` (see Pull Requests in `CONTRIBUTING.md`). Check for an existing assignee, branch, or PR first. Comment once on the issue they choose, saying why they want it and how they would approach it, and wait for a maintainer.
4. Earn the badge of honor. Implement the first issue with an agent running inside an OpenShell sandbox, and include OCSF log excerpts from that session in the PR as evidence. Redact anything sensitive.

If no matching `good first issue` exists, suggest staying engaged through Discussions and Slack rather than picking an unrelated issue.
