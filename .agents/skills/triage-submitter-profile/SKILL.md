---
name: triage-submitter-profile
description: Summarize who filed an OpenShell issue, their affiliation, and their track record in the repository, without changing anything on GitHub. Use when triaging an issue, or when asked who filed it, what they have contributed, or what else they have open.
metadata:
  internal: true
---

# Triage Submitter Profile

Give the maintainer reading an issue the context about its author. This skill is read-only: every command it runs is a GET, and it posts nothing. It does not validate the issue or recommend a disposition. For those, run `/triage-validate-issue` and `/triage-recommend-actions` separately.

## No arguments

If `/triage-submitter-profile` was invoked with no arguments, reply with exactly this and end your turn:

```
Usage:
  /triage-submitter-profile <issue>              Submitter identity, affiliation, and track record
  /triage-submitter-profile other-open [issue]   Submitter's open issues and PRs (default: last issue profiled)
```

## Submitter

Run from the repository root:

```bash
bash .agents/skills/triage-submitter-profile/scripts/submitter.sh <issue-number>
```

It prints JSON with the author's profile, their NVIDIA org membership (private membership is visible to org members), and their PR and issue counts in the repo **excluding the issue or PR being profiled**.

Fill this from the JSON:

```markdown
**Submitter of [#N](https://github.com/NVIDIA/OpenShell/issues/N):** <name or "no name listed"> ([GitHub profile](<profile_url>), `@<login>`)
- **Affiliation:** <company or "none listed">; NVIDIA org member: <yes/no>; repo association: <author_association>
- **PRs:** <merged> merged, <closed_unmerged> closed unmerged, <open> open
- **Other issues:** <completed> completed, <not_planned> not planned, <duplicate> duplicate, <open> open
```

- Affiliation comes only from the profile `company` field and org membership. Put a company that starts with `@` in backticks (`` `@Docker` ``) so it does not mention the organization.
- If N is a pull request (`gh api repos/NVIDIA/OpenShell/issues/N --jq '.pull_request != null'` prints `true`), the header reads `**Submitter of PR [#N](…):**` and the rest of the profile is the same.
- If the author is an app or bot (`user.type` is `Bot`, or the login ends in `[bot]`), say so on the header line, for example `` (`@linear[bot]`, GitHub app) ``. Mark any field the script could not fetch as "unavailable".
- Refer to the submitter by name, by `` `@login` ``, or as they/them. Never infer pronouns from a name.
- Stop after the profile. Do not add triage advice, ownership guesses, or a disposition.

## Subcommand: `other-open [N]`

This runs on `/triage-submitter-profile other-open`, on "other open", or when someone asks what else the submitter has open. It summarizes the submitter's open issues and PRs. N is the issue whose submitter you mean. Without N, use the issue most recently profiled in this conversation. If there is none, ask for the number.

```bash
bash .agents/skills/triage-submitter-profile/scripts/open-work.sh <N>
```

Render the JSON as one line per open issue, with issue N first because the script orders it that way. Then add one line per unlinked PR:

```markdown
Open issues from `@login` ([GitHub profile](https://github.com/login)), each with its open PR:

- [#3960](https://github.com/NVIDIA/OpenShell/issues/3960)/PR [#3962](https://github.com/NVIDIA/OpenShell/issues/3962): <summary>
- [#3961](https://github.com/NVIDIA/OpenShell/issues/3961)/PR [#3975](https://github.com/NVIDIA/OpenShell/issues/3975) (draft): <summary>
- [#3882](https://github.com/NVIDIA/OpenShell/issues/3882)/PR [#3901](https://github.com/NVIDIA/OpenShell/issues/3901) by `@ericcurtin`: <summary>
- [#3877](https://github.com/NVIDIA/OpenShell/issues/3877)/no PR: <summary>
- PR [#2184](https://github.com/NVIDIA/OpenShell/issues/2184), no linked issue: <summary>

<one sentence naming each issue whose state label is not `state:triage-needed`, with its label or "no state label"; omit it when every issue has `state:triage-needed`>
```

- The PR slot lists `own_prs` first, then `other_prs` with "by `@author`". Separate multiple PRs with commas. Write "no PR" when both are empty.
- `<summary>` is a plain-English, one-line version of the title, without the conventional-commit prefix.

## Issue, PR, and people references

Write every issue or PR number as a markdown link whose text is `#N`:

```markdown
[#3955](https://github.com/NVIDIA/OpenShell/issues/3955)
```

- Use `/issues/N` for PRs too. GitHub redirects it to `/pull/N`, so you don't need to look up which it is.
- Write a reference to another repo as `[owner/repo#N](https://github.com/owner/repo/issues/N)`.
- The rule covers every mention: the header line, lists, and lists of numbers.
- Write every GitHub login in backticks (`` `@login` ``) so a pasted summary notifies no one. Never write a bare `@login` or `[@login](…)`.

## Common mistakes

| Mistake | Fix |
|---|---|
| Bare `#3967` | `[#3967](https://github.com/NVIDIA/OpenShell/issues/3967)` |
| `Maya Wang (@mayawang)` | ``Maya Wang ([GitHub profile](https://github.com/mayawang), `@mayawang`)`` |
| "she" or "he" guessed from a name | Use the name, `` `@login` ``, or they/them |
| Counting the profiled issue as one of their open issues | Use the script's counts; they already exclude it |
| "Not a public NVIDIA member" | The script checks real membership; report yes or no |
| Ad hoc `gh` searches in place of the script | Run the script; output must match the template |
| Adding acceptance or routing advice | Stop after the profile; point to `/triage-recommend-actions` |
| Script denied, errors, or hits the search rate limit (30 searches a minute; the script uses 7) | Send the section anyway, mark the fields "unavailable", and give the user the exact command to run |
