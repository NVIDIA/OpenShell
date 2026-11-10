#!/usr/bin/env bash
# Print JSON of an issue author's open issues (each with the open PRs that
# close it) and their open PRs that close none of those issues. Read-only.
# Usage: bash open-work.sh <issue-number> [owner/repo]
set -euo pipefail

num="${1#\#}"
repo="${2:-NVIDIA/OpenShell}"

login=$(gh api "repos/$repo/issues/$num" --jq .user.login)

issues=$(gh issue list -R "$repo" --author "$login" --state open --limit 200 \
  --json number,title,labels,closedByPullRequestsReferences \
  --jq 'map({number, title,
             state: ([.labels[].name | select(startswith("state:"))] | first),
             pr_refs: [.closedByPullRequestsReferences[].number]})')

prs=$(gh pr list -R "$repo" --author "$login" --state open --limit 200 \
  --json number,title,isDraft,closingIssuesReferences \
  --jq 'map({number, title, draft: .isDraft, closes: [.closingIssuesReferences[].number]})')

# Closing PRs from other authors: look up state and author individually.
others='[]'
for n in $(jq -r --argjson prs "$prs" \
    '[.[].pr_refs[]] | unique | map(select(. as $n | $prs | any(.[]; .number == $n) | not)) | .[]' \
    <<<"$issues"); do
  pr=$(gh pr view "$n" -R "$repo" --json number,state,author \
    --jq '{number, state, author: .author.login}')
  others=$(jq --argjson pr "$pr" '. + [$pr]' <<<"$others")
done

jq -n --arg login "$login" --argjson triaged "$num" \
  --argjson issues "$issues" --argjson prs "$prs" --argjson others "$others" '
  ($issues | map(.number)) as $issue_nums
  | ($others | map(select(.state == "OPEN"))) as $open_others
  | {
      login: $login,
      triaged_issue: $triaged,
      open_issues: ($issues
        | sort_by([(.number != $triaged), -.number])
        | map(. as $i | {
            number, title, state,
            own_prs: [$prs[] | select(any(.closes[]; . == $i.number)) | {number, draft}],
            other_prs: [$open_others[] | select(.number as $n | any($i.pr_refs[]; . == $n))
                        | {number, author}]
          })),
      unlinked_open_prs: [$prs[]
        | select((.closes - $issue_nums) == .closes)
        | {number, title, draft}]
    }'
