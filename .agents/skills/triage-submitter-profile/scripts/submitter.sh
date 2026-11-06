#!/usr/bin/env bash
# Print a JSON profile of an issue's author: identity, affiliation, and
# contribution counts in the repo, excluding the issue itself. Read-only.
# Usage: bash submitter.sh <issue-number> [owner/repo]
set -euo pipefail

num="${1#\#}"
repo="${2:-NVIDIA/OpenShell}"
org="${repo%%/*}"

issue=$(gh api "repos/$repo/issues/$num" \
  --jq '{login: .user.login, association: .author_association, state, state_reason,
         is_pr: (.pull_request != null), merged: (.pull_request.merged_at != null)}')
login=$(jq -r .login <<<"$issue")

user=$(gh api "users/$login" --jq '{name, company, location, blog, bio, created_at}')

# 204 = member (private membership visible when the caller is an org member).
if gh api "orgs/$org/members/$login" --silent 2>/dev/null; then
  org_member=true
else
  org_member=false
fi

# Read-only: every call below is an HTTP GET.
count() {
  gh api -X GET search/issues -f q="repo:$repo author:$login $1" -f per_page=1 --jq .total_count
}
counts=$(jq -n \
  --argjson prs_merged          "$(count 'is:pr is:merged')" \
  --argjson prs_closed_unmerged "$(count 'is:pr is:closed is:unmerged')" \
  --argjson prs_open            "$(count 'is:pr is:open')" \
  --argjson issues_completed    "$(count 'is:issue is:closed reason:completed')" \
  --argjson issues_not_planned  "$(count 'is:issue is:closed reason:"not planned"')" \
  --argjson issues_duplicate    "$(count 'is:issue is:closed reason:duplicate')" \
  --argjson issues_open         "$(count 'is:issue is:open')" \
  '$ARGS.named')

# Remove the issue under triage from its own bucket so counts are "other" work.
jq -n \
  --argjson issue "$issue" --argjson user "$user" --argjson counts "$counts" \
  --argjson org_member "$org_member" --arg org "$org" '
  ($issue | if .is_pr and .state == "open" then "prs_open"
            elif .is_pr and .merged then "prs_merged"
            elif .is_pr then "prs_closed_unmerged"
            elif .state == "open" then "issues_open"
            elif .state_reason == "not_planned" then "issues_not_planned"
            elif .state_reason == "duplicate" then "issues_duplicate"
            else "issues_completed" end) as $self
  | {
      login: $issue.login,
      profile_url: (if $issue.login | endswith("[bot]")
                    then "https://github.com/apps/\($issue.login | rtrimstr("[bot]"))"
                    else "https://github.com/\($issue.login)" end),
      name: $user.name,
      company: $user.company,
      location: $user.location,
      bio: $user.bio,
      blog: $user.blog,
      account_created: $user.created_at,
      author_association: $issue.association,
      ("\($org | ascii_downcase)_org_member"): $org_member,
      counts_excluding_this_issue: ($counts | .[$self] -= 1)
    }'
