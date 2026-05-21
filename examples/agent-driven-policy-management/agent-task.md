<!-- SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Agent Task

You are running inside an OpenShell sandbox. Your job is to write one
markdown file to GitHub via the GitHub Contents API.

## Target

- Repository: `{{OWNER}}/{{REPO}}`
- Branch: `{{BRANCH}}`
- File path: `{{FILE_PATH}}`
- Run id: `{{RUN_ID}}`

## What to do

1. PUT the file with `curl` against
   `https://api.github.com/repos/{{OWNER}}/{{REPO}}/contents/{{FILE_PATH}}`.
   Authenticate with the `GITHUB_TOKEN` environment variable. Do not echo the
   token. Body content (base64-encoded into the JSON `content` field):

   ```
   # OpenShell policy advisor demo

   Run id: {{RUN_ID}}

   Written from inside an OpenShell sandbox after a narrowly-scoped policy
   proposal was approved by the developer.
   ```

2. The first attempt will fail with HTTP 403 and a JSON body containing
   `"error": "policy_denied"`. Read the body — it tells you which layer denied
   you (`l7`/`rest`), which method/path was missing, and where to learn more.

3. Read `/etc/openshell/skills/policy_advisor.md` and follow it. Submit the
   narrowest possible proposal to `http://policy.local/v1/proposals` — exact
   host, exact port, exact method, exact path, binary `/usr/bin/curl`. Do not
   include query strings. Do not propose wildcard hosts. The 202 response
   carries `accepted_chunk_ids`; this demo submits one rule per proposal, so
   the list always has exactly one element. Save `accepted_chunk_ids[0]`,
   you need it for step 4.

4. Block on the developer's decision by calling
   `GET http://policy.local/v1/proposals/{chunk_id}/wait?timeout=300`. This is
   a single HTTP request that the supervisor holds open until the developer
   approves or rejects; do not run a polling loop yourself.

   - `status: "approved"` — retry the PUT once. Policy has hot-reloaded.
   - `status: "rejected"` — read `rejection_reason`. If it has text, address
     the specific feedback and submit a revised proposal (back to step 3);
     otherwise stop and tell the developer you can't proceed.
   - `status: "pending"` with `timed_out: true` — the supervisor returned
     without a decision after the full timeout window elapsed. Immediately
     re-issue the same `/wait` request once. Each `/wait` is one long-lived
     HTTP call; do not sleep, do not loop with a short timeout, do not
     decrease `timeout=300`.

5. On a successful PUT (HTTP 200 or 201), print a short summary showing
   `content.path` and `content.html_url` from the GitHub response. Do not
   print the full response body.

If anything is unclear, prefer making a narrower proposal and asking for
approval again over widening the rule.
