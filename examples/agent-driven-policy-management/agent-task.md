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
   include query strings. Do not propose wildcard hosts.

4. After submitting, retry the PUT every few seconds for up to 120 seconds.
   The developer is approving from outside the sandbox; once approved, the
   sandbox hot-reloads policy and the same PUT will succeed.

5. Stop as soon as the PUT returns HTTP 200 or 201. Print a short summary
   showing whether it succeeded, plus `content.path` and `content.html_url`
   from the GitHub response. Do not print the full response body.

If anything is unclear, prefer making a narrower proposal and asking for
approval again over widening the rule.
