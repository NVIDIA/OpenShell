<!-- SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Agent Task

You are running inside an OpenShell sandbox. Your job has two steps. Each
step starts with a `curl` call that the L7 proxy will deny; for each
denial, read `/etc/openshell/skills/policy_advisor.md`, draft a narrow
proposal, submit it to `http://policy.local/v1/proposals`, wait on
`GET /v1/proposals/{chunk_id}/wait?timeout=300`, then retry.

## Target

- Repository: `{{OWNER}}/{{REPO}}`
- Branch: `{{BRANCH}}`
- File path: `{{FILE_PATH}}`
- Run id: `{{RUN_ID}}`

## What to do

### Step 1 — Fetch a public schema (un-credentialed action)

1. Fetch the well-known GitHub OpenAPI description from
   `https://raw.githubusercontent.com/github/rest-api-description/main/descriptions/api.github.com/api.github.com.json`
   with `curl`. Do not send any authentication header — this resource is
   public. Save the response to `/tmp/github-openapi.json`.

   The first attempt will fail with HTTP 403 and a JSON body containing
   `"error": "policy_denied"`. Read the body — it tells you which layer
   denied you, which method/path was missing, and where to learn more.

2. Read `/etc/openshell/skills/policy_advisor.md` and follow it. Submit
   the narrowest possible proposal to `http://policy.local/v1/proposals`
   — exact host (`raw.githubusercontent.com`), exact port (443), exact
   method (`GET`), exact path (`/github/rest-api-description/main/descriptions/api.github.com/api.github.com.json`),
   binary `/usr/bin/curl`. Do not propose wildcard hosts. Save
   `accepted_chunk_ids[0]`.

3. Block on the gateway's decision by calling
   `GET http://policy.local/v1/proposals/{chunk_id}/wait?timeout=300`.

   - `status: "approved"` — retry the fetch once. Because the host has
     no credentials in scope (it's a public-content endpoint), the
     prover sees no findings and the gateway auto-approves the
     proposal without human review. The whole step typically completes
     in ~1 second after submission.
   - `status: "rejected"` — read `rejection_reason`. If it has text,
     address the specific feedback and submit a revised proposal;
     otherwise stop and tell the developer you can't proceed.
   - `status: "pending"` with `timed_out: true` — re-issue the same
     `/wait` request once. Each `/wait` is one long-lived HTTP call.

4. After the retry, verify the file exists at `/tmp/github-openapi.json`
   and is non-empty.

### Step 2 — Write to GitHub (credentialed action)

1. PUT the file with `curl` against
   `https://api.github.com/repos/{{OWNER}}/{{REPO}}/contents/{{FILE_PATH}}`.
   Authenticate with the `GITHUB_TOKEN` environment variable. Do not
   echo the token. Body content (base64-encoded into the JSON `content`
   field):

   ```
   # OpenShell policy advisor demo

   Run id: {{RUN_ID}}

   Written from inside an OpenShell sandbox after a narrowly-scoped
   policy proposal was reviewed by the developer.
   ```

2. The first attempt will fail with HTTP 403 and a JSON body containing
   `"error": "policy_denied"`. Read the body — it tells you which layer
   denied you (`l7`/`rest`), which method/path was missing, and where to
   learn more.

3. Submit the narrowest possible proposal to
   `http://policy.local/v1/proposals` — exact host (`api.github.com`),
   exact port (443), exact method (`PUT`), exact path
   (`/repos/{{OWNER}}/{{REPO}}/contents/{{FILE_PATH}}`), binary
   `/usr/bin/curl`. Do not include query strings. Do not propose
   wildcard hosts. Save `accepted_chunk_ids[0]`.

4. Block on the developer's decision by calling
   `GET http://policy.local/v1/proposals/{chunk_id}/wait?timeout=300`.

   - This sandbox is unmanaged, so the gateway holds every accepted
     proposal in `pending` for human review. The `/wait` call parks on
     a socket, so no LLM tokens burn while the human decides.
   - `status: "approved"` — retry the PUT once. Policy has hot-reloaded.
   - `status: "rejected"` — read `rejection_reason`. If it has text,
     address the specific feedback and submit a revised proposal (back
     to step 3); otherwise stop and tell the developer you can't
     proceed.
   - `status: "pending"` with `timed_out: true` — re-issue the same
     `/wait` request once.

5. On a successful PUT (HTTP 200 or 201), print a short summary showing
   `content.path` and `content.html_url` from the GitHub response. Do
   not print the full response body.

If anything is unclear, prefer making a narrower proposal and asking for
approval again over widening the rule.
