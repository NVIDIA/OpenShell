<!-- SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Codex Policy Dogfood Task

You are inside an OpenShell sandbox. The user asked you to write one markdown
file to GitHub using the GitHub Contents API.

Target:

- Repository: `{{OWNER}}/{{REPO}}`
- Branch: `{{BRANCH}}`
- File path: `{{FILE_PATH}}`
- Run id: `{{RUN_ID}}`

Requirements:

- Use `curl` and the `GITHUB_TOKEN` environment variable.
- Use ordinary shell commands for this demo. Do not use GitHub MCP tools or
  repository-specific helper skills.
- Do not print, echo, or reveal the token.
- First try to write the file with `PUT /repos/{{OWNER}}/{{REPO}}/contents/{{FILE_PATH}}`.
- If OpenShell returns `policy_denied`, read
  `/etc/openshell/skills/policy_advisor.md` and follow the local API workflow
  there.
- Submit the narrowest proposal that permits only this write.
- Do not include a `tls` field in the proposed endpoint unless you are
  explicitly disabling TLS inspection.
- After submitting a proposal, retry the write for up to 90 seconds. The
  developer may approve while you are waiting.
- Do not print the full GitHub response body. It can include temporary
  `download_url` query tokens. Extract only `content.path`, `content.html_url`,
  and `commit.sha`.
- Finish with a short summary that says whether the write succeeded. Include
  the GitHub file path and URL if GitHub returns them.

Suggested file content:

```markdown
# OpenShell policy advisor dogfood

Run id: {{RUN_ID}}

This file was written by Codex from inside an OpenShell sandbox after Codex read
the policy advisor skill, submitted a narrow policy proposal, and waited for
developer approval.
```
