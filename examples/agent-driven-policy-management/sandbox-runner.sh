#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

RUNNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cmd="$1"
shift

json_status_response() {
    local status="$1"
    local body="$2"
    printf 'HTTP_STATUS=%s\n' "$status"
    cat "$body"
    printf '\n'
}

render_template() {
    local template="$1"
    local owner="$2"
    local repo="$3"
    local branch="$4"
    local file_path="$5"
    local run_id="$6"

    python3 - "$template" "$owner" "$repo" "$branch" "$file_path" "$run_id" <<'PY'
from pathlib import Path
import sys

template, owner, repo, branch, file_path, run_id = sys.argv[1:7]
text = Path(template).read_text(encoding="utf-8")
for key, value in {
    "OWNER": owner,
    "REPO": repo,
    "BRANCH": branch,
    "FILE_PATH": file_path,
    "RUN_ID": run_id,
}.items():
    text = text.replace("{{" + key + "}}", value)
print(text, end="")
PY
}

bootstrap_codex_oauth() {
    mkdir -p "$HOME/.codex"
    python3 - <<'PY'
from pathlib import Path
import base64
import json
import os
import time

def b64url_json(payload):
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

now = int(time.time())
fake_id_token = ".".join([
    b64url_json({"alg": "none", "typ": "JWT"}),
    b64url_json({
        "iss": "https://auth.openai.com",
        "aud": "codex",
        "sub": "openshell-placeholder",
        "email": "placeholder@example.com",
        "iat": now,
        "exp": now + 3600,
    }),
    "placeholder",
])

path = Path.home() / ".codex" / "auth.json"
path.write_text(json.dumps({
    "auth_mode": "chatgpt",
    "OPENAI_API_KEY": None,
    "tokens": {
        "id_token": fake_id_token,
        "access_token": os.environ["CODEX_AUTH_ACCESS_TOKEN"],
        "refresh_token": os.environ["CODEX_AUTH_REFRESH_TOKEN"],
        "account_id": os.environ["CODEX_AUTH_ACCOUNT_ID"],
    },
    "last_refresh": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
}, indent=2), encoding="utf-8")
path.chmod(0o600)
PY
}

run_codex_dogfood() {
    local owner="$1"
    local repo="$2"
    local branch="$3"
    local file_path="$4"
    local run_id="$5"
    local prompt final

    command -v codex >/dev/null 2>&1 || {
        echo "codex is not installed in this sandbox image" >&2
        exit 69
    }

    bootstrap_codex_oauth
    prompt="$(mktemp)"
    final="/sandbox/codex-policy-dogfood-final.md"
    render_template \
        "${RUNNER_DIR}/prompts/codex-dogfood.md" \
        "$owner" \
        "$repo" \
        "$branch" \
        "$file_path" \
        "$run_id" > "$prompt"

    codex exec \
        --skip-git-repo-check \
        --dangerously-bypass-approvals-and-sandbox \
        --ephemeral \
        --cd /sandbox \
        --color never \
        -c shell_environment_policy.inherit=all \
        --output-last-message "$final" \
        - < "$prompt"

    printf '\nCODEX_FINAL_MESSAGE_BEGIN\n'
    sed 's/^/  /' "$final"
    printf 'CODEX_FINAL_MESSAGE_END\n'
}

case "$cmd" in
    check-skill)
        test -f /etc/openshell/skills/policy_advisor.md
        sed -n '1,40p' /etc/openshell/skills/policy_advisor.md
        ;;

    current-policy)
        body="$(mktemp)"
        status="$(curl -sS -o "$body" -w "%{http_code}" http://policy.local/v1/policy/current)"
        json_status_response "$status" "$body"
        ;;

    put-file)
        owner="$1"
        repo="$2"
        branch="$3"
        file_path="$4"
        run_id="$5"
        body="$(mktemp)"
        payload="$(mktemp)"

        python3 - "$branch" "$run_id" > "$payload" <<'PY'
import base64
import json
import sys

branch, run_id = sys.argv[1:3]
content = f"""# OpenShell policy advisor demo

Run id: {run_id}

This file was written from inside an OpenShell sandbox after an agent-authored
policy proposal was approved.
"""

payload = {
    "message": f"docs: add OpenShell policy advisor demo note {run_id}",
    "branch": branch,
    "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
}
print(json.dumps(payload))
PY

        status="$(curl -sS \
            -o "$body" \
            -w "%{http_code}" \
            -X PUT \
            -H "Accept: application/vnd.github+json" \
            -H "Authorization: Bearer ${GITHUB_TOKEN}" \
            -H "X-GitHub-Api-Version: 2022-11-28" \
            -H "Content-Type: application/json" \
            --data-binary "@${payload}" \
            "https://api.github.com/repos/${owner}/${repo}/contents/${file_path}")"
        json_status_response "$status" "$body"
        ;;

    submit-proposal)
        owner="$1"
        repo="$2"
        file_path="$3"
        body="$(mktemp)"
        payload="$(mktemp)"

        python3 - "$owner" "$repo" "$file_path" > "$payload" <<'PY'
import json
import sys

owner, repo, file_path = sys.argv[1:4]
rule_path = f"/repos/{owner}/{repo}/contents/{file_path}"
payload = {
    "intent_summary": (
        "Allow curl to write the demo note to "
        f"{owner}/{repo} at {file_path} only."
    ),
    "operations": [
        {
            "addRule": {
                "ruleName": "github_api_demo_contents_write",
                "rule": {
                    "name": "github_api_demo_contents_write",
                    "endpoints": [
                        {
                            "host": "api.github.com",
                            "port": 443,
                            "protocol": "rest",
                            "enforcement": "enforce",
                            "rules": [
                                {
                                    "allow": {
                                        "method": "PUT",
                                        "path": rule_path,
                                    }
                                }
                            ],
                        }
                    ],
                    "binaries": [
                        {
                            "path": "/usr/bin/curl",
                        }
                    ],
                },
            }
        }
    ],
}
print(json.dumps(payload))
PY

        status="$(curl -sS \
            -o "$body" \
            -w "%{http_code}" \
            -X POST \
            -H "Content-Type: application/json" \
            --data-binary "@${payload}" \
            http://policy.local/v1/proposals)"
        json_status_response "$status" "$body"
        ;;

    codex-dogfood)
        run_codex_dogfood "$@"
        ;;

    *)
        echo "unknown command: $cmd" >&2
        exit 64
        ;;
esac
