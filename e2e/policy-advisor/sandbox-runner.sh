#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

cmd="$1"
shift

json_status_response() {
    local status="$1"
    local body="$2"
    printf 'HTTP_STATUS=%s\n' "$status"
    cat "$body"
    printf '\n'
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

    submit-test-proposal)
        # Synthetic proposal for the wait-loop smoke. No GitHub creds needed
        # — we never make outbound calls, the gateway just persists the
        # chunk and the reviewer decides on it.
        rule_id="$1"
        body="$(mktemp)"
        payload="$(mktemp)"

        python3 - "$rule_id" > "$payload" <<'PY'
import json
import sys

rule_id = sys.argv[1]
payload = {
    "intent_summary": f"Smoke test proposal {rule_id}",
    "operations": [{
        "addRule": {
            "ruleName": f"smoke_{rule_id}",
            "rule": {
                "name": f"smoke_{rule_id}",
                "endpoints": [{
                    "host": "example.invalid",
                    "port": 443,
                    "protocol": "rest",
                    "enforcement": "enforce",
                    "rules": [{
                        "allow": {"method": "GET", "path": f"/{rule_id}"}
                    }],
                }],
                "binaries": [{"path": "/usr/bin/curl"}],
            },
        }
    }],
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

    proposal-status)
        chunk_id="$1"
        body="$(mktemp)"
        status="$(curl -sS \
            -o "$body" \
            -w "%{http_code}" \
            "http://policy.local/v1/proposals/${chunk_id}")"
        json_status_response "$status" "$body"
        ;;

    proposal-wait)
        chunk_id="$1"
        timeout="${2:-60}"
        body="$(mktemp)"
        # No --max-time on curl: the server bounds the wait at `timeout`,
        # which is already clamped to [1, 300] by policy.local. Let the
        # request return naturally.
        status="$(curl -sS \
            -o "$body" \
            -w "%{http_code}" \
            "http://policy.local/v1/proposals/${chunk_id}/wait?timeout=${timeout}")"
        json_status_response "$status" "$body"
        ;;

    *)
        echo "unknown command: $cmd" >&2
        exit 64
        ;;
esac
