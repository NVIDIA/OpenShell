#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# This script runs INSIDE each OpenShell sandbox.
#
# It is uploaded to /sandbox/payload/demo-runner.sh by demo.sh and invoked as
# the sandbox entrypoint. It receives positional arguments from `run_sandbox()`
# in demo.sh and reads DEMO_GITHUB_TOKEN from the environment, where the
# OpenShell proxy resolves the provider placeholder at the network boundary.
#
# Modes:
#   worker     — render the worker prompt for a slice, run codex, PUT the note.
#   synthesis  — read every worker note, run the synthesis prompt, PUT summary.

set -euo pipefail

MODE="$1"
OWNER="$2"
REPO="$3"
BRANCH="$4"
RUN_ID="$5"
AGENT_INDEX="${6:-0}"
AGENT_COUNT="${7:-0}"
TOPIC="${8:-}"

api_url() {
    printf 'https://api.github.com%s' "$1"
}

github_request() {
    local method="$1"
    local path="$2"
    local output="$3"
    shift 3
    curl -sS \
        -X "$method" \
        -H "Accept: application/vnd.github+json" \
        -H "Authorization: Bearer ${DEMO_GITHUB_TOKEN}" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        "$@" \
        -o "$output" \
        -w "%{http_code}" \
        "$(api_url "$path")"
}

render_template() {
    local template="$1"
    local slice="${2:-}"
    node - "$template" "$AGENT_INDEX" "$AGENT_COUNT" "$TOPIC" "$slice" <<'NODE'
const fs = require("fs");
const [templatePath, agentIndex, agentCount, topic, slice] = process.argv.slice(2);
let text = fs.readFileSync(templatePath, "utf8");
text = text.replace(/^(?:<!-- [^\n]* -->\n)+\n?/, "");
const replacements = {
  "{{AGENT_INDEX}}": agentIndex,
  "{{AGENT_COUNT}}": agentCount,
  "{{TOPIC}}": topic,
  "{{SLICE}}": slice,
};
for (const [needle, value] of Object.entries(replacements)) {
  text = text.split(needle).join(value);
}
process.stdout.write(text);
NODE
}

bootstrap_codex_oauth() {
    mkdir -p "$HOME/.codex"
    node - <<'NODE'
const fs = require("fs");
const path = `${process.env.HOME}/.codex/auth.json`;
const b64u = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");
const now = Math.floor(Date.now() / 1000);
const fakeIdToken = [
  b64u({ alg: "none", typ: "JWT" }),
  b64u({
    iss: "https://auth.openai.com",
    aud: "codex",
    sub: "openshell-placeholder",
    email: "placeholder@example.com",
    iat: now,
    exp: now + 3600,
  }),
  "placeholder",
].join(".");

fs.writeFileSync(path, JSON.stringify({
  auth_mode: "chatgpt",
  OPENAI_API_KEY: null,
  tokens: {
    id_token: fakeIdToken,
    access_token: process.env.CODEX_AUTH_ACCESS_TOKEN,
    refresh_token: process.env.CODEX_AUTH_REFRESH_TOKEN,
    account_id: process.env.CODEX_AUTH_ACCOUNT_ID,
  },
  last_refresh: new Date().toISOString(),
}, null, 2));
NODE
    chmod 600 "$HOME/.codex/auth.json"
}

put_contents() {
    local repo_path="$1"
    local source_file="$2"
    local message="$3"
    local get_body put_body put_response status sha
    local attempt=0
    local max_attempts=6
    local sleep_secs=1
    get_body="$(mktemp)"
    put_body="$(mktemp)"
    put_response="$(mktemp)"

    while (( attempt < max_attempts )); do
        attempt=$((attempt + 1))

        status="$(github_request GET "/repos/${OWNER}/${REPO}/contents/${repo_path}?ref=${BRANCH}" "$get_body")"
        if [[ "$status" == "200" ]]; then
            sha="$(node -e 'const fs=require("fs"); const p=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); process.stdout.write(p.sha || "");' "$get_body")"
        elif [[ "$status" == "404" ]]; then
            sha=""
        else
            echo "GitHub GET ${repo_path} failed with HTTP ${status}" >&2
            cat "$get_body" >&2
            return 1
        fi

        node - "$source_file" "$message" "$BRANCH" "$sha" > "$put_body" <<'NODE'
const fs = require("fs");
const [file, message, branch, sha] = process.argv.slice(2);
const body = {
  message,
  branch,
  content: fs.readFileSync(file).toString("base64"),
};
if (sha) body.sha = sha;
process.stdout.write(JSON.stringify(body));
NODE

        status="$(github_request PUT "/repos/${OWNER}/${REPO}/contents/${repo_path}" "$put_response" --data-binary "@${put_body}")"
        if [[ "$status" == "200" || "$status" == "201" ]]; then
            return 0
        fi

        # Retry on 409 (concurrent writer) and 5xx (transient server error)
        # with decorrelated jitter so racing workers don't retry in lockstep.
        if [[ "$status" =~ ^(409|5[0-9][0-9])$ && $attempt -lt $max_attempts ]]; then
            sleep "$(( sleep_secs + RANDOM % sleep_secs ))"
            sleep_secs=$((sleep_secs * 2))
            continue
        fi

        echo "GitHub PUT ${repo_path} failed with HTTP ${status} (attempt ${attempt}/${max_attempts})" >&2
        cat "$put_response" >&2
        return 1
    done
}

get_contents_file() {
    local repo_path="$1"
    local destination="$2"
    local body status
    body="$(mktemp)"
    status="$(github_request GET "/repos/${OWNER}/${REPO}/contents/${repo_path}?ref=${BRANCH}" "$body")"
    if [[ "$status" != "200" ]]; then
        echo "GitHub GET ${repo_path} failed with HTTP ${status}" >&2
        cat "$body" >&2
        return 1
    fi
    node - "$body" "$destination" <<'NODE'
const fs = require("fs");
const [bodyPath, destination] = process.argv.slice(2);
const body = JSON.parse(fs.readFileSync(bodyPath, "utf8"));
fs.writeFileSync(destination, Buffer.from((body.content || "").replace(/\s/g, ""), "base64"));
NODE
}

run_codex_to_file() {
    local prompt_file="$1"
    local output_file="$2"
    codex exec \
        --skip-git-repo-check \
        --sandbox read-only \
        --ephemeral \
        --output-last-message "$output_file" \
        "$(cat "$prompt_file")"
}

worker() {
    local slice="$1"
    local prompt_file output_file repo_path
    bootstrap_codex_oauth
    prompt_file="$(mktemp)"
    output_file="$(mktemp)"
    repo_path="runs/${RUN_ID}/notes/agent-${AGENT_INDEX}.md"

    render_template /sandbox/payload/prompts/worker.md "$slice" > "$prompt_file"
    run_codex_to_file "$prompt_file" "$output_file"
    put_contents "$repo_path" "$output_file" "Add agent ${AGENT_INDEX} note for ${RUN_ID}"
    printf 'wrote %s\n' "$repo_path"
}

synthesis() {
    local notes_dir prompt_file output_file repo_path
    bootstrap_codex_oauth
    notes_dir="$(mktemp -d)"
    prompt_file="$(mktemp)"
    output_file="$(mktemp)"
    repo_path="runs/${RUN_ID}/summary.md"

    for i in $(seq 1 "$AGENT_COUNT"); do
        get_contents_file "runs/${RUN_ID}/notes/agent-${i}.md" "${notes_dir}/agent-${i}.md"
    done

    render_template /sandbox/payload/prompts/synthesis.md "" > "$prompt_file"
    {
        printf '\n\n## Worker Notes\n\n'
        for i in $(seq 1 "$AGENT_COUNT"); do
            printf '\n\n---\n\n'
            cat "${notes_dir}/agent-${i}.md"
        done
    } >> "$prompt_file"

    run_codex_to_file "$prompt_file" "$output_file"
    put_contents "$repo_path" "$output_file" "Add multi-agent summary for ${RUN_ID}"
    printf 'wrote %s\n' "$repo_path"
}

case "$MODE" in
    worker) worker "${9:-}" ;;
    synthesis) synthesis ;;
    *) echo "unknown mode: $MODE" >&2; exit 2 ;;
esac
