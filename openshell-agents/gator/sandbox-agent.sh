#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

require_env() {
    local name="$1"
    [[ -n "${!name:-}" ]] || { echo "missing required env: $name" >&2; exit 1; }
}

require_env CODEX_AUTH_ACCESS_TOKEN
require_env CODEX_AUTH_REFRESH_TOKEN
require_env CODEX_AUTH_ACCOUNT_ID
require_env GITHUB_TOKEN

export GH_TOKEN="$GITHUB_TOKEN"
export HOME=/sandbox/home

mkdir -p "$HOME/.codex"
node - <<'NODE'
const fs = require("fs");
const path = `${process.env.HOME}/.codex/auth.json`;
const b64u = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");
const now = Math.floor(Date.now() / 1000);
const fallbackIdToken = [
  b64u({ alg: "none", typ: "JWT" }),
  b64u({
    iss: "https://auth.openai.com",
    aud: "codex",
    sub: "openshell-gator",
    email: "gator@openshell.local",
    iat: now,
    exp: now + 3600,
  }),
  "placeholder",
].join(".");

fs.writeFileSync(path, JSON.stringify({
  auth_mode: "chatgpt",
  OPENAI_API_KEY: null,
  tokens: {
    id_token: fallbackIdToken,
    access_token: process.env.CODEX_AUTH_ACCESS_TOKEN,
    refresh_token: process.env.CODEX_AUTH_REFRESH_TOKEN,
    account_id: process.env.CODEX_AUTH_ACCOUNT_ID,
  },
  last_refresh: new Date().toISOString(),
}, null, 2));
NODE
chmod 600 "$HOME/.codex/auth.json"

WORK="$(mktemp -d)"
cd "$WORK"

CODEX_BIN="${CODEX_BIN:-codex}"
if [[ -x /sandbox/payload/codex ]]; then
    CODEX_BIN=/sandbox/payload/codex
fi
CODEX_MODEL="${CODEX_MODEL:-gpt-5.5}"
CODEX_REASONING="${CODEX_REASONING:-high}"

CODEX_EXEC_ARGS=(
    exec
    --skip-git-repo-check
    --sandbox danger-full-access
    --ephemeral
)

if "$CODEX_BIN" exec --help 2>/dev/null | grep -q -- "--ignore-user-config"; then
    CODEX_EXEC_ARGS+=(--ignore-user-config)
fi
if "$CODEX_BIN" exec --help 2>/dev/null | grep -q -- "--ignore-rules"; then
    CODEX_EXEC_ARGS+=(--ignore-rules)
fi

exec "$CODEX_BIN" "${CODEX_EXEC_ARGS[@]}" \
    -c "model=\"${CODEX_MODEL}\"" \
    -c "model_reasoning_effort=\"${CODEX_REASONING}\"" \
    "$(cat /sandbox/payload/gator-prompt.md)"
