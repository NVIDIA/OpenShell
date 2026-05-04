#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Runs inside the sandbox. Bootstraps Codex from the credentials injected by
# the openshell provider, then drives the agent-task prompt to completion.

set -euo pipefail

require_env() {
    local name="$1"
    [[ -n "${!name:-}" ]] || { echo "missing required env: $name" >&2; exit 1; }
}

require_env CODEX_AUTH_ACCESS_TOKEN
require_env CODEX_AUTH_REFRESH_TOKEN
require_env CODEX_AUTH_ACCOUNT_ID
require_env DEMO_GITHUB_TOKEN

# Make the GitHub token visible to Codex's tool loop under the conventional name.
export GITHUB_TOKEN="$DEMO_GITHUB_TOKEN"

# Codex looks for ~/.codex/auth.json. The OpenShell provider only injects env
# vars, so we materialize the file Codex expects from those credentials.
mkdir -p "$HOME/.codex"
node - <<'NODE'
const fs = require("fs");
const path = `${process.env.HOME}/.codex/auth.json`;
const b64u = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");
const now = Math.floor(Date.now() / 1000);
// Placeholder id_token is required by Codex but never validated against an
// upstream JWKS in this flow.
const idToken = [
  b64u({ alg: "none", typ: "JWT" }),
  b64u({
    iss: "https://auth.openai.com",
    aud: "codex",
    sub: "openshell-policy-demo",
    email: "demo@openshell.local",
    iat: now,
    exp: now + 3600,
  }),
  "placeholder",
].join(".");
fs.writeFileSync(path, JSON.stringify({
  auth_mode: "chatgpt",
  OPENAI_API_KEY: null,
  tokens: {
    id_token: idToken,
    access_token: process.env.CODEX_AUTH_ACCESS_TOKEN,
    refresh_token: process.env.CODEX_AUTH_REFRESH_TOKEN,
    account_id: process.env.CODEX_AUTH_ACCOUNT_ID,
  },
  last_refresh: new Date().toISOString(),
}, null, 2));
NODE
chmod 600 "$HOME/.codex/auth.json"

# Codex needs a writable cwd; /sandbox is uploaded read-only-ish, so work in /tmp.
WORK="$(mktemp -d)"
cd "$WORK"

# Disable Codex's internal bubblewrap sandbox — OpenShell is already the
# security boundary, and bwrap can't create nested user namespaces inside the
# OpenShell sandbox container without extra capabilities. The "danger" framing
# is from Codex's perspective on a developer host; here the OpenShell network
# policy and filesystem constraints are doing the actual containment.
exec codex exec \
    --skip-git-repo-check \
    --sandbox danger-full-access \
    --ephemeral \
    "$(cat /sandbox/payload/agent-task.md)"
