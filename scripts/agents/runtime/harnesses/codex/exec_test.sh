#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

ACCESS_PLACEHOLDER="openshell:resolve:env:s$(printf 'a%.0s' {1..64})_CODEX_AUTH_ACCESS_TOKEN"
ACCOUNT_PLACEHOLDER="openshell:resolve:env:v42_CODEX_AUTH_ACCOUNT_ID"
ACCOUNT_ID="test-codex-account"

cat > "$TMP_DIR/codex" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "exec" && "${2:-}" == "--help" ]]; then
    exit 0
fi

access="$(jq -r '.tokens.access_token' "$HOME/.codex/auth.json")"
account="$(jq -r '.tokens.account_id' "$HOME/.codex/auth.json")"
[[ "$access" == "$EXPECTED_ACCESS_PLACEHOLDER" ]]
[[ "$account" == "$EXPECTED_ACCOUNT_ID" ]]
[[ "$account" != openshell:resolve:* ]]
[[ "$(jq -r '.tokens.refresh_token' "$HOME/.codex/auth.json")" == "gateway-managed-refresh-token" ]]
[[ "$(node -e 'console.log((require("fs").statSync(process.env.HOME + "/.codex/auth.json").mode & 0o777).toString(8))')" == 600 ]]
printf '%s\n' 'ok - Codex auth preserves token placeholders and uses a literal account ID'
MOCK
chmod +x "$TMP_DIR/codex"
printf '%s\n' 'test prompt' > "$TMP_DIR/prompt.md"

OPENSHELL_AGENT_HOME="$TMP_DIR/home" \
CODEX_BIN="$TMP_DIR/codex" \
CODEX_AUTH_ACCESS_TOKEN="$ACCESS_PLACEHOLDER" \
CODEX_AUTH_ACCOUNT_ID="$ACCOUNT_PLACEHOLDER" \
CODEX_ACCOUNT_ID="$ACCOUNT_ID" \
GITHUB_TOKEN="openshell:resolve:env:v42_GITHUB_TOKEN" \
EXPECTED_ACCESS_PLACEHOLDER="$ACCESS_PLACEHOLDER" \
EXPECTED_ACCOUNT_ID="$ACCOUNT_ID" \
    bash "$SCRIPT_DIR/exec.sh" "$TMP_DIR/prompt.md"

# Fail before launching Codex when the routing identity is absent or opaque.
for invalid_account_id in "" "$ACCOUNT_PLACEHOLDER"; do
    if OPENSHELL_AGENT_HOME="$TMP_DIR/invalid-home" \
        CODEX_BIN="$TMP_DIR/codex" \
        CODEX_AUTH_ACCESS_TOKEN="$ACCESS_PLACEHOLDER" \
        CODEX_ACCOUNT_ID="$invalid_account_id" \
        GITHUB_TOKEN="placeholder" \
        bash "$SCRIPT_DIR/exec.sh" "$TMP_DIR/prompt.md" >"$TMP_DIR/error" 2>&1; then
        echo "unexpected success with invalid Codex account ID" >&2
        exit 1
    fi
    [[ ! -e "$TMP_DIR/invalid-home/.codex/auth.json" ]]
done
printf '%s\n' 'ok - missing and placeholder account IDs are rejected'
