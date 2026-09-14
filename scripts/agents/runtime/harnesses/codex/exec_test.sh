#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

ACCESS_PLACEHOLDER="openshell:resolve:env:s$(printf 'a%.0s' {1..64})_CODEX_AUTH_ACCESS_TOKEN"
ACCOUNT_PLACEHOLDER="openshell:resolve:env:v42_CODEX_AUTH_ACCOUNT_ID"

cat > "$TMP_DIR/codex" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "exec" && "${2:-}" == "--help" ]]; then
    exit 0
fi

access="$(jq -r '.tokens.access_token' "$HOME/.codex/auth.json")"
account="$(jq -r '.tokens.account_id' "$HOME/.codex/auth.json")"
[[ "$access" == "$EXPECTED_ACCESS_PLACEHOLDER" ]]
[[ "$account" == "$EXPECTED_ACCOUNT_PLACEHOLDER" ]]
printf '%s\n' 'ok - Codex auth preserves opaque provider placeholders'
MOCK
chmod +x "$TMP_DIR/codex"
printf '%s\n' 'test prompt' > "$TMP_DIR/prompt.md"

OPENSHELL_AGENT_HOME="$TMP_DIR/home" \
CODEX_BIN="$TMP_DIR/codex" \
CODEX_AUTH_ACCESS_TOKEN="$ACCESS_PLACEHOLDER" \
CODEX_AUTH_ACCOUNT_ID="$ACCOUNT_PLACEHOLDER" \
GITHUB_TOKEN="openshell:resolve:env:v42_GITHUB_TOKEN" \
EXPECTED_ACCESS_PLACEHOLDER="$ACCESS_PLACEHOLDER" \
EXPECTED_ACCOUNT_PLACEHOLDER="$ACCOUNT_PLACEHOLDER" \
    bash "$SCRIPT_DIR/exec.sh" "$TMP_DIR/prompt.md"
