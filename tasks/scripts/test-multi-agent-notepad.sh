#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

home_dir="${tmpdir}/home"
fake_openshell="${tmpdir}/openshell"
call_log="${tmpdir}/openshell-calls"
mkdir -p "${home_dir}/.codex"

cat >"${home_dir}/.codex/auth.json" <<'EOF'
{
  "tokens": {
    "access_token": "test-access-token",
    "refresh_token": "test-refresh-token",
    "account_id": "test-account-id"
  }
}
EOF

cat >"$fake_openshell" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

printf '%q' "$1" >>"$OPENSHELL_TEST_CALL_LOG"
shift
for arg in "$@"; do
  printf ' %q' "$arg" >>"$OPENSHELL_TEST_CALL_LOG"
done
printf '\n' >>"$OPENSHELL_TEST_CALL_LOG"
EOF
chmod +x "$fake_openshell"

HOME="$home_dir" \
OPENSHELL_BIN="$fake_openshell" \
OPENSHELL_TEST_CALL_LOG="$call_log" \
DEMO_GITHUB_OWNER="example-owner" \
DEMO_GITHUB_REPO="example-repo" \
DEMO_GITHUB_TOKEN="test-github-token" \
DEMO_AGENT_IMAGE="example.invalid/codex-agent:test" \
DEMO_AGENT_COUNT=1 \
DEMO_RUN_ID="test-run" \
bash "${ROOT}/examples/multi-agent-notepad/demo.sh" >"${tmpdir}/demo.out"

create_count="$(grep -c '^sandbox create ' "$call_log")"
exec_count="$(grep -c '^sandbox exec ' "$call_log")"

if [ "$create_count" -ne 2 ]; then
  echo "FAIL: expected worker and synthesis sandbox create calls" >&2
  cat "$call_log" >&2
  exit 1
fi

if [ "$exec_count" -ne 2 ]; then
  echo "FAIL: expected worker and synthesis sandbox exec calls" >&2
  cat "$call_log" >&2
  exit 1
fi

while IFS= read -r call; do
  if [[ "$call" != *" --upload "* ]]; then
    echo "FAIL: sandbox create must upload the demo payload" >&2
    echo "$call" >&2
    exit 1
  fi
  if [[ "$call" != *" --detach "* ]]; then
    echo "FAIL: sandbox create must detach before the demo command runs" >&2
    echo "$call" >&2
    exit 1
  fi
  if [[ "$call" == *" demo-runner.sh"* ]]; then
    echo "FAIL: sandbox create must not include the demo command" >&2
    echo "$call" >&2
    exit 1
  fi
done < <(grep '^sandbox create ' "$call_log")

while IFS= read -r call; do
  if [[ "$call" != *" --no-tty -- bash /sandbox/payload/demo-runner.sh "* ]]; then
    echo "FAIL: sandbox exec must run the uploaded demo payload" >&2
    echo "$call" >&2
    exit 1
  fi
  if [[ "$call" == *" --upload "* ]]; then
    echo "FAIL: sandbox exec must not include upload arguments" >&2
    echo "$call" >&2
    exit 1
  fi
done < <(grep '^sandbox exec ' "$call_log")

echo "Multi-agent notepad demo tests passed."
