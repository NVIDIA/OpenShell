#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$(mktemp -d)"
trap 'rm -rf "$TEST_DIR"' EXIT

mkdir -p "$TEST_DIR/agent"
cat > "$TEST_DIR/agent/agent.yaml" <<'YAML'
id: test
sandbox:
  name_prefix: gtr
  from: agent://.
harness:
  default: codex
  supported:
    codex: {}
prompt_template: prompt.md
YAML
printf 'FROM scratch\n' > "$TEST_DIR/agent/Dockerfile"
printf '{{USER_PROMPT}}\n' > "$TEST_DIR/agent/prompt.md"

# Stop at the first gateway call, before any image build or gateway mutation.
cat > "$TEST_DIR/openshell" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$TEST_CALLS"
exit 1
MOCK
chmod +x "$TEST_DIR/openshell"
export TEST_CALLS="$TEST_DIR/calls"
export OPENSHELL_BIN="$TEST_DIR/openshell"
unset GATOR_SANDBOX_NAME GATOR_SANDBOX_FROM OPENSHELL_AGENT_DIR

reject_name() {
    local expected="$1"
    shift
    : > "$TEST_CALLS"
    if bash "$SCRIPT_DIR/run.sh" --agent "$TEST_DIR/agent" "$@" 'test prompt' > "$TEST_DIR/output" 2>&1; then
        echo 'expected invalid sandbox name to fail' >&2
        exit 1
    fi
    grep -q "$expected" "$TEST_DIR/output"
    [[ ! -s "$TEST_CALLS" ]]
    if grep -q 'Preparing\|Building\|Configuring' "$TEST_DIR/output"; then
        echo 'name validation ran after launch preparation' >&2
        exit 1
    fi
}

reject_name 'maximum length is 19' --name gator-pr-4633-supervised
reject_name 'maximum length is 19' --name abcdefghijklmnopqrst
for name in Gator gator_pr gator.pr -gator gator- 'gator name'; do
    reject_name 'expected a DNS-1123 label' --name "$name"
done
GATOR_SANDBOX_NAME=gator-pr-4633-supervised reject_name 'maximum length is 19'
# An oversized manifest prefix also produces an invalid generated name.
sed 's/name_prefix: gtr/name_prefix: toolong/' "$TEST_DIR/agent/agent.yaml" > "$TEST_DIR/manifest"
cp "$TEST_DIR/manifest" "$TEST_DIR/agent/agent.yaml"
reject_name 'maximum length is 19'
sed 's/name_prefix: toolong/name_prefix: gtr/' "$TEST_DIR/agent/agent.yaml" > "$TEST_DIR/manifest"
cp "$TEST_DIR/manifest" "$TEST_DIR/agent/agent.yaml"
printf '%s\n' 'ok - invalid explicit, environment, and generated names fail before launch work'

for name in a abcdefghijklmnopqrs gtr-pr-4633-watch; do
    : > "$TEST_CALLS"
    if bash "$SCRIPT_DIR/run.sh" --agent "$TEST_DIR/agent" --name "$name" 'test prompt' > "$TEST_DIR/output" 2>&1; then
        echo 'expected gateway stub to stop launch' >&2
        exit 1
    fi
    grep -q 'gateway info --output json' "$TEST_CALLS"
done
: > "$TEST_CALLS"
if bash "$SCRIPT_DIR/run.sh" --agent "$TEST_DIR/agent" 'test prompt' > "$TEST_DIR/output" 2>&1; then
    echo 'expected gateway stub to stop launch' >&2
    exit 1
fi
grep -q 'gateway info --output json' "$TEST_CALLS"
printf '%s\n' 'ok - one-character, 19-character, documented, and default generated names reach gateway preflight'
