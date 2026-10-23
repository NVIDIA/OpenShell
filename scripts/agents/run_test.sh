#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"

# Stop at the build boundary. No image build, gateway writes, provider imports,
# credential reads, or sandbox launches are allowed in this test.
cat > "$tmp/bin/openshell" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == *'gateway info --output json' ]] || exit 90
printf '%s\n' '{"compute_drivers":[{"name":"docker"}]}'
SH
cat > "$tmp/bin/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == --version ]]; then echo 'Docker test stub'; exit 0; fi
[[ "$1 $2" == 'buildx build' ]] || exit 91
cp -R "${!#}" "$CAPTURE_CONTEXT"
exit 77
SH
chmod +x "$tmp/bin/openshell" "$tmp/bin/docker"

capture_build() {
    local label="$1" task="$2" mode="$3" interval="$4" status=0
    PATH="$tmp/bin:$PATH" OPENSHELL_BIN="$tmp/bin/openshell" \
        CONTAINER_ENGINE=docker CAPTURE_CONTEXT="$tmp/$label" \
        bash "$SCRIPT_DIR/run.sh" --agent gator --gateway test --name test \
        "$mode" --poll-interval "$interval" "$task" > "$tmp/$label.log" 2>&1 || status=$?
    if [[ "$status" != 77 ]]; then
        cat "$tmp/$label.log" >&2
        echo "expected to stop at image build, got $status" >&2
        exit 1
    fi
}

capture_build first 'TASK_FIRST_UNIQUE Review PR #123; /ok to test' --watch 15
capture_build second 'TASK_SECOND_UNIQUE Review PR #456; do not test' --once 30
if grep -R -E 'TASK_FIRST_UNIQUE|TASK_SECOND_UNIQUE' "$tmp/first" "$tmp/second"; then
    echo 'task leaked into image build context' >&2
    exit 1
fi
diff -r "$tmp/first" "$tmp/second"
grep -Fq '{{USER_PROMPT}}' "$tmp/first/openshell-agent-payload/agent-prompt.md"
grep -Fq '{{RUN_MODE}}' "$tmp/first/openshell-agent-payload/agent-prompt.md"
echo 'ok - different assignments and runtime settings produce identical tooling build contexts'

# Exercise the complete launcher with a credential-free agent fixture. All
# external commands remain mocked; the runtime task must reach sandbox create.
mkdir -p "$tmp/agent"
cat > "$tmp/agent/agent.yaml" <<'YAML'
id: fixture
payload_version: 1
prompt_template: agent://prompt.md
harness:
  default: codex
  supported:
    codex: {}
YAML
printf '%s\n' '{{USER_PROMPT}}' > "$tmp/agent/prompt.md"
cat > "$tmp/bin/openshell" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
    *'gateway info --output json') echo '{"compute_drivers":[{"name":"kubernetes"}]}' ;;
    *'sandbox create'*) printf '%s\n' "$@" > "$LAUNCH_ARGS" ;;
    *) exit 90 ;;
esac
SH
image="registry.test/team/gator@sha256:$(printf 'a%.0s' {1..64})"
PATH="$tmp/bin:$PATH" OPENSHELL_BIN="$tmp/bin/openshell" \
    CODEX_AUTH_ACCOUNT_ID=fixture-account LAUNCH_ARGS="$tmp/launch.args" \
    bash "$SCRIPT_DIR/run.sh" --agent "$tmp/agent" --gateway test --name fixture \
    --image "$image" --watch 'RUNTIME_ONLY_TASK; /ok to test' > "$tmp/launch.log" 2>&1
grep -Fxq "$image" "$tmp/launch.args"
grep -Fxq 'OPENSHELL_AGENT_TASK=RUNTIME_ONLY_TASK; /ok to test' "$tmp/launch.args"
grep -Fxq 'OPENSHELL_AGENT_RUN_MODE=watch' "$tmp/launch.args"
grep -Fxq '/etc/openshell/agent-payload/runtime/launch.sh' "$tmp/launch.args"
echo 'ok - prebuilt Kubernetes launch carries task and watch mode at runtime'
