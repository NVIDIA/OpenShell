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
