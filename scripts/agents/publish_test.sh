#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/openshell-agent-publish-test.XXXXXX")"

cleanup() {
    rm -rf "$TEST_ROOT"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

assert_contains() {
    local file="$1"
    local expected="$2"
    grep -F -- "$expected" "$file" >/dev/null || fail "expected '$expected' in $file"
}

mkdir -p "$TEST_ROOT/context" "$TEST_ROOT/mocks"
cat >"$TEST_ROOT/context/Dockerfile" <<'DOCKERFILE'
FROM scratch
COPY payload.txt /payload.txt
DOCKERFILE
printf 'decoupled publisher fixture\n' >"$TEST_ROOT/context/payload.txt"

cat >"$TEST_ROOT/mocks/docker" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"$MOCK_DOCKER_LOG"
printf '\n' >>"$MOCK_DOCKER_LOG"

args=("$@")
metadata_file=""
for ((index = 0; index < ${#args[@]}; index++)); do
    if [[ "${args[$index]}" == "--metadata-file" ]]; then
        metadata_file="${args[$((index + 1))]}"
    fi
done
printf '{"containerimage.digest":"sha256:%064d"}\n' 7 >"$metadata_file"
MOCK
chmod +x "$TEST_ROOT/mocks/docker"

MOCK_DOCKER_LOG="$TEST_ROOT/docker.log" \
    DOCKER_BIN="$TEST_ROOT/mocks/docker" \
    "$SCRIPT_DIR/publish.sh" \
    --from "$TEST_ROOT/context" \
    --publish-to registry.example.com/agents/reusable \
    --platform linux/arm64 >"$TEST_ROOT/reference.txt"

assert_contains "$TEST_ROOT/reference.txt" "registry.example.com/agents/reusable@sha256:"
assert_contains "$TEST_ROOT/docker.log" "buildx build"
assert_contains "$TEST_ROOT/docker.log" "--platform linux/arm64"
assert_contains "$TEST_ROOT/docker.log" "--push"
assert_contains "$TEST_ROOT/docker.log" "--tag registry.example.com/agents/reusable:payload-"
assert_contains "$TEST_ROOT/docker.log" "context/Dockerfile"

if DOCKER_BIN="$TEST_ROOT/mocks/docker" "$SCRIPT_DIR/publish.sh" \
    --from "$TEST_ROOT/context" \
    --publish-to registry.example.com/agents/reusable:latest >/dev/null 2>&1; then
    fail "publisher unexpectedly accepted a mutable tag"
fi

echo "publish.sh tests passed"
