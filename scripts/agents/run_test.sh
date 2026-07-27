#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/openshell-agent-run-test.XXXXXX")"

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

assert_not_contains() {
    local file="$1"
    local unexpected="$2"
    if grep -F -- "$unexpected" "$file" >/dev/null; then
        fail "did not expect '$unexpected' in $file"
    fi
}

make_fixture() {
    local fixture_dir="$1"
    mkdir -p "$fixture_dir"
    cat >"$fixture_dir/agent.yaml" <<'YAML'
id: fixture
display_name: Fixture Agent
sandbox:
  from: agent://.
  gateway: fixture-gateway
harness:
  default: codex
  supported:
    codex:
      model: fixture-model
      reasoning: low
runtime:
  mode: once
  poll_interval_seconds: 60
  max_transient_failures: 2
profile_paths: []
settings: []
providers: []
skills: []
subagents: []
prompt_template: prompt.md
YAML
    cat >"$fixture_dir/Dockerfile" <<'DOCKERFILE'
FROM scratch
USER fixture
DOCKERFILE
    cat >"$fixture_dir/prompt.md" <<'PROMPT'
Fixture prompt: {{USER_PROMPT}}
PROMPT
}

make_mocks() {
    local mock_dir="$1"
    mkdir -p "$mock_dir"
cat >"$mock_dir/openshell" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"$MOCK_OPENSHELL_LOG"
printf '\n' >>"$MOCK_OPENSHELL_LOG"
if [[ "$*" == "gateway list --output json" ]]; then
    if [[ "${MOCK_GATEWAY_REMOTE:-0}" == "1" ]]; then
        printf '[{"name":"fixture-gateway","is_remote":true}]\n'
    else
        printf '[{"name":"fixture-gateway","is_remote":false}]\n'
    fi
fi
MOCK
    cat >"$mock_dir/docker" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"$MOCK_DOCKER_LOG"
printf '\n' >>"$MOCK_DOCKER_LOG"

metadata_file=""
dockerfile=""
context=""
args=("$@")
for ((index = 0; index < ${#args[@]}; index++)); do
    case "${args[$index]}" in
        --metadata-file)
            metadata_file="${args[$((index + 1))]}"
            ;;
        --file)
            dockerfile="${args[$((index + 1))]}"
            ;;
    esac
done
context="${args[$((${#args[@]} - 1))]}"

[[ -f "$dockerfile" ]]
grep -F 'COPY openshell-agent-payload/ /etc/openshell/agent-payload/' "$dockerfile" >/dev/null
grep -F 'Fixture prompt: review PR 2253' "$context/openshell-agent-payload/agent-prompt.md" >/dev/null

case "${MOCK_DOCKER_MODE:-success}" in
    success)
        printf '{"containerimage.digest":"sha256:%064d"}\n' 1 >"$metadata_file"
        ;;
    missing_digest)
        printf '{}\n' >"$metadata_file"
        ;;
    invalid_digest)
        printf '{"containerimage.digest":"sha256:not-a-digest"}\n' >"$metadata_file"
        ;;
    failure)
        exit 42
        ;;
    *)
        exit 2
        ;;
esac
MOCK
    chmod +x "$mock_dir/openshell" "$mock_dir/docker"
}

run_launcher() {
    local case_dir="$1"
    shift
    MOCK_OPENSHELL_LOG="$case_dir/openshell.log" \
        MOCK_DOCKER_LOG="$case_dir/docker.log" \
        OPENSHELL_BIN="$case_dir/mocks/openshell" \
        DOCKER_BIN="$case_dir/mocks/docker" \
        "$SCRIPT_DIR/run.sh" \
        --agent "$case_dir/agent" \
        --gateway fixture-gateway \
        --name fixture-agent \
        "$@" \
        "review PR 2253"
}

test_publishes_and_launches_by_digest() {
    local case_dir="$TEST_ROOT/publish"
    make_fixture "$case_dir/agent"
    make_mocks "$case_dir/mocks"

    run_launcher "$case_dir" \
        --publish-to registry.example.com/openshell/fixture \
        --platform linux/amd64

    assert_contains "$case_dir/docker.log" "buildx build"
    assert_contains "$case_dir/docker.log" "--platform linux/amd64"
    assert_contains "$case_dir/docker.log" "--push"
    assert_contains "$case_dir/docker.log" "--metadata-file"
    assert_contains "$case_dir/docker.log" "--tag registry.example.com/openshell/fixture:payload-"
    assert_contains "$case_dir/openshell.log" "--from registry.example.com/openshell/fixture@sha256:"
    assert_not_contains "$case_dir/openshell.log" "fixture:payload-"
}

test_environment_overrides_publish_defaults() {
    local case_dir="$TEST_ROOT/environment"
    make_fixture "$case_dir/agent"
    make_mocks "$case_dir/mocks"

    OPENSHELL_AGENT_PUBLISH_TO="registry.example.com/openshell/from-env" \
        OPENSHELL_AGENT_PLATFORM="linux/arm64" \
        run_launcher "$case_dir"

    assert_contains "$case_dir/docker.log" "--platform linux/arm64"
    assert_contains "$case_dir/openshell.log" "--from registry.example.com/openshell/from-env@sha256:"
}

test_local_launch_does_not_invoke_docker() {
    local case_dir="$TEST_ROOT/local"
    make_fixture "$case_dir/agent"
    make_mocks "$case_dir/mocks"

    run_launcher "$case_dir"

    [[ ! -e "$case_dir/docker.log" ]] || fail "local launch unexpectedly invoked docker"
    assert_contains "$case_dir/openshell.log" "--from /"
    assert_contains "$case_dir/openshell.log" "/build-context/Dockerfile"
}

test_remote_launch_requires_publish_repository() {
    local case_dir="$TEST_ROOT/remote-without-publish"
    make_fixture "$case_dir/agent"
    make_mocks "$case_dir/mocks"

    if MOCK_GATEWAY_REMOTE=1 run_launcher "$case_dir" >"$case_dir/output.log" 2>&1; then
        fail "remote launch unexpectedly accepted a local Dockerfile source"
    fi

    assert_contains "$case_dir/output.log" "use --publish-to REPOSITORY"
    assert_not_contains "$case_dir/openshell.log" "sandbox create"
}

test_publish_failure_precedes_gateway_changes() {
    local case_dir="$TEST_ROOT/publish-failure"
    make_fixture "$case_dir/agent"
    make_mocks "$case_dir/mocks"

    if MOCK_DOCKER_MODE=failure run_launcher "$case_dir" \
        --publish-to registry.example.com/openshell/fixture; then
        fail "launcher unexpectedly succeeded after docker failure"
    fi

    [[ ! -e "$case_dir/openshell.log" ]] || fail "gateway was contacted after docker failure"
}

test_rejects_missing_or_invalid_digest() {
    local mode
    for mode in missing_digest invalid_digest; do
        local case_dir="$TEST_ROOT/$mode"
        make_fixture "$case_dir/agent"
        make_mocks "$case_dir/mocks"

        if MOCK_DOCKER_MODE="$mode" run_launcher "$case_dir" \
            --publish-to registry.example.com/openshell/fixture; then
            fail "launcher unexpectedly accepted $mode"
        fi

        [[ ! -e "$case_dir/openshell.log" ]] || fail "gateway was contacted after $mode"
    done
}

test_rejects_invalid_publish_options() {
    local case_dir="$TEST_ROOT/invalid-options"
    make_fixture "$case_dir/agent"
    make_mocks "$case_dir/mocks"

    if run_launcher "$case_dir" --platform linux/amd64; then
        fail "--platform unexpectedly succeeded without --publish-to"
    fi
    if run_launcher "$case_dir" --publish-to registry.example.com/openshell/fixture:latest; then
        fail "--publish-to unexpectedly accepted a tag"
    fi
}

test_publishes_and_launches_by_digest
test_environment_overrides_publish_defaults
test_local_launch_does_not_invoke_docker
test_remote_launch_requires_publish_repository
test_publish_failure_precedes_gateway_changes
test_rejects_missing_or_invalid_digest
test_rejects_invalid_publish_options

echo "run.sh tests passed"
