#!/usr/bin/env fish
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Fish e2e tests for install.sh.
#
# Uses fake release assets and validates:
#   - Binary is installed to the correct directory
#   - Binary is executable and runs
#   - PATH guidance shows fish_add_path (not export PATH)

set -g PASS 0
set -g FAIL 0

# Resolve paths relative to this script
set -g SCRIPT_DIR (builtin cd (dirname (status filename)) && pwd)
set -g REPO_ROOT (builtin cd "$SCRIPT_DIR/../.." && pwd)
set -g INSTALL_SCRIPT "$REPO_ROOT/install.sh"

# Set by run_install
set -g INSTALL_DIR ""
set -g INSTALL_OUTPUT ""
set -g TEST_ROOT ""
set -g TEST_RELEASE_VERSION "v0.0.10-test"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function pass
    set -g PASS (math $PASS + 1)
    printf '  PASS: %s\n' $argv[1]
end

function fail
    set -g FAIL (math $FAIL + 1)
    printf '  FAIL: %s\n' $argv[1] >&2
    if test (count $argv) -gt 1
        printf '        %s\n' $argv[2] >&2
    end
end

function assert_output_contains
    set -l output $argv[1]
    set -l pattern $argv[2]
    set -l label $argv[3]

    if string match -q -- "*$pattern*" "$output"
        pass "$label"
    else
        fail "$label" "expected '$pattern' in output"
    end
end

function assert_output_not_contains
    set -l output $argv[1]
    set -l pattern $argv[2]
    set -l label $argv[3]

    if string match -q -- "*$pattern*" "$output"
        fail "$label" "unexpected '$pattern' found in output"
    else
        pass "$label"
    end
end

function assert_setup_selection
    set -l kind $argv[1]
    set -l value $argv[2]
    set -l label $argv[3]

    assert_output_contains "$INSTALL_OUTPUT" "validated setup $kind selection: $value" "$label"
end

function assert_setup_selection_notice
    assert_output_contains "$INSTALL_OUTPUT" "applies to later OpenShell setup" "mentions later setup flow"
    assert_output_contains "$INSTALL_OUTPUT" "installs the openshell CLI" "keeps CLI installer scope clear"
end

function test_target
    switch (uname -m)
        case x86_64 amd64
            set -l arch x86_64
        case aarch64 arm64
            set -l arch aarch64
        case '*'
            set -l arch x86_64
    end

    switch (uname -s)
        case Darwin
            set -l os apple-darwin
        case '*'
            set -l os unknown-linux-musl
    end

    printf '%s-%s\n' $arch $os
end

function setup_fake_release_assets
    set -g TEST_ROOT (mktemp -d)
    set -l target (test_target)
    set -l filename "openshell-$target.tar.gz"
    set -l release_dir "$TEST_ROOT/releases/download/$TEST_RELEASE_VERSION"
    set -l fake_bin_dir "$TEST_ROOT/fakebin"

    mkdir -p "$release_dir" "$fake_bin_dir"

    cat > "$TEST_ROOT/openshell" <<EOF
#!/bin/sh
if [ "\${1:-}" = "--version" ]; then
  printf 'openshell %s\n' "$TEST_RELEASE_VERSION"
else
  printf 'openshell test binary\n'
fi
EOF
    chmod 755 "$TEST_ROOT/openshell"
    tar -czf "$release_dir/$filename" -C "$TEST_ROOT" openshell

    if command -v shasum >/dev/null 2>&1
        shasum -a 256 "$release_dir/$filename" | awk '{print $1 "  '$filename'"}' > "$release_dir/openshell-checksums-sha256.txt"
    else
        sha256sum "$release_dir/$filename" | awk '{print $1 "  '$filename'"}' > "$release_dir/openshell-checksums-sha256.txt"
    end

    cat > "$fake_bin_dir/curl" <<'EOF'
#!/bin/sh
set -eu

_output=""
_format=""
_url=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    -o)
      _output="$2"
      shift 2
      ;;
    -w)
      _format="$2"
      shift 2
      ;;
    --retry)
      shift 2
      ;;
    -f|-L|-s|-S)
      shift
      ;;
    *)
      _url="$1"
      shift
      ;;
  esac
done

if [ -n "$_format" ]; then
  case "$_url" in
    */releases/latest)
      printf '%s/releases/tag/%s' "${TEST_GITHUB_URL}" "${TEST_RELEASE_VERSION}"
      ;;
    *)
      printf '%s' "$_url"
      ;;
  esac
  exit 0
fi

_name="${_url##*/}"
[ -n "$_output" ] || exit 1
cp "${TEST_RELEASE_DIR}/${_name}" "$_output"
EOF
    chmod 755 "$fake_bin_dir/curl"
end

function run_with_test_env
    set -l cmd $argv
    setup_fake_release_assets

    set -g INSTALL_OUTPUT (env \
        OPENSHELL_INSTALL_DIR="$INSTALL_DIR" \
        PATH="$TEST_ROOT/fakebin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
        SHELL="/usr/bin/fish" \
        TEST_RELEASE_DIR="$TEST_ROOT/releases/download/$TEST_RELEASE_VERSION" \
        TEST_RELEASE_VERSION="$TEST_RELEASE_VERSION" \
        TEST_GITHUB_URL="https://github.com/NVIDIA/OpenShell" \
        $cmd 2>&1)

    return $status
end

function run_install
    set -g INSTALL_DIR (mktemp -d)/bin

    run_with_test_env sh "$INSTALL_SCRIPT"

    if test $status -ne 0
        printf 'install.sh failed:\n%s\n' "$INSTALL_OUTPUT" >&2
        return 1
    end
end

function run_install_with_env
    set -g INSTALL_DIR (mktemp -d)/bin

    run_with_test_env $argv sh "$INSTALL_SCRIPT"

    if test $status -ne 0
        printf 'install.sh failed:\n%s\n' "$INSTALL_OUTPUT" >&2
        return 1
    end
end

function run_install_with_args
    set -g INSTALL_DIR (mktemp -d)/bin

    run_with_test_env sh "$INSTALL_SCRIPT" $argv

    if test $status -ne 0
        printf 'install.sh failed:\n%s\n' "$INSTALL_OUTPUT" >&2
        return 1
    end
end

function run_install_expect_failure
    set -g INSTALL_DIR (mktemp -d)/bin

    run_with_test_env $argv sh "$INSTALL_SCRIPT"

    if test $status -eq 0
        printf 'install.sh unexpectedly succeeded:\n%s\n' "$INSTALL_OUTPUT" >&2
        return 1
    end
end

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

function test_binary_installed
    printf 'TEST: binary exists in install directory\n'

    if test -f "$INSTALL_DIR/openshell"
        pass "openshell binary exists at $INSTALL_DIR/openshell"
    else
        fail "openshell binary exists" "not found at $INSTALL_DIR/openshell"
    end
end

function test_binary_executable
    printf 'TEST: binary is executable\n'

    if test -x "$INSTALL_DIR/openshell"
        pass "openshell binary is executable"
    else
        fail "openshell binary is executable" "$INSTALL_DIR/openshell is not executable"
    end
end

function test_binary_runs
    printf 'TEST: binary runs successfully\n'

    set -l version_output ("$INSTALL_DIR/openshell" --version 2>/dev/null)
    if test $status -eq 0
        pass "openshell --version succeeds: $version_output"
    else
        fail "openshell --version succeeds" "exit code: $status"
    end
end

function test_guidance_shows_fish_add_path
    printf 'TEST: guidance shows fish_add_path for fish users\n'

    assert_output_contains "$INSTALL_OUTPUT" "fish_add_path" "shows fish_add_path command"
    assert_output_not_contains "$INSTALL_OUTPUT" 'export PATH="' "does not show POSIX export"
end

function test_guidance_mentions_not_on_path
    printf 'TEST: guidance mentions install dir is not on PATH\n'

    assert_output_contains "$INSTALL_OUTPUT" "is not on your PATH" "mentions PATH issue"
    assert_output_contains "$INSTALL_OUTPUT" "$INSTALL_DIR" "includes install dir in guidance"
end

function test_selects_claude_code
    printf 'TEST: installer accepts claude code selection\n'

    run_install_with_env OPENSHELL_TOOL=claude-code

    assert_setup_selection tool claude-code "shows claude code selection"
    assert_setup_selection_notice
end

function test_selects_opencode
    printf 'TEST: installer accepts opencode selection\n'

    run_install_with_env OPENSHELL_TOOL=opencode

    assert_setup_selection tool opencode "shows opencode selection"
end

function test_selects_vendor_model_path
    printf 'TEST: installer accepts vendor and model path selection\n'

    run_install_with_env OPENSHELL_TOOL=claude-code OPENSHELL_VENDOR=anthropic OPENSHELL_MODEL_PATH=claude-sonnet-4

    assert_setup_selection vendor anthropic "shows vendor selection"
    assert_setup_selection "model path" claude-sonnet-4 "shows model path selection"
end

function test_rejects_unsupported_combination
    printf 'TEST: installer rejects unsupported tool and vendor selection\n'

    run_install_expect_failure OPENSHELL_TOOL=claude-code OPENSHELL_VENDOR=github-copilot

    assert_output_contains "$INSTALL_OUTPUT" "unsupported installer selection" "reports unsupported combination"
    assert_output_contains "$INSTALL_OUTPUT" "claude-code + github-copilot" "includes unsupported pair"
end

function test_accepts_selection_flags
    printf 'TEST: installer accepts setup selection flags\n'

    run_install_with_args --tool opencode --vendor github-copilot --model-path copilot/chat

    assert_setup_selection tool opencode "shows tool flag selection"
    assert_setup_selection vendor github-copilot "shows vendor flag selection"
    assert_setup_selection "model path" copilot/chat "shows model-path flag selection"
end

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

printf '=== install.sh e2e tests: fish ===\n\n'

printf 'Installing openshell...\n'
run_install
printf 'Done.\n\n'

test_binary_installed
echo ""
test_binary_executable
echo ""
test_binary_runs
echo ""
test_guidance_shows_fish_add_path
echo ""
test_guidance_mentions_not_on_path
echo ""
test_selects_claude_code
echo ""
test_selects_opencode
echo ""
test_selects_vendor_model_path
echo ""
test_rejects_unsupported_combination
echo ""
test_accepts_selection_flags

printf '\n=== Results: %d passed, %d failed ===\n' $PASS $FAIL

if test $FAIL -gt 0
    exit 1
end
