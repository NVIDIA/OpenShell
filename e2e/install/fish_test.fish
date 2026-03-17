#!/usr/bin/env fish
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Fish e2e tests for install.sh.
#
# Downloads the latest release for real and validates:
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

function run_install
    set -g INSTALL_DIR (mktemp -d)/bin

    set -g INSTALL_OUTPUT (OPENSHELL_INSTALL_DIR="$INSTALL_DIR" \
        SHELL="/usr/bin/fish" \
        PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
        sh "$INSTALL_SCRIPT" 2>&1)

    if test $status -ne 0
        printf 'install.sh failed:\n%s\n' "$INSTALL_OUTPUT" >&2
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

printf '\n=== Results: %d passed, %d failed ===\n' $PASS $FAIL

if test $FAIL -gt 0
    exit 1
end
