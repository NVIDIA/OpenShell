#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# POSIX sh e2e tests for install.sh.
#
# Downloads the latest release for real and validates:
#   - Binary is installed to the correct directory
#   - Binary is executable and runs
#   - PATH guidance shows the correct export command for sh
#   - No rc files or env scripts are created
#
set -eu

. "$(dirname "$0")/helpers.sh"

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

test_binary_installed() {
  printf 'TEST: binary exists in install directory\n'

  if [ -f "$INSTALL_DIR/openshell" ]; then
    pass "openshell binary exists at $INSTALL_DIR/openshell"
  else
    fail "openshell binary exists" "not found at $INSTALL_DIR/openshell"
  fi
}

test_binary_executable() {
  printf 'TEST: binary is executable\n'

  if [ -x "$INSTALL_DIR/openshell" ]; then
    pass "openshell binary is executable"
  else
    fail "openshell binary is executable" "$INSTALL_DIR/openshell is not executable"
  fi
}

test_binary_runs() {
  printf 'TEST: binary runs successfully\n'

  if _version="$("$INSTALL_DIR/openshell" --version 2>/dev/null)"; then
    pass "openshell --version succeeds: $_version"
  else
    fail "openshell --version succeeds" "exit code: $?"
  fi
}

test_guidance_shows_export_path() {
  printf 'TEST: guidance shows export PATH for sh users\n'

  assert_output_contains "$INSTALL_OUTPUT" 'export PATH="' "shows export PATH command"
  assert_output_not_contains "$INSTALL_OUTPUT" "fish_add_path" "does not show fish command"
}

test_guidance_mentions_not_on_path() {
  printf 'TEST: guidance mentions install dir is not on PATH\n'

  assert_output_contains "$INSTALL_OUTPUT" "is not on your PATH" "mentions PATH issue"
  assert_output_contains "$INSTALL_OUTPUT" "$INSTALL_DIR" "includes install dir in guidance"
}

test_guidance_mentions_restart() {
  printf 'TEST: guidance tells user to restart shell\n'

  assert_output_contains "$INSTALL_OUTPUT" "restart your shell" "mentions shell restart"
}

test_no_env_scripts_created() {
  printf 'TEST: no env scripts are created in install dir\n'

  if [ -f "$INSTALL_DIR/env" ]; then
    fail "no env script created" "found $INSTALL_DIR/env"
  else
    pass "no env script created"
  fi

  if [ -f "$INSTALL_DIR/env.fish" ]; then
    fail "no env.fish script created" "found $INSTALL_DIR/env.fish"
  else
    pass "no env.fish script created"
  fi
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

printf '=== install.sh e2e tests: sh ===\n\n'

printf 'Installing openshell...\n'
SHELL="/bin/sh" run_install
printf 'Done.\n\n'

test_binary_installed;            echo ""
test_binary_executable;           echo ""
test_binary_runs;                 echo ""
test_guidance_shows_export_path;  echo ""
test_guidance_mentions_not_on_path; echo ""
test_guidance_mentions_restart;   echo ""
test_no_env_scripts_created

print_summary
