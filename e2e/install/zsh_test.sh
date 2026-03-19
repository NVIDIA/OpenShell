#!/bin/zsh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Zsh e2e tests for install.sh.
#
# Downloads the latest release for real and validates:
#   - Binary is installed to the correct directory
#   - Binary is executable and runs
#   - PATH guidance shows the correct export command for zsh
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
  printf 'TEST: guidance shows export PATH for zsh users\n'

  assert_output_contains "$INSTALL_OUTPUT" 'export PATH="' "shows export PATH command"
  assert_output_not_contains "$INSTALL_OUTPUT" "fish_add_path" "does not show fish command"
}

test_guidance_mentions_not_on_path() {
  printf 'TEST: guidance mentions install dir is not on PATH\n'

  assert_output_contains "$INSTALL_OUTPUT" "is not on your PATH" "mentions PATH issue"
  assert_output_contains "$INSTALL_OUTPUT" "$INSTALL_DIR" "includes install dir in guidance"
}

test_selects_claude_code() {
  printf 'TEST: installer accepts claude code selection\n'

  SHELL="/bin/zsh" run_install_with_env \
    OPENSHELL_TOOL=claude-code

  assert_setup_selection "tool" "claude-code" "shows claude code selection"
  assert_setup_selection_notice
}

test_selects_opencode() {
  printf 'TEST: installer accepts opencode selection\n'

  SHELL="/bin/zsh" run_install_with_env \
    OPENSHELL_TOOL=opencode

  assert_setup_selection "tool" "opencode" "shows opencode selection"
}

test_selects_vendor_model_path() {
  printf 'TEST: installer accepts vendor and model path selection\n'

  SHELL="/bin/zsh" run_install_with_env \
    OPENSHELL_TOOL=claude-code \
    OPENSHELL_VENDOR=anthropic \
    OPENSHELL_MODEL_PATH=claude-sonnet-4

  assert_setup_selection "vendor" "anthropic" "shows vendor selection"
  assert_setup_selection "model path" "claude-sonnet-4" "shows model path selection"
}

test_rejects_unsupported_combination() {
  printf 'TEST: installer rejects unsupported tool and vendor selection\n'

  SHELL="/bin/zsh" run_install_expect_failure \
    OPENSHELL_TOOL=claude-code \
    OPENSHELL_VENDOR=github-copilot

  assert_output_contains "$INSTALL_OUTPUT" "unsupported installer selection" "reports unsupported combination"
  assert_output_contains "$INSTALL_OUTPUT" "claude-code + github-copilot" "includes unsupported pair"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

printf '=== install.sh e2e tests: zsh ===\n\n'

printf 'Installing openshell...\n'
SHELL="/bin/zsh" run_install
printf 'Done.\n\n'

test_binary_installed;              echo ""
test_binary_executable;             echo ""
test_binary_runs;                   echo ""
test_guidance_shows_export_path;    echo ""
test_guidance_mentions_not_on_path; echo ""
test_selects_claude_code;           echo ""
test_selects_opencode;              echo ""
test_selects_vendor_model_path;     echo ""
test_rejects_unsupported_combination

print_summary
