#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Bash e2e tests for install.sh.
#
# Uses fake release assets and validates:
#   - Binary is installed to the correct directory
#   - Binary is executable and runs
#   - PATH guidance shows the correct export command for bash
#
set -euo pipefail

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
    if [ "$_version" = "openshell ${TEST_RELEASE_VERSION}" ]; then
      pass "openshell --version matches fake release: $_version"
    else
      fail "openshell --version matches fake release" "expected openshell ${TEST_RELEASE_VERSION}, got $_version"
    fi
  else
    fail "openshell --version matches fake release" "exit code: $?"
  fi
}

test_guidance_shows_export_path() {
  printf 'TEST: guidance shows export PATH for bash users\n'

  assert_output_contains "$INSTALL_OUTPUT" 'export PATH="' "shows export PATH command"
  assert_output_not_contains "$INSTALL_OUTPUT" "fish_add_path" "does not show fish command"
}

test_guidance_mentions_not_on_path() {
  printf 'TEST: guidance mentions install dir is not on PATH\n'

  assert_output_contains "$INSTALL_OUTPUT" "is not on your PATH" "mentions PATH issue"
  assert_output_contains "$INSTALL_OUTPUT" "$INSTALL_DIR" "includes install dir in guidance"
}

test_default_release_root_uses_fork_repo() {
  printf 'TEST: default release root uses selected fork-owned repo\n'

  SHELL="/bin/bash" run_install

  assert_release_root_uses_repo "linuxdevel/OpenShell" "default release root"
}

test_release_root_override_changes_repo() {
  printf 'TEST: explicit repo override changes derived release root\n'

  SHELL="/bin/bash" run_install_with_env \
    OPENSHELL_RELEASE_REPO=example/custom-openshell

  assert_release_root_uses_repo "example/custom-openshell" "override release root"
}

test_release_root_override_rejects_malformed_repo() {
  printf 'TEST: malformed repo override fails clearly\n'

  SHELL="/bin/bash" run_install_expect_failure \
    OPENSHELL_RELEASE_REPO=not-a-valid-repo

  assert_release_repo_validation_error "not-a-valid-repo"
}

test_tagged_release_fails_without_checksum_manifest() {
  printf 'TEST: tagged release fails when checksum manifest is missing\n'

  if SHELL="/bin/bash" run_install_with_checksum_state_expect_failure manifest-missing; then
    assert_output_contains "$(read_curl_log)" "/openshell-checksums-sha256.txt" "downloads checksum manifest"
    assert_output_not_contains "$(read_curl_log)" ".sig" "does not download detached signature metadata"
    assert_output_contains "$INSTALL_OUTPUT" "missing checksum manifest" "fails clearly for missing checksum manifest"
  else
    fail "tagged release fails when checksum manifest is missing" "installer unexpectedly succeeded without checksum manifest"
  fi
}

test_tagged_release_verifies_archive_checksum_against_manifest() {
  printf 'TEST: tagged release verifies archive checksum against checksum manifest\n'

  if SHELL="/bin/bash" run_install_with_checksum_state manifest-present; then
    assert_output_contains "$(read_curl_log)" "/openshell-checksums-sha256.txt" "downloads checksum manifest before install"
    assert_output_contains "$INSTALL_OUTPUT" "verifying checksum..." "announces checksum verification"
  else
    fail "tagged release verifies archive checksum against checksum manifest" "$INSTALL_OUTPUT"
  fi
}

test_tagged_release_fails_when_checksum_mismatches_manifest() {
  printf 'TEST: tagged release fails when archive checksum does not match manifest\n'

  if SHELL="/bin/bash" run_install_with_checksum_state_expect_failure checksum-mismatch; then
    assert_output_contains "$INSTALL_OUTPUT" "checksum verification failed for openshell-" "fails on checksum mismatch"
  else
    fail "tagged release fails when archive checksum does not match manifest" "installer unexpectedly accepted a tampered archive"
  fi
}

test_tagged_release_does_not_require_detached_signature_artifacts() {
  printf 'TEST: tagged release succeeds without detached signature artifacts\n'

  if SHELL="/bin/bash" run_install_with_checksum_state manifest-present; then
    assert_output_not_contains "$(read_curl_log)" ".sig" "does not request detached signature metadata"
    assert_output_not_contains "$INSTALL_OUTPUT" "signature metadata" "does not mention detached signature verification"
    assert_output_not_contains "$INSTALL_OUTPUT" "openshell-verify-signature" "does not require verifier helper in active path"
  else
    fail "tagged release succeeds without detached signature artifacts" "$INSTALL_OUTPUT"
  fi
}

test_selects_claude_code() {
  printf 'TEST: installer accepts claude code selection\n'

  SHELL="/bin/bash" run_install_with_env \
    OPENSHELL_TOOL=claude-code

  assert_setup_selection "tool" "claude-code" "shows claude code selection"
  assert_setup_selection_notice
}

test_selects_opencode() {
  printf 'TEST: installer accepts opencode selection\n'

  SHELL="/bin/bash" run_install_with_env \
    OPENSHELL_TOOL=opencode

  assert_setup_selection "tool" "opencode" "shows opencode selection"
}

test_selects_vendor_model_path() {
  printf 'TEST: installer accepts vendor and model path selection\n'

  SHELL="/bin/bash" run_install_with_env \
    OPENSHELL_TOOL=claude-code \
    OPENSHELL_VENDOR=anthropic \
    OPENSHELL_MODEL_PATH=claude-sonnet-4

  assert_setup_selection "vendor" "anthropic" "shows vendor selection"
  assert_setup_selection "model path" "claude-sonnet-4" "shows model path selection"
}

test_rejects_unsupported_combination() {
  printf 'TEST: installer rejects unsupported tool and vendor selection\n'

  SHELL="/bin/bash" run_install_expect_failure \
    OPENSHELL_TOOL=claude-code \
    OPENSHELL_VENDOR=github-copilot

  assert_output_contains "$INSTALL_OUTPUT" "unsupported installer selection" "reports unsupported combination"
  assert_output_contains "$INSTALL_OUTPUT" "claude-code + github-copilot" "includes unsupported pair"
}

test_accepts_selection_flags() {
  printf 'TEST: installer accepts setup selection flags\n'

  SHELL="/bin/bash" run_install_with_args \
    --tool opencode \
    --vendor github-copilot \
    --model-path copilot/chat

  assert_setup_selection "tool" "opencode" "shows tool flag selection"
  assert_setup_selection "vendor" "github-copilot" "shows vendor flag selection"
  assert_setup_selection "model path" "copilot/chat" "shows model-path flag selection"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

printf '=== install.sh e2e tests: bash ===\n\n'

printf 'Installing openshell...\n'
SHELL="/bin/bash" run_install
printf 'Done.\n\n'

test_binary_installed;              echo ""
test_binary_executable;             echo ""
test_binary_runs;                   echo ""
test_guidance_shows_export_path;    echo ""
test_guidance_mentions_not_on_path; echo ""
test_default_release_root_uses_fork_repo; echo ""
test_release_root_override_changes_repo; echo ""
test_release_root_override_rejects_malformed_repo; echo ""
test_tagged_release_fails_without_checksum_manifest; echo ""
test_tagged_release_verifies_archive_checksum_against_manifest; echo ""
test_tagged_release_fails_when_checksum_mismatches_manifest; echo ""
test_tagged_release_does_not_require_detached_signature_artifacts; echo ""
test_selects_claude_code;           echo ""
test_selects_opencode;              echo ""
test_selects_vendor_model_path;     echo ""
test_rejects_unsupported_combination; echo ""
test_accepts_selection_flags

print_summary
