#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Tests for install.sh PATH setup logic.
#
# Validates that:
#   - env scripts contain correct shell-specific syntax
#   - POSIX rc files source the POSIX env script (not fish)
#   - fish conf.d sources the fish env script
#   - existing rc file content is preserved (no overwrites)
#   - duplicate source lines are not appended on re-runs
#   - user-facing guidance matches the detected shell
#
# Usage:
#   ./tests/test-install.sh
#
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INSTALL_SCRIPT="$REPO_ROOT/install.sh"

PASS=0
FAIL=0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

pass() {
  PASS=$((PASS + 1))
  printf '  PASS: %s\n' "$1"
}

fail() {
  FAIL=$((FAIL + 1))
  printf '  FAIL: %s\n' "$1" >&2
  if [ -n "${2:-}" ]; then
    printf '        %s\n' "$2" >&2
  fi
}

assert_file_contains() {
  _afc_file="$1"
  _afc_pattern="$2"
  _afc_label="$3"

  if grep -qF "$_afc_pattern" "$_afc_file" 2>/dev/null; then
    pass "$_afc_label"
  else
    fail "$_afc_label" "expected '$_afc_pattern' in $_afc_file"
  fi
}

assert_file_not_contains() {
  _afnc_file="$1"
  _afnc_pattern="$2"
  _afnc_label="$3"

  if grep -qF "$_afnc_pattern" "$_afnc_file" 2>/dev/null; then
    fail "$_afnc_label" "unexpected '$_afnc_pattern' found in $_afnc_file"
  else
    pass "$_afnc_label"
  fi
}

count_occurrences() {
  _co_file="$1"
  _co_pattern="$2"
  grep -cF "$_co_pattern" "$_co_file" 2>/dev/null || echo "0"
}

# Create a fresh temporary HOME for each test.
make_test_home() {
  _mth_dir="$(mktemp -d)"
  echo "$_mth_dir"
}

cleanup_test_home() {
  rm -rf "$1"
}

# Source the install script functions without running main.
# We do this by extracting everything except the final `main "$@"` line.
prepare_install_functions() {
  _pif_tmpscript="$(mktemp)"
  sed '$d' "$INSTALL_SCRIPT" > "$_pif_tmpscript"
  echo "$_pif_tmpscript"
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

test_env_script_posix_syntax() {
  printf 'TEST: env script contains POSIX syntax\n'
  _test_home="$(make_test_home)"
  _install_dir="$_test_home/.local/bin"
  mkdir -p "$_install_dir"

  _funcs="$(prepare_install_functions)"
  HOME="$_test_home" sh -c ". '$_funcs' && write_env_script_sh '\$HOME/.local/bin' '$_install_dir/env'"
  rm -f "$_funcs"

  assert_file_contains "$_install_dir/env" 'export PATH=' "env has 'export PATH='"
  assert_file_contains "$_install_dir/env" 'case ":${PATH}:"' "env uses POSIX case syntax"
  assert_file_not_contains "$_install_dir/env" 'set -gx' "env does not contain fish syntax"
  assert_file_not_contains "$_install_dir/env" 'not contains' "env does not contain fish keywords"

  cleanup_test_home "$_test_home"
}

test_env_script_fish_syntax() {
  printf 'TEST: env.fish script contains fish syntax\n'
  _test_home="$(make_test_home)"
  _install_dir="$_test_home/.local/bin"
  mkdir -p "$_install_dir"

  _funcs="$(prepare_install_functions)"
  HOME="$_test_home" sh -c ". '$_funcs' && write_env_script_fish '\$HOME/.local/bin' '$_install_dir/env.fish'"
  rm -f "$_funcs"

  assert_file_contains "$_install_dir/env.fish" 'set -gx PATH' "env.fish has fish PATH syntax"
  assert_file_contains "$_install_dir/env.fish" 'not contains' "env.fish uses fish conditionals"
  assert_file_not_contains "$_install_dir/env.fish" 'export PATH=' "env.fish does not contain POSIX export"

  cleanup_test_home "$_test_home"
}

test_bashrc_sources_posix_env() {
  printf 'TEST: .bashrc sources POSIX env script (not env.fish)\n'
  _test_home="$(make_test_home)"
  _install_dir="$_test_home/.local/bin"
  mkdir -p "$_install_dir"

  # Pre-create .bashrc with existing content
  echo '# existing bashrc content' > "$_test_home/.bashrc"

  _funcs="$(prepare_install_functions)"
  HOME="$_test_home" sh -c ". '$_funcs' && setup_path '$_install_dir'"
  rm -f "$_funcs"

  assert_file_contains "$_test_home/.bashrc" ". \"$_install_dir/env\"" ".bashrc sources env"
  assert_file_not_contains "$_test_home/.bashrc" "env.fish" ".bashrc does not reference env.fish"

  cleanup_test_home "$_test_home"
}

test_profile_sources_posix_env() {
  printf 'TEST: .profile sources POSIX env script (not env.fish)\n'
  _test_home="$(make_test_home)"
  _install_dir="$_test_home/.local/bin"
  mkdir -p "$_install_dir"

  # Pre-create .profile with existing content
  echo '# existing profile content' > "$_test_home/.profile"

  _funcs="$(prepare_install_functions)"
  HOME="$_test_home" sh -c ". '$_funcs' && setup_path '$_install_dir'"
  rm -f "$_funcs"

  assert_file_contains "$_test_home/.profile" ". \"$_install_dir/env\"" ".profile sources env"
  assert_file_not_contains "$_test_home/.profile" "env.fish" ".profile does not reference env.fish"

  cleanup_test_home "$_test_home"
}

test_fish_conf_sources_fish_env() {
  printf 'TEST: fish conf.d sources fish env script\n'
  _test_home="$(make_test_home)"
  _install_dir="$_test_home/.local/bin"
  mkdir -p "$_install_dir"
  mkdir -p "$_test_home/.config/fish"

  _funcs="$(prepare_install_functions)"
  HOME="$_test_home" sh -c ". '$_funcs' && setup_path '$_install_dir'"
  rm -f "$_funcs"

  _fish_conf="$_test_home/.config/fish/conf.d/openshell.env.fish"
  assert_file_contains "$_fish_conf" "env.fish" "fish conf.d sources env.fish"
  assert_file_not_contains "$_fish_conf" ". \"" "fish conf.d does not use POSIX dot-source"

  cleanup_test_home "$_test_home"
}

test_existing_content_preserved() {
  printf 'TEST: existing rc file content is preserved\n'
  _test_home="$(make_test_home)"
  _install_dir="$_test_home/.local/bin"
  mkdir -p "$_install_dir"

  # Write distinctive content to rc files
  printf '# my custom bashrc aliases\nalias ll="ls -la"\nexport MY_VAR=hello\n' > "$_test_home/.bashrc"
  printf '# my custom profile\nexport EDITOR=vim\n' > "$_test_home/.profile"

  _funcs="$(prepare_install_functions)"
  HOME="$_test_home" sh -c ". '$_funcs' && setup_path '$_install_dir'"
  rm -f "$_funcs"

  assert_file_contains "$_test_home/.bashrc" 'alias ll="ls -la"' ".bashrc alias preserved"
  assert_file_contains "$_test_home/.bashrc" 'export MY_VAR=hello' ".bashrc export preserved"
  assert_file_contains "$_test_home/.profile" 'export EDITOR=vim' ".profile export preserved"

  cleanup_test_home "$_test_home"
}

test_no_duplicate_source_lines() {
  printf 'TEST: running setup_path twice does not duplicate source lines\n'
  _test_home="$(make_test_home)"
  _install_dir="$_test_home/.local/bin"
  mkdir -p "$_install_dir"

  echo '# bashrc' > "$_test_home/.bashrc"

  _funcs="$(prepare_install_functions)"
  HOME="$_test_home" sh -c ". '$_funcs' && setup_path '$_install_dir'"
  # Run again
  HOME="$_test_home" sh -c ". '$_funcs' && setup_path '$_install_dir'"
  rm -f "$_funcs"

  _count="$(count_occurrences "$_test_home/.bashrc" ". \"$_install_dir/env\"")"
  if [ "$_count" = "1" ]; then
    pass "source line appears exactly once in .bashrc"
  else
    fail "source line appears exactly once in .bashrc" "found $_count occurrences"
  fi

  cleanup_test_home "$_test_home"
}

test_guidance_shows_posix_for_bash() {
  printf 'TEST: guidance shows POSIX source for bash users\n'
  _test_home="$(make_test_home)"
  _install_dir="$_test_home/.local/bin"
  mkdir -p "$_install_dir"

  echo '# bashrc' > "$_test_home/.bashrc"

  _funcs="$(prepare_install_functions)"
  _output="$(HOME="$_test_home" SHELL="/bin/bash" PATH="/usr/bin:/bin:/usr/sbin:/sbin" sh -c ". '$_funcs' && setup_path '$_install_dir'" 2>&1)"
  rm -f "$_funcs"

  if echo "$_output" | grep -qF '. "'; then
    pass "bash user sees POSIX dot-source command"
  else
    fail "bash user sees POSIX dot-source command" "output: $_output"
  fi

  if echo "$_output" | grep -qF 'env.fish'; then
    fail "bash user does not see env.fish hint" "output: $_output"
  else
    pass "bash user does not see env.fish hint"
  fi

  cleanup_test_home "$_test_home"
}

test_guidance_shows_fish_for_fish() {
  printf 'TEST: guidance shows fish source for fish users\n'
  _test_home="$(make_test_home)"
  _install_dir="$_test_home/.local/bin"
  mkdir -p "$_install_dir"

  echo '# bashrc' > "$_test_home/.bashrc"

  _funcs="$(prepare_install_functions)"
  _output="$(HOME="$_test_home" SHELL="/usr/bin/fish" PATH="/usr/bin:/bin:/usr/sbin:/sbin" sh -c ". '$_funcs' && setup_path '$_install_dir'" 2>&1)"
  rm -f "$_funcs"

  if echo "$_output" | grep -qF 'env.fish'; then
    pass "fish user sees env.fish source command"
  else
    fail "fish user sees env.fish source command" "output: $_output"
  fi

  cleanup_test_home "$_test_home"
}

test_no_variable_clobbering() {
  printf 'TEST: helper functions do not clobber caller variables\n'
  _test_home="$(make_test_home)"
  _install_dir="$_test_home/.local/bin"
  mkdir -p "$_install_dir"

  echo '# bashrc' > "$_test_home/.bashrc"

  # This test verifies the core bug from #394: write_env_script_fish must not
  # clobber _env_script. We call setup_path and check that .bashrc does NOT
  # get env.fish sourced (which was the symptom of the clobbering bug).
  _funcs="$(prepare_install_functions)"
  HOME="$_test_home" sh -c ". '$_funcs' && setup_path '$_install_dir'"
  rm -f "$_funcs"

  # The POSIX env script should be sourced, not env.fish
  assert_file_not_contains "$_test_home/.bashrc" "env.fish" ".bashrc does not source env.fish (no variable clobbering)"
  assert_file_contains "$_test_home/.bashrc" ". \"$_install_dir/env\"" ".bashrc sources the correct POSIX env script"

  cleanup_test_home "$_test_home"
}

test_creates_profile_when_no_rc_files() {
  printf 'TEST: creates .profile when no rc files exist\n'
  _test_home="$(make_test_home)"
  _install_dir="$_test_home/.local/bin"
  mkdir -p "$_install_dir"

  # Don't create any rc files — empty home
  _funcs="$(prepare_install_functions)"
  HOME="$_test_home" sh -c ". '$_funcs' && setup_path '$_install_dir'"
  rm -f "$_funcs"

  if [ -f "$_test_home/.profile" ]; then
    pass ".profile was created"
    assert_file_contains "$_test_home/.profile" ". \"$_install_dir/env\"" ".profile sources POSIX env"
    assert_file_not_contains "$_test_home/.profile" "env.fish" ".profile does not reference env.fish"
  else
    fail ".profile was created" "file does not exist"
  fi

  cleanup_test_home "$_test_home"
}

test_zshrc_sources_posix_env() {
  printf 'TEST: .zshrc sources POSIX env script\n'
  _test_home="$(make_test_home)"
  _install_dir="$_test_home/.local/bin"
  mkdir -p "$_install_dir"

  echo '# existing zshrc' > "$_test_home/.zshrc"

  _funcs="$(prepare_install_functions)"
  HOME="$_test_home" sh -c ". '$_funcs' && setup_path '$_install_dir'"
  rm -f "$_funcs"

  assert_file_contains "$_test_home/.zshrc" ". \"$_install_dir/env\"" ".zshrc sources env"
  assert_file_not_contains "$_test_home/.zshrc" "env.fish" ".zshrc does not reference env.fish"

  cleanup_test_home "$_test_home"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

main() {
  printf '=== install.sh PATH setup tests ===\n\n'

  test_env_script_posix_syntax
  echo ""
  test_env_script_fish_syntax
  echo ""
  test_bashrc_sources_posix_env
  echo ""
  test_profile_sources_posix_env
  echo ""
  test_fish_conf_sources_fish_env
  echo ""
  test_existing_content_preserved
  echo ""
  test_no_duplicate_source_lines
  echo ""
  test_guidance_shows_posix_for_bash
  echo ""
  test_guidance_shows_fish_for_fish
  echo ""
  test_no_variable_clobbering
  echo ""
  test_creates_profile_when_no_rc_files
  echo ""
  test_zshrc_sources_posix_env

  printf '\n=== Results: %d passed, %d failed ===\n' "$PASS" "$FAIL"

  if [ "$FAIL" -gt 0 ]; then
    exit 1
  fi
}

main
