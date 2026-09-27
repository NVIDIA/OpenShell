#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Every e2e/rust test target eligible under the `e2e-podman` Cargo feature
# must be accounted for somewhere: selected by the required-CI test set in
# e2e/rust/e2e-podman.sh, or explicitly ignored as a perf benchmark below. A
# target that is eligible but appears in neither list is a silent CI coverage
# gap (see https://github.com/NVIDIA/OpenShell/issues/3712) and fails this
# check.

set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
E2E_MANIFEST="${ROOT}/e2e/rust/Cargo.toml"
PODMAN_SCRIPT="${ROOT}/e2e/rust/e2e-podman.sh"

# Features enabled when building with --features e2e-podman (the feature
# itself plus everything it implies; see e2e/rust/Cargo.toml's [features]).
ENABLED_FEATURES=(e2e-podman e2e e2e-host-gateway e2e-local-container-driver)

# Perf benchmarks are intentionally excluded from required CI and run
# manually. Every test function in these binaries must be #[ignore]d so a
# newly added, non-ignored test can't silently ride along unexamined.
PERF_BENCHMARK_TARGETS=(internet_network_perf live_internet_traffic_perf)

# Targets wired into required CI through a mechanism other than
# PODMAN_CI_TESTS, with where and why noted so this doesn't just become a
# second silent-omission list.
#
# - podman_preflight: needs only the standalone openshell-driver-podman
#   binary, not a gateway, so it runs as a chained step in the
#   podman-external-driver-e2e job (branch-e2e.yml) via the
#   e2e:podman:preflight mise task instead of through the gateway-backed
#   PODMAN_CI_TESTS array.
SEPARATELY_WIRED_TARGETS=(podman_preflight)

# Pre-existing gaps this check finds on introduction, tracked collectively by
# https://github.com/NVIDIA/OpenShell/issues/3712 pending the follow-up work
# that either wires each one into CI or gives it its own permanent, justified
# exclusion. Remove an entry here only when it is actually accounted for
# above (selected, ignored, or separately wired) -- do not grow this list for
# new gaps; new eligible targets must be handled properly from the start.
KNOWN_GAP_TARGETS=(
  # Superseded by the rootful/rootless driver-podman tmachine suite; slated
  # for removal once that migration lands (tracked in #3712).
  podman_userns
  # Deliberately distinct-scope exclusions needing their own follow-up work,
  # per #3712's triage: SPIFFE fixture plumbing, a purpose-built long-running
  # rotation suite, and a multi-case conformance migration respectively.
  podman_oci_identity
  provider_refresh_handles
  sandbox_lifecycle
  # Already tracked separately in #3009 (needs a prebuilt musl DNS probe in
  # guest artifact mode); not duplicated here.
  transparent_tcp
  # Plausible quick fixes once triaged against a live Podman run; not yet
  # investigated.
  podman_resource_limits
  port_forward
  provider_auto_create
  proxy_egress_pipeline
  sandbox_labels
  sandbox_templates
  settings_management
  sync
  upload_create
  websocket_conformance
  workspace_lifecycle
)

is_enabled_feature() {
  local feature="$1"
  local candidate
  for candidate in "${ENABLED_FEATURES[@]}"; do
    [[ "${candidate}" == "${feature}" ]] && return 0
  done
  return 1
}

is_in_array() {
  local needle="$1"
  shift
  local candidate
  for candidate in "$@"; do
    [[ "${candidate}" == "${needle}" ]] && return 0
  done
  return 1
}

# Read the PODMAN_CI_TESTS bash array literal out of e2e-podman.sh without
# sourcing the whole script (which also runs the gateway harness).
read_podman_ci_tests() {
  sed -n '/^PODMAN_CI_TESTS=(/,/^)/p' "${PODMAN_SCRIPT}" \
    | sed '1d;$d' \
    | tr -d ' \t'
}

# Eligibility under e2e-podman for one cargo-metadata test target: explicit
# required-features must all be enabled-by-e2e-podman features; targets with
# no manifest-level required-features (auto-discovered files) fall back to
# the file's own #![cfg(feature = "...")] gate, or are eligible unconditionally
# if the file has no such gate at all.
target_is_eligible() {
  local name="$1"
  local src_path="$2"
  shift 2
  local required_features=("$@")

  if [[ "${#required_features[@]}" -gt 0 ]]; then
    local feature
    for feature in "${required_features[@]}"; do
      is_enabled_feature "${feature}" || return 1
    done
    return 0
  fi

  local cfg_feature
  cfg_feature="$(head -n 20 "${src_path}" \
    | grep -m1 -oP '^#!\[cfg\(feature\s*=\s*"\K[^"]+' || true)"
  if [[ -z "${cfg_feature}" ]]; then
    return 0
  fi
  is_enabled_feature "${cfg_feature}"
}

verify_perf_benchmarks_are_ignored() {
  # cargo test -- --list does not distinguish #[ignore]d tests from runnable
  # ones in its plain output, so check the source directly: every #[test]/
  # #[tokio::test] attribute must be immediately followed by #[ignore...].
  local target
  local src_path
  local failed=0
  for target in "${PERF_BENCHMARK_TARGETS[@]}"; do
    src_path="${ROOT}/e2e/rust/tests/${target}.rs"
    local non_ignored
    non_ignored="$(awk '
      /^[[:space:]]*#\[(tokio::)?test\][[:space:]]*$/ { pending = 1; next }
      pending && /^[[:space:]]*#\[ignore/ { pending = 0; next }
      pending { print; pending = 0 }
    ' "${src_path}" | grep -c . || true)"
    if [[ "${non_ignored}" -ne 0 ]]; then
      printf 'error: perf benchmark target "%s" (%s) has %s non-#[ignore]d test(s); a new test there would silently skip required-CI accounting\n' \
        "${target}" "${src_path#"${ROOT}"/}" "${non_ignored}" >&2
      failed=1
    fi
  done
  return "${failed}"
}

main() {
  cd "${ROOT}"

  local -a ci_tests
  mapfile -t ci_tests < <(read_podman_ci_tests)

  local -a unaccounted=()
  local -a stale_known_gaps=()
  local -a seen_eligible=()
  local accounted_count=0

  while IFS=$'\t' read -r name src_path required_features_csv; do
    local -a required_features=()
    if [[ -n "${required_features_csv}" ]]; then
      IFS=',' read -r -a required_features <<<"${required_features_csv}"
    fi

    if ! target_is_eligible "${name}" "${src_path}" "${required_features[@]}"; then
      continue
    fi
    seen_eligible+=("${name}")

    if is_in_array "${name}" "${ci_tests[@]}" \
      || is_in_array "${name}" "${PERF_BENCHMARK_TARGETS[@]}" \
      || is_in_array "${name}" "${SEPARATELY_WIRED_TARGETS[@]}"; then
      accounted_count=$((accounted_count + 1))
      is_in_array "${name}" "${KNOWN_GAP_TARGETS[@]}" && stale_known_gaps+=("${name}")
    elif is_in_array "${name}" "${KNOWN_GAP_TARGETS[@]}"; then
      accounted_count=$((accounted_count + 1))
    else
      unaccounted+=("${name}")
    fi
  done < <(cargo metadata --manifest-path "${E2E_MANIFEST}" --no-deps --format-version 1 \
    | jq -r '
        .packages[].targets[]
        | select(.kind == ["test"])
        | [.name, .src_path, (."required-features" // [] | join(","))]
        | @tsv
      ')

  local gap
  for gap in "${KNOWN_GAP_TARGETS[@]}"; do
    is_in_array "${gap}" "${seen_eligible[@]}" || stale_known_gaps+=("${gap}")
  done

  local eligible_count=$((accounted_count + ${#unaccounted[@]}))

  if [[ "${#unaccounted[@]}" -gt 0 ]]; then
    printf 'error: %d e2e-podman-eligible test target(s) are not accounted for in required Podman CI:\n' \
      "${#unaccounted[@]}" >&2
    local name
    for name in "${unaccounted[@]}"; do
      printf '  - %s\n' "${name}" >&2
    done
    printf 'Add each to PODMAN_CI_TESTS in %s, or mark it an ignored perf benchmark with a rationale.\n' \
      "${PODMAN_SCRIPT#"${ROOT}"/}" >&2
    return 1
  fi

  if [[ "${#stale_known_gaps[@]}" -gt 0 ]]; then
    printf 'error: %d entries in KNOWN_GAP_TARGETS no longer belong there (already accounted for elsewhere, or no longer an eligible target) -- remove them:\n' \
      "${#stale_known_gaps[@]}" >&2
    local name
    for name in "${stale_known_gaps[@]}"; do
      printf '  - %s\n' "${name}" >&2
    done
    return 1
  fi

  if ! verify_perf_benchmarks_are_ignored; then
    return 1
  fi

  printf 'Podman e2e coverage: %d eligible target(s), %d accounted for (%d selected, %d perf-ignored, %d separately wired)\n' \
    "${eligible_count}" "${accounted_count}" "${#ci_tests[@]}" "${#PERF_BENCHMARK_TARGETS[@]}" "${#SEPARATELY_WIRED_TARGETS[@]}"
}

main "$@"
