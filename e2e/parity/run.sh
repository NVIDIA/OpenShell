#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Compare the frozen schema-v1 gateway contract with the checkout's schema-v2
# contract. This intentionally begins with one small semantic scenario; later
# parity waves add scenarios without changing the isolated variant runner.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MANIFEST="${OPENSHELL_PARITY_CAPABILITY_MANIFEST:-${ROOT}/e2e/configs/gateway/schema-v2-capability-parity.toml}"
DRIVER=""
BASELINE_WORKTREE="${OPENSHELL_PARITY_BASELINE_WORKTREE:-}"
RESULTS_DIR="${OPENSHELL_PARITY_RESULTS_DIR:-}"
WRAPPER="${OPENSHELL_PARITY_PODMAN_WRAPPER:-${ROOT}/e2e/with-podman-gateway.sh}"
TEMP_WORKTREE=""
RUN_DIR=""

usage() {
  cat >&2 <<EOF
Usage: e2e/parity/run.sh --driver podman [--baseline-worktree PATH] [--results-dir PATH]

The default baseline is the immutable baseline_commit in ${MANIFEST}.
Overrides:
  OPENSHELL_PARITY_BASELINE_{GATEWAY,CLI,CONFORMANCE}_BIN
  OPENSHELL_PARITY_CANDIDATE_{GATEWAY,CLI,CONFORMANCE}_BIN
  OPENSHELL_PARITY_{BASELINE,CANDIDATE}_CARGO_TARGET_DIR
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --driver)
      [ "$#" -ge 2 ] || { echo "ERROR: --driver requires a value." >&2; exit 2; }
      DRIVER=$2
      shift 2
      ;;
    --baseline-worktree)
      [ "$#" -ge 2 ] || { echo "ERROR: --baseline-worktree requires a path." >&2; exit 2; }
      BASELINE_WORKTREE=$2
      shift 2
      ;;
    --results-dir)
      [ "$#" -ge 2 ] || { echo "ERROR: --results-dir requires a path." >&2; exit 2; }
      RESULTS_DIR=$2
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

if [ "${DRIVER}" != "podman" ]; then
  echo "ERROR: only --driver podman is supported by the schema parity harness (got ${DRIVER:-<none>})." >&2
  echo "       Docker, Kubernetes, and VM backends are reserved for later parity waves." >&2
  exit 2
fi

if [ ! -f "${MANIFEST}" ]; then
  echo "ERROR: parity capability manifest not found: ${MANIFEST}" >&2
  exit 2
fi
BASELINE_SHA="$(awk -F '"' '/^[[:space:]]*baseline_commit[[:space:]]*=/ { print $2; exit }' "${MANIFEST}")"
if ! [[ "${BASELINE_SHA}" =~ ^[0-9a-fA-F]{40}$ ]]; then
  echo "ERROR: manifest baseline_commit must be a full 40-character SHA: ${MANIFEST}" >&2
  exit 2
fi
BASELINE_SHA="${BASELINE_SHA,,}"
CANDIDATE_SHA="$(git -C "${ROOT}" rev-parse HEAD)"

cleanup() {
  local status=$?
  if [ -n "${TEMP_WORKTREE}" ]; then
    git -C "${ROOT}" worktree remove --force "${TEMP_WORKTREE}" >/dev/null 2>&1 || true
  fi
  if [ -n "${RUN_DIR}" ]; then
    rm -rf "${RUN_DIR}" || true
  fi
  exit "${status}"
}
trap cleanup EXIT

if [ -n "${BASELINE_WORKTREE}" ]; then
  if [ ! -d "${BASELINE_WORKTREE}" ]; then
    echo "ERROR: baseline worktree does not exist: ${BASELINE_WORKTREE}" >&2
    exit 2
  fi
  resolved_baseline_sha="$(git -C "${BASELINE_WORKTREE}" rev-parse HEAD 2>/dev/null || true)"
  if [ "${resolved_baseline_sha}" != "${BASELINE_SHA}" ]; then
    echo "ERROR: baseline worktree is not frozen manifest commit ${BASELINE_SHA}: ${BASELINE_WORKTREE}" >&2
    exit 2
  fi
else
  if ! git -C "${ROOT}" cat-file -e "${BASELINE_SHA}^{commit}" 2>/dev/null; then
    echo "ERROR: frozen baseline ${BASELINE_SHA} is unavailable locally; fetch it before running parity." >&2
    exit 2
  fi
  TEMP_WORKTREE="$(mktemp -d "${TMPDIR:-/tmp}/openshell-parity-baseline.XXXXXX")"
  # Remove mktemp's directory so git worktree can create and register it.
  rmdir "${TEMP_WORKTREE}"
  git -C "${ROOT}" worktree add --detach "${TEMP_WORKTREE}" "${BASELINE_SHA}" >/dev/null
  BASELINE_WORKTREE="${TEMP_WORKTREE}"
fi

RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/openshell-parity-run.XXXXXX")"
RESULTS_DIR="${RESULTS_DIR:-${ROOT}/target/parity/results}"
mkdir -p "${RESULTS_DIR}"

require_executable() {
  local label=$1
  local binary=$2
  if [ ! -x "${binary}" ]; then
    echo "ERROR: ${label} binary is not executable: ${binary}" >&2
    exit 2
  fi
}

build_variant() {
  local variant=$1 source_root=$2 target_dir=$3 gateway_override=$4 cli_override=$5 conformance_override=$6
  local gateway_var=$7 cli_var=$8 conformance_var=$9
  local gateway cli conformance jobs=()

  if [ -n "${CARGO_BUILD_JOBS:-}" ]; then jobs=(-j "${CARGO_BUILD_JOBS}"); fi
  target_dir="${target_dir:-${ROOT}/target/parity/${variant}}"
  case "${target_dir}" in /*) ;; *) target_dir="${ROOT}/${target_dir}" ;; esac
  gateway="${gateway_override:-${target_dir}/debug/openshell-gateway}"
  cli="${cli_override:-${target_dir}/debug/openshell}"
  conformance="${conformance_override:-${target_dir}/debug/openshell-conformance}"

  if [ -z "${gateway_override}" ]; then
    echo "Building ${variant} gateway in ${target_dir}..."
    (cd "${source_root}" && CARGO_TARGET_DIR="${target_dir}" cargo build "${jobs[@]}" -p openshell-gateway --bin openshell-gateway)
  fi
  if [ -z "${cli_override}" ]; then
    echo "Building ${variant} CLI in ${target_dir}..."
    (cd "${source_root}" && CARGO_TARGET_DIR="${target_dir}" cargo build "${jobs[@]}" -p openshell-cli)
  fi
  if [ -z "${conformance_override}" ]; then
    echo "Building ${variant} conformance CLI in ${target_dir}..."
    (cd "${source_root}" && CARGO_TARGET_DIR="${target_dir}" cargo build "${jobs[@]}" -p openshell-conformance-cli)
  fi
  require_executable "${variant} gateway" "${gateway}"
  require_executable "${variant} CLI" "${cli}"
  require_executable "${variant} conformance" "${conformance}"
  printf -v "${gateway_var}" '%s' "${gateway}"
  printf -v "${cli_var}" '%s' "${cli}"
  printf -v "${conformance_var}" '%s' "${conformance}"
}

BASELINE_GATEWAY="" BASELINE_CLI="" BASELINE_CONFORMANCE=""
CANDIDATE_GATEWAY="" CANDIDATE_CLI="" CANDIDATE_CONFORMANCE=""
build_variant baseline "${BASELINE_WORKTREE}" "${OPENSHELL_PARITY_BASELINE_CARGO_TARGET_DIR:-}" "${OPENSHELL_PARITY_BASELINE_GATEWAY_BIN:-}" "${OPENSHELL_PARITY_BASELINE_CLI_BIN:-}" "${OPENSHELL_PARITY_BASELINE_CONFORMANCE_BIN:-}" BASELINE_GATEWAY BASELINE_CLI BASELINE_CONFORMANCE
build_variant candidate "${ROOT}" "${OPENSHELL_PARITY_CANDIDATE_CARGO_TARGET_DIR:-}" "${OPENSHELL_PARITY_CANDIDATE_GATEWAY_BIN:-}" "${OPENSHELL_PARITY_CANDIDATE_CLI_BIN:-}" "${OPENSHELL_PARITY_CANDIDATE_CONFORMANCE_BIN:-}" CANDIDATE_GATEWAY CANDIDATE_CLI CANDIDATE_CONFORMANCE
require_executable "Podman parity wrapper" "${WRAPPER}"

write_result() {
  local variant=$1 source_sha=$2 schema=$3 status=$4
  cat >"${RESULTS_DIR}/${variant}.json" <<EOF
{"variant":"${variant}","source_sha":"${source_sha}","schema_version":${schema},"driver":"${DRIVER}","command_class":"conformance_smoke","success":${status}}
EOF
}

write_comparison() {
  local baseline_status=$1 candidate_status=$2 parity=false
  if [ "${baseline_status}" = true ] && [ "${candidate_status}" = true ]; then
    parity=true
  fi
  cat >"${RESULTS_DIR}/comparison.json" <<EOF
{"driver":"${DRIVER}","command_class":"conformance_smoke","baseline_success":${baseline_status},"candidate_success":${candidate_status},"parity":${parity}}
EOF
}

run_variant() {
  local variant=$1 source_sha=$2 schema=$3 gateway=$4 cli=$5 conformance=$6 result_status
  local variant_home="${RUN_DIR}/${variant}"
  mkdir -p "${variant_home}/config" "${variant_home}/state" "${variant_home}/cache" "${variant_home}/data"
  echo "==> schema parity ${variant} (schema v${schema}, ${DRIVER})"
  if env \
    OPENSHELL_PARITY_VARIANT="${variant}" \
    OPENSHELL_E2E_CONFIG_SCHEMA_VERSION="${schema}" \
    OPENSHELL_GATEWAY_BIN="${gateway}" \
    OPENSHELL_BIN="${cli}" \
    OPENSHELL_CONFORMANCE_BIN="${conformance}" \
    XDG_CONFIG_HOME="${variant_home}/config" \
    XDG_STATE_HOME="${variant_home}/state" \
    XDG_CACHE_HOME="${variant_home}/cache" \
    XDG_DATA_HOME="${variant_home}/data" \
    "${WRAPPER}" "${conformance}" run --openshell-bin "${cli}" --output json \
    2>&1 | tee "${RESULTS_DIR}/${variant}.log"; then
    result_status=true
  else
    result_status=false
  fi
  write_result "${variant}" "${source_sha}" "${schema}" "${result_status}"
  [ "${result_status}" = true ]
}

baseline_exit=0
candidate_exit=0
run_variant baseline "${BASELINE_SHA}" 1 "${BASELINE_GATEWAY}" "${BASELINE_CLI}" "${BASELINE_CONFORMANCE}" || baseline_exit=$?
# Do not short-circuit: a candidate result is useful even when the frozen
# baseline failed, and two equal failures must never constitute parity.
run_variant candidate "${CANDIDATE_SHA}" 2 "${CANDIDATE_GATEWAY}" "${CANDIDATE_CLI}" "${CANDIDATE_CONFORMANCE}" || candidate_exit=$?

baseline_success=$([ "${baseline_exit}" -eq 0 ] && printf true || printf false)
candidate_success=$([ "${candidate_exit}" -eq 0 ] && printf true || printf false)
write_comparison "${baseline_success}" "${candidate_success}"

if [ "${baseline_exit}" -ne 0 ] || [ "${candidate_exit}" -ne 0 ]; then
  echo "ERROR: schema parity requires both baseline and candidate conformance smoke runs to succeed." >&2
  exit 1
fi
echo "Schema parity passed: baseline schema v1 and candidate schema v2 succeeded."
