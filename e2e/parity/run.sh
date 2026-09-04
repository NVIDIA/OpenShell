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
SCENARIO="smoke"
COMMAND_CLASS="conformance_smoke"
BASELINE_WORKTREE="${OPENSHELL_PARITY_BASELINE_WORKTREE:-}"
CANDIDATE_WORKTREE="${OPENSHELL_PARITY_CANDIDATE_WORKTREE:-${ROOT}}"
RESULTS_DIR="${OPENSHELL_PARITY_RESULTS_DIR:-}"
WRAPPER="${OPENSHELL_PARITY_PODMAN_WRAPPER:-${ROOT}/e2e/with-podman-gateway.sh}"
PODMAN_OPTIONS_ORACLE="${OPENSHELL_PARITY_PODMAN_OPTIONS_ORACLE:-${ROOT}/e2e/parity/podman-options.sh}"
PODMAN_BIN="${OPENSHELL_PARITY_PODMAN_BIN:-podman}"
TEMP_WORKTREE=""
RUN_DIR=""

usage() {
  cat >&2 <<EOF
Usage: e2e/parity/run.sh --driver podman [--scenario smoke|external-driver|podman-options] [--baseline-worktree PATH] [--results-dir PATH]

The default baseline is the immutable baseline_commit in ${MANIFEST}.
Overrides:
  OPENSHELL_PARITY_BASELINE_{GATEWAY,CLI,CONFORMANCE}_BIN
  OPENSHELL_PARITY_CANDIDATE_{GATEWAY,CLI,CONFORMANCE}_BIN
  OPENSHELL_PARITY_{BASELINE,CANDIDATE}_EXTERNAL_DRIVER_BIN
  OPENSHELL_PARITY_{BASELINE,CANDIDATE}_SUPERVISOR_BIN
  OPENSHELL_PARITY_{BASELINE,CANDIDATE}_CARGO_TARGET_DIR
  OPENSHELL_PARITY_CANDIDATE_WORKTREE (clean checkout at the current HEAD)
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --driver)
      [ "$#" -ge 2 ] || { echo "ERROR: --driver requires a value." >&2; exit 2; }
      DRIVER=$2
      shift 2
      ;;
    --scenario)
      [ "$#" -ge 2 ] || { echo "ERROR: --scenario requires a value." >&2; exit 2; }
      SCENARIO=$2
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

case "${SCENARIO}" in
  smoke) COMMAND_CLASS="conformance_smoke" ;;
  external-driver) COMMAND_CLASS="external_driver_conformance_smoke" ;;
  podman-options) COMMAND_CLASS="podman_options" ;;
  *) echo "ERROR: unsupported parity scenario: ${SCENARIO}." >&2; exit 2 ;;
esac

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
EXPECTED_CANDIDATE_SHA="$(git -C "${ROOT}" rev-parse HEAD)"
if [ ! -d "${CANDIDATE_WORKTREE}" ]; then
  echo "ERROR: candidate worktree does not exist: ${CANDIDATE_WORKTREE}" >&2
  exit 2
fi
CANDIDATE_SHA="$(git -C "${CANDIDATE_WORKTREE}" rev-parse HEAD 2>/dev/null || true)"
if [ "${CANDIDATE_SHA}" != "${EXPECTED_CANDIDATE_SHA}" ]; then
  echo "ERROR: candidate worktree must be at current commit ${EXPECTED_CANDIDATE_SHA}: ${CANDIDATE_WORKTREE}" >&2
  exit 2
fi

cleanup() {
  local status=$?
  if [ -n "${TEMP_WORKTREE}" ]; then
    git -C "${ROOT}" worktree remove --force "${TEMP_WORKTREE}" >/dev/null 2>&1 || true
  fi
  if [ -n "${RUN_DIR}" ]; then
    # Rootless Podman overlay files can be owned by subordinate UIDs. Remove an
    # isolated container store from Podman's user namespace before falling back
    # to ordinary cleanup for runs that never reached the container runtime.
    if { [ -d "${RUN_DIR}/baseline/data/containers/storage" ] \
      || [ -d "${RUN_DIR}/candidate/data/containers/storage" ]; } \
      && command -v "${PODMAN_BIN}" >/dev/null 2>&1; then
      "${PODMAN_BIN}" unshare rm -rf -- "${RUN_DIR}" >/dev/null 2>&1 || true
    fi
    rm -rf "${RUN_DIR}" >/dev/null 2>&1 || true
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

require_clean_source() {
  local variant=$1 source_root=$2 dirty
  dirty="$(git -C "${source_root}" status --porcelain=v1 --untracked-files=all)"
  if [ -n "${dirty}" ]; then
    echo "ERROR: ${variant} source worktree must be clean before building parity artifacts: ${source_root}" >&2
    printf '%s\n' "${dirty}" >&2
    exit 2
  fi
}

RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/openshell-parity-run.XXXXXX")"
RESULTS_DIR="${RESULTS_DIR:-${ROOT}/target/parity/results}"
mkdir -p "${RESULTS_DIR}"
RESULTS_DIR="$(cd "${RESULTS_DIR}" && pwd)"

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
  local gateway cli conformance jobs=() gateway_features=()

  if [ -n "${CARGO_BUILD_JOBS:-}" ]; then jobs=(-j "${CARGO_BUILD_JOBS}"); fi
  if [ "${SCENARIO}" = external-driver ]; then
    gateway_features=(--no-default-features --features telemetry)
  fi
  target_dir="${target_dir:-${ROOT}/target/parity/${variant}}"
  case "${target_dir}" in /*) ;; *) target_dir="${ROOT}/${target_dir}" ;; esac
  gateway="${gateway_override:-${target_dir}/debug/openshell-gateway}"
  cli="${cli_override:-${target_dir}/debug/openshell}"
  conformance="${conformance_override:-${target_dir}/debug/openshell-conformance}"

  if [ -z "${gateway_override}" ]; then
    require_clean_source "${variant}" "${source_root}"
    echo "Building ${variant} gateway in ${target_dir}..."
    (cd "${source_root}" && CARGO_TARGET_DIR="${target_dir}" cargo build "${jobs[@]}" -p openshell-gateway --bin openshell-gateway "${gateway_features[@]}")
  fi
  if [ -z "${cli_override}" ]; then
    require_clean_source "${variant}" "${source_root}"
    echo "Building ${variant} CLI in ${target_dir}..."
    (cd "${source_root}" && CARGO_TARGET_DIR="${target_dir}" cargo build "${jobs[@]}" -p openshell-cli)
  fi
  if [ -z "${conformance_override}" ]; then
    require_clean_source "${variant}" "${source_root}"
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
build_variant candidate "${CANDIDATE_WORKTREE}" "${OPENSHELL_PARITY_CANDIDATE_CARGO_TARGET_DIR:-}" "${OPENSHELL_PARITY_CANDIDATE_GATEWAY_BIN:-}" "${OPENSHELL_PARITY_CANDIDATE_CLI_BIN:-}" "${OPENSHELL_PARITY_CANDIDATE_CONFORMANCE_BIN:-}" CANDIDATE_GATEWAY CANDIDATE_CLI CANDIDATE_CONFORMANCE

BASELINE_GATEWAY_ORIGIN=built_by_harness
BASELINE_CLI_ORIGIN=built_by_harness
BASELINE_CONFORMANCE_ORIGIN=built_by_harness
CANDIDATE_GATEWAY_ORIGIN=built_by_harness
CANDIDATE_CLI_ORIGIN=built_by_harness
CANDIDATE_CONFORMANCE_ORIGIN=built_by_harness
[ -z "${OPENSHELL_PARITY_BASELINE_GATEWAY_BIN:-}" ] || BASELINE_GATEWAY_ORIGIN=supplied_override
[ -z "${OPENSHELL_PARITY_BASELINE_CLI_BIN:-}" ] || BASELINE_CLI_ORIGIN=supplied_override
[ -z "${OPENSHELL_PARITY_BASELINE_CONFORMANCE_BIN:-}" ] || BASELINE_CONFORMANCE_ORIGIN=supplied_override
[ -z "${OPENSHELL_PARITY_CANDIDATE_GATEWAY_BIN:-}" ] || CANDIDATE_GATEWAY_ORIGIN=supplied_override
[ -z "${OPENSHELL_PARITY_CANDIDATE_CLI_BIN:-}" ] || CANDIDATE_CLI_ORIGIN=supplied_override
[ -z "${OPENSHELL_PARITY_CANDIDATE_CONFORMANCE_BIN:-}" ] || CANDIDATE_CONFORMANCE_ORIGIN=supplied_override

build_external_driver() {
  local variant=$1 source_root=$2 target_dir=$3 override=$4 output_var=$5
  local binary
  if [ "${SCENARIO}" != external-driver ]; then
    printf -v "${output_var}" '%s' ""
    return
  fi
  target_dir="${target_dir:-${ROOT}/target/parity/${variant}}"
  case "${target_dir}" in /*) ;; *) target_dir="${ROOT}/${target_dir}" ;; esac
  binary="${override:-${target_dir}/debug/openshell-driver-podman}"
  if [ -z "${override}" ]; then
    require_clean_source "${variant}" "${source_root}"
    echo "Building ${variant} external Podman driver in ${target_dir}..."
    (cd "${source_root}" && CARGO_TARGET_DIR="${target_dir}" cargo build -p openshell-driver-podman --bin openshell-driver-podman)
  fi
  require_executable "${variant} external Podman driver" "${binary}"
  printf -v "${output_var}" '%s' "${binary}"
}

BASELINE_EXTERNAL_DRIVER="" CANDIDATE_EXTERNAL_DRIVER=""
BASELINE_EXTERNAL_DRIVER_ORIGIN=not_applicable
CANDIDATE_EXTERNAL_DRIVER_ORIGIN=not_applicable
if [ "${SCENARIO}" = external-driver ]; then
  BASELINE_EXTERNAL_DRIVER_ORIGIN=built_by_harness
  CANDIDATE_EXTERNAL_DRIVER_ORIGIN=built_by_harness
  [ -z "${OPENSHELL_PARITY_BASELINE_EXTERNAL_DRIVER_BIN:-}" ] || BASELINE_EXTERNAL_DRIVER_ORIGIN=supplied_override
  [ -z "${OPENSHELL_PARITY_CANDIDATE_EXTERNAL_DRIVER_BIN:-}" ] || CANDIDATE_EXTERNAL_DRIVER_ORIGIN=supplied_override
fi
build_external_driver baseline "${BASELINE_WORKTREE}" "${OPENSHELL_PARITY_BASELINE_CARGO_TARGET_DIR:-}" "${OPENSHELL_PARITY_BASELINE_EXTERNAL_DRIVER_BIN:-}" BASELINE_EXTERNAL_DRIVER
build_external_driver candidate "${CANDIDATE_WORKTREE}" "${OPENSHELL_PARITY_CANDIDATE_CARGO_TARGET_DIR:-}" "${OPENSHELL_PARITY_CANDIDATE_EXTERNAL_DRIVER_BIN:-}" CANDIDATE_EXTERNAL_DRIVER
if [ "${SCENARIO}" = external-driver ]; then
  baseline_external_realpath="$(realpath "${BASELINE_EXTERNAL_DRIVER}")"
  candidate_external_realpath="$(realpath "${CANDIDATE_EXTERNAL_DRIVER}")"
  if [ "${baseline_external_realpath}" = "${candidate_external_realpath}" ] \
    || [ "${BASELINE_EXTERNAL_DRIVER}" -ef "${CANDIDATE_EXTERNAL_DRIVER}" ]; then
    echo "ERROR: external-driver parity requires distinct baseline and candidate driver artifacts." >&2
    exit 2
  fi
fi

supervisor_target_triple() {
  case "$(uname -sm)" in
    "Linux x86_64") printf '%s\n' x86_64-unknown-linux-musl ;;
    "Linux aarch64"|"Linux arm64") printf '%s\n' aarch64-unknown-linux-musl ;;
    *) echo "ERROR: Podman parity supervisor builds require Linux x86_64 or arm64." >&2; return 2 ;;
  esac
}

build_supervisor() {
  local variant=$1 source_root=$2 target_dir=$3 override=$4 output_var=$5
  local binary target jobs=()
  target="$(supervisor_target_triple)"
  target_dir="${target_dir:-${ROOT}/target/parity/${variant}}"
  case "${target_dir}" in /*) ;; *) target_dir="${ROOT}/${target_dir}" ;; esac
  binary="${override:-${target_dir}/${target}/release/openshell-sandbox}"
  if [ -z "${override}" ]; then
    require_clean_source "${variant}" "${source_root}"
    if [ -n "${CARGO_BUILD_JOBS:-}" ]; then jobs=(-j "${CARGO_BUILD_JOBS}"); fi
    echo "Building ${variant} supervisor in ${target_dir}..."
    (cd "${source_root}" && CARGO_TARGET_DIR="${target_dir}" cargo build "${jobs[@]}" --release --target "${target}" -p openshell-sandbox --bin openshell-sandbox)
    "${source_root}/tasks/scripts/verify-static-binary.sh" "${binary}"
  fi
  require_executable "${variant} supervisor" "${binary}"
  printf -v "${output_var}" '%s' "${binary}"
}

BASELINE_SUPERVISOR="" CANDIDATE_SUPERVISOR=""
BASELINE_SUPERVISOR_ORIGIN=built_by_harness
CANDIDATE_SUPERVISOR_ORIGIN=built_by_harness
[ -z "${OPENSHELL_PARITY_BASELINE_SUPERVISOR_BIN:-}" ] || BASELINE_SUPERVISOR_ORIGIN=supplied_override
[ -z "${OPENSHELL_PARITY_CANDIDATE_SUPERVISOR_BIN:-}" ] || CANDIDATE_SUPERVISOR_ORIGIN=supplied_override
build_supervisor baseline "${BASELINE_WORKTREE}" "${OPENSHELL_PARITY_BASELINE_CARGO_TARGET_DIR:-}" "${OPENSHELL_PARITY_BASELINE_SUPERVISOR_BIN:-}" BASELINE_SUPERVISOR
build_supervisor candidate "${CANDIDATE_WORKTREE}" "${OPENSHELL_PARITY_CANDIDATE_CARGO_TARGET_DIR:-}" "${OPENSHELL_PARITY_CANDIDATE_SUPERVISOR_BIN:-}" CANDIDATE_SUPERVISOR

stage_artifact() {
  local variant=$1 role=$2 source=$3 mode=$4 path_var=$5 digest_var=$6
  local destination="${RESULTS_DIR}/artifacts/${variant}/${role}"
  mkdir -p "$(dirname "${destination}")"
  install -m "${mode}" "${source}" "${destination}"
  printf -v "${path_var}" '%s' "${destination}"
  printf -v "${digest_var}" '%s' "$(sha256sum "${destination}" | cut -d' ' -f1)"
}

stage_executable() {
  stage_artifact "$1" "$2" "$3" 0555 "$4" "$5"
}

BASELINE_GATEWAY_DIGEST="" BASELINE_CLI_DIGEST="" BASELINE_CONFORMANCE_DIGEST="" BASELINE_EXTERNAL_DRIVER_DIGEST="" BASELINE_SUPERVISOR_DIGEST="" BASELINE_SUPERVISOR_DOCKERFILE="" BASELINE_SUPERVISOR_DOCKERFILE_DIGEST=""
CANDIDATE_GATEWAY_DIGEST="" CANDIDATE_CLI_DIGEST="" CANDIDATE_CONFORMANCE_DIGEST="" CANDIDATE_EXTERNAL_DRIVER_DIGEST="" CANDIDATE_SUPERVISOR_DIGEST="" CANDIDATE_SUPERVISOR_DOCKERFILE="" CANDIDATE_SUPERVISOR_DOCKERFILE_DIGEST=""
stage_executable baseline gateway "${BASELINE_GATEWAY}" BASELINE_GATEWAY BASELINE_GATEWAY_DIGEST
stage_executable baseline cli "${BASELINE_CLI}" BASELINE_CLI BASELINE_CLI_DIGEST
stage_executable baseline conformance "${BASELINE_CONFORMANCE}" BASELINE_CONFORMANCE BASELINE_CONFORMANCE_DIGEST
stage_executable baseline supervisor "${BASELINE_SUPERVISOR}" BASELINE_SUPERVISOR BASELINE_SUPERVISOR_DIGEST
stage_artifact baseline supervisor.Dockerfile "${BASELINE_WORKTREE}/deploy/docker/Dockerfile.supervisor" 0444 BASELINE_SUPERVISOR_DOCKERFILE BASELINE_SUPERVISOR_DOCKERFILE_DIGEST
stage_executable candidate gateway "${CANDIDATE_GATEWAY}" CANDIDATE_GATEWAY CANDIDATE_GATEWAY_DIGEST
stage_executable candidate cli "${CANDIDATE_CLI}" CANDIDATE_CLI CANDIDATE_CLI_DIGEST
stage_executable candidate conformance "${CANDIDATE_CONFORMANCE}" CANDIDATE_CONFORMANCE CANDIDATE_CONFORMANCE_DIGEST
stage_executable candidate supervisor "${CANDIDATE_SUPERVISOR}" CANDIDATE_SUPERVISOR CANDIDATE_SUPERVISOR_DIGEST
stage_artifact candidate supervisor.Dockerfile "${CANDIDATE_WORKTREE}/deploy/docker/Dockerfile.supervisor" 0444 CANDIDATE_SUPERVISOR_DOCKERFILE CANDIDATE_SUPERVISOR_DOCKERFILE_DIGEST
if [ "${SCENARIO}" = external-driver ]; then
  stage_executable baseline external-driver "${BASELINE_EXTERNAL_DRIVER}" BASELINE_EXTERNAL_DRIVER BASELINE_EXTERNAL_DRIVER_DIGEST
  stage_executable candidate external-driver "${CANDIDATE_EXTERNAL_DRIVER}" CANDIDATE_EXTERNAL_DRIVER CANDIDATE_EXTERNAL_DRIVER_DIGEST
fi

require_executable "Podman parity wrapper" "${WRAPPER}"
if [ "${SCENARIO}" = "podman-options" ] && [ ! -f "${PODMAN_OPTIONS_ORACLE}" ]; then
  echo "ERROR: Podman options oracle does not exist: ${PODMAN_OPTIONS_ORACLE}" >&2
  exit 2
fi

write_result() {
  local variant=$1 source_sha=$2 schema=$3 status=$4
  local gateway_digest=$5 cli_digest=$6 conformance_digest=$7 external_driver_digest_value=$8 supervisor_digest=$9 supervisor_dockerfile_digest=${10}
  local normalized_result="" external_driver_digest="" gateway_profile="in-tree"
  local gateway_features=default
  local gateway_origin cli_origin conformance_origin external_driver_origin supervisor_origin
  if [ "${variant}" = baseline ]; then
    gateway_origin=${BASELINE_GATEWAY_ORIGIN}
    cli_origin=${BASELINE_CLI_ORIGIN}
    conformance_origin=${BASELINE_CONFORMANCE_ORIGIN}
    external_driver_origin=${BASELINE_EXTERNAL_DRIVER_ORIGIN}
    supervisor_origin=${BASELINE_SUPERVISOR_ORIGIN}
  else
    gateway_origin=${CANDIDATE_GATEWAY_ORIGIN}
    cli_origin=${CANDIDATE_CLI_ORIGIN}
    conformance_origin=${CANDIDATE_CONFORMANCE_ORIGIN}
    external_driver_origin=${CANDIDATE_EXTERNAL_DRIVER_ORIGIN}
    supervisor_origin=${CANDIDATE_SUPERVISOR_ORIGIN}
  fi
  if [ -n "${external_driver_digest_value}" ]; then
    external_driver_digest=",\"external_driver_sha256\":\"${external_driver_digest_value}\""
    gateway_profile="driver-free"
    gateway_features="--no-default-features --features telemetry"
  fi
  if [ "${SCENARIO}" = "podman-options" ]; then normalized_result=",\"normalized_result\":\"${variant}.normalized.json\""; fi
  cat >"${RESULTS_DIR}/${variant}.json" <<EOF
{"variant":"${variant}","source_sha":"${source_sha}","schema_version":${schema},"driver":"${DRIVER}","scenario":"${SCENARIO}","command_class":"${COMMAND_CLASS}","gateway_profile":"${gateway_profile}","gateway_cargo_features":"${gateway_features}","gateway_origin":"${gateway_origin}","cli_origin":"${cli_origin}","conformance_origin":"${conformance_origin}","external_driver_origin":"${external_driver_origin}","supervisor_origin":"${supervisor_origin}","gateway_sha256":"${gateway_digest}","cli_sha256":"${cli_digest}","conformance_sha256":"${conformance_digest}","supervisor_sha256":"${supervisor_digest}","supervisor_dockerfile_sha256":"${supervisor_dockerfile_digest}"${normalized_result}${external_driver_digest},"success":${status}}
EOF
}

COMPARISON_ACCEPTED=false
COMPARISON_CLASSIFICATION="regression"
write_comparison() {
  local baseline_status=$1 candidate_status=$2 parity=false intentional_change_id=null
  COMPARISON_ACCEPTED=false
  COMPARISON_CLASSIFICATION="regression"

  if [ "${baseline_status}" = true ] && [ "${candidate_status}" = true ]; then
    if [ "${SCENARIO}" != "podman-options" ]; then
      parity=true
      COMPARISON_ACCEPTED=true
      COMPARISON_CLASSIFICATION="pass"
    elif [ ! -s "${RESULTS_DIR}/baseline.normalized.json" ] \
      || [ ! -s "${RESULTS_DIR}/candidate.normalized.json" ]; then
      COMPARISON_CLASSIFICATION="regression"
    elif cmp -s "${RESULTS_DIR}/baseline.normalized.json" "${RESULTS_DIR}/candidate.normalized.json"; then
      parity=true
      COMPARISON_ACCEPTED=true
      COMPARISON_CLASSIFICATION="pass"
    else
      sed -E 's/"pids_limit":[0-9]+/"pids_limit":IGNORED/' "${RESULTS_DIR}/baseline.normalized.json" >"${RUN_DIR}/baseline.semantic"
      sed -E 's/"pids_limit":[0-9]+/"pids_limit":IGNORED/' "${RESULTS_DIR}/candidate.normalized.json" >"${RUN_DIR}/candidate.semantic"
      if grep -F '"pids_limit":2048' "${RESULTS_DIR}/baseline.normalized.json" >/dev/null \
        && grep -F '"pids_limit":31' "${RESULTS_DIR}/candidate.normalized.json" >/dev/null \
        && cmp -s "${RUN_DIR}/baseline.semantic" "${RUN_DIR}/candidate.semantic"; then
        COMPARISON_ACCEPTED=true
        COMPARISON_CLASSIFICATION="intentional_change"
        intentional_change_id='"podman-pid-limit-restored"'
      fi
    fi
  fi
  cat >"${RESULTS_DIR}/comparison.json" <<EOF
{"driver":"${DRIVER}","scenario":"${SCENARIO}","command_class":"${COMMAND_CLASS}","baseline_success":${baseline_status},"candidate_success":${candidate_status},"parity":${parity},"classification":"${COMPARISON_CLASSIFICATION}","intentional_change_id":${intentional_change_id},"accepted":${COMPARISON_ACCEPTED}}
EOF
}

verify_artifact_digest() {
  local label=$1 path=$2 expected=$3 actual
  actual="$(sha256sum "${path}" | cut -d' ' -f1)"
  if [ "${actual}" != "${expected}" ]; then
    echo "ERROR: ${label} changed after it was staged for execution." >&2
    return 1
  fi
}

run_variant() {
  local variant=$1 source_sha=$2 schema=$3 gateway=$4 cli=$5 conformance=$6 external_driver=$7 supervisor=$8 supervisor_dockerfile=$9
  local gateway_digest=${10} cli_digest=${11} conformance_digest=${12} external_driver_digest=${13} supervisor_digest=${14} supervisor_dockerfile_digest=${15}
  local result_status variant_home="${RUN_DIR}/${variant}"
  local supervisor_image="openshell/supervisor:parity-${variant}-${source_sha:0:12}"
  mkdir -p "${variant_home}/config" "${variant_home}/state" "${variant_home}/cache" "${variant_home}/data"
  echo "==> schema parity ${variant} (schema v${schema}, ${DRIVER}, ${SCENARIO})"
  local option_profile=""
  local -a command
  if [ "${SCENARIO}" = "podman-options" ]; then
    option_profile="podman-options"
    command=(bash "${PODMAN_OPTIONS_ORACLE}")
  else
    command=("${conformance}" run --openshell-bin "${cli}" --output json)
  fi
  if env -u OPENSHELL_GATEWAY_ENDPOINT -u OPENSHELL_GATEWAY_CONFIG \
    -u OPENSHELL_COMPUTE_DRIVER -u OPENSHELL_COMPUTE_DRIVER_SOCKET -u OPENSHELL_DRIVERS \
    OPENSHELL_PARITY_VARIANT="${variant}" \
    OPENSHELL_E2E_CONFIG_SCHEMA_VERSION="${schema}" \
    OPENSHELL_E2E_EXTERNAL_COMPUTE_DRIVER="$([ "${SCENARIO}" = external-driver ] && printf 1 || printf 0)" \
    OPENSHELL_EXTERNAL_DRIVER_BIN="${external_driver}" \
    OPENSHELL_E2E_SUPERVISOR_BIN="${supervisor}" \
    OPENSHELL_E2E_SUPERVISOR_DOCKERFILE="${supervisor_dockerfile}" \
    OPENSHELL_SUPERVISOR_IMAGE="${supervisor_image}" \
    OPENSHELL_E2E_PODMAN_OPTION_PROFILE="${option_profile}" \
    OPENSHELL_PARITY_ORACLE_RESULT="${RESULTS_DIR}/${variant}.normalized.json" \
    OPENSHELL_PARITY_GATEWAY_CONFIG_CAPTURE="${RESULTS_DIR}/${variant}.gateway.toml" \
    OPENSHELL_PARITY_LAUNCH_MANIFEST_CAPTURE="${RESULTS_DIR}/${variant}.launch.json" \
    OPENSHELL_GATEWAY_BIN="${gateway}" \
    OPENSHELL_BIN="${cli}" \
    OPENSHELL_CONFORMANCE_BIN="${conformance}" \
    MISE_TRUSTED_CONFIG_PATHS="${MISE_TRUSTED_CONFIG_PATHS:-${ROOT}}" \
    XDG_CONFIG_HOME="${variant_home}/config" \
    XDG_STATE_HOME="${variant_home}/state" \
    XDG_CACHE_HOME="${variant_home}/cache" \
    XDG_DATA_HOME="${variant_home}/data" \
    "${WRAPPER}" "${command[@]}" \
    2>&1 | tee "${RESULTS_DIR}/${variant}.log"; then
    result_status=true
  else
    result_status=false
  fi
  if [ ! -s "${RESULTS_DIR}/${variant}.launch.json" ]; then
    echo "ERROR: ${variant} launcher did not emit a launch manifest." >&2
    result_status=false
  fi
  verify_artifact_digest "${variant} gateway" "${gateway}" "${gateway_digest}" || result_status=false
  verify_artifact_digest "${variant} CLI" "${cli}" "${cli_digest}" || result_status=false
  verify_artifact_digest "${variant} conformance CLI" "${conformance}" "${conformance_digest}" || result_status=false
  verify_artifact_digest "${variant} supervisor" "${supervisor}" "${supervisor_digest}" || result_status=false
  verify_artifact_digest "${variant} supervisor Dockerfile" "${supervisor_dockerfile}" "${supervisor_dockerfile_digest}" || result_status=false
  if [ -n "${external_driver}" ]; then
    verify_artifact_digest "${variant} external driver" "${external_driver}" "${external_driver_digest}" || result_status=false
  fi
  write_result "${variant}" "${source_sha}" "${schema}" "${result_status}" "${gateway_digest}" "${cli_digest}" "${conformance_digest}" "${external_driver_digest}" "${supervisor_digest}" "${supervisor_dockerfile_digest}"
  [ "${result_status}" = true ]
}

baseline_exit=0
candidate_exit=0
run_variant baseline "${BASELINE_SHA}" 1 "${BASELINE_GATEWAY}" "${BASELINE_CLI}" "${BASELINE_CONFORMANCE}" "${BASELINE_EXTERNAL_DRIVER}" "${BASELINE_SUPERVISOR}" "${BASELINE_SUPERVISOR_DOCKERFILE}" "${BASELINE_GATEWAY_DIGEST}" "${BASELINE_CLI_DIGEST}" "${BASELINE_CONFORMANCE_DIGEST}" "${BASELINE_EXTERNAL_DRIVER_DIGEST}" "${BASELINE_SUPERVISOR_DIGEST}" "${BASELINE_SUPERVISOR_DOCKERFILE_DIGEST}" || baseline_exit=$?
# Do not short-circuit: a candidate result is useful even when the frozen
# baseline failed, and two equal failures must never constitute parity.
run_variant candidate "${CANDIDATE_SHA}" 2 "${CANDIDATE_GATEWAY}" "${CANDIDATE_CLI}" "${CANDIDATE_CONFORMANCE}" "${CANDIDATE_EXTERNAL_DRIVER}" "${CANDIDATE_SUPERVISOR}" "${CANDIDATE_SUPERVISOR_DOCKERFILE}" "${CANDIDATE_GATEWAY_DIGEST}" "${CANDIDATE_CLI_DIGEST}" "${CANDIDATE_CONFORMANCE_DIGEST}" "${CANDIDATE_EXTERNAL_DRIVER_DIGEST}" "${CANDIDATE_SUPERVISOR_DIGEST}" "${CANDIDATE_SUPERVISOR_DOCKERFILE_DIGEST}" || candidate_exit=$?

baseline_success=$([ "${baseline_exit}" -eq 0 ] && printf true || printf false)
candidate_success=$([ "${candidate_exit}" -eq 0 ] && printf true || printf false)
write_comparison "${baseline_success}" "${candidate_success}"

if [ "${COMPARISON_ACCEPTED}" != true ]; then
  echo "ERROR: schema parity comparison classified ${SCENARIO} as a regression." >&2
  exit 1
fi
if [ "${COMPARISON_CLASSIFICATION}" = intentional_change ]; then
  echo "Schema parity accepted an intentional change: podman-pid-limit-restored (${SCENARIO})."
else
  echo "Schema parity passed: baseline schema v1 and candidate schema v2 succeeded (${SCENARIO})."
fi
