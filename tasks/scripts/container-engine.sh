#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Shared container engine detection and abstraction layer.
#
# Source this file in any script that needs to run container commands:
#   SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#   source "${SCRIPT_DIR}/container-engine.sh"  # or adjust path accordingly
#
# After sourcing, use these instead of bare `docker` / `podman`:
#   ce <subcommand> [args...]        — run container engine command
#   ce_build [args...]               — container image build (handles buildx differences)
#   ce_is_podman / ce_is_docker      — check which engine is active
#   ce_info_arch                     — host architecture (handles format differences)
#   ce_network_gateway [network]     — default network gateway IP
#   ce_builder_prune [args...]       — prune build cache
#   ce_buildx_inspect [args...]      — inspect buildx builder (no-op for podman)
#   ce_build_multiarch               — multi-arch build + push workflow
#
# Override the auto-detected engine by setting CONTAINER_ENGINE=docker or
# CONTAINER_ENGINE=podman before sourcing. Scripts that build images directly
# into a local Kubernetes cluster can also set
# CONTAINER_ENGINE_TARGET=local-k8s-cluster so the helper validates the active
# k3d/kind context before choosing an engine.
# Suppress the detection log line with CONTAINER_ENGINE_QUIET=1 (useful in
# CI pipelines or scripts that source this file multiple times in a pipeline).

# Guard against double-sourcing.
if [[ -n "${_CONTAINER_ENGINE_LOADED:-}" ]]; then
  return 0
fi
_CONTAINER_ENGINE_LOADED=1

# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

_ce_lower() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

_ce_error() {
  echo "Error: $*" >&2
  exit 1
}

_ce_validate_engine_value() {
  local name=$1
  local value=$2

  case "${value}" in
    docker|podman)
      ;;
    *)
      _ce_error "${name}=${value} is invalid; expected docker or podman"
      ;;
  esac
}

_ce_docker_is_podman_shim() {
  command -v docker >/dev/null 2>&1 && docker --version 2>/dev/null | grep -qi podman
}

_ce_require_engine_available() {
  local engine=$1

  case "${engine}" in
    docker)
      if ! command -v docker >/dev/null 2>&1; then
        _ce_error "CONTAINER_ENGINE=docker requires the docker CLI to be installed and in PATH"
      fi
      if _ce_docker_is_podman_shim; then
        _ce_error "CONTAINER_ENGINE=docker was requested, but docker appears to be a Podman compatibility shim"
      fi
      ;;
    podman)
      if command -v podman >/dev/null 2>&1 || _ce_docker_is_podman_shim; then
        return
      fi
      _ce_error "CONTAINER_ENGINE=podman requires the podman CLI or a docker-compatible Podman shim to be installed and in PATH"
      ;;
  esac
}

_ce_auto_detect_engine() {
  # Prefer podman when available.
  if command -v podman >/dev/null 2>&1; then
    echo "podman"
    return
  fi

  # Fall back to docker — but detect the podman-masquerading-as-docker shim
  # shipped by some distros (e.g. Fedora, RHEL).
  if command -v docker >/dev/null 2>&1; then
    if _ce_docker_is_podman_shim; then
      echo "podman"
    else
      echo "docker"
    fi
    return
  fi

  echo "Error: neither podman nor docker is installed." >&2
  echo "       Install one of them, or set CONTAINER_ENGINE=docker|podman." >&2
  exit 1
}

_ce_required_engine_from_e2e_driver() {
  local driver
  driver="$(_ce_lower "${OPENSHELL_E2E_DRIVER:-}")"

  case "${driver}" in
    docker|podman)
      echo "${driver}"
      ;;
  esac
}

_ce_required_engine_from_local_cluster() {
  local explicit_engine=$1

  if [[ "${CONTAINER_ENGINE_TARGET:-}" != "local-k8s-cluster" ]]; then
    return
  fi

  local context=""
  if command -v kubectl >/dev/null 2>&1; then
    context="$(kubectl config current-context 2>/dev/null || true)"
  fi

  case "${context}" in
    k3d-*)
      echo "docker"
      ;;
    kind-*)
      case "$(_ce_lower "${KIND_EXPERIMENTAL_PROVIDER:-}")" in
        docker|podman)
          _ce_lower "${KIND_EXPERIMENTAL_PROVIDER}"
          ;;
        *)
          if [[ -z "${explicit_engine}" ]]; then
            _ce_error "CONTAINER_ENGINE_TARGET=local-k8s-cluster cannot infer the container engine for kind context '${context}'; set CONTAINER_ENGINE=docker or CONTAINER_ENGINE=podman"
          fi
          ;;
      esac
      ;;
    "")
      if [[ -z "${explicit_engine}" ]]; then
        _ce_error "CONTAINER_ENGINE_TARGET=local-k8s-cluster requires an active k3d/kind Kubernetes context, or an explicit CONTAINER_ENGINE=docker|podman"
      fi
      ;;
    *)
      if [[ -z "${explicit_engine}" ]]; then
        _ce_error "cannot infer container engine for Kubernetes context '${context}'; set CONTAINER_ENGINE=docker|podman"
      fi
      ;;
  esac
}

_detect_container_engine() {
  if [[ -n "${OPENSHELL_E2E_CONTAINER_ENGINE:-}" ]]; then
    _ce_error "OPENSHELL_E2E_CONTAINER_ENGINE is no longer supported; set CONTAINER_ENGINE=docker|podman instead"
  fi

  case "${CONTAINER_ENGINE_TARGET:-}" in
    ""|local-k8s-cluster)
      ;;
    *)
      _ce_error "CONTAINER_ENGINE_TARGET=${CONTAINER_ENGINE_TARGET} is invalid; expected local-k8s-cluster"
      ;;
  esac

  local explicit_engine=""
  if [[ -n "${CONTAINER_ENGINE:-}" ]]; then
    explicit_engine="$(_ce_lower "${CONTAINER_ENGINE}")"
    _ce_validate_engine_value "CONTAINER_ENGINE" "${explicit_engine}"
  fi

  local e2e_required=""
  if ! e2e_required="$(_ce_required_engine_from_e2e_driver)"; then
    exit 1
  fi

  local local_cluster_required=""
  if ! local_cluster_required="$(_ce_required_engine_from_local_cluster "${explicit_engine}")"; then
    exit 1
  fi

  if [[ -n "${e2e_required}" && -n "${local_cluster_required}" && "${e2e_required}" != "${local_cluster_required}" ]]; then
    _ce_error "OPENSHELL_E2E_DRIVER=${OPENSHELL_E2E_DRIVER} requires ${e2e_required}, but CONTAINER_ENGINE_TARGET=local-k8s-cluster requires ${local_cluster_required}"
  fi

  if [[ -n "${explicit_engine}" ]]; then
    if [[ -n "${e2e_required}" && "${explicit_engine}" != "${e2e_required}" ]]; then
      _ce_error "CONTAINER_ENGINE=${explicit_engine} conflicts with OPENSHELL_E2E_DRIVER=${OPENSHELL_E2E_DRIVER}; use CONTAINER_ENGINE=${e2e_required} or unset CONTAINER_ENGINE"
    fi
    if [[ -n "${local_cluster_required}" && "${explicit_engine}" != "${local_cluster_required}" ]]; then
      _ce_error "CONTAINER_ENGINE=${explicit_engine} conflicts with CONTAINER_ENGINE_TARGET=local-k8s-cluster; active local cluster requires ${local_cluster_required}"
    fi
    CONTAINER_ENGINE="${explicit_engine}"
    _CE_SELECTION_REASON=explicit
  elif [[ -n "${e2e_required}" ]]; then
    CONTAINER_ENGINE="${e2e_required}"
    _CE_SELECTION_REASON=e2e-driver
  elif [[ -n "${local_cluster_required}" ]]; then
    CONTAINER_ENGINE="${local_cluster_required}"
    _CE_SELECTION_REASON=local-k8s-cluster
  else
    if ! CONTAINER_ENGINE="$(_ce_auto_detect_engine)"; then
      exit 1
    fi
    _CE_SELECTION_REASON=auto
  fi

  _ce_require_engine_available "${CONTAINER_ENGINE}"
}

_detect_container_engine

# The actual binary to invoke — usually equals CONTAINER_ENGINE, but when
# podman is detected via the docker shim we still call `docker` (the shim
# execs podman internally).
_CE_BIN="${CONTAINER_ENGINE}"
if [[ "${CONTAINER_ENGINE}" == "podman" ]] && ! command -v podman >/dev/null 2>&1; then
  # podman detected through docker shim; call docker (which execs podman).
  _CE_BIN=docker
fi

# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

# Run the container engine with arbitrary arguments.
ce() {
  "${_CE_BIN}" "$@"
}

ce_is_podman() {
  [[ "${CONTAINER_ENGINE}" == "podman" ]]
}

ce_is_docker() {
  [[ "${CONTAINER_ENGINE}" == "docker" ]]
}

# ---------------------------------------------------------------------------
# ce_build — abstraction over `docker buildx build` / `podman build`
#
# Accepts the same flags as `docker buildx build`.  For podman the function:
#   - Strips --load (podman loads locally by default)
#   - Strips --provenance (podman doesn't generate provenance attestations)
#   - Strips --builder (podman has no builder concept)
#   - Converts --push to a post-build `podman push` (podman build has no --push)
#
# All other flags (--platform, --build-arg, --cache-from, --cache-to,
# --output, -t, -f, --target, etc.) are passed through as-is since podman
# build supports them.
# ---------------------------------------------------------------------------
ce_build() {
  if ce_is_docker; then
    "${_CE_BIN}" buildx build "$@"
    return
  fi

  # Podman path — filter out unsupported flags.
  local args=()
  local push_after=false
  local image_tags=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --load)
        # Podman loads locally by default; skip.
        shift
        ;;
      --push)
        push_after=true
        shift
        ;;
      --provenance|--provenance=*)
        # Podman doesn't support provenance attestations; skip.
        shift
        ;;
      --builder|--builder=*)
        # Podman has no builder concept; skip.
        if [[ "$1" == "--builder" ]]; then
          shift 2  # skip --builder <name>
        else
          shift    # skip --builder=<name>
        fi
        ;;
      -t|--tag)
        image_tags+=("$2")
        args+=("$1" "$2")
        shift 2
        ;;
      -t=*|--tag=*)
        image_tags+=("${1#*=}")
        args+=("$1")
        shift
        ;;
      *)
        args+=("$1")
        shift
        ;;
    esac
  done

  "${_CE_BIN}" build "${args[@]}"

  if [[ "${push_after}" == "true" ]]; then
    for tag in "${image_tags[@]}"; do
      "${_CE_BIN}" push "${tag}"
    done
  fi
}

# ---------------------------------------------------------------------------
# ce_normalize_arch — normalize common architecture names.
#
# Keeps container-engine helpers from silently drifting between Docker,
# Podman, and kernel naming conventions.
# ---------------------------------------------------------------------------
ce_normalize_arch() {
  case "$1" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) echo "$1" ;;
  esac
}

# ---------------------------------------------------------------------------
# ce_host_arch — kernel architecture normalized for Docker platform names.
# ---------------------------------------------------------------------------
ce_host_arch() {
  ce_normalize_arch "$(uname -m)"
}

# ---------------------------------------------------------------------------
# ce_info_arch — host architecture reported by the container engine.
#
# Docker: docker info --format '{{.Architecture}}'
# Podman: podman info --format '{{.Host.Arch}}'
# Fails directly when the engine query is unavailable or returns malformed
# metadata. Silently falling back to the host architecture can make cross-VM
# builds use the wrong target.
# ---------------------------------------------------------------------------
ce_info_arch() {
  local info_output info_error_file arch normalized format

  if ce_is_docker; then
    format='{{.Architecture}}'
  else
    format='{{.Host.Arch}}'
  fi

  info_error_file="$(mktemp "${TMPDIR:-/tmp}/openshell-ce-info.XXXXXX")"
  if ! info_output=$("${_CE_BIN}" info --format "${format}" 2>"${info_error_file}"); then
    echo "Error: failed to query ${CONTAINER_ENGINE} architecture with '${_CE_BIN} info':" >&2
    if [[ -n "${info_output}" ]]; then
      printf '%s\n' "${info_output}" >&2
    fi
    cat "${info_error_file}" >&2 || true
    rm -f "${info_error_file}"
    exit 1
  fi
  rm -f "${info_error_file}"

  arch="$(printf '%s\n' "${info_output}" | awk 'NF { print; exit }')"
  if [[ -z "${arch}" ]]; then
    _ce_error "${CONTAINER_ENGINE} info did not report a host architecture"
  fi

  normalized="$(ce_normalize_arch "${arch}")"
  case "${normalized}" in
    amd64|arm64)
      echo "${normalized}"
      ;;
    *)
      _ce_error "unsupported ${CONTAINER_ENGINE} architecture '${arch}' reported by '${_CE_BIN} info'"
      ;;
  esac
}

# ---------------------------------------------------------------------------
# ce_network_gateway — default network gateway IP.
#
# Docker: docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}'
# Podman: podman network inspect podman --format '{{(index .Subnets 0).Gateway}}'
#
# Accepts an optional network name override; defaults to the engine's default.
# ---------------------------------------------------------------------------
ce_network_gateway() {
  local network="${1:-}"
  if ce_is_docker; then
    network="${network:-bridge}"
    "${_CE_BIN}" network inspect "${network}" --format '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null || true
  else
    network="${network:-podman}"
    "${_CE_BIN}" network inspect "${network}" --format '{{(index .Subnets 0).Gateway}}' 2>/dev/null || true
  fi
}

# ---------------------------------------------------------------------------
# ce_builder_prune — prune build cache.
#
# Docker: docker builder prune -af
# Podman: podman system reset is too aggressive; use buildah prune or image prune.
# ---------------------------------------------------------------------------
ce_builder_prune() {
  if ce_is_docker; then
    "${_CE_BIN}" builder prune "$@"
  else
    # Podman doesn't have `builder prune`.  `podman image prune` removes
    # dangling build layers.  `buildah prune` is closest but may not be
    # installed.  Fall back gracefully.
    if command -v buildah >/dev/null 2>&1; then
      buildah prune "$@"
    else
      "${_CE_BIN}" image prune "$@"
    fi
  fi
}

# ---------------------------------------------------------------------------
# ce_buildx_inspect — inspect a buildx builder.
#
# Docker: docker buildx inspect [name]
# Podman: returns a synthetic "podman" driver response to satisfy callers that
#         check for "Driver: docker-container".
# ---------------------------------------------------------------------------
ce_buildx_inspect() {
  if ce_is_docker; then
    "${_CE_BIN}" buildx inspect "$@"
  else
    # Podman doesn't have real buildx builders.  Emit a minimal response so
    # callers that grep for "Driver:" get a predictable answer.
    echo "Name:   default"
    echo "Driver: podman"
  fi
}

# ---------------------------------------------------------------------------
# ce_context_name — current context/connection name.
#
# Docker: docker context inspect --format '{{.Name}}'
# Podman: always "default"
# ---------------------------------------------------------------------------
ce_context_name() {
  if ce_is_docker; then
    "${_CE_BIN}" context inspect --format '{{.Name}}' 2>/dev/null || echo "default"
  else
    echo "default"
  fi
}

# ---------------------------------------------------------------------------
# ce_imagetools_create — create/re-tag a multi-arch manifest.
#
# Docker: docker buildx imagetools create -t <new> <source>
# Podman: no direct equivalent — the caller should use podman manifest
#         workflows instead.  This helper exists so scripts can call it
#         without engine checks; for podman it falls back to tag + push.
# ---------------------------------------------------------------------------
ce_imagetools_create() {
  if ce_is_docker; then
    "${_CE_BIN}" buildx imagetools create "$@"
    return
  fi

  # Podman fallback: parse -t <tag> and the trailing source image, then
  # use skopeo or podman tag.  This is a best-effort shim for simple
  # re-tagging; full multi-arch manifest manipulation should use the
  # podman-native code path in docker-publish-multiarch.sh.
  #
  # Argument parsing uses a sentinel ("__next__") to capture the value
  # that follows a two-token -t / --tag flag.  --prefer-index is accepted
  # and silently ignored (the Docker path passes it through to buildx;
  # the Podman path has no equivalent concept).
  local new_tag="" source_image=""
  for arg in "$@"; do
    case "${arg}" in
      -t|--tag)
        new_tag="__next__"
        continue
        ;;
      --prefer-index|--prefer-index=*)
        # No podman equivalent; accepted and ignored for call-site compatibility.
        continue
        ;;
    esac
    if [[ "${new_tag}" == "__next__" ]]; then
      new_tag="${arg}"
    else
      source_image="${arg}"
    fi
  done

  if [[ -n "${new_tag}" && -n "${source_image}" ]]; then
    if command -v skopeo >/dev/null 2>&1; then
      skopeo copy --all "docker://${source_image}" "docker://${new_tag}"
    else
      "${_CE_BIN}" tag "${source_image}" "${new_tag}"
      "${_CE_BIN}" push "${new_tag}"
    fi
  fi
}

# ---------------------------------------------------------------------------
# Log the detected engine so developers always know which tool is active.
# Emitted once per script invocation (the double-source guard at the top
# prevents repeated output when scripts source each other).
# Suppress with CONTAINER_ENGINE_QUIET=1 for CI or non-interactive use.
# ---------------------------------------------------------------------------
_ce_log_detected() {
  if [[ "${CONTAINER_ENGINE_QUIET:-}" == "1" ]]; then
    return
  fi
  case "${_CE_SELECTION_REASON:-auto}" in
    explicit)
      echo "[container-engine] using ${CONTAINER_ENGINE} (set via CONTAINER_ENGINE env)" >&2
      ;;
    e2e-driver)
      echo "[container-engine] using ${CONTAINER_ENGINE} (required by OPENSHELL_E2E_DRIVER=${OPENSHELL_E2E_DRIVER})" >&2
      ;;
    local-k8s-cluster)
      echo "[container-engine] using ${CONTAINER_ENGINE} (required by CONTAINER_ENGINE_TARGET=local-k8s-cluster)" >&2
      ;;
    *)
      echo "[container-engine] auto-detected: ${CONTAINER_ENGINE} (override with CONTAINER_ENGINE=docker|podman)" >&2
      ;;
  esac
}
_ce_log_detected
