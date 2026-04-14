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
# CONTAINER_ENGINE=podman before sourcing.
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

_detect_container_engine() {
  # Honour explicit override.
  if [[ -n "${CONTAINER_ENGINE:-}" ]]; then
    if ! command -v "${CONTAINER_ENGINE}" >/dev/null 2>&1; then
      echo "Error: CONTAINER_ENGINE=${CONTAINER_ENGINE} is not installed or not in PATH" >&2
      exit 1
    fi
    _CE_EXPLICIT_OVERRIDE=1
    return
  fi

  # Prefer podman when available.
  if command -v podman >/dev/null 2>&1; then
    CONTAINER_ENGINE=podman
    return
  fi

  # Fall back to docker — but detect the podman-masquerading-as-docker shim
  # shipped by some distros (e.g. Fedora, RHEL).
  if command -v docker >/dev/null 2>&1; then
    if docker --version 2>/dev/null | grep -qi podman; then
      CONTAINER_ENGINE=podman
    else
      CONTAINER_ENGINE=docker
    fi
    return
  fi

  echo "Error: neither podman nor docker is installed." >&2
  echo "       Install one of them and try again." >&2
  exit 1
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
# ce_info_arch — host architecture reported by the container engine.
#
# Docker: docker info --format '{{.Architecture}}'
# Podman: podman info --format '{{.Host.Arch}}'
# ---------------------------------------------------------------------------
ce_info_arch() {
  if ce_is_docker; then
    "${_CE_BIN}" info --format '{{.Architecture}}' 2>/dev/null || echo "amd64"
  else
    "${_CE_BIN}" info --format '{{.Host.Arch}}' 2>/dev/null || echo "amd64"
  fi
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
  if [[ -n "${_CE_EXPLICIT_OVERRIDE:-}" ]]; then
    echo "[container-engine] using ${CONTAINER_ENGINE} (set via CONTAINER_ENGINE env)" >&2
  else
    echo "[container-engine] auto-detected: ${CONTAINER_ENGINE} (override with CONTAINER_ENGINE=docker|podman)" >&2
  fi
}
_ce_log_detected
