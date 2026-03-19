#!/usr/bin/env bats

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

setup() {
  export TEST_TMPDIR
  TEST_TMPDIR="$(mktemp -d)"
  export FAKE_BIN_DIR="$TEST_TMPDIR/bin"
  export FAKE_CURL_LOG="$TEST_TMPDIR/curl.log"
  export FAKE_MISE_LOG="$TEST_TMPDIR/mise.log"
  mkdir -p "$FAKE_BIN_DIR"

  cat > "$FAKE_BIN_DIR/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FAKE_CURL_LOG"
output=""
url=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--output)
      output="$2"
      shift 2
      ;;
    http://*|https://*)
      url="$1"
      shift
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -z "$output" ]]; then
  echo "missing output path" >&2
  exit 1
fi
printf 'downloaded from %s\n' "$url" > "$output"
EOF
  chmod +x "$FAKE_BIN_DIR/curl"

  cat > "$FAKE_BIN_DIR/mise" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s|%s|%s|%s|%s|%s\n' "$*" "${OPENSHELL_RUNTIME_BUNDLE_TARBALL:-}" "${OPENSHELL_RUNTIME_BUNDLE_TARBALL_AMD64:-}" "${OPENSHELL_RUNTIME_BUNDLE_TARBALL_ARM64:-}" "${DOCKER_PLATFORM:-}" "${DOCKER_REGISTRY:-}" >> "$FAKE_MISE_LOG"
EOF
  chmod +x "$FAKE_BIN_DIR/mise"
}

teardown() {
  rm -rf "$TEST_TMPDIR"
}

make_ci_harness() {
  local harness_root="$TEST_TMPDIR/ci-harness"
  mkdir -p "$harness_root/tasks/scripts"
  cp "tasks/scripts/download-runtime-bundle.sh" "$harness_root/tasks/scripts/download-runtime-bundle.sh" 2>/dev/null || true
  cp "tasks/scripts/ci-build-cluster-image.sh" "$harness_root/tasks/scripts/ci-build-cluster-image.sh" 2>/dev/null || true
  printf '%s\n' "$harness_root"
}

@test "download-runtime-bundle.sh downloads a runtime bundle into the build cache and reuses it on repeat" {
  local harness_root output_path first_contents second_contents
  harness_root="$(make_ci_harness)"

  run env \
    PATH="$FAKE_BIN_DIR:$PATH" \
    bash -lc "cd '$harness_root' && bash tasks/scripts/download-runtime-bundle.sh --arch amd64 --url https://example.com/runtime-bundle-amd64.tar.gz"

  [ "$status" -eq 0 ]
  output_path="$output"
  [ -f "$output_path" ]
  first_contents="$(<"$output_path")"
  [[ "$first_contents" == *"downloaded from https://example.com/runtime-bundle-amd64.tar.gz"* ]]
  [[ "$(wc -l < "$FAKE_CURL_LOG")" -eq 1 ]]

  run env \
    PATH="$FAKE_BIN_DIR:$PATH" \
    bash -lc "cd '$harness_root' && bash tasks/scripts/download-runtime-bundle.sh --arch amd64 --url https://example.com/runtime-bundle-amd64.tar.gz"

  [ "$status" -eq 0 ]
  [ "$output" = "$output_path" ]
  second_contents="$(<"$output_path")"
  [ "$second_contents" = "$first_contents" ]
  [[ "$(wc -l < "$FAKE_CURL_LOG")" -eq 1 ]]
}

@test "download-runtime-bundle.sh caches different URLs with the same basename separately" {
  local harness_root first_path second_path
  harness_root="$(make_ci_harness)"

  run env \
    PATH="$FAKE_BIN_DIR:$PATH" \
    bash -lc "cd '$harness_root' && bash tasks/scripts/download-runtime-bundle.sh --arch amd64 --url https://example.com/releases/a/runtime-bundle.tar.gz"

  [ "$status" -eq 0 ]
  first_path="$output"
  [[ "$(<"$first_path")" == *"https://example.com/releases/a/runtime-bundle.tar.gz"* ]]

  run env \
    PATH="$FAKE_BIN_DIR:$PATH" \
    bash -lc "cd '$harness_root' && bash tasks/scripts/download-runtime-bundle.sh --arch amd64 --url https://mirror.example.com/releases/b/runtime-bundle.tar.gz"

  [ "$status" -eq 0 ]
  second_path="$output"
  [ "$second_path" != "$first_path" ]
  [[ "$(<"$second_path")" == *"https://mirror.example.com/releases/b/runtime-bundle.tar.gz"* ]]
  [[ "$(wc -l < "$FAKE_CURL_LOG")" -eq 2 ]]
}

@test "ci-build-cluster-image.sh routes single-arch cluster builds through docker:build:cluster with a downloaded bundle" {
  local harness_root
  harness_root="$(make_ci_harness)"

  run env \
    PATH="$FAKE_BIN_DIR:$PATH" \
    bash -lc "cd '$harness_root' && bash tasks/scripts/ci-build-cluster-image.sh --platform linux/arm64 --runtime-bundle-url https://example.com/runtime-bundle-arm64.tar.gz"

  [ "$status" -eq 0 ]
  [[ "$(<"$FAKE_MISE_LOG")" == *"run --no-prepare docker:build:cluster"* ]]
  [[ "$(<"$FAKE_MISE_LOG")" == *"runtime-bundle-arm64.tar.gz"* ]]
}

@test "ci-build-cluster-image.sh accepts the matching arch-specific runtime bundle URL in single-arch mode" {
  local harness_root curl_log
  harness_root="$(make_ci_harness)"

  run env \
    PATH="$FAKE_BIN_DIR:$PATH" \
    bash -lc "cd '$harness_root' && bash tasks/scripts/ci-build-cluster-image.sh --platform linux/arm64 --runtime-bundle-url-arm64 https://example.com/runtime-bundle-arm64-specific.tar.gz"

  [ "$status" -eq 0 ]
  curl_log="$(<"$FAKE_CURL_LOG")"
  [[ "$curl_log" == *"https://example.com/runtime-bundle-arm64-specific.tar.gz"* ]]
  [[ "$(<"$FAKE_MISE_LOG")" == *"runtime-bundle-arm64-specific.tar.gz"* ]]
}

@test "ci-build-cluster-image.sh rejects the wrong arch-specific runtime bundle URL in single-arch mode" {
  local harness_root
  harness_root="$(make_ci_harness)"

  run env \
    PATH="$FAKE_BIN_DIR:$PATH" \
    bash -lc "cd '$harness_root' && bash tasks/scripts/ci-build-cluster-image.sh --platform linux/arm64 --runtime-bundle-url-amd64 https://example.com/runtime-bundle-amd64.tar.gz"

  [ "$status" -ne 0 ]
  [[ "$output" == *"--runtime-bundle-url-amd64 is not supported for single-arch platform linux/arm64; use --runtime-bundle-url or --runtime-bundle-url-arm64"* ]]
  [ ! -f "$FAKE_CURL_LOG" ]
  [ ! -f "$FAKE_MISE_LOG" ]
}

@test "ci-build-cluster-image.sh derives a default GitHub Releases asset URL for single-arch builds from producer metadata" {
  local harness_root
  harness_root="$(make_ci_harness)"

  run env \
    PATH="$FAKE_BIN_DIR:$PATH" \
    bash -lc "cd '$harness_root' && bash tasks/scripts/ci-build-cluster-image.sh --platform linux/arm64 --runtime-bundle-github-repo acme/nvidia-container-toolkit --runtime-bundle-release-tag toolkit-v1.2.3 --runtime-bundle-filename-prefix runtime-bundle --runtime-bundle-version 1.2.3"

  [ "$status" -eq 0 ]
  [[ "$(<"$FAKE_CURL_LOG")" == *"https://github.com/acme/nvidia-container-toolkit/releases/download/toolkit-v1.2.3/runtime-bundle_1.2.3_arm64.tar.gz"* ]]
  [[ "$(<"$FAKE_MISE_LOG")" == *"run --no-prepare docker:build:cluster"* ]]
  [[ "$(<"$FAKE_MISE_LOG")" == *"runtime-bundle_1.2.3_arm64.tar.gz"* ]]
}

@test "ci-build-cluster-image.sh routes multi-arch cluster builds through docker:build:cluster:multiarch with per-arch bundles" {
  local harness_root
  harness_root="$(make_ci_harness)"

  run env \
    PATH="$FAKE_BIN_DIR:$PATH" \
    IMAGE_REGISTRY=ghcr.io/nvidia/openshell \
    bash -lc "cd '$harness_root' && bash tasks/scripts/ci-build-cluster-image.sh --platform linux/amd64,linux/arm64 --runtime-bundle-url-amd64 https://example.com/runtime-bundle-amd64.tar.gz --runtime-bundle-url-arm64 https://example.com/runtime-bundle-arm64.tar.gz"

  [ "$status" -eq 0 ]
  [[ "$(<"$FAKE_MISE_LOG")" == *"run --no-prepare docker:build:cluster:multiarch"* ]]
  [[ "$(<"$FAKE_MISE_LOG")" == *"runtime-bundle-amd64.tar.gz"* ]]
  [[ "$(<"$FAKE_MISE_LOG")" == *"runtime-bundle-arm64.tar.gz"* ]]
  [[ "$(<"$FAKE_MISE_LOG")" == *"|ghcr.io/nvidia/openshell" ]]
}

@test "ci-build-cluster-image.sh derives both default GitHub Releases asset URLs for multi-arch builds from producer metadata" {
  local harness_root curl_log
  harness_root="$(make_ci_harness)"

  run env \
    PATH="$FAKE_BIN_DIR:$PATH" \
    IMAGE_REGISTRY=ghcr.io/nvidia/openshell \
    bash -lc "cd '$harness_root' && bash tasks/scripts/ci-build-cluster-image.sh --platform linux/amd64,linux/arm64 --runtime-bundle-github-repo acme/nvidia-container-toolkit --runtime-bundle-release-tag toolkit-v1.2.3 --runtime-bundle-filename-prefix runtime-bundle --runtime-bundle-version 1.2.3"

  [ "$status" -eq 0 ]
  curl_log="$(<"$FAKE_CURL_LOG")"
  [[ "$curl_log" == *"https://github.com/acme/nvidia-container-toolkit/releases/download/toolkit-v1.2.3/runtime-bundle_1.2.3_amd64.tar.gz"* ]]
  [[ "$curl_log" == *"https://github.com/acme/nvidia-container-toolkit/releases/download/toolkit-v1.2.3/runtime-bundle_1.2.3_arm64.tar.gz"* ]]
  [[ "$(<"$FAKE_MISE_LOG")" == *"run --no-prepare docker:build:cluster:multiarch"* ]]
  [[ "$(<"$FAKE_MISE_LOG")" == *"runtime-bundle_1.2.3_amd64.tar.gz"* ]]
  [[ "$(<"$FAKE_MISE_LOG")" == *"runtime-bundle_1.2.3_arm64.tar.gz"* ]]
}

@test "ci-build-cluster-image.sh prefers explicit runtime bundle URLs over derived GitHub Releases defaults" {
  local harness_root curl_log
  harness_root="$(make_ci_harness)"

  run env \
    PATH="$FAKE_BIN_DIR:$PATH" \
    IMAGE_REGISTRY=ghcr.io/nvidia/openshell \
    bash -lc "cd '$harness_root' && bash tasks/scripts/ci-build-cluster-image.sh --platform linux/amd64,linux/arm64 --runtime-bundle-url-amd64 https://example.com/explicit-amd64.tar.gz --runtime-bundle-url-arm64 https://example.com/explicit-arm64.tar.gz --runtime-bundle-github-repo acme/nvidia-container-toolkit --runtime-bundle-release-tag toolkit-v9.9.9 --runtime-bundle-filename-prefix runtime-bundle --runtime-bundle-version 9.9.9"

  [ "$status" -eq 0 ]
  curl_log="$(<"$FAKE_CURL_LOG")"
  [[ "$curl_log" == *"https://example.com/explicit-amd64.tar.gz"* ]]
  [[ "$curl_log" == *"https://example.com/explicit-arm64.tar.gz"* ]]
  [[ "$curl_log" != *"github.com/acme/nvidia-container-toolkit/releases/download/toolkit-v9.9.9/runtime-bundle_9.9.9_amd64.tar.gz"* ]]
  [[ "$curl_log" != *"github.com/acme/nvidia-container-toolkit/releases/download/toolkit-v9.9.9/runtime-bundle_9.9.9_arm64.tar.gz"* ]]
}

@test "ci-build-cluster-image.sh rejects unsupported multi-arch platform lists instead of assuming amd64+arm64" {
  local harness_root
  harness_root="$(make_ci_harness)"

  run env \
    PATH="$FAKE_BIN_DIR:$PATH" \
    IMAGE_REGISTRY=ghcr.io/nvidia/openshell \
    bash -lc "cd '$harness_root' && bash tasks/scripts/ci-build-cluster-image.sh --platform linux/amd64,linux/s390x --runtime-bundle-url-amd64 https://example.com/runtime-bundle-amd64.tar.gz --runtime-bundle-url-arm64 https://example.com/runtime-bundle-arm64.tar.gz"

  [ "$status" -ne 0 ]
  [[ "$output" == *"unsupported multi-arch platform set: linux/amd64,linux/s390x"* ]]
  [ ! -f "$FAKE_CURL_LOG" ]
  [ ! -f "$FAKE_MISE_LOG" ]
}

@test "ci-build-cluster-image.sh rejects --runtime-bundle-url in multi-arch mode" {
  local harness_root
  harness_root="$(make_ci_harness)"

  run env \
    PATH="$FAKE_BIN_DIR:$PATH" \
    IMAGE_REGISTRY=ghcr.io/nvidia/openshell \
    bash -lc "cd '$harness_root' && bash tasks/scripts/ci-build-cluster-image.sh --platform linux/amd64,linux/arm64 --runtime-bundle-url https://example.com/runtime-bundle.tar.gz --runtime-bundle-url-amd64 https://example.com/runtime-bundle-amd64.tar.gz --runtime-bundle-url-arm64 https://example.com/runtime-bundle-arm64.tar.gz"

  [ "$status" -ne 0 ]
  [[ "$output" == *"--runtime-bundle-url is not supported for multi-arch builds; use --runtime-bundle-url-amd64 and --runtime-bundle-url-arm64"* ]]
  [ ! -f "$FAKE_CURL_LOG" ]
  [ ! -f "$FAKE_MISE_LOG" ]
}
