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
