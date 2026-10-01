#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ci_image_refs() {
  # Consumer references stay literal so GitHub can pull the job container before
  # checkout, and Zizmor can audit it. The producer's bare repository is excluded.
  grep -rhE '^[[:space:]]*image:' "$1" |
    grep -oE "ghcr.io/nvidia/openshell/ci([:@][^[:space:]\"']+)?" |
    sort -u
}

ci_image_ref_valid() {
  [[ "$1" =~ ^ghcr\.io/nvidia/openshell/ci:[0-9a-f]{40}@sha256:[0-9a-f]{64}$ ]]
}

ci_image_index_valid() {
  # BuildKit provenance descriptors (unknown/unknown) may coexist with images.
  jq -e '
    (.mediaType == "application/vnd.oci.image.index.v1+json" or
     .mediaType == "application/vnd.docker.distribution.manifest.list.v2+json") and
    ([.manifests[] | select(.platform.os == "linux" and
       .platform.architecture == "amd64")] | length == 1) and
    ([.manifests[] | select(.platform.os == "linux" and
       .platform.architecture == "arm64")] | length == 1)
  ' >/dev/null
}

ci_image_smoke() {
  local image=$1 arch=$2
  printf 'Checking multiarchitecture index: %s\n' "$image"
  if ! docker buildx imagetools inspect --raw "$image" | ci_image_index_valid; then
    echo "Cannot verify a Linux amd64/arm64 index for $image" >&2
    return 1
  fi
  # No host mounts, Docker socket, registry credentials, or network inside the
  # container. Exercise the baked tools without installing replacements.
  docker run --rm --pull=always --platform "linux/$arch" --network none \
    --env "CI_IMAGE_ARCH=$arch" --workdir /opt/mise --entrypoint bash -i "$image" -s <<'SMOKE'
set -euo pipefail
case "$CI_IMAGE_ARCH:$(uname -m)" in
  amd64:x86_64|arm64:aarch64) ;;
  *) echo "Unexpected container architecture" >&2; exit 1 ;;
esac
mise --version
gh --version
docker buildx version
rustc --version
cargo --version
go version
node --version
npm --version
uv --version
protoc --version
buf --version
helm version --short
zig version
cc --version
pkg-config --exists openssl

smoke_dir=$(mktemp -d)
trap 'rm -rf "$smoke_dir"' EXIT
printf 'int main(void) { return 0; }\n' > "$smoke_dir/main.c"
cc "$smoke_dir/main.c" -o "$smoke_dir/c-smoke"
"$smoke_dir/c-smoke"
printf 'fn main() { assert_eq!(2 + 2, 4); }\n' > "$smoke_dir/main.rs"
rustc "$smoke_dir/main.rs" -o "$smoke_dir/rust-smoke"
"$smoke_dir/rust-smoke"
printf 'package main\nfunc main() {}\n' > "$smoke_dir/main.go"
GOTOOLCHAIN=local go build -o "$smoke_dir/go-smoke" "$smoke_dir/main.go"
"$smoke_dir/go-smoke"
uv run --no-project --offline --python "$(mise which python)" \
  python -c 'import ssl; assert ssl.OPENSSL_VERSION'
node -e 'if (2 + 2 !== 4) process.exit(1)'
SMOKE
}

main() {
  local mode=${1:---check} arch=${2:-} native_arch refs image
  local root
  root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
  case "$mode" in
    --check) ;;
    --smoke)
      case "$(uname -m)" in
        x86_64) native_arch=amd64 ;;
        aarch64|arm64) native_arch=arm64 ;;
        *) echo "Unsupported native architecture" >&2; return 1 ;;
      esac
      [[ "$arch" == "$native_arch" ]] || {
        echo "Run smoke tests on a native $arch runner (host is $native_arch)" >&2
        return 1
      }
      ;;
    *) echo "Usage: $0 [--check | --smoke amd64|arm64]" >&2; return 1 ;;
  esac
  refs=$(ci_image_refs "$root/.github/workflows") || {
    echo "No CI image references found" >&2
    return 1
  }
  # Validate all references before executing any container.
  while IFS= read -r image; do
    ci_image_ref_valid "$image" || {
      printf 'CI image requires a source commit tag and SHA-256 digest: %s\n' "$image" >&2
      return 1
    }
    printf '%s\n' "$image"
  done <<< "$refs"
  if [[ "$mode" == --smoke ]]; then
    while IFS= read -r image; do
      ci_image_smoke "$image" "$arch"
    done <<< "$refs"
  fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
