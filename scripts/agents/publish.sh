#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

DOCKER_BIN="${DOCKER_BIN:-docker}"
SOURCE=""
REPOSITORY=""
PLATFORM="linux/amd64"
TEMP_DIR=""

fail() {
    echo "error: $*" >&2
    exit 1
}

cleanup() {
    if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
}
trap cleanup EXIT

usage() {
    cat <<'EOF'
Usage: scripts/agents/publish.sh --from DOCKERFILE|DIR --publish-to REPOSITORY [options]

Build and push a Docker context, then print its digest-pinned OCI reference.

Options:
  --from DOCKERFILE|DIR   Dockerfile or directory containing Dockerfile
  --publish-to REPOSITORY OCI repository without a tag or digest
  --platform PLATFORM     Published image platform (default: linux/amd64)
  -h, --help              Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --from)
            [[ $# -ge 2 ]] || fail "--from requires a value"
            SOURCE="$2"
            shift 2
            ;;
        --publish-to)
            [[ $# -ge 2 ]] || fail "--publish-to requires a value"
            REPOSITORY="$2"
            shift 2
            ;;
        --platform)
            [[ $# -ge 2 ]] || fail "--platform requires a value"
            PLATFORM="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "unknown argument: $1"
            ;;
    esac
done

[[ -n "$SOURCE" ]] || fail "--from is required"
[[ -n "$REPOSITORY" ]] || fail "--publish-to is required"
[[ "$REPOSITORY" != *[[:space:]]* ]] || fail "--publish-to must not contain whitespace"
[[ "$REPOSITORY" != *@* ]] || fail "--publish-to must be a repository without a digest"
[[ "${REPOSITORY##*/}" != *:* ]] || fail "--publish-to must be a repository without a tag"
[[ -n "$PLATFORM" ]] || fail "--platform requires a non-empty value"
[[ "$PLATFORM" != *[[:space:]]* ]] || fail "--platform must not contain whitespace"
command -v ruby >/dev/null 2>&1 || fail "required command not found: ruby"
command -v "$DOCKER_BIN" >/dev/null 2>&1 || fail "required command not found: $DOCKER_BIN"

if [[ -d "$SOURCE" ]]; then
    CONTEXT="$(cd "$SOURCE" && pwd)"
    DOCKERFILE="$CONTEXT/Dockerfile"
elif [[ -f "$SOURCE" ]]; then
    DOCKERFILE="$(cd "$(dirname "$SOURCE")" && pwd)/$(basename "$SOURCE")"
    CONTEXT="$(dirname "$DOCKERFILE")"
else
    fail "--from source does not exist: $SOURCE"
fi
[[ -f "$DOCKERFILE" ]] || fail "Dockerfile not found: $DOCKERFILE"

FINGERPRINT="$(ruby -rdigest - "$CONTEXT" <<'RUBY'
root = File.expand_path(ARGV.fetch(0))
digest = Digest::SHA256.new
Dir.glob(File.join(root, "**", "*"), File::FNM_DOTMATCH).sort.each do |path|
  relative = path.delete_prefix("#{root}/")
  next if relative.empty? || relative.split("/").include?(".") || relative.split("/").include?("..")

  stat = File.lstat(path)
  digest.update(relative)
  digest.update("\0")
  if stat.symlink?
    digest.update("symlink\0")
    digest.update(File.readlink(path))
  elsif stat.file?
    digest.update("file\0")
    digest.update(File.binread(path))
  else
    next
  end
  digest.update("\0")
end
puts digest.hexdigest
RUBY
)"
[[ "$FINGERPRINT" =~ ^[0-9a-f]{64}$ ]] || fail "failed to fingerprint image context"
IMAGE_TAG="${REPOSITORY}:payload-${FINGERPRINT:0:16}"

TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/openshell-agent-publish.XXXXXX")"
METADATA_FILE="$TEMP_DIR/build-metadata.json"

echo "openshell-agent-publisher: Publishing '$IMAGE_TAG' for platform '$PLATFORM'." >&2
"$DOCKER_BIN" buildx build \
    --platform "$PLATFORM" \
    --push \
    --metadata-file "$METADATA_FILE" \
    --tag "$IMAGE_TAG" \
    --file "$DOCKERFILE" \
    "$CONTEXT"

if ! PUBLISHED_DIGEST="$(ruby -rjson - "$METADATA_FILE" <<'RUBY'
metadata = JSON.parse(File.read(ARGV.fetch(0)))
digest = metadata["containerimage.digest"]
abort "missing containerimage.digest" unless digest.is_a?(String)
print digest
RUBY
)"; then
    fail "published image metadata does not contain containerimage.digest"
fi
[[ "$PUBLISHED_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "published image metadata contains an invalid digest"

printf '%s@%s\n' "$REPOSITORY" "$PUBLISHED_DIGEST"
