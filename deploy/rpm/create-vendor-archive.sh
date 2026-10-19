#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Create the vendored Cargo dependency tarball (Source1 in openshell.spec) for
# the offline RPM build. Invoked by the create-archive action in .packit.yaml,
# which exports PACKIT_PROJECT_VERSION; a version may also be passed as $1.
#
# `cargo vendor` prints the cargo config needed to use the vendor directory to
# stdout (only without --quiet, which silences it). `%cargo_prep -v vendor`
# already writes the crates-io -> vendored-sources mapping, but git
# dependencies need their own [source."git+..."] tables or cargo refuses to
# resolve them offline. Capture only those tables into
# vendor/.cargo-git-sources.toml; %prep in openshell.spec appends the file to
# the cargo config the macro writes. Cargo ignores dotfiles inside a directory
# source, so the extra file is harmless.
set -euo pipefail

version=${1:-${PACKIT_PROJECT_VERSION:-}}
if [ -z "${version}" ]; then
  echo "usage: $0 <version> (or set PACKIT_PROJECT_VERSION)" >&2
  exit 1
fi
archive="openshell-${version}-vendor.tar.xz"
git_sources=vendor/.cargo-git-sources.toml

rm -rf vendor
config=$(CARGO_HTTP_TIMEOUT=600 CARGO_NET_RETRY=5 cargo vendor --locked vendor)
printf '%s\n' "${config}" |
  awk '/^\[source\."git\+/ {p=1} /^\[/ && !/^\[source\."git\+/ {p=0} p' \
    >"${git_sources}"
if [ -s "${git_sources}" ]; then
  echo "captured git source replacements:" >&2
  grep '^\[source' "${git_sources}" >&2
else
  rm -f "${git_sources}"
fi

tar -cJf "${archive}" vendor/
rm -rf vendor
