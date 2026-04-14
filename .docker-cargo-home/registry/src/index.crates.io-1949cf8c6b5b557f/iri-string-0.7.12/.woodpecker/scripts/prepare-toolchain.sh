#!/bin/sh
set -eu

cd "$(readlink -f "$(dirname "$0")/../..")"

set -x

RUST_CHANNEL="$1"

# Use the preset for CI environment.
cp .woodpecker/cargo-config.toml ${CARGO_HOME}/config.toml

# The repository should not have a directory which would be used as the cached `$RUSTUP_HOME`.
CACHED_RUSTUP_HOME=${CI_WORKSPACE}/.tmp-rustup-home && test ! -e ${CACHED_RUSTUP_HOME}

# Copy the pre-installed toolchains of the Docker container into the new `$RUSTUP_HOME`.
cp -a /usr/local/rustup ${CACHED_RUSTUP_HOME} && test -d ${CACHED_RUSTUP_HOME}

# Use the new `$RUSTUP_HOME` variable.
export RUSTUP_HOME=${CACHED_RUSTUP_HOME}

# Install the toolchain of the specified version (if not yet available locally).
rustup update --no-self-update ${RUST_CHANNEL} && rustup default ${RUST_CHANNEL}

rustc --version && cargo --version
