#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Start a gateway and the sandbox-shim compute driver for one substrate and
# one explicit privilege setting. Ctrl-C stops everything.
#
#   ./run.sh <firecracker|gvisor> <privileged|nonprivileged>
#
# Inputs (environment):
#   SHIM_ROOTFS_DIR   extracted guest root filesystem (both substrates)
#   SHIM_FIRECRACKER  firecracker binary            (firecracker)
#   SHIM_KERNEL       uncompressed guest kernel     (firecracker)
#   SHIM_RUNSC_DIR    directory containing runsc    (gvisor)
#   SHIM_HELPER_IMAGE Docker image with sh, cp, chown, mkfs.ext4
#                     (default buildpack-deps:26.04)
#   SHIM_PORT         gateway port (default 18780)
set -euo pipefail
umask 077

substrate="${1:-}"
privilege="${2:-}"
case "$substrate/$privilege" in
  firecracker/privileged|firecracker/nonprivileged|gvisor/privileged|gvisor/nonprivileged) ;;
  *) echo "usage: $0 <firecracker|gvisor> <privileged|nonprivileged>" >&2; exit 2 ;;
esac
if [[ "$(id -u)" == 0 ]]; then
  echo "Run this example as a non-root user." >&2
  exit 1
fi
: "${SHIM_ROOTFS_DIR:?set SHIM_ROOTFS_DIR to an extracted guest rootfs}"
helper_image="${SHIM_HELPER_IMAGE:-buildpack-deps:26.04}"
port="${SHIM_PORT:-18780}"

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
example_dir="$PWD"
repo_dir="$(cd ../.. && pwd)"
# The shim is static so it can run from the guest's otherwise empty root.
host_triple="$(rustc -vV | sed -n 's/^host: //p')"
RUSTFLAGS="-C target-feature=+crt-static" cargo build --quiet --release --target "$host_triple"
cargo build --quiet --manifest-path "$repo_dir/Cargo.toml" \
  -p openshell-gateway -p openshell-supervisor -p openshell-cli
shim="$example_dir/target/$host_triple/release/sandbox-shim"
export PATH="$repo_dir/target/debug:$PATH"

cache="$example_dir/target/guest"
mkdir -p "$cache"
# Content digest of the rootfs source tree (names, modes, link targets, file
# bytes), recomputed on every run. Host ownership and mtimes are excluded;
# the driver's ownership transform and the shim are declared separately.
echo "Hashing $SHIM_ROOTFS_DIR"
rootfs_digest="$(tar --sort=name --owner=0 --group=0 --numeric-owner --mtime=@0 \
  -C "$SHIM_ROOTFS_DIR" -cf - . | sha256sum | cut -d' ' -f1)"

substrate_args=()
backend_socket_rel="backend.sock"
if [[ "$substrate" == firecracker ]]; then
  : "${SHIM_FIRECRACKER:?set SHIM_FIRECRACKER}"
  : "${SHIM_KERNEL:?set SHIM_KERNEL}"
  [[ -r /dev/kvm && -w /dev/kvm ]] || { echo "/dev/kvm is not usable" >&2; exit 1; }
  owner=0 workload_id=10001
  [[ "$privilege" == privileged ]] && owner=100000 workload_id=100000
  # Keyed by everything that shapes the image: source content, the ownership
  # transform, and this layout's version.
  image="$cache/workload-v4-$privilege-$rootfs_digest.ext4"
  if [[ ! -s "$image" ]]; then
    size_mib=$(( $(du -sm "$SHIM_ROOTFS_DIR" | cut -f1) + 3072 ))
    echo "Building $image (${size_mib}M; Docker supplies root for ownership only)"
    tmp_name="image.$$.tmp"
    docker run --rm --network none \
      --mount "type=bind,src=$SHIM_ROOTFS_DIR,dst=/src,readonly" \
      --mount "type=bind,src=$cache,dst=/out" \
      --entrypoint /bin/sh "$helper_image" -euc "
        mkdir /r && cp -a /src/. /r/
        mkdir -p /r/proc /r/dev /r/sys /r/tmp /r/sandbox /r/etc/openshell-tls
        chown -R $owner:$owner /r
        chown $workload_id:$workload_id /r/sandbox
        chmod 1777 /r/tmp
        # Native mediation answers DNS on the broker relay only.
        rm -f /r/etc/resolv.conf && echo 'nameserver 127.0.0.53' > /r/etc/resolv.conf
        chown 0:0 /r/etc/resolv.conf && chmod 0644 /r/etc/resolv.conf
        mkfs.ext4 -q -F -L workload -E root_owner=$owner:$owner -d /r /out/$tmp_name ${size_mib}M
        chown $(id -u):$(id -g) /out/$tmp_name"
    mv "$cache/$tmp_name" "$image"
  fi
  substrate_args=(--firecracker "$SHIM_FIRECRACKER" --kernel "$SHIM_KERNEL" --rootfs-image "$image"
    --memory-mib "${SHIM_MEMORY_MIB:-2048}")
else
  : "${SHIM_RUNSC_DIR:?set SHIM_RUNSC_DIR}"
  [[ -x "$SHIM_RUNSC_DIR/runsc" ]] || { echo "runsc not found in $SHIM_RUNSC_DIR" >&2; exit 1; }
  substrate_args=(--runsc-dir "$SHIM_RUNSC_DIR" --rootfs-dir "$SHIM_ROOTFS_DIR" --docker-image "$helper_image")
  backend_socket_rel="chan/backend.sock"
fi

state="$(mktemp -d /tmp/sbx-shim.XXXXXX)"
run_id="${state##*.}"
export OPENSHELL_GATEWAY_ENDPOINT="http://127.0.0.1:$port"
openshell-gateway generate-certs --output-dir "$state/tls" > /dev/null
cat > "$state/gateway.toml" <<TOML
[openshell]
version = 2

[openshell.gateway]
bind_address = "127.0.0.1:$port"
disable_tls = true
compute_driver = "sandbox-shim"

[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.gateway.gateway_jwt]
signing_key_path = "$state/tls/jwt/signing.pem"
public_key_path = "$state/tls/jwt/public.pem"
kid_path = "$state/tls/jwt/kid"
gateway_id = "sandbox-shim-demo"

[openshell.drivers.sandbox-shim]
socket_path = "$state/compute.sock"
isolation_backend = "sandbox-shim"

[[openshell.supervisor.isolation_backends]]
name = "sandbox-shim"
endpoint = { kind = "unix", socket_path = "$state/$backend_socket_rel" }
TOML

children=()
cleanup() {
  trap - EXIT INT TERM
  for ((i=${#children[@]}-1; i>=0; i--)); do
    kill "${children[i]}" 2>/dev/null || true
    wait "${children[i]}" 2>/dev/null || true
  done
  # Only containers started by this run's driver.
  docker ps -aq --filter "label=openshell-sandbox-shim.run=$run_id" \
    | xargs -r docker rm -f > /dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

"$shim" driver --state-dir "$state" --substrate "$substrate" --privilege "$privilege" \
  --rootfs-source-digest "$rootfs_digest" --shim "$shim" --run-id "$run_id" \
  --supervisor "$repo_dir/target/debug/openshell-supervisor" \
  --policy-rules "$repo_dir/crates/openshell-supervisor-network/data/sandbox-policy.rego" \
  --gateway-endpoint "$OPENSHELL_GATEWAY_ENDPOINT" \
  "${substrate_args[@]}" > "$state/driver.log" 2>&1 &
children+=("$!")
for ((i=0; i<100; i++)); do
  [[ -S "$state/compute.sock" ]] && break
  if ! kill -0 "${children[0]}" 2>/dev/null; then cat "$state/driver.log" >&2; exit 1; fi
  sleep 0.1
done
[[ -S "$state/compute.sock" ]] || { echo "driver did not start; see $state/driver.log" >&2; exit 1; }

openshell-gateway --config "$state/gateway.toml" \
  --db-url "sqlite://$state/gateway.db?mode=rwc" > "$state/gateway.log" 2>&1 &
children+=("$!")
echo "$state" > "${SHIM_STATE_FILE:-/dev/null}"
printf 'sandbox-shim: %s, %s\nstate and logs: %s\ngateway: %s\n' \
  "$substrate" "$privilege" "$state" "$OPENSHELL_GATEWAY_ENDPOINT"
wait "${children[1]}"
